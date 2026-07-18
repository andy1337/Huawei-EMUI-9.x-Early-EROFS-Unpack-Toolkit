#!/usr/bin/env python3
"""Patch an Android 13 arm64 GSI so Huawei EMUI 9.1 ext4 vendor can mount.

Huawei Kirin970 EMUI 9.1 device trees advertise /vendor as EROFS. When the
vendor partition has been converted to ext4, generic GSI first-stage mount
logic still passes "erofs" to mount(2) and reboots to recovery. This tool
patches the GSI's /system/lib64/libfs_mgr.so so only the /vendor mount target
uses the existing "ext4" rodata string as the filesystem type. Other mounts,
including ODM EROFS, keep their original fstab type.
"""

import argparse
import hashlib
import shutil
import struct
from pathlib import Path

from ext4_read import Ext4Image
from ext4_replace_file import replace_file


SPARSE_MAGIC = 0xED26FF3A
LIB_PATH = "/system/lib64/libfs_mgr.so"
EXT4_LITERAL = b"ext4\0"
NOP = 0xD503201F


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


# This signature is from AOSP/Lineage Android 13 arm64 libfs_mgr around the
# __mount(source, target, fs_type, flags, data) argument setup.
MOUNT_ARG_SIGNATURE = words(
    0x37000820,  # tbnz w0, #0, verbose-log-block
    0xA9472FE3,  # ldp x3, x11, [sp, #0x70]
    0x394002A8,  # ldrb w8, [x21]
    0xF9400AA9,  # ldr x9, [x21, #0x10]
    0xF94033ED,  # ldr x13, [sp, #0x60]
    0x3940016A,  # ldrb w10, [x11]
    0x7200011F,  # tst w8, #1
    0xF940096B,  # ldr x11, [x11, #0x10]
    0x9A8901A0,  # csel x0, x13, x9, eq
    0xF94037ED,  # ldr x13, [sp, #0x68]
    0x3941236C,  # ldrb w12, [x27, #0x48]
    0x7200015F,  # tst w10, #1
    0xF9402F68,  # ldr x8, [x27, #0x58]
    0x9A8B01A1,  # csel x1, x13, x11, eq
    0xF94027EB,  # ldr x11, [sp, #0x48]
    0x385C03A9,  # ldurb w9, [x29, #-0x40]
    0x7200019F,  # tst w12, #1
    0xF85D03AA,  # ldur x10, [x29, #-0x30]
    0x9A880162,  # csel x2, x11, x8, eq
    0xF9402BE8,  # ldr x8, [sp, #0x50]
    0x7200013F,  # tst w9, #1
    0x9A8A0104,  # csel x4, x8, x10, eq
)

PATCHED_STUB_MARKER = words(
    0x9A880162,
    0xF9402BE8,
    0xF940002E,
    0xD28EC5EF,
    0xF2ADCCAF,
    0xF2CDEC8F,
    0xF2E00E4F,
    0xEB0F01DF,
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def write_u32(data, offset, value):
    struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)


def encode_b(pc, target):
    diff = target - pc
    if diff % 4:
        raise ValueError(f"branch target is not 4-byte aligned: pc=0x{pc:x}, target=0x{target:x}")
    imm26 = diff // 4
    if not -(1 << 25) <= imm26 < (1 << 25):
        raise ValueError("branch target is out of range")
    return 0x14000000 | (imm26 & 0x03FFFFFF)


def encode_adrp(rd, pc, target):
    pc_page = pc & ~0xFFF
    target_page = target & ~0xFFF
    diff = target_page - pc_page
    if diff % 0x1000:
        raise ValueError("ADRP page diff is not page-aligned")
    imm = diff // 0x1000
    if not -(1 << 20) <= imm < (1 << 20):
        raise ValueError("ADRP target is out of range")
    imm21 = imm & ((1 << 21) - 1)
    immlo = imm21 & 0x3
    immhi = imm21 >> 2
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd


def encode_add_imm(rd, rn, imm):
    if not 0 <= imm < 0x1000:
        raise ValueError("ADD immediate must fit in 12 bits")
    return 0x91000000 | (imm << 10) | (rn << 5) | rd


def build_stub(cave_off, back_off, ext4_off):
    words = [
        0x9A880162,  # csel x2, x11, x8, eq     ; original fs_type pointer
        0xF9402BE8,  # ldr x8, [sp, #0x50]      ; original flags/options setup
        0xF940002E,  # ldr x14, [x1]            ; target string first 8 bytes
        0xD28EC5EF,  # movz x15, #0x762f        ; "/v"
        0xF2ADCCAF,  # movk x15, #0x6e65, lsl #16
        0xF2CDEC8F,  # movk x15, #0x6f64, lsl #32
        0xF2E00E4F,  # movk x15, #0x72,   lsl #48
        0xEB0F01DF,  # cmp x14, x15             ; "/vendor\0"
        0x54000061,  # b.ne no_vendor
        encode_adrp(2, cave_off + 0x24, ext4_off),
        encode_add_imm(2, 2, ext4_off & 0xFFF),
        0x7200013F,  # tst w9, #1
        0x9A8A0104,  # csel x4, x8, x10, eq
        encode_b(cave_off + 0x34, back_off),
    ]
    return b"".join(struct.pack("<I", word) for word in words)


def find_mount_patch_site(lib):
    start = lib.find(MOUNT_ARG_SIGNATURE)
    if start < 0:
        return None
    if lib.find(MOUNT_ARG_SIGNATURE, start + 1) >= 0:
        raise RuntimeError("mount argument signature is not unique")
    return {
        "signature_off": start,
        "log_branch_off": start,
        "arg_off": start + 0x48,
        "cave_off": start + 0x104,
        # This is the exact return target used by the known-good v2 patch.
        # It re-executes csel x4 once, which is harmless and was boot-tested.
        "back_off": start + 0x54,
    }


def is_already_patched(lib):
    return lib.find(PATCHED_STUB_MARKER) >= 0


def patch_libfs_mgr(lib):
    original_sha = sha256(lib)
    if is_already_patched(lib):
        return lib, {
            "already_patched": True,
            "sha256_before": original_sha,
            "sha256_after": original_sha,
        }

    site = find_mount_patch_site(lib)
    if site is None:
        raise RuntimeError(
            "unsupported libfs_mgr.so: Android 13 mount signature was not found. "
            "Use a compatible AOSP-style arm64 Android 13 GSI build, or inspect this lib manually."
        )

    ext4_off = lib.find(EXT4_LITERAL)
    if ext4_off < 0:
        raise RuntimeError('unsupported libfs_mgr.so: no exact "ext4\\0" literal found')
    if lib.find(EXT4_LITERAL, ext4_off + 1) >= 0:
        raise RuntimeError('unsupported libfs_mgr.so: "ext4\\0" literal is not unique')

    patched = bytearray(lib)
    write_u32(patched, site["log_branch_off"], NOP)
    write_u32(patched, site["arg_off"], encode_b(site["arg_off"], site["cave_off"]))
    stub = build_stub(site["cave_off"], site["back_off"], ext4_off)
    patched[site["cave_off"] : site["cave_off"] + len(stub)] = stub

    return bytes(patched), {
        "already_patched": False,
        "sha256_before": original_sha,
        "sha256_after": sha256(patched),
        "signature_off": f"0x{site['signature_off']:x}",
        "arg_off": f"0x{site['arg_off']:x}",
        "cave_off": f"0x{site['cave_off']:x}",
        "back_off": f"0x{site['back_off']:x}",
        "ext4_literal_off": f"0x{ext4_off:x}",
        "stub_size": len(stub),
    }


def is_android_sparse(path):
    with open(path, "rb") as f:
        raw = f.read(4)
    return len(raw) == 4 and struct.unpack("<I", raw)[0] == SPARSE_MAGIC


def copy_if_needed(input_image, output_image, in_place):
    input_image = Path(input_image)
    if in_place:
        return input_image

    output_image = Path(output_image) if output_image else input_image.with_name(
        f"{input_image.stem}_vendor-ext4-libfs{input_image.suffix or '.img'}"
    )
    if input_image.resolve() != output_image.resolve():
        print(f"copy_image={input_image} -> {output_image}", flush=True)
        shutil.copyfile(input_image, output_image)
    return output_image


def patch_image(args):
    input_image = Path(args.input_image)
    if is_android_sparse(input_image):
        raise RuntimeError("GSI image is Android sparse; convert it to raw ext4 first with emui91_erofs_ext4.py unsparse")

    image_path = input_image if args.dry_run else copy_if_needed(input_image, args.output_image, args.in_place)
    img = Ext4Image(image_path)
    lib_ino = img.lookup(args.lib_path)
    lib_inode = img.read_inode(lib_ino)
    lib_data = img.read_file(lib_ino)
    img.f.close()
    patched_lib, info = patch_libfs_mgr(lib_data)

    if args.dry_run:
        info["dry_run"] = True
        for key, value in info.items():
            print(f"{key}={value}")
        return

    if patched_lib != lib_data:
        result = replace_file(image_path, args.lib_path, patched_lib)
        info.update({f"replace_{key}": value for key, value in result.items()})

    verify_img = Ext4Image(image_path)
    readback = verify_img.read_file(verify_img.lookup(args.lib_path))
    verify_img.f.close()
    if readback != patched_lib:
        raise RuntimeError("readback verification failed after replacing libfs_mgr.so")

    info["image"] = str(image_path)
    info["lib_path"] = args.lib_path
    info["lib_inode"] = lib_ino
    info["lib_old_size"] = lib_inode.size
    info["readback_ok"] = True
    for key, value in info.items():
        print(f"{key}={value}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Patch a raw ext4 Android 13 arm64 GSI so /vendor mounts as ext4 on EMUI 9.1 DT fstab devices."
    )
    parser.add_argument("input_image", help="raw ext4 GSI system image")
    parser.add_argument("output_image", nargs="?", help="patched output image; omitted derives *_vendor-ext4-libfs.img")
    parser.add_argument("--in-place", action="store_true", help="patch input image directly")
    parser.add_argument("--lib-path", default=LIB_PATH)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.in_place and args.output_image:
        parser.error("--in-place cannot be used together with output_image")
    patch_image(args)


if __name__ == "__main__":
    raise SystemExit(main())
