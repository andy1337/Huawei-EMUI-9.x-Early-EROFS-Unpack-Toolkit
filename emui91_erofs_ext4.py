#!/usr/bin/env python3
"""Huawei EMUI 9.1 early-EROFS unpack/ext4/GSI helper.

This is a stable front-end over the lower-level scripts in this directory.
It is intended for Huawei's early EMUI 9.1 EROFS system/vendor images, where
ordinary upstream EROFS extractors can corrupt compressed file contents.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path


DEFAULTS = {
    "system": {
        "image": "system.img",
        "out_dir": "system_extracted",
        "raw_ext4": "system_rw_ext4.img",
        "sparse_ext4": "system_rw_ext4_sparse.img",
        "extra_free_mb": 512,
    },
    "vendor": {
        "image": "vendor.img",
        "out_dir": "vendor_extracted",
        "raw_ext4": "vendor_rw_ext4_xattr.img",
        "sparse_ext4": "vendor_rw_ext4_xattr_sparse.img",
        "extra_free_mb": 512,
    },
}


def tool_dir():
    return Path(__file__).resolve().parent


def choose_dir(path):
    candidate = Path(path)
    if not candidate.exists():
        return candidate
    try:
        if candidate.is_dir() and not any(candidate.iterdir()):
            return candidate
    except OSError:
        pass

    stamp = time.strftime("%Y%m%d_%H%M%S")
    for index in range(100):
        suffix = stamp if index == 0 else f"{stamp}_{index}"
        trial = candidate.parent / f"{candidate.name}_{suffix}"
        if not trial.exists():
            return trial
    raise RuntimeError(f"cannot choose a free output directory near {path}")


def run_py(script_name, args):
    cmd = [sys.executable, str(tool_dir() / script_name), *[str(arg) for arg in args]]
    print("+ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def defaults_for(partition):
    try:
        return DEFAULTS[partition]
    except KeyError as exc:
        raise SystemExit(f"unsupported partition: {partition}") from exc


def cmd_unpack(args):
    d = defaults_for(args.partition)
    image = args.image or d["image"]
    out_dir = choose_dir(args.out_dir or d["out_dir"])
    run_py(
        "extract_huawei_erofs.py",
        [
            image,
            out_dir,
            "--workers",
            args.workers,
            "--symlink-mode",
            args.symlink_mode,
        ],
    )
    print(f"partition={args.partition}")
    print(f"image={image}")
    print(f"out_dir={out_dir}")


def cmd_pack_ext4(args):
    d = defaults_for(args.partition)
    extracted_dir = args.extracted_dir or d["out_dir"]
    raw_ext4 = args.raw_ext4 or d["raw_ext4"]
    extra_free_mb = args.extra_free_mb if args.extra_free_mb is not None else d["extra_free_mb"]

    run_py("build_rw_ext4.py", [extracted_dir, raw_ext4, "--extra-free-mb", extra_free_mb])

    if not args.no_verify:
        run_py("verify_rw_ext4.py", [extracted_dir, raw_ext4, "--extra-free-mb", extra_free_mb])

    if args.sparse:
        sparse_ext4 = args.sparse_ext4 or d["sparse_ext4"]
        run_py("raw_to_android_sparse.py", [raw_ext4, sparse_ext4, "--block-size", args.sparse_block_size])
        print(f"sparse_ext4={sparse_ext4}")

    print(f"partition={args.partition}")
    print(f"extracted_dir={extracted_dir}")
    print(f"raw_ext4={raw_ext4}")


def cmd_unpack_ext4(args):
    run_py(
        "extract_ext4_image.py",
        [
            args.image,
            args.out_dir,
            "--workers",
            args.workers,
            "--symlink-mode",
            args.symlink_mode,
            "--file-data-mode",
            args.file_data_mode,
            *(["--patch-libfs-vendor-ext4"] if args.patch_libfs_vendor_ext4 else []),
        ],
    )


def cmd_convert(args):
    d = defaults_for(args.partition)
    image = args.image or d["image"]
    raw_ext4 = args.raw_ext4 or d["raw_ext4"]
    work_dir = Path(args.reuse_extracted) if args.reuse_extracted else choose_dir(args.work_dir or d["out_dir"])
    extra_free_mb = args.extra_free_mb if args.extra_free_mb is not None else d["extra_free_mb"]

    if args.reuse_extracted:
        print(f"reuse_extracted={work_dir}")
    else:
        run_py(
            "extract_huawei_erofs.py",
            [
                image,
                work_dir,
                "--workers",
                args.workers,
                "--symlink-mode",
                args.symlink_mode,
            ],
        )

    run_py("build_rw_ext4.py", [work_dir, raw_ext4, "--extra-free-mb", extra_free_mb])

    if not args.no_verify:
        run_py("verify_rw_ext4.py", [work_dir, raw_ext4, "--extra-free-mb", extra_free_mb])

    if args.sparse:
        sparse_ext4 = args.sparse_ext4 or d["sparse_ext4"]
        run_py("raw_to_android_sparse.py", [raw_ext4, sparse_ext4, "--block-size", args.sparse_block_size])
        print(f"sparse_ext4={sparse_ext4}")

    print(f"partition={args.partition}")
    print(f"image={image}")
    print(f"extracted_dir={work_dir}")
    print(f"raw_ext4={raw_ext4}")


def cmd_verify(args):
    d = defaults_for(args.partition)
    extracted_dir = args.extracted_dir or d["out_dir"]
    raw_ext4 = args.raw_ext4 or d["raw_ext4"]
    extra_free_mb = args.extra_free_mb if args.extra_free_mb is not None else d["extra_free_mb"]
    run_py("verify_rw_ext4.py", [extracted_dir, raw_ext4, "--extra-free-mb", extra_free_mb])


def cmd_sparse(args):
    run_py("raw_to_android_sparse.py", [args.raw_ext4, args.sparse_ext4, "--block-size", args.block_size])


def cmd_unsparse(args):
    run_py("android_sparse_to_raw.py", [args.sparse_image, args.raw_image])


def cmd_patch_gsi(args):
    run_py(
        "patch_gsi_ext4_vendor.py",
        [
            args.input_image,
            *( [args.output_image] if args.output_image else [] ),
            *( ["--in-place"] if args.in_place else [] ),
            "--lib-path",
            args.lib_path,
            *( ["--dry-run"] if args.dry_run else [] ),
        ],
    )


def build_parser():
    parser = argparse.ArgumentParser(
        description="Unpack Huawei EMUI 9.1 early EROFS images, build RW ext4 images, and patch GSI vendor mounting."
    )
    parser.add_argument(
        "--partition",
        choices=sorted(DEFAULTS),
        default="system",
        help="select default filenames and free-space sizing",
    )
    partition_parent = argparse.ArgumentParser(add_help=False)
    partition_parent.add_argument(
        "--partition",
        choices=sorted(DEFAULTS),
        default=argparse.SUPPRESS,
        help="select default filenames and free-space sizing",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "unpack",
        parents=[partition_parent],
        help="extract and verify a Huawei EMUI 9.1 EROFS image",
    )
    p.add_argument("image", nargs="?")
    p.add_argument("out_dir", nargs="?")
    p.add_argument("--workers", type=int, default=0, help="0 means os.cpu_count()")
    p.add_argument("--symlink-mode", choices=("auto", "marker", "symlink"), default="auto")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser(
        "pack-ext4",
        parents=[partition_parent],
        help="build a raw RW ext4 image from an extracted tree",
    )
    p.add_argument("extracted_dir", nargs="?")
    p.add_argument("raw_ext4", nargs="?")
    p.add_argument("--extra-free-mb", type=int)
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--sparse", action="store_true", help="also write Android sparse output")
    p.add_argument("--sparse-ext4")
    p.add_argument("--sparse-block-size", type=int, default=4096)
    p.set_defaults(func=cmd_pack_ext4)

    p = sub.add_parser(
        "unpack-ext4",
        help="extract a raw ext4 Android image into metadata.jsonl",
    )
    p.add_argument("image")
    p.add_argument("out_dir", nargs="?", default="ext4_extracted")
    p.add_argument("--workers", type=int, default=0, help="0 means os.cpu_count()")
    p.add_argument("--symlink-mode", choices=("auto", "marker", "symlink", "none"), default="auto")
    p.add_argument(
        "--file-data-mode",
        choices=("tree", "flat"),
        default="tree",
        help="flat stores file payloads by inode under .file_data to avoid Windows case collisions",
    )
    p.add_argument("--patch-libfs-vendor-ext4", action="store_true")
    p.set_defaults(func=cmd_unpack_ext4)

    p = sub.add_parser(
        "convert",
        parents=[partition_parent],
        help="unpack EROFS, build RW ext4, verify, and optionally sparse-wrap",
    )
    p.add_argument("image", nargs="?")
    p.add_argument("raw_ext4", nargs="?")
    p.add_argument("--work-dir")
    p.add_argument("--reuse-extracted")
    p.add_argument("--workers", type=int, default=0, help="0 means os.cpu_count()")
    p.add_argument("--symlink-mode", choices=("auto", "marker", "symlink"), default="auto")
    p.add_argument("--extra-free-mb", type=int)
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--sparse", action="store_true", help="also write Android sparse output")
    p.add_argument("--sparse-ext4")
    p.add_argument("--sparse-block-size", type=int, default=4096)
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser(
        "verify",
        parents=[partition_parent],
        help="verify a generated raw ext4 image against metadata.jsonl",
    )
    p.add_argument("extracted_dir", nargs="?")
    p.add_argument("raw_ext4", nargs="?")
    p.add_argument("--extra-free-mb", type=int)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("sparse", help="convert a raw ext4 image to Android sparse")
    p.add_argument("raw_ext4")
    p.add_argument("sparse_ext4")
    p.add_argument("--block-size", type=int, default=4096)
    p.set_defaults(func=cmd_sparse)

    p = sub.add_parser("unsparse", help="convert an Android sparse image to raw")
    p.add_argument("sparse_image")
    p.add_argument("raw_image")
    p.set_defaults(func=cmd_unsparse)

    p = sub.add_parser("patch-gsi", help="patch raw ext4 Android 13 arm64 GSI libfs_mgr.so for ext4 /vendor")
    p.add_argument("input_image")
    p.add_argument("output_image", nargs="?")
    p.add_argument("--in-place", action="store_true")
    p.add_argument("--lib-path", default="/system/lib64/libfs_mgr.so")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_patch_gsi)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
