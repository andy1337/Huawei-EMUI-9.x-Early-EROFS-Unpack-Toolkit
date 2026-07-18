#!/usr/bin/env python3
import argparse
import hashlib
import os
import struct

import build_rw_ext4 as b


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inode_offset(node, layouts, inodes_per_group):
    group = (node.ino - 1) // inodes_per_group
    index = (node.ino - 1) % inodes_per_group
    return layouts[group].inode_table * b.BLOCK_SIZE + index * b.INODE_SIZE


def read_image_data(f, node):
    remaining = node.ext4_size
    out = bytearray()
    for logical, length, start in node.extents:
        take = min(remaining, length * b.BLOCK_SIZE)
        f.seek(start * b.BLOCK_SIZE)
        out += f.read(take)
        remaining -= take
    return bytes(out[: node.ext4_size])


def hash_image_data(f, node):
    h = hashlib.sha256()
    remaining = node.ext4_size
    for _logical, length, start in node.extents:
        take = min(remaining, length * b.BLOCK_SIZE)
        f.seek(start * b.BLOCK_SIZE)
        while take:
            chunk = f.read(min(1024 * 1024, take))
            if not chunk:
                raise EOFError(f"short read from ext4 image for {node.path}")
            h.update(chunk)
            take -= len(chunk)
            remaining -= len(chunk)
    return h.hexdigest()


def ext4_full_xattr_name(name_index, name):
    prefixes = {
        1: "user.",
        4: "trusted.",
        6: "security.",
    }
    prefix = prefixes.get(name_index)
    if prefix is None:
        return None
    return prefix + name


def read_inline_xattrs(raw_inode):
    extra_isize = struct.unpack_from("<H", raw_inode, 128)[0]
    offset = 128 + extra_isize
    if offset + 4 > len(raw_inode):
        return {}

    area = raw_inode[offset:]
    magic = struct.unpack_from("<I", area, 0)[0]
    if magic == 0:
        return {}
    if magic != b.EXT4_XATTR_MAGIC:
        raise RuntimeError(f"bad inline xattr magic 0x{magic:08x}")

    attrs = {}
    entry_offset = 4
    while entry_offset + 16 <= len(area):
        name_len, name_index, value_offs, value_inum, value_size, _hash = struct.unpack_from(
            "<BBHIII", area, entry_offset
        )
        if name_len == 0 and name_index == 0 and value_offs == 0:
            break
        if value_inum:
            raise RuntimeError("external xattr inode is not supported by this verifier")
        if entry_offset + 16 + name_len > len(area):
            raise RuntimeError("inline xattr name runs past inode")
        value_start = 4 + value_offs
        if value_start + value_size > len(area):
            raise RuntimeError("inline xattr value runs past inode")

        short_name = area[entry_offset + 16 : entry_offset + 16 + name_len].decode(
            "utf-8", "surrogateescape"
        )
        full_name = ext4_full_xattr_name(name_index, short_name)
        if full_name is not None:
            attrs[full_name] = area[value_start : value_start + value_size]
        entry_offset += b.round_up(16 + name_len, 4)
    return attrs


def verify(extracted_dir, image, extra_free_mb):
    nodes = b.load_nodes(extracted_dir)
    total_data_blocks = b.prepare_node_sizes(nodes)
    max_ino = max(node.ino for node in nodes.values())
    total_blocks, total_inodes, inodes_per_group, _gdt_blocks, layouts = b.compute_layout(
        total_data_blocks, max_ino, extra_free_mb
    )
    _reserved, _used_blocks = b.allocate_data_blocks(nodes, total_blocks, layouts)

    expected_size = total_blocks * b.BLOCK_SIZE
    actual_size = os.path.getsize(image)
    failures = []
    if actual_size != expected_size:
        failures.append(("image-size", "/", f"actual={actual_size} expected={expected_size}"))

    with open(image, "rb") as f:
        f.seek(1024 + 56)
        magic = struct.unpack("<H", f.read(2))[0]
        if magic != b.EXT4_SUPER_MAGIC:
            failures.append(("super", "/", f"bad magic 0x{magic:04x}"))

        checked = 0
        for node in nodes.values():
            f.seek(inode_offset(node, layouts, inodes_per_group))
            raw_inode = f.read(b.INODE_SIZE)
            mode = struct.unpack_from("<H", raw_inode, 0)[0]
            size_lo = struct.unpack_from("<I", raw_inode, 4)[0]
            size_hi = struct.unpack_from("<I", raw_inode, 108)[0]
            inode_size = size_lo | (size_hi << 32)
            if mode != (node.mode & 0xFFFF):
                failures.append(("inode-mode", node.path, f"actual={oct(mode)} expected={oct(node.mode & 0xFFFF)}"))
            if inode_size != node.ext4_size:
                failures.append(("inode-size", node.path, f"actual={inode_size} expected={node.ext4_size}"))

            try:
                actual_xattrs = read_inline_xattrs(raw_inode)
                if actual_xattrs != node.xattrs:
                    failures.append(
                        (
                            "xattrs",
                            node.path,
                            f"actual={sorted(actual_xattrs)} expected={sorted(node.xattrs)}",
                        )
                    )
            except Exception as exc:
                failures.append(("xattrs", node.path, f"{type(exc).__name__}: {exc}"))

            if node.kind == "file":
                image_sha = hash_image_data(f, node)
                source_sha = sha256_file(node.host_path)
                if image_sha != source_sha:
                    failures.append(("file-sha256", node.path, f"image={image_sha} source={source_sha}"))
            elif node.kind == "dir":
                image_data = read_image_data(f, node)
                if image_data != node.data_bytes:
                    failures.append(("dir-data", node.path, "directory block mismatch"))
            elif node.kind == "symlink":
                target = (node.target or "").encode("utf-8", "surrogateescape")
                if node.data_bytes is None:
                    actual = raw_inode[40 : 40 + len(target)]
                else:
                    actual = read_image_data(f, node)
                if actual != target:
                    failures.append(("symlink", node.path, "target mismatch"))

            checked += 1
            if checked % 1000 == 0:
                print(f"checked={checked}/{len(nodes)} failures={len(failures)}", flush=True)

    return nodes, failures


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify the generated raw ext4 image against extracted files.")
    parser.add_argument("extracted_dir")
    parser.add_argument("image")
    parser.add_argument("--extra-free-mb", type=int, default=512)
    args = parser.parse_args(argv)

    nodes, failures = verify(args.extracted_dir, args.image, args.extra_free_mb)
    print(f"nodes={len(nodes)} failures={len(failures)}")
    for kind, path, detail in failures[:100]:
        print(f"{kind} {path}: {detail}")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
