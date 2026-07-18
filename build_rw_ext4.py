#!/usr/bin/env python3
import argparse
import base64
import json
import math
import os
import stat
import struct
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path


BLOCK_SIZE = 4096
BLOCKS_PER_GROUP = 32768
INODE_SIZE = 512
INODE_EXTRA_ISIZE = 32
FIRST_NORMAL_INO = 11
GROUP_DESC_SIZE = 32

EXT4_SUPER_MAGIC = 0xEF53
EXT4_XATTR_MAGIC = 0xEA020000
EXT4_FEATURE_COMPAT_EXT_ATTR = 0x0008
EXT4_EXTENTS_FL = 0x00080000
EXT4_FEATURE_INCOMPAT_FILETYPE = 0x0002
EXT4_FEATURE_INCOMPAT_EXTENTS = 0x0040
EXT4_FEATURE_RO_COMPAT_LARGE_FILE = 0x0002
EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE = 0x0040

FT_UNKNOWN = 0
FT_REG_FILE = 1
FT_DIR = 2
FT_SYMLINK = 7


@dataclass
class Node:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    size: int
    host_path: str | None = None
    target: str | None = None
    xattrs: dict[str, bytes] = field(default_factory=dict)
    parent: "Node | None" = None
    children: list["Node"] = field(default_factory=list)
    ino: int = 0
    nlink: int = 1
    ext4_size: int = 0
    data_bytes: bytes | None = None
    extents: list[tuple[int, int, int]] = field(default_factory=list)

    @property
    def name(self):
        if self.path == "/":
            return ""
        return self.path.rstrip("/").rsplit("/", 1)[-1]

    @property
    def file_type(self):
        if self.kind == "file":
            return FT_REG_FILE
        if self.kind == "dir":
            return FT_DIR
        if self.kind == "symlink":
            return FT_SYMLINK
        return FT_UNKNOWN


@dataclass
class GroupLayout:
    index: int
    start: int
    end: int
    block_bitmap: int
    inode_bitmap: int
    inode_table: int
    inode_table_blocks: int
    metadata_blocks: set[int] = field(default_factory=set)


def round_up(value, unit):
    return ((value + unit - 1) // unit) * unit


def block_count(size):
    return (size + BLOCK_SIZE - 1) // BLOCK_SIZE


def parent_path(path):
    if path == "/":
        return None
    parts = path.strip("/").split("/")
    if len(parts) == 1:
        return "/"
    return "/" + "/".join(parts[:-1])


def load_nodes(extracted_dir):
    metadata_path = Path(extracted_dir) / "metadata.jsonl"
    if not metadata_path.exists():
        raise FileNotFoundError(f"metadata not found: {metadata_path}")

    nodes = {}
    with open(metadata_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            kind = entry.get("kind")
            if kind not in ("file", "dir", "symlink"):
                continue
            path = entry["path"]
            nodes[path] = Node(
                path=path,
                kind=kind,
                mode=int(entry["mode"]),
                uid=int(entry.get("uid", 0)),
                gid=int(entry.get("gid", 0)),
                size=int(entry.get("size", 0)),
                host_path=entry.get("host_path"),
                target=entry.get("target"),
                xattrs={
                    name: base64.b64decode(value)
                    for name, value in entry.get("xattrs", {}).items()
                },
                nlink=int(entry.get("nlink", 1)),
            )

    if "/" not in nodes:
        nodes["/"] = Node("/", "dir", stat.S_IFDIR | 0o755, 0, 0, 0)

    for path, node in list(nodes.items()):
        if path == "/":
            continue
        ppath = parent_path(path)
        parent = nodes.get(ppath)
        if parent is None:
            parent = Node(ppath, "dir", stat.S_IFDIR | 0o755, 0, 0, 0)
            nodes[ppath] = parent
        node.parent = parent
        parent.children.append(node)

    for node in nodes.values():
        node.children.sort(key=lambda n: n.name.encode("utf-8", "surrogateescape"))

    nodes["/"].ino = 2
    next_ino = FIRST_NORMAL_INO
    for path in sorted((p for p in nodes if p != "/"), key=lambda p: (p.count("/"), p)):
        nodes[path].ino = next_ino
        next_ino += 1
    return nodes


def dir_entry_min_len(name):
    return round_up(8 + len(name.encode("utf-8", "surrogateescape")), 4)


def build_dir_data(node):
    entries = [(".", node, FT_DIR), ("..", node.parent or node, FT_DIR)]
    entries.extend((child.name, child, child.file_type) for child in node.children)
    blocks = []
    current = []
    used = 0

    for name, child, file_type in entries:
        need = dir_entry_min_len(name)
        if current and used + need > BLOCK_SIZE:
            blocks.append(pack_dir_block(current))
            current = []
            used = 0
        current.append((name, child.ino, file_type, need))
        used += need

    if current:
        blocks.append(pack_dir_block(current))
    if not blocks:
        blocks.append(b"\0" * BLOCK_SIZE)
    return b"".join(blocks)


def pack_dir_block(entries):
    out = bytearray(BLOCK_SIZE)
    offset = 0
    for index, (name, ino, file_type, min_len) in enumerate(entries):
        name_bytes = name.encode("utf-8", "surrogateescape")
        rec_len = BLOCK_SIZE - offset if index == len(entries) - 1 else min_len
        struct.pack_into("<IHBB", out, offset, ino, rec_len, len(name_bytes), file_type)
        out[offset + 8 : offset + 8 + len(name_bytes)] = name_bytes
        offset += rec_len
    return bytes(out)


def prepare_node_sizes(nodes):
    data_blocks = 0
    for node in nodes.values():
        if node.kind == "dir":
            node.data_bytes = build_dir_data(node)
            node.ext4_size = len(node.data_bytes)
        elif node.kind == "symlink":
            target = (node.target or "").encode("utf-8", "surrogateescape")
            node.ext4_size = len(target)
            if len(target) > 60:
                node.data_bytes = target
        elif node.kind == "file":
            node.ext4_size = node.size

        if node.kind == "file" or node.data_bytes is not None:
            data_blocks += block_count(node.ext4_size)
    return data_blocks


def compute_layout(total_data_blocks, max_ino, extra_free_mb):
    extra_free_blocks = (extra_free_mb * 1024 * 1024) // BLOCK_SIZE
    groups = 1
    while True:
        inodes_per_group = round_up(max(1024, math.ceil((max_ino + 1) / groups)), 128)
        inode_table_blocks = (inodes_per_group * INODE_SIZE + BLOCK_SIZE - 1) // BLOCK_SIZE
        gdt_blocks = (groups * GROUP_DESC_SIZE + BLOCK_SIZE - 1) // BLOCK_SIZE
        metadata_per_group = 1 + gdt_blocks + 1 + 1 + inode_table_blocks
        total_blocks = total_data_blocks + extra_free_blocks + groups * metadata_per_group
        new_groups = max(1, math.ceil(total_blocks / BLOCKS_PER_GROUP))
        if new_groups == groups:
            break
        groups = new_groups

    total_blocks = total_data_blocks + extra_free_blocks + groups * metadata_per_group
    total_blocks = max(total_blocks, groups * metadata_per_group)
    total_inodes = groups * inodes_per_group
    layouts = []
    for g in range(groups):
        start = g * BLOCKS_PER_GROUP
        end = min(total_blocks, start + BLOCKS_PER_GROUP)
        block_bitmap = start + 1 + gdt_blocks
        inode_bitmap = block_bitmap + 1
        inode_table = inode_bitmap + 1
        metadata = set(range(start, min(end, inode_table + inode_table_blocks)))
        layouts.append(GroupLayout(g, start, end, block_bitmap, inode_bitmap, inode_table, inode_table_blocks, metadata))
    return total_blocks, total_inodes, inodes_per_group, gdt_blocks, layouts


def allocate_data_blocks(nodes, total_blocks, layouts):
    reserved = set()
    for layout in layouts:
        reserved.update(layout.metadata_blocks)
    used = set(reserved)
    cursor = 0

    for node in sorted(nodes.values(), key=lambda n: block_count(n.ext4_size), reverse=True):
        needed = block_count(node.ext4_size) if node.kind == "file" or node.data_bytes is not None else 0
        if needed == 0:
            continue

        logical = 0
        while needed:
            while cursor < total_blocks and cursor in used:
                cursor += 1
            if cursor >= total_blocks:
                raise RuntimeError("ext4 image size estimate was too small")
            run_start = cursor
            run_len = 0
            while cursor < total_blocks and cursor not in used and needed:
                used.add(cursor)
                cursor += 1
                run_len += 1
                needed -= 1
            node.extents.append((logical, run_len, run_start))
            logical += run_len

        if len(node.extents) > 4:
            raise RuntimeError(f"{node.path} needs {len(node.extents)} extents; this simple builder supports 4")

    return reserved, used


def write_at(f, block, data):
    f.seek(block * BLOCK_SIZE)
    f.write(data)


def make_extent_block(extents):
    raw = bytearray(60)
    struct.pack_into("<HHHHI", raw, 0, 0xF30A, len(extents), 4, 0, 0)
    off = 12
    for logical, length, start in extents:
        struct.pack_into("<IHHI", raw, off, logical, length, (start >> 32) & 0xFFFF, start & 0xFFFFFFFF)
        off += 12
    return bytes(raw)


def ext4_xattr_name(name):
    prefixes = (
        ("user.", 1),
        ("trusted.", 4),
        ("security.", 6),
    )
    for prefix, index in prefixes:
        if name.startswith(prefix):
            return index, name[len(prefix) :].encode("utf-8", "surrogateescape")
    return None


def pack_inline_xattrs(xattrs):
    if not xattrs:
        return b""

    normalized = []
    for full_name, value in xattrs.items():
        parsed = ext4_xattr_name(full_name)
        if parsed is None:
            continue
        name_index, short_name = parsed
        normalized.append((name_index, short_name, value))
    if not normalized:
        return b""

    normalized.sort(key=lambda item: (item[0], item[1]))
    available = INODE_SIZE - (128 + INODE_EXTRA_ISIZE)
    raw = bytearray(available)
    struct.pack_into("<I", raw, 0, EXT4_XATTR_MAGIC)

    entry_offset = 4
    raw_value_offset = available
    for name_index, short_name, value in normalized:
        entry_len = round_up(16 + len(short_name), 4)
        value_len = round_up(len(value), 4)
        raw_value_offset -= value_len
        if entry_offset + entry_len + 4 > raw_value_offset:
            raise RuntimeError("inline ext4 xattr area is too small; increase INODE_SIZE")

        struct.pack_into(
            "<BBHIII",
            raw,
            entry_offset,
            len(short_name),
            name_index,
            raw_value_offset - 4,
            0,
            len(value),
            0,
        )
        raw[entry_offset + 16 : entry_offset + 16 + len(short_name)] = short_name
        raw[raw_value_offset : raw_value_offset + len(value)] = value
        entry_offset += entry_len

    return bytes(raw)


def pack_inode(node, now):
    raw = bytearray(INODE_SIZE)
    mode = node.mode
    size = node.ext4_size
    blocks_512 = sum(length for _logical, length, _start in node.extents) * (BLOCK_SIZE // 512)
    links = 1
    if node.kind == "dir":
        links = 2 + sum(1 for child in node.children if child.kind == "dir")
    elif node.kind == "file":
        links = max(1, int(getattr(node, "nlink", 1) or 1))

    struct.pack_into("<HHI", raw, 0, mode & 0xFFFF, node.uid & 0xFFFF, size & 0xFFFFFFFF)
    struct.pack_into("<IIII", raw, 8, now, now, now, 0)
    struct.pack_into("<HHI", raw, 24, node.gid & 0xFFFF, min(links, 0xFFFF), blocks_512)

    if node.kind == "symlink" and node.data_bytes is None:
        target = (node.target or "").encode("utf-8", "surrogateescape")
        raw[40 : 40 + len(target)] = target
    else:
        struct.pack_into("<I", raw, 32, EXT4_EXTENTS_FL)
        raw[40:100] = make_extent_block(node.extents)

    struct.pack_into("<I", raw, 108, (size >> 32) & 0xFFFFFFFF)
    struct.pack_into("<H", raw, 120, node.uid >> 16)
    struct.pack_into("<H", raw, 122, node.gid >> 16)
    struct.pack_into("<H", raw, 128, INODE_EXTRA_ISIZE)
    inline_xattrs = pack_inline_xattrs(node.xattrs)
    if inline_xattrs:
        raw[128 + INODE_EXTRA_ISIZE : 128 + INODE_EXTRA_ISIZE + len(inline_xattrs)] = inline_xattrs
    return bytes(raw)


def write_inode(f, node, layouts, inodes_per_group, now):
    group = (node.ino - 1) // inodes_per_group
    index = (node.ino - 1) % inodes_per_group
    offset = layouts[group].inode_table * BLOCK_SIZE + index * INODE_SIZE
    f.seek(offset)
    f.write(pack_inode(node, now))


def set_bit(bitmap, index):
    bitmap[index // 8] |= 1 << (index % 8)


def make_superblock(total_blocks, total_inodes, free_blocks, free_inodes, inodes_per_group, uuid_bytes, now, label):
    sb = bytearray(1024)
    struct.pack_into("<IIIIII", sb, 0, total_inodes, total_blocks, 0, free_blocks, free_inodes, 0)
    struct.pack_into("<IIIIII", sb, 24, 2, 2, BLOCKS_PER_GROUP, BLOCKS_PER_GROUP, inodes_per_group, now)
    struct.pack_into("<IHHHHHHI", sb, 48, now, 0, 0xFFFF, EXT4_SUPER_MAGIC, 1, 1, 0, now)
    struct.pack_into("<IIHH", sb, 68, 0, 0, 0, 0)
    struct.pack_into("<I", sb, 76, 1)
    struct.pack_into("<IHH", sb, 84, FIRST_NORMAL_INO, INODE_SIZE, 0)
    struct.pack_into(
        "<III",
        sb,
        92,
        EXT4_FEATURE_COMPAT_EXT_ATTR,
        EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS,
        EXT4_FEATURE_RO_COMPAT_LARGE_FILE | EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE,
    )
    sb[104:120] = uuid_bytes
    sb[120:136] = label.encode("ascii", "ignore")[:16].ljust(16, b"\0")
    sb[136:200] = b"/\0"
    struct.pack_into("<H", sb, 254, GROUP_DESC_SIZE)
    struct.pack_into("<I", sb, 264, now)
    struct.pack_into("<HH", sb, 348, INODE_EXTRA_ISIZE, INODE_EXTRA_ISIZE)
    return bytes(sb)


def make_group_desc(layouts, used_blocks, used_inodes, inodes_per_group):
    out = bytearray(round_up(len(layouts) * GROUP_DESC_SIZE, BLOCK_SIZE))
    for layout in layouts:
        blocks_in_group = layout.end - layout.start
        used_block_count = sum(1 for b in range(layout.start, layout.end) if b in used_blocks)
        first_ino = layout.index * inodes_per_group + 1
        last_ino = first_ino + inodes_per_group
        used_inode_count = sum(1 for ino in used_inodes if first_ino <= ino < last_ino)
        used_dirs = sum(1 for ino, kind in used_inodes.items() if kind == "dir" and first_ino <= ino < last_ino)
        free_blocks = blocks_in_group - used_block_count
        free_inodes = inodes_per_group - used_inode_count
        struct.pack_into(
            "<IIIHHHHIHHHH",
            out,
            layout.index * GROUP_DESC_SIZE,
            layout.block_bitmap,
            layout.inode_bitmap,
            layout.inode_table,
            free_blocks,
            free_inodes,
            used_dirs,
            0,
            0,
            0,
            0,
            max(0, free_inodes),
            0,
        )
    return bytes(out)


def write_bitmaps(f, layouts, total_blocks, used_blocks, used_inodes, inodes_per_group):
    for layout in layouts:
        block_bitmap = bytearray(BLOCK_SIZE)
        for local in range(BLOCKS_PER_GROUP):
            global_block = layout.start + local
            if global_block >= total_blocks or global_block in used_blocks:
                set_bit(block_bitmap, local)
        write_at(f, layout.block_bitmap, block_bitmap)

        inode_bitmap = bytearray(BLOCK_SIZE)
        first_ino = layout.index * inodes_per_group + 1
        for local in range(inodes_per_group):
            ino = first_ino + local
            if ino in used_inodes:
                set_bit(inode_bitmap, local)
        for local in range(inodes_per_group, BLOCK_SIZE * 8):
            set_bit(inode_bitmap, local)
        write_at(f, layout.inode_bitmap, inode_bitmap)


def write_node_data(f, nodes):
    for node in nodes.values():
        if not node.extents:
            continue
        if node.kind == "file":
            with open(node.host_path, "rb") as src:
                for _logical, length, start in node.extents:
                    remaining = length * BLOCK_SIZE
                    f.seek(start * BLOCK_SIZE)
                    while remaining:
                        chunk = src.read(min(1024 * 1024, remaining))
                        if not chunk:
                            f.write(b"\0" * remaining)
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
        else:
            data = node.data_bytes or b""
            for logical, length, start in node.extents:
                chunk = data[logical * BLOCK_SIZE : (logical + length) * BLOCK_SIZE]
                chunk = chunk.ljust(length * BLOCK_SIZE, b"\0")
                write_at(f, start, chunk)


def build_ext4(extracted_dir, output, extra_free_mb):
    output = Path(output)
    nodes = load_nodes(extracted_dir)
    total_data_blocks = prepare_node_sizes(nodes)
    max_ino = max(node.ino for node in nodes.values())
    total_blocks, total_inodes, inodes_per_group, gdt_blocks, layouts = compute_layout(
        total_data_blocks, max_ino, extra_free_mb
    )
    reserved, used_blocks = allocate_data_blocks(nodes, total_blocks, layouts)
    used_inodes = {ino: "reserved" for ino in range(1, FIRST_NORMAL_INO)}
    for node in nodes.values():
        used_inodes[node.ino] = node.kind

    free_blocks = total_blocks - len(used_blocks)
    free_inodes = total_inodes - len(used_inodes)
    now = int(time.time())
    fs_uuid = uuid.uuid4().bytes
    gdt = make_group_desc(layouts, used_blocks, used_inodes, inodes_per_group)
    label = output.stem[:16] or "rw_ext4"
    sb = make_superblock(total_blocks, total_inodes, free_blocks, free_inodes, inodes_per_group, fs_uuid, now, label)

    with open(output, "wb") as f:
        f.truncate(total_blocks * BLOCK_SIZE)
        f.seek(1024)
        f.write(sb)
        write_at(f, 1, gdt)

        for layout in layouts[1:]:
            write_at(f, layout.start, sb)
            write_at(f, layout.start + 1, gdt)

        write_bitmaps(f, layouts, total_blocks, used_blocks, used_inodes, inodes_per_group)
        for layout in layouts:
            f.seek(layout.inode_table * BLOCK_SIZE)
            f.write(b"\0" * (layout.inode_table_blocks * BLOCK_SIZE))
        for node in nodes.values():
            write_inode(f, node, layouts, inodes_per_group, now)
        write_node_data(f, nodes)

    return {
        "output": str(output),
        "size": total_blocks * BLOCK_SIZE,
        "blocks": total_blocks,
        "free_blocks": free_blocks,
        "inodes": total_inodes,
        "free_inodes": free_inodes,
        "nodes": len(nodes),
        "xattr_nodes": sum(1 for node in nodes.values() if node.xattrs),
        "xattrs": sum(len(node.xattrs) for node in nodes.values()),
        "data_blocks": total_data_blocks,
        "groups": len(layouts),
        "gdt_blocks": gdt_blocks,
    }


def quick_verify(image):
    with open(image, "rb") as f:
        f.seek(1024 + 56)
        magic = struct.unpack("<H", f.read(2))[0]
        if magic != EXT4_SUPER_MAGIC:
            raise RuntimeError(f"bad ext4 magic: 0x{magic:04x}")
        f.seek(1024)
        sb = f.read(1024)
        block_size = 1024 << struct.unpack_from("<I", sb, 24)[0]
        inode_size = struct.unpack_from("<H", sb, 88)[0]
        incompat = struct.unpack_from("<I", sb, 96)[0]
    return {"block_size": block_size, "inode_size": inode_size, "feature_incompat": incompat}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build a raw read-write ext4 image from an extracted EROFS tree.")
    parser.add_argument("extracted_dir")
    parser.add_argument("output", nargs="?", default="system_rw_ext4.img")
    parser.add_argument("--extra-free-mb", type=int, default=512)
    args = parser.parse_args(argv)

    info = build_ext4(args.extracted_dir, args.output, args.extra_free_mb)
    verify = quick_verify(args.output)
    info.update(verify)
    for key, value in info.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    raise SystemExit(main())
