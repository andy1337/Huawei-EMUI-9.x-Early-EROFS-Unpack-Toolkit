#!/usr/bin/env python3
import argparse
import stat
import struct
from dataclasses import dataclass
from pathlib import PurePosixPath


EXT4_SUPER_MAGIC = 0xEF53
EXT4_EXTENTS_FL = 0x00080000
EXT4_XATTR_MAGIC = 0xEA020000

EXT4_XATTR_PREFIX = {
    1: "user.",
    2: "system.posix_acl_access",
    3: "system.posix_acl_default",
    4: "trusted.",
    6: "security.",
}


@dataclass
class Inode:
    ino: int
    mode: int
    uid: int
    gid: int
    links_count: int
    size: int
    flags: int
    file_acl: int
    raw: bytes
    block: bytes

    @property
    def type(self):
        return stat.S_IFMT(self.mode)


class Ext4Image:
    def __init__(self, image):
        self.image = image
        self.f = open(image, "rb")
        self.f.seek(1024)
        sb = self.f.read(1024)
        if len(sb) != 1024:
            raise ValueError("short ext4 superblock")
        magic = struct.unpack_from("<H", sb, 56)[0]
        if magic != EXT4_SUPER_MAGIC:
            raise ValueError(f"bad ext4 magic: 0x{magic:04x}")

        self.inodes_count = struct.unpack_from("<I", sb, 0)[0]
        blocks_lo = struct.unpack_from("<I", sb, 4)[0]
        blocks_hi = struct.unpack_from("<I", sb, 336)[0] if len(sb) >= 340 else 0
        self.blocks_count = blocks_lo | (blocks_hi << 32)
        self.block_size = 1024 << struct.unpack_from("<I", sb, 24)[0]
        self.blocks_per_group = struct.unpack_from("<I", sb, 32)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 40)[0]
        self.inode_size = struct.unpack_from("<H", sb, 88)[0]
        desc_size = struct.unpack_from("<H", sb, 254)[0]
        self.desc_size = desc_size or 32
        self.group_count = (self.blocks_count + self.blocks_per_group - 1) // self.blocks_per_group
        self.gdt_offset = self.block_size if self.block_size > 1024 else 2048
        self._inode_cache = {}

    def read_at(self, offset, size):
        self.f.seek(offset)
        data = self.f.read(size)
        if len(data) != size:
            raise EOFError(f"short read at {offset} size {size}")
        return data

    def group_desc(self, group):
        raw = self.read_at(self.gdt_offset + group * self.desc_size, self.desc_size)
        inode_table_lo = struct.unpack_from("<I", raw, 8)[0]
        inode_table_hi = struct.unpack_from("<I", raw, 40)[0] if self.desc_size >= 64 else 0
        return inode_table_lo | (inode_table_hi << 32)

    def read_inode(self, ino):
        cached = self._inode_cache.get(ino)
        if cached is not None:
            return cached

        group = (ino - 1) // self.inodes_per_group
        index = (ino - 1) % self.inodes_per_group
        inode_table = self.group_desc(group)
        raw = self.read_at(inode_table * self.block_size + index * self.inode_size, self.inode_size)
        mode = struct.unpack_from("<H", raw, 0)[0]
        size_lo = struct.unpack_from("<I", raw, 4)[0]
        uid_lo = struct.unpack_from("<H", raw, 2)[0]
        gid_lo = struct.unpack_from("<H", raw, 24)[0]
        links_count = struct.unpack_from("<H", raw, 26)[0]
        flags = struct.unpack_from("<I", raw, 32)[0]
        file_acl_lo = struct.unpack_from("<I", raw, 104)[0]
        size_hi = struct.unpack_from("<I", raw, 108)[0]
        file_acl_hi = struct.unpack_from("<H", raw, 118)[0] if self.inode_size >= 128 else 0
        uid_hi = struct.unpack_from("<H", raw, 120)[0] if self.inode_size >= 128 else 0
        gid_hi = struct.unpack_from("<H", raw, 122)[0] if self.inode_size >= 128 else 0
        size = size_lo | (size_hi << 32)
        inode = Inode(
            ino=ino,
            mode=mode,
            uid=uid_lo | (uid_hi << 16),
            gid=gid_lo | (gid_hi << 16),
            links_count=links_count,
            size=size,
            flags=flags,
            file_acl=file_acl_lo | (file_acl_hi << 32),
            raw=raw,
            block=raw[40:100],
        )
        self._inode_cache[ino] = inode
        return inode

    def extent_runs(self, inode):
        if not inode.flags & EXT4_EXTENTS_FL:
            raise NotImplementedError(f"inode {inode.ino} does not use extents")
        return self._extent_runs_from_block(inode.block)

    def _extent_runs_from_block(self, raw):
        magic, entries, _max_entries, depth, _generation = struct.unpack_from("<HHHHI", raw, 0)
        if magic != 0xF30A:
            raise ValueError("bad extent header")
        runs = []
        if depth == 0:
            for i in range(entries):
                off = 12 + i * 12
                logical, length, start_hi, start_lo = struct.unpack_from("<IHHI", raw, off)
                length &= 0x7FFF
                start = start_lo | (start_hi << 32)
                runs.append((logical, length, start))
            return runs

        for i in range(entries):
            off = 12 + i * 12
            _logical, leaf_lo, leaf_hi, _unused = struct.unpack_from("<IIHH", raw, off)
            leaf = leaf_lo | (leaf_hi << 32)
            child = self.read_at(leaf * self.block_size, self.block_size)
            runs.extend(self._extent_runs_from_block(child))
        return runs

    def read_file(self, ino):
        inode = self.read_inode(ino)
        if inode.type == stat.S_IFLNK and inode.size <= 60 and not (inode.flags & EXT4_EXTENTS_FL):
            return inode.block[: inode.size]
        if inode.size == 0:
            return b""
        out = bytearray(inode.size)
        for logical, length, start in self.extent_runs(inode):
            dst = logical * self.block_size
            take = min(length * self.block_size, max(0, inode.size - dst))
            if take <= 0:
                continue
            out[dst : dst + take] = self.read_at(start * self.block_size, take)
        return bytes(out)

    def _full_xattr_name(self, name_index, short_name):
        prefix = EXT4_XATTR_PREFIX.get(name_index)
        if prefix is None:
            return None
        return prefix + short_name

    def _parse_xattr_entries(self, area, entry_offset, value_base, value_limit):
        attrs = {}
        while entry_offset + 16 <= len(area):
            name_len, name_index, value_offs, value_inum, value_size, _hash = struct.unpack_from(
                "<BBHIII", area, entry_offset
            )
            if name_len == 0 and name_index == 0 and value_offs == 0:
                break
            name_start = entry_offset + 16
            if name_start + name_len > len(area):
                raise RuntimeError("xattr name runs past xattr area")
            if value_inum:
                raise RuntimeError("external xattr inode values are not supported")

            short_name = area[name_start : name_start + name_len].decode(
                "utf-8", "surrogateescape"
            )
            full_name = self._full_xattr_name(name_index, short_name)
            value_start = value_base + value_offs
            if value_start + value_size > value_limit:
                raise RuntimeError("xattr value runs past xattr area")
            if full_name is not None:
                attrs[full_name] = area[value_start : value_start + value_size]
            entry_offset += (16 + name_len + 3) & ~3
        return attrs

    def _read_inline_xattrs(self, inode):
        if self.inode_size <= 128:
            return {}
        extra_isize = struct.unpack_from("<H", inode.raw, 128)[0]
        offset = 128 + extra_isize
        if offset + 4 > len(inode.raw):
            return {}
        area = inode.raw[offset:]
        magic = struct.unpack_from("<I", area, 0)[0]
        if magic == 0:
            return {}
        if magic != EXT4_XATTR_MAGIC:
            raise RuntimeError(f"bad inline xattr magic 0x{magic:08x}")
        return self._parse_xattr_entries(area, 4, 4, len(area))

    def _read_block_xattrs(self, inode):
        if not inode.file_acl:
            return {}
        area = self.read_at(inode.file_acl * self.block_size, self.block_size)
        magic = struct.unpack_from("<I", area, 0)[0]
        if magic != EXT4_XATTR_MAGIC:
            raise RuntimeError(f"bad xattr block magic 0x{magic:08x}")
        return self._parse_xattr_entries(area, 32, 0, len(area))

    def read_xattrs(self, ino):
        inode = self.read_inode(ino)
        attrs = self._read_block_xattrs(inode)
        attrs.update(self._read_inline_xattrs(inode))
        return attrs

    def list_dir_ino(self, ino):
        inode = self.read_inode(ino)
        if inode.type != stat.S_IFDIR:
            raise NotADirectoryError(ino)
        data = self.read_file(ino)
        entries = []
        offset = 0
        while offset + 8 <= len(data):
            child_ino, rec_len, name_len, file_type = struct.unpack_from("<IHBB", data, offset)
            if rec_len < 8:
                break
            if child_ino and name_len:
                name = data[offset + 8 : offset + 8 + name_len].decode("utf-8", "surrogateescape")
                if name not in (".", ".."):
                    entries.append((name, child_ino, file_type))
            offset += rec_len
        return entries

    def lookup(self, path):
        p = PurePosixPath(path)
        ino = 2
        for part in p.parts:
            if part == "/":
                continue
            found = None
            for name, child_ino, _file_type in self.list_dir_ino(ino):
                if name == part:
                    found = child_ino
                    break
            if found is None:
                raise FileNotFoundError(path)
            ino = found
        return ino

    def walk(self, start="/"):
        start_ino = self.lookup(start)
        stack = [(PurePosixPath(start), start_ino)]
        while stack:
            path, ino = stack.pop()
            inode = self.read_inode(ino)
            yield str(path), ino, inode
            if inode.type == stat.S_IFDIR:
                entries = self.list_dir_ino(ino)
                for name, child_ino, _file_type in reversed(entries):
                    stack.append((path / name, child_ino))


def mode_kind(mode):
    t = stat.S_IFMT(mode)
    if t == stat.S_IFDIR:
        return "dir"
    if t == stat.S_IFREG:
        return "file"
    if t == stat.S_IFLNK:
        return "symlink"
    return oct(t)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read files from a raw ext4 image.")
    parser.add_argument("image")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_list = sub.add_parser("list")
    p_list.add_argument("path", nargs="?", default="/")
    p_cat = sub.add_parser("cat")
    p_cat.add_argument("path")
    p_find = sub.add_parser("find")
    p_find.add_argument("pattern")
    args = parser.parse_args(argv)

    img = Ext4Image(args.image)
    if args.cmd == "list":
        for name, ino, file_type in img.list_dir_ino(img.lookup(args.path)):
            inode = img.read_inode(ino)
            print(f"{mode_kind(inode.mode):8} {ino:8d} {inode.size:10d} {args.path.rstrip('/')}/{name}")
    elif args.cmd == "cat":
        ino = img.lookup(args.path)
        data = img.read_file(ino)
        print(data.decode("utf-8", "surrogateescape"), end="")
    elif args.cmd == "find":
        needle = args.pattern.lower()
        for path, ino, inode in img.walk("/"):
            if needle in path.lower():
                print(f"{mode_kind(inode.mode):8} {ino:8d} {inode.size:10d} {path}")


if __name__ == "__main__":
    raise SystemExit(main())
