#!/usr/bin/env python3
import argparse
import struct
import time
from pathlib import Path

from ext4_read import Ext4Image


def inode_offset(img, ino):
    group = (ino - 1) // img.inodes_per_group
    index = (ino - 1) % img.inodes_per_group
    inode_table = img.group_desc(group)
    return inode_table * img.block_size + index * img.inode_size


def replace_file(image, path, data):
    img = Ext4Image(image)
    ino = img.lookup(path)
    inode = img.read_inode(ino)
    runs = img.extent_runs(inode)
    capacity = sum(length for _logical, length, _start in runs) * img.block_size
    if len(data) > capacity:
        raise RuntimeError(f"{path} has capacity {capacity}, new data is {len(data)} bytes")

    with open(image, "r+b") as f:
        written = 0
        for logical, length, start in runs:
            run_size = length * img.block_size
            chunk = data[written : written + run_size]
            f.seek(start * img.block_size)
            f.write(chunk)
            if len(chunk) < run_size:
                f.write(b"\0" * (run_size - len(chunk)))
            written += len(chunk)
            if written >= len(data):
                break

        off = inode_offset(img, ino)
        now = int(time.time())
        f.seek(off + 4)
        f.write(struct.pack("<I", len(data) & 0xFFFFFFFF))
        f.seek(off + 108)
        f.write(struct.pack("<I", (len(data) >> 32) & 0xFFFFFFFF))
        f.seek(off + 12)
        f.write(struct.pack("<I", now))
        f.seek(off + 16)
        f.write(struct.pack("<I", now))

    return {"path": path, "inode": ino, "old_size": inode.size, "new_size": len(data), "capacity": capacity}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Replace an existing file in a raw ext4 image in-place.")
    parser.add_argument("image")
    parser.add_argument("path")
    parser.add_argument("input_file")
    args = parser.parse_args(argv)

    data = Path(args.input_file).read_bytes()
    info = replace_file(args.image, args.path, data)
    for key, value in info.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    raise SystemExit(main())
