#!/usr/bin/env python3
import argparse
import os
import struct
from pathlib import Path


SPARSE_MAGIC = 0xED26FF3A
CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_DONT_CARE = 0xCAC3


def is_zero(block):
    return not block.strip(b"\0")


def write_chunk(out, chunk_type, blocks, payload=b""):
    total_size = 12 + len(payload)
    out.write(struct.pack("<HHII", chunk_type, 0, blocks, total_size))
    out.write(payload)


def convert(raw_path, sparse_path, block_size):
    raw_path = Path(raw_path)
    sparse_path = Path(sparse_path)
    size = raw_path.stat().st_size
    if size % block_size:
        raise ValueError(f"raw image size must be aligned to {block_size}")

    total_blocks = size // block_size
    chunks = []
    with open(raw_path, "rb") as src:
        block_index = 0
        while block_index < total_blocks:
            block = src.read(block_size)
            if len(block) != block_size:
                raise EOFError("short raw image read")

            zero = is_zero(block)
            start = block_index
            payload = bytearray()
            blocks = 0
            while True:
                blocks += 1
                if not zero:
                    payload += block
                block_index += 1
                if block_index >= total_blocks:
                    break
                pos = src.tell()
                block = src.read(block_size)
                if len(block) != block_size:
                    raise EOFError("short raw image read")
                if is_zero(block) != zero:
                    src.seek(pos)
                    break
            chunks.append((CHUNK_TYPE_DONT_CARE if zero else CHUNK_TYPE_RAW, blocks, bytes(payload)))

    with open(sparse_path, "wb") as out:
        out.write(struct.pack("<IHHHHIIII", SPARSE_MAGIC, 1, 0, 28, 12, block_size, total_blocks, len(chunks), 0))
        for chunk_type, blocks, payload in chunks:
            write_chunk(out, chunk_type, blocks, payload)

    return {
        "raw": str(raw_path),
        "sparse": str(sparse_path),
        "raw_size": size,
        "sparse_size": os.path.getsize(sparse_path),
        "block_size": block_size,
        "blocks": total_blocks,
        "chunks": len(chunks),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Wrap a raw filesystem image in Android sparse format.")
    parser.add_argument("raw")
    parser.add_argument("sparse")
    parser.add_argument("--block-size", type=int, default=4096)
    args = parser.parse_args(argv)

    info = convert(args.raw, args.sparse, args.block_size)
    for key, value in info.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    raise SystemExit(main())
