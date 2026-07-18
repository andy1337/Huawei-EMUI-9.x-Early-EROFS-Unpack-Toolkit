#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path


SPARSE_MAGIC = 0xED26FF3A
CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4


def convert(sparse_path, raw_path):
    sparse_path = Path(sparse_path)
    raw_path = Path(raw_path)

    with sparse_path.open("rb") as src:
        header = src.read(28)
        if len(header) != 28:
            raise ValueError("short Android sparse header")
        (
            magic,
            major,
            minor,
            file_hdr_sz,
            chunk_hdr_sz,
            block_size,
            total_blocks,
            total_chunks,
            _checksum,
        ) = struct.unpack("<IHHHHIIII", header)
        if magic != SPARSE_MAGIC:
            raise ValueError(f"bad sparse magic: 0x{magic:08x}")
        if major != 1 or file_hdr_sz < 28 or chunk_hdr_sz < 12:
            raise ValueError("unsupported sparse format")
        if file_hdr_sz > 28:
            src.read(file_hdr_sz - 28)

        with raw_path.open("wb") as out:
            for index in range(total_chunks):
                chunk = src.read(12)
                if len(chunk) != 12:
                    raise ValueError(f"short sparse chunk header at {index}")
                chunk_type, _reserved, chunk_blocks, total_sz = struct.unpack("<HHII", chunk)
                if chunk_hdr_sz > 12:
                    src.read(chunk_hdr_sz - 12)

                logical_sz = chunk_blocks * block_size
                payload_sz = total_sz - chunk_hdr_sz
                if chunk_type == CHUNK_RAW:
                    if payload_sz != logical_sz:
                        raise ValueError(
                            f"raw chunk {index} payload {payload_sz}, expected {logical_sz}"
                        )
                    remaining = logical_sz
                    while remaining:
                        data = src.read(min(1024 * 1024, remaining))
                        if not data:
                            raise ValueError(f"short raw chunk data at {index}")
                        out.write(data)
                        remaining -= len(data)
                elif chunk_type == CHUNK_FILL:
                    if payload_sz != 4:
                        raise ValueError(f"fill chunk {index} payload {payload_sz}, expected 4")
                    fill = src.read(4)
                    pattern = fill * (block_size // 4)
                    for _ in range(chunk_blocks):
                        out.write(pattern)
                elif chunk_type == CHUNK_DONT_CARE:
                    if payload_sz:
                        src.read(payload_sz)
                    out.write(b"\0" * logical_sz)
                elif chunk_type == CHUNK_CRC32:
                    if payload_sz != 4:
                        raise ValueError(f"crc chunk {index} payload {payload_sz}, expected 4")
                    src.read(4)
                else:
                    raise ValueError(f"unsupported chunk type 0x{chunk_type:04x} at {index}")

            expected = total_blocks * block_size
            actual = out.tell()
            if actual != expected:
                raise ValueError(f"raw size mismatch: wrote {actual}, expected {expected}")

    return {
        "sparse": str(sparse_path),
        "raw": str(raw_path),
        "block_size": block_size,
        "chunks": total_chunks,
        "raw_size": raw_path.stat().st_size,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Convert an Android sparse image to raw.")
    parser.add_argument("sparse")
    parser.add_argument("raw")
    args = parser.parse_args(argv)

    info = convert(args.sparse, args.raw)
    for key, value in info.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    raise SystemExit(main())
