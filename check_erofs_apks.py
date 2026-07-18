#!/usr/bin/env python3
import argparse
import bisect
import io
import os
import stat
import struct
import sys
import time
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath


SPARSE_MAGIC = 0xED26FF3A
CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4

EROFS_SUPER_OFFSET = 1024
EROFS_MAGIC = 0xE0F5E1E2

EROFS_FT_REG_FILE = 1
EROFS_FT_DIR = 2
EROFS_FT_SYMLINK = 7

EROFS_INODE_FLAT_PLAIN = 0
EROFS_INODE_COMPRESSED_LEGACY = 1
EROFS_INODE_FLAT_INLINE = 2
Z_EROFS_CLUSTER_TYPE_PLAIN = 0
Z_EROFS_CLUSTER_TYPE_HEAD = 1
Z_EROFS_CLUSTER_TYPE_NONHEAD = 2
Z_EROFS_CLUSTER_TYPE_HEAD2 = 3
Z_EROFS_VLE_DI_D0_CBLKCNT = 0x0800

EROFS_XATTR_INDEX_PREFIX = {
    1: "user.",
    2: "system.posix_acl_access",
    3: "system.posix_acl_default",
    4: "trusted.",
    5: "lustre.",
    6: "security.",
}


class SparseReader:
    def __init__(self, image_path):
        self.image_path = image_path
        self.f = open(image_path, "rb")
        header = self.f.read(28)
        if len(header) != 28:
            raise ValueError("short Android sparse header")
        (
            magic,
            major,
            minor,
            file_hdr_sz,
            chunk_hdr_sz,
            blk_sz,
            total_blks,
            total_chunks,
            checksum,
        ) = struct.unpack("<IHHHHIIII", header)
        if magic != SPARSE_MAGIC:
            raise ValueError(f"{image_path!r} is not an Android sparse image")
        if file_hdr_sz < 28 or chunk_hdr_sz < 12:
            raise ValueError("unsupported Android sparse header sizes")

        self.block_size = blk_sz
        self.logical_size = total_blks * blk_sz
        self.segments = []

        if file_hdr_sz > 28:
            self.f.seek(file_hdr_sz)

        logical = 0
        for chunk_index in range(total_chunks):
            chunk_off = self.f.tell()
            raw = self.f.read(chunk_hdr_sz)
            if len(raw) != chunk_hdr_sz:
                raise ValueError(f"short sparse chunk header at chunk {chunk_index}")
            chunk_type, _reserved, chunk_sz, total_sz = struct.unpack("<HHII", raw[:12])
            payload_sz = total_sz - chunk_hdr_sz
            logical_sz = chunk_sz * blk_sz

            if chunk_type == CHUNK_TYPE_RAW:
                if payload_sz != logical_sz:
                    raise ValueError(
                        f"raw sparse chunk {chunk_index} has payload {payload_sz}, expected {logical_sz}"
                    )
                self.segments.append((logical, logical + logical_sz, "raw", self.f.tell(), None))
                self.f.seek(payload_sz, os.SEEK_CUR)
                logical += logical_sz
            elif chunk_type == CHUNK_TYPE_FILL:
                fill = self.f.read(4)
                if len(fill) != 4:
                    raise ValueError(f"short fill sparse chunk at chunk {chunk_index}")
                if payload_sz > 4:
                    self.f.seek(payload_sz - 4, os.SEEK_CUR)
                self.segments.append((logical, logical + logical_sz, "fill", None, fill))
                logical += logical_sz
            elif chunk_type == CHUNK_TYPE_DONT_CARE:
                if payload_sz:
                    self.f.seek(payload_sz, os.SEEK_CUR)
                self.segments.append((logical, logical + logical_sz, "zero", None, None))
                logical += logical_sz
            elif chunk_type == CHUNK_TYPE_CRC32:
                if payload_sz:
                    self.f.seek(payload_sz, os.SEEK_CUR)
            else:
                raise ValueError(
                    f"unsupported sparse chunk type 0x{chunk_type:04x} at chunk {chunk_index}, offset {chunk_off}"
                )

        self.starts = [segment[0] for segment in self.segments]

    def read_at(self, offset, size):
        if size <= 0:
            return b""
        end = offset + size
        if offset < 0 or end > self.logical_size:
            raise ValueError(f"read outside logical image: offset={offset}, size={size}")

        out = bytearray()
        while offset < end:
            idx = bisect.bisect_right(self.starts, offset) - 1
            if idx < 0:
                raise ValueError(f"read before first sparse segment at offset {offset}")
            seg_start, seg_end, seg_kind, file_off, fill = self.segments[idx]
            take = min(end, seg_end) - offset
            if take <= 0:
                raise ValueError(f"sparse segment gap at offset {offset}")

            if seg_kind == "raw":
                self.f.seek(file_off + offset - seg_start)
                data = self.f.read(take)
                if len(data) != take:
                    raise ValueError(f"short image read at logical offset {offset}")
                out += data
            elif seg_kind == "zero":
                out += b"\0" * take
            elif seg_kind == "fill":
                rel = offset - seg_start
                repeated = fill * ((take + (rel % 4) + 3) // 4 + 1)
                out += repeated[rel % 4 : rel % 4 + take]
            offset += take
        return bytes(out)


class RawReader:
    def __init__(self, image_path):
        self.image_path = image_path
        self.f = open(image_path, "rb")
        self.logical_size = os.path.getsize(image_path)
        self.block_size = 4096

    def read_at(self, offset, size):
        if size <= 0:
            return b""
        end = offset + size
        if offset < 0 or end > self.logical_size:
            raise ValueError(f"read outside raw image: offset={offset}, size={size}")
        self.f.seek(offset)
        data = self.f.read(size)
        if len(data) != size:
            raise ValueError(f"short raw image read at offset {offset}")
        return data


def open_image_reader(image_path):
    with open(image_path, "rb") as f:
        header = f.read(4)
    if len(header) != 4:
        raise ValueError(f"{image_path!r} is too small")
    magic = struct.unpack("<I", header)[0]
    if magic == SPARSE_MAGIC:
        return SparseReader(image_path)
    return RawReader(image_path)


def lz4_raw_decompress(src, min_output_size):
    out = bytearray()
    i = 0
    n = len(src)

    while len(out) < min_output_size:
        if i >= n:
            raise EOFError(f"LZ4 stream ended after {len(out)} bytes, needed {min_output_size}")
        token = src[i]
        i += 1

        lit_len = token >> 4
        if lit_len == 15:
            while True:
                if i >= n:
                    raise EOFError("LZ4 literal length overflow")
                value = src[i]
                i += 1
                lit_len += value
                if value != 255:
                    break

        if i + lit_len > n:
            raise EOFError("LZ4 literals run past compressed cluster")
        out += src[i : i + lit_len]
        i += lit_len
        if len(out) >= min_output_size:
            break

        if i + 2 > n:
            raise EOFError("LZ4 stream missing match offset")
        match_offset = src[i] | (src[i + 1] << 8)
        i += 2
        if match_offset == 0:
            raise ValueError("LZ4 match offset is zero")

        match_len = token & 0x0F
        if match_len == 15:
            while True:
                if i >= n:
                    raise EOFError("LZ4 match length overflow")
                value = src[i]
                i += 1
                match_len += value
                if value != 255:
                    break
        match_len += 4

        start = len(out) - match_offset
        if start < 0:
            raise ValueError(f"LZ4 match offset {match_offset} before output start")
        for _ in range(match_len):
            out.append(out[start])
            start += 1
            if len(out) >= min_output_size:
                break

    return bytes(out[:min_output_size])


@dataclass
class Inode:
    nid: int
    offset: int
    version: int
    layout: int
    xattr_count: int
    mode: int
    nlink: int
    size: int
    u: int
    ino: int
    uid: int
    gid: int
    inode_size: int

    @property
    def type(self):
        return stat.S_IFMT(self.mode)

    @property
    def data_offset(self):
        if self.xattr_count:
            xattr_size = 12 + 4 * (self.xattr_count - 1)
        else:
            xattr_size = 0
        return self.offset + self.inode_size + xattr_size

    @property
    def compressed_index_offset(self):
        # Full legacy VLE indexes begin after the 8-byte z_erofs_map_header
        # and the 8-byte legacy padding.  The map header itself is 8-byte
        # aligned after the inode/xattr body.
        aligned = (self.data_offset + 7) & ~7
        return aligned + 16


class HuaweiErofs:
    def __init__(self, image_path):
        self.reader = open_image_reader(image_path)
        sb = self.reader.read_at(EROFS_SUPER_OFFSET, 128)
        magic = struct.unpack_from("<I", sb, 0)[0]
        if magic != EROFS_MAGIC:
            raise ValueError(f"EROFS superblock magic not found at offset {EROFS_SUPER_OFFSET}")

        self.block_bits = sb[12]
        self.block_size = 1 << self.block_bits
        self.root_nid = struct.unpack_from("<H", sb, 14)[0]
        self.blocks = struct.unpack_from("<I", sb, 36)[0]
        self.meta_blkaddr = struct.unpack_from("<I", sb, 40)[0]
        self.xattr_blkaddr = struct.unpack_from("<I", sb, 44)[0]
        self.feature_incompat = struct.unpack_from("<I", sb, 80)[0]
        self._inode_cache = {}
        self._shared_xattr_cache = {}
        self.layout_counter = Counter()
        self.index_type_counter = Counter()

    def read_inode(self, nid):
        cached = self._inode_cache.get(nid)
        if cached is not None:
            return cached

        offset = self.meta_blkaddr * self.block_size + nid * 32
        raw = self.reader.read_at(offset, 96)
        i_format, xattr_count, mode = struct.unpack_from("<HHH", raw, 0)
        version = i_format & 1
        layout = (i_format >> 1) & 7

        if version == 0:
            (
                _fmt,
                xattr_count,
                mode,
                nlink,
                size,
                _reserved,
                u,
                ino,
                uid,
                gid,
                _reserved2,
            ) = struct.unpack_from("<HHHHII I I HH I", raw, 0)
            inode_size = 32
        else:
            (
                _fmt,
                xattr_count,
                mode,
                _reserved,
                size,
                u,
                ino,
                uid,
                gid,
                _ctime,
                _ctime_nsec,
                nlink,
            ) = struct.unpack_from("<HHHHQ I I I I Q I I", raw, 0)
            inode_size = 64

        inode = Inode(
            nid=nid,
            offset=offset,
            version=version,
            layout=layout,
            xattr_count=xattr_count,
            mode=mode,
            nlink=nlink,
            size=size,
            u=u,
            ino=ino,
            uid=uid,
            gid=gid,
            inode_size=inode_size,
        )
        self._inode_cache[nid] = inode
        self.layout_counter[layout] += 1
        return inode

    def _parse_xattr_entry(self, raw, offset):
        if offset + 4 > len(raw):
            return None
        name_len, name_index, value_size = struct.unpack_from("<BBH", raw, offset)
        if name_len == 0 and name_index == 0 and value_size == 0:
            return None

        entry_size = (4 + name_len + value_size + 3) & ~3
        if entry_size <= 0 or offset + entry_size > len(raw):
            return None

        name_start = offset + 4
        name = raw[name_start : name_start + name_len].decode("utf-8", "surrogateescape")
        value_start = name_start + name_len
        value = raw[value_start : value_start + value_size]
        prefix = EROFS_XATTR_INDEX_PREFIX.get(name_index & 0x7F, "")
        return prefix + name, value, entry_size

    def _read_shared_xattr(self, xattr_id):
        cached = self._shared_xattr_cache.get(xattr_id)
        if cached is not None:
            return cached

        offset = self.xattr_blkaddr * self.block_size + 4 * xattr_id
        header = self.reader.read_at(offset, 4)
        name_len, _name_index, value_size = struct.unpack("<BBH", header)
        entry_size = (4 + name_len + value_size + 3) & ~3
        raw = self.reader.read_at(offset, entry_size)
        parsed = self._parse_xattr_entry(raw, 0)
        self._shared_xattr_cache[xattr_id] = parsed
        return parsed

    def read_xattrs(self, nid):
        inode = self.read_inode(nid)
        if not inode.xattr_count:
            return {}

        xattr_size = inode.data_offset - inode.offset - inode.inode_size
        if xattr_size < 12:
            return {}

        raw = self.reader.read_at(inode.offset + inode.inode_size, xattr_size)
        shared_count = raw[4]
        attrs = {}

        if shared_count <= 128:
            for index in range(shared_count):
                id_offset = 12 + index * 4
                if id_offset + 4 > len(raw):
                    break
                xattr_id = struct.unpack_from("<I", raw, id_offset)[0]
                parsed = self._read_shared_xattr(xattr_id)
                if parsed is not None:
                    name, value, _entry_size = parsed
                    attrs[name] = value

        offset = 12 + shared_count * 4
        while offset + 4 <= len(raw):
            parsed = self._parse_xattr_entry(raw, offset)
            if parsed is None:
                break
            full_name, value, entry_size = parsed
            attrs[full_name] = value
            offset += entry_size

        return attrs

    def read_file(self, nid):
        inode = self.read_inode(nid)
        if inode.size == 0:
            return b""

        if inode.layout == EROFS_INODE_FLAT_PLAIN:
            return self.reader.read_at(inode.u * self.block_size, inode.size)
        if inode.layout == EROFS_INODE_FLAT_INLINE:
            # Flat inline stores complete filesystem blocks at raw_blkaddr and
            # only packs the final partial tail after the inode body.
            full_size = inode.size & ~(self.block_size - 1)
            tail_size = inode.size - full_size
            data = bytearray()
            if full_size:
                data += self.reader.read_at(inode.u * self.block_size, full_size)
            if tail_size:
                data += self.reader.read_at(inode.data_offset, tail_size)
            return bytes(data)
        if inode.layout == EROFS_INODE_COMPRESSED_LEGACY:
            return self._read_legacy_compressed(inode)
        raise NotImplementedError(f"unsupported EROFS data layout {inode.layout} for nid {nid}")

    def _read_legacy_compressed(self, inode):
        logical_clusters = (inode.size + self.block_size - 1) // self.block_size
        index_offset = inode.compressed_index_offset
        indexes = []

        for lcn in range(logical_clusters):
            advise, clusterofs, blkaddr = struct.unpack(
                "<HHI", self.reader.read_at(index_offset + lcn * 8, 8)
            )
            cluster_type = advise & 3
            self.index_type_counter[cluster_type] += 1
            entry = {
                "lcn": lcn,
                "type": cluster_type,
                "clusterofs": clusterofs & (self.block_size - 1),
                "raw_clusterofs": clusterofs,
                "u": blkaddr,
            }
            if cluster_type == Z_EROFS_CLUSTER_TYPE_NONHEAD:
                entry["delta0"] = blkaddr & 0xFFFF
                entry["delta1"] = (blkaddr >> 16) & 0xFFFF
            else:
                entry["blkaddr"] = blkaddr
            indexes.append(entry)

        groups = []
        if not any(entry["type"] == Z_EROFS_CLUSTER_TYPE_NONHEAD for entry in indexes):
            for entry in indexes:
                low_clusterofs = entry["clusterofs"]
                logical_start = entry["lcn"] * self.block_size + low_clusterofs
                if not groups or groups[-1]["blkaddr"] != entry["blkaddr"] or groups[-1]["low"] != low_clusterofs:
                    groups.append(
                        {
                            "blkaddr": entry["blkaddr"],
                            "type": entry["type"],
                            "low": low_clusterofs,
                            "logical_start": logical_start,
                            "compressed_blocks": 1,
                        }
                    )
            groups.sort(key=lambda item: item["logical_start"])
            for idx, group in enumerate(groups):
                group["logical_end"] = groups[idx + 1]["logical_start"] if idx + 1 < len(groups) else inode.size
        else:
            for index, entry in enumerate(indexes):
                if entry["type"] == Z_EROFS_CLUSTER_TYPE_NONHEAD:
                    continue
                start = entry["lcn"] * self.block_size + entry["clusterofs"]
                next_head = logical_clusters
                for later in indexes[index + 1 :]:
                    if later["type"] != Z_EROFS_CLUSTER_TYPE_NONHEAD:
                        next_head = later["lcn"]
                        break
                end = min(next_head * self.block_size, inode.size)
                compressed_blocks = 1
                if entry["type"] in (Z_EROFS_CLUSTER_TYPE_HEAD, Z_EROFS_CLUSTER_TYPE_HEAD2):
                    if index + 1 < len(indexes) and indexes[index + 1]["type"] == Z_EROFS_CLUSTER_TYPE_NONHEAD:
                        delta0 = indexes[index + 1]["delta0"]
                        if delta0 & Z_EROFS_VLE_DI_D0_CBLKCNT:
                            compressed_blocks = delta0 & ~Z_EROFS_VLE_DI_D0_CBLKCNT
                    if compressed_blocks <= 0:
                        compressed_blocks = 1
                groups.append(
                    {
                        "blkaddr": entry["blkaddr"],
                        "type": entry["type"],
                        "logical_start": start,
                        "logical_end": end,
                        "compressed_blocks": compressed_blocks,
                    }
                )

        out = bytearray(inode.size)
        for group in groups:
            start = group["logical_start"]
            if start >= inode.size:
                continue
            end = min(max(group["logical_end"], start), inode.size)
            needed = end - start
            if needed <= 0:
                continue

            paddr = group["blkaddr"] * self.block_size
            cluster = self.reader.read_at(paddr, group["compressed_blocks"] * self.block_size)

            # In this EMUI 9.1 image the legacy VLE index uses type 3 for LZ4
            # heads. Some public extractors reject that early Huawei encoding.
            if group["type"] in (Z_EROFS_CLUSTER_TYPE_HEAD, Z_EROFS_CLUSTER_TYPE_NONHEAD, Z_EROFS_CLUSTER_TYPE_HEAD2):
                decoded = lz4_raw_decompress(cluster, needed)
            else:
                decoded = cluster[:needed]
            out[start:end] = decoded

        return bytes(out)

    def read_dir(self, nid):
        data = self.read_file(nid)
        entries = []
        for block_start in range(0, len(data), self.block_size):
            block = data[block_start : block_start + self.block_size]
            if len(block) < 12:
                continue
            first_nameoff = struct.unpack_from("<H", block, 8)[0]
            if first_nameoff == 0 or first_nameoff > len(block) or first_nameoff % 12 != 0:
                continue
            count = first_nameoff // 12
            for idx in range(count):
                rec_off = idx * 12
                child_nid, nameoff, file_type, _reserved = struct.unpack_from("<QHBB", block, rec_off)
                if nameoff >= len(block):
                    continue
                if idx + 1 < count:
                    next_nameoff = struct.unpack_from("<H", block, (idx + 1) * 12 + 8)[0]
                else:
                    next_nameoff = len(block)
                raw_name = block[nameoff:next_nameoff].split(b"\0", 1)[0]
                if not raw_name:
                    continue
                name = raw_name.decode("utf-8", "surrogateescape")
                if name in (".", ".."):
                    continue
                entries.append((name, child_nid, file_type))
        return entries

    def walk(self):
        stack = [(PurePosixPath("/"), self.root_nid)]
        seen_dirs = set()
        while stack:
            path, nid = stack.pop()
            if nid in seen_dirs:
                continue
            seen_dirs.add(nid)
            try:
                entries = self.read_dir(nid)
            except Exception as exc:
                yield path, nid, "dir-error", exc
                continue
            for name, child_nid, file_type in entries:
                child_path = path / name
                yield child_path, child_nid, file_type, None
                if file_type == EROFS_FT_DIR:
                    stack.append((child_path, child_nid))


def check_apk_bytes(data):
    if not data.startswith(b"PK\x03\x04"):
        return False, len(data), "not a ZIP/APK local-file header"

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as apk:
            bad_member = apk.testzip()
            if bad_member:
                return False, len(data), f"CRC failed: {bad_member}"
            return True, len(data), f"{len(apk.infolist())} zip entries"
    except Exception as exc:
        return False, len(data), f"{type(exc).__name__}: {exc}"


def check_apk(fs, path, nid, dump_dir=None):
    data = fs.read_file(nid)
    if dump_dir:
        out_path = os.path.join(dump_dir, str(path).lstrip("/").replace("/", os.sep))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as out:
            out.write(data)

    return check_apk_bytes(data)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check APK integrity directly inside a sparse Huawei EMUI 9.1 EROFS image."
    )
    parser.add_argument("image", nargs="?", default="system.img")
    parser.add_argument("--dump-apks", metavar="DIR", help="optional directory to write reconstructed APKs")
    parser.add_argument("--limit", type=int, default=0, help="check only the first N APKs")
    args = parser.parse_args(argv)

    started = time.time()
    fs = HuaweiErofs(args.image)
    print(
        f"image={args.image} block={fs.block_size} root_nid={fs.root_nid} "
        f"meta_blkaddr={fs.meta_blkaddr} logical={fs.reader.logical_size}"
    )

    apks = []
    for path, nid, file_type, error in fs.walk():
        if error is not None:
            print(f"DIR-ERROR {path}: {error}", file=sys.stderr)
            continue
        if file_type == EROFS_FT_REG_FILE and str(path).lower().endswith(".apk"):
            apks.append((path, nid))
            if args.limit and len(apks) >= args.limit:
                break

    print(f"found_apks={len(apks)}")
    ok_count = 0
    bad = []
    for idx, (path, nid) in enumerate(apks, 1):
        try:
            ok, size, detail = check_apk(fs, path, nid, args.dump_apks)
        except Exception as exc:
            ok, size, detail = False, 0, f"{type(exc).__name__}: {exc}"
        status = "OK" if ok else "BAD"
        if ok:
            ok_count += 1
        else:
            bad.append((path, detail))
        print(f"[{idx:04d}/{len(apks):04d}] {status} {size:>10} {path} - {detail}")

    print(f"summary ok={ok_count} bad={len(bad)} elapsed={time.time() - started:.1f}s")
    if bad:
        print("bad_apks:")
        for path, detail in bad:
            print(f"  {path}: {detail}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
