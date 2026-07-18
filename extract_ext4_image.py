#!/usr/bin/env python3
"""Extract a raw ext4 Android image into files plus metadata.jsonl."""

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import stat
import time
from pathlib import Path, PurePosixPath

from ext4_read import Ext4Image
from patch_gsi_ext4_vendor import LIB_PATH, patch_libfs_mgr


WORKER_IMG = None
WORKER_PATCH_LIBFS = False


def choose_output_dir(requested):
    out = Path(requested)
    if not out.exists():
        return out
    try:
        if out.is_dir() and not any(out.iterdir()):
            return out
    except OSError:
        pass

    stamp = time.strftime("%Y%m%d_%H%M%S")
    for index in range(100):
        suffix = stamp if index == 0 else f"{stamp}_{index}"
        candidate = out.parent / f"{out.name}_{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"cannot choose a free output directory near {requested!r}")


def host_path_for(out_dir, image_path):
    p = PurePosixPath(image_path)
    parts = p.parts
    if parts and parts[0] == "/":
        parts = parts[1:]
    return out_dir.joinpath(*parts)


def file_payload_path(out_dir, ino):
    return out_dir / ".file_data" / f"{ino:08d}.bin"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def encode_xattrs(attrs):
    return {
        name: base64.b64encode(value).decode("ascii")
        for name, value in sorted(attrs.items())
    }


def write_file(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def write_symlink_or_marker(path, target, mode):
    if mode == "none":
        return "metadata-only"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        return "exists"
    if mode in ("auto", "symlink"):
        try:
            os.symlink(target, path)
            return "symlink"
        except OSError:
            if mode == "symlink":
                raise
    write_file(path, f"SYMLINK -> {target}\n".encode("utf-8", "surrogateescape"))
    return "marker"


def init_worker(image, patch_libfs):
    global WORKER_IMG, WORKER_PATCH_LIBFS
    WORKER_IMG = Ext4Image(image)
    WORKER_PATCH_LIBFS = patch_libfs


def extract_file_task(task):
    image_path, host_path_text, ino, expected_size = task
    host_path = Path(host_path_text)
    data = WORKER_IMG.read_file(ino)
    patch_info = None
    if WORKER_PATCH_LIBFS and image_path == LIB_PATH:
        data, patch_info = patch_libfs_mgr(data)

    write_file(host_path, data)
    disk_size = host_path.stat().st_size
    disk_sha = sha256_file(host_path)
    image_sha = sha256_bytes(data)
    failures = []
    if disk_size != len(data):
        failures.append({"kind": "size", "path": image_path, "detail": f"disk={disk_size} memory={len(data)}"})
    if disk_sha != image_sha:
        failures.append({"kind": "sha256", "path": image_path, "detail": f"disk={disk_sha} memory={image_sha}"})
    if not patch_info and disk_size != expected_size:
        failures.append({"kind": "inode-size", "path": image_path, "detail": f"disk={disk_size} inode={expected_size}"})

    return {
        "path": image_path,
        "size": disk_size,
        "sha256": disk_sha,
        "patch_info": patch_info,
        "failures": failures,
    }


def mode_kind(mode):
    mode_type = stat.S_IFMT(mode)
    if mode_type == stat.S_IFDIR:
        return "dir"
    if mode_type == stat.S_IFREG:
        return "file"
    if mode_type == stat.S_IFLNK:
        return "symlink"
    return f"special:{oct(mode_type)}"


def write_report(report_path, image, out_dir, elapsed, counts, failures, patch_info):
    with open(report_path, "w", encoding="utf-8") as report:
        report.write(f"image={image}\n")
        report.write(f"out_dir={out_dir}\n")
        report.write(f"elapsed_seconds={elapsed:.1f}\n")
        for key in ("files", "dirs", "symlinks", "other", "xattr_nodes", "xattrs"):
            report.write(f"{key}={counts[key]}\n")
        report.write(f"failures={len(failures)}\n")
        if patch_info:
            report.write("libfs_patch=" + json.dumps(patch_info, ensure_ascii=False) + "\n")
        for failure in failures:
            report.write(json.dumps(failure, ensure_ascii=False) + "\n")


def extract_ext4(image, out_dir, workers=0, symlink_mode="auto", patch_libfs=False, file_data_mode="tree"):
    started = time.time()
    out_dir = choose_output_dir(out_dir)
    out_dir.mkdir(parents=True, exist_ok=False)
    metadata_path = out_dir / "metadata.jsonl"
    report_path = out_dir / "verify_report.txt"

    img = Ext4Image(image)
    counts = {"dirs": 0, "files": 0, "symlinks": 0, "other": 0, "xattr_nodes": 0, "xattrs": 0}
    failures = []
    metadata_entries = []
    file_tasks = []

    print(f"walking_ext4={image}", flush=True)
    for index, (image_path, ino, inode) in enumerate(img.walk("/"), 1):
        kind = mode_kind(inode.mode)
        host_path = file_payload_path(out_dir, ino) if kind == "file" and file_data_mode == "flat" else host_path_for(out_dir, image_path)
        try:
            xattrs = img.read_xattrs(ino)
        except Exception as exc:
            xattrs = {}
            failures.append({"kind": "xattrs", "path": image_path, "detail": f"{type(exc).__name__}: {exc}"})

        entry = {
            "path": image_path,
            "host_path": str(host_path),
            "nid": ino,
            "mode": inode.mode,
            "uid": inode.uid,
            "gid": inode.gid,
            "nlink": inode.links_count,
            "size": inode.size,
            "xattrs": encode_xattrs(xattrs),
            "kind": kind,
        }

        counts["xattr_nodes"] += 1 if xattrs else 0
        counts["xattrs"] += len(xattrs)

        try:
            if kind == "dir":
                host_path.mkdir(parents=True, exist_ok=True)
                counts["dirs"] += 1
            elif kind == "file":
                counts["files"] += 1
                file_tasks.append((image_path, str(host_path), ino, inode.size))
            elif kind == "symlink":
                target = img.read_file(ino).decode("utf-8", "surrogateescape")
                materialized = write_symlink_or_marker(host_path, target, symlink_mode)
                entry.update({"target": target, "materialized": materialized, "size": len(target)})
                counts["symlinks"] += 1
            else:
                counts["other"] += 1
                failures.append({"kind": "special", "path": image_path, "detail": kind})
        except Exception as exc:
            failures.append({"kind": "extract", "path": image_path, "detail": f"{type(exc).__name__}: {exc}"})
            entry["error"] = f"{type(exc).__name__}: {exc}"

        metadata_entries.append(entry)
        if index % 1000 == 0:
            print(
                f"walked={index} files={counts['files']} dirs={counts['dirs']} "
                f"symlinks={counts['symlinks']} failures={len(failures)}",
                flush=True,
            )

    img.f.close()

    workers = workers or (os.cpu_count() or 1)
    workers = max(1, workers)
    print(f"extracting_files={len(file_tasks)} workers={workers}", flush=True)

    entries_by_path = {entry["path"]: entry for entry in metadata_entries}
    patch_info = None
    completed = 0
    if workers == 1:
        init_worker(image, patch_libfs)
        result_iter = map(extract_file_task, file_tasks)
    else:
        pool = concurrent.futures.ProcessPoolExecutor(
            max_workers=workers,
            initializer=init_worker,
            initargs=(image, patch_libfs),
        )
        result_iter = pool.map(extract_file_task, file_tasks, chunksize=16)

    try:
        for result in result_iter:
            entry = entries_by_path[result["path"]]
            entry["sha256"] = result["sha256"]
            entry["size"] = result["size"]
            if result["patch_info"]:
                patch_info = result["patch_info"]
                entry["patched"] = "libfs_vendor_ext4"
            failures.extend(result["failures"])
            completed += 1
            if completed % 1000 == 0:
                print(f"extracted_files={completed}/{len(file_tasks)} failures={len(failures)}", flush=True)
    finally:
        if workers != 1:
            pool.shutdown()

    with open(metadata_path, "w", encoding="utf-8") as meta:
        for entry in metadata_entries:
            meta.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    if patch_libfs and patch_info is None:
        failures.append({"kind": "libfs-patch", "path": LIB_PATH, "detail": "target file was not patched"})

    elapsed = time.time() - started
    write_report(report_path, image, out_dir, elapsed, counts, failures, patch_info)
    return {
        "image": str(image),
        "out_dir": str(out_dir),
        "metadata": str(metadata_path),
        "report": str(report_path),
        "elapsed_seconds": f"{elapsed:.1f}",
        "failures": len(failures),
        "libfs_patched": bool(patch_info),
        **counts,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract a raw ext4 Android image into metadata.jsonl.")
    parser.add_argument("image")
    parser.add_argument("out_dir", nargs="?", default="ext4_extracted")
    parser.add_argument("--workers", type=int, default=0, help="0 means os.cpu_count()")
    parser.add_argument("--symlink-mode", choices=("auto", "marker", "symlink", "none"), default="auto")
    parser.add_argument(
        "--file-data-mode",
        choices=("tree", "flat"),
        default="tree",
        help="flat stores file payloads by inode under .file_data to avoid Windows case collisions",
    )
    parser.add_argument(
        "--patch-libfs-vendor-ext4",
        action="store_true",
        help="patch /system/lib64/libfs_mgr.so while extracting, for EMUI 9.1 ext4 vendor GSIs",
    )
    args = parser.parse_args(argv)

    info = extract_ext4(
        args.image,
        args.out_dir,
        workers=args.workers,
        symlink_mode=args.symlink_mode,
        patch_libfs=args.patch_libfs_vendor_ext4,
        file_data_mode=args.file_data_mode,
    )
    for key, value in info.items():
        print(f"{key}={value}")
    return 0 if info["failures"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
