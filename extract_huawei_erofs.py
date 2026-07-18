#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import stat
import time
from pathlib import Path

from check_erofs_apks import EROFS_FT_DIR, EROFS_FT_REG_FILE, HuaweiErofs, check_apk_bytes


WORKER_FS = None


def choose_output_dir(requested):
    out = Path(requested)
    if not out.exists():
        return out
    try:
        empty = out.is_dir() and not any(out.iterdir())
    except OSError:
        empty = False
    if empty:
        return out

    stamp = time.strftime("%Y%m%d_%H%M%S")
    parent = out.parent
    stem = out.name
    for index in range(100):
        candidate = parent / f"{stem}_{stamp}" if index == 0 else parent / f"{stem}_{stamp}_{index}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"cannot choose a non-existing output directory for {requested!r}")


def host_path_for(out_dir, image_path):
    parts = image_path.parts
    if parts and parts[0] == "/":
        parts = parts[1:]
    return out_dir.joinpath(*parts)


def sha256_bytes(data):
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


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

    marker = f"SYMLINK -> {target}\n".encode("utf-8", "surrogateescape")
    write_file(path, marker)
    return "marker"


def init_worker(image):
    global WORKER_FS
    WORKER_FS = HuaweiErofs(image)


def extract_file_task(task):
    image_path, host_path_text, nid, expected_size = task
    host_path = Path(host_path_text)
    data = WORKER_FS.read_file(nid)
    image_sha = sha256_bytes(data)
    write_file(host_path, data)
    disk_sha = sha256_file(host_path)
    disk_size = host_path.stat().st_size

    failures = []
    if disk_size != expected_size:
        failures.append({"kind": "size", "path": image_path, "detail": f"disk={disk_size} image={expected_size}"})
    if disk_sha != image_sha:
        failures.append({"kind": "sha256", "path": image_path, "detail": f"disk={disk_sha} image={image_sha}"})

    apk = None
    if image_path.lower().endswith(".apk"):
        ok, _size, detail = check_apk_bytes(data)
        apk = {"ok": ok, "detail": detail}
        if not ok:
            failures.append({"kind": "apk", "path": image_path, "detail": detail})

    return {
        "path": image_path,
        "sha256": image_sha,
        "apk": apk,
        "failures": failures,
    }


def write_report(report_path, image, out_dir, elapsed, counts, failures):
    with open(report_path, "w", encoding="utf-8") as report:
        report.write(f"image={image}\n")
        report.write(f"out_dir={out_dir}\n")
        report.write(f"elapsed_seconds={elapsed:.1f}\n")
        for key in ("files", "dirs", "symlinks", "other", "apk_ok", "apk_bad"):
            report.write(f"{key}={counts[key]}\n")
        report.write(f"failures={len(failures)}\n")
        for failure in failures:
            report.write(json.dumps(failure, ensure_ascii=False) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract and verify a sparse Huawei EMUI 9.1 EROFS image.")
    parser.add_argument("image", nargs="?", default="system.img")
    parser.add_argument("out_dir", nargs="?", default="system_extracted")
    parser.add_argument("--workers", type=int, default=0, help="file extraction workers; 0 means os.cpu_count()")
    parser.add_argument(
        "--symlink-mode",
        choices=("auto", "marker", "symlink"),
        default="auto",
        help="auto tries real Windows symlinks and falls back to marker files",
    )
    args = parser.parse_args(argv)

    started = time.time()
    fs = HuaweiErofs(args.image)
    out_dir = choose_output_dir(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=False)
    metadata_path = out_dir / "metadata.jsonl"
    report_path = out_dir / "verify_report.txt"

    counts = {"dirs": 0, "files": 0, "symlinks": 0, "other": 0, "apk_ok": 0, "apk_bad": 0}
    failures = []
    metadata_entries = []
    file_tasks = []

    def record_failure(kind, path, detail):
        failures.append({"kind": kind, "path": str(path), "detail": str(detail)})

    root = fs.read_inode(fs.root_nid)
    metadata_entries.append(
        {
            "path": "/",
            "nid": fs.root_nid,
            "kind": "dir",
            "mode": root.mode,
            "uid": root.uid,
            "gid": root.gid,
            "nlink": root.nlink,
            "size": root.size,
            "layout": root.layout,
            "xattrs": encode_xattrs(fs.read_xattrs(fs.root_nid)),
        }
    )

    print(f"walking image={args.image}", flush=True)
    for index, (image_path, nid, file_type, error) in enumerate(fs.walk(), 1):
        if error is not None:
            record_failure("walk", image_path, error)
            continue

        inode = fs.read_inode(nid)
        host_path = host_path_for(out_dir, image_path)
        mode_type = inode.type
        entry = {
            "path": str(image_path),
            "host_path": str(host_path),
            "nid": nid,
            "mode": inode.mode,
            "uid": inode.uid,
            "gid": inode.gid,
            "nlink": inode.nlink,
            "size": inode.size,
            "layout": inode.layout,
            "xattrs": encode_xattrs(fs.read_xattrs(nid)),
        }

        try:
            if mode_type == stat.S_IFDIR or file_type == EROFS_FT_DIR:
                host_path.mkdir(parents=True, exist_ok=True)
                counts["dirs"] += 1
                entry["kind"] = "dir"

            elif mode_type == stat.S_IFREG or file_type == EROFS_FT_REG_FILE:
                counts["files"] += 1
                entry["kind"] = "file"
                file_tasks.append((str(image_path), str(host_path), nid, inode.size))

            elif mode_type == stat.S_IFLNK:
                target = fs.read_file(nid).decode("utf-8", "surrogateescape")
                materialized = write_symlink_or_marker(host_path, target, args.symlink_mode)
                counts["symlinks"] += 1
                entry.update({"kind": "symlink", "target": target, "materialized": materialized})

                if materialized == "symlink":
                    if os.readlink(host_path) != target:
                        record_failure("symlink", image_path, "readlink target mismatch")
                elif materialized == "marker":
                    marker = host_path.read_bytes().decode("utf-8", "surrogateescape").rstrip("\n")
                    if marker != f"SYMLINK -> {target}":
                        record_failure("symlink-marker", image_path, "marker target mismatch")

            else:
                counts["other"] += 1
                entry["kind"] = f"special:{oct(mode_type)}"
                record_failure("special", image_path, f"unsupported special file type {oct(mode_type)}")

        except Exception as exc:
            record_failure("extract", image_path, f"{type(exc).__name__}: {exc}")
            entry["error"] = f"{type(exc).__name__}: {exc}"

        metadata_entries.append(entry)

        if index % 1000 == 0:
            print(
                f"walked={index} files={counts['files']} dirs={counts['dirs']} "
                f"symlinks={counts['symlinks']} failures={len(failures)}",
                flush=True,
            )

    workers = args.workers or (os.cpu_count() or 1)
    workers = max(1, workers)
    print(f"extracting_files={len(file_tasks)} workers={workers}", flush=True)

    entries_by_path = {entry["path"]: entry for entry in metadata_entries}
    completed_files = 0

    if workers == 1:
        init_worker(args.image)
        result_iter = map(extract_file_task, file_tasks)
    else:
        pool = concurrent.futures.ProcessPoolExecutor(
            max_workers=workers, initializer=init_worker, initargs=(args.image,)
        )
        result_iter = concurrent.futures.as_completed([pool.submit(extract_file_task, task) for task in file_tasks])

    try:
        for item in result_iter:
            completed_files += 1
            try:
                result = item.result() if hasattr(item, "result") else item
                entry = entries_by_path[result["path"]]
                entry["sha256"] = result["sha256"]
                if result["apk"] is not None:
                    entry["apk_check"] = result["apk"]["detail"]
                    if result["apk"]["ok"]:
                        counts["apk_ok"] += 1
                    else:
                        counts["apk_bad"] += 1
                failures.extend(result["failures"])
            except Exception as exc:
                failures.append({"kind": "worker", "path": "<unknown>", "detail": f"{type(exc).__name__}: {exc}"})

            if completed_files % 500 == 0:
                print(
                    f"extracted_files={completed_files}/{len(file_tasks)} "
                    f"apk_ok={counts['apk_ok']} apk_bad={counts['apk_bad']} failures={len(failures)}",
                    flush=True,
                )
    finally:
        if workers != 1:
            pool.shutdown(wait=True, cancel_futures=False)

    with open(metadata_path, "w", encoding="utf-8") as meta:
        for entry in metadata_entries:
            meta.write(json.dumps(entry, ensure_ascii=False) + "\n")

    elapsed = time.time() - started
    write_report(report_path, args.image, out_dir, elapsed, counts, failures)

    print(f"out_dir={out_dir}")
    print(
        f"summary files={counts['files']} dirs={counts['dirs']} symlinks={counts['symlinks']} "
        f"apk_ok={counts['apk_ok']} apk_bad={counts['apk_bad']} failures={len(failures)} "
        f"elapsed={elapsed:.1f}s"
    )
    print(f"metadata={metadata_path}")
    print(f"report={report_path}")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
