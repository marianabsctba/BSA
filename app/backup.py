"""Operational backup/restore for BSA SQLite state.

Creates consistent SQLite snapshots using the online backup API, writes a
manifest with SHA-256 checksums, and restores only known BSA database files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path


_DB_ENV = {
    "auth": ("BSA_AUTH_DB", "/data/bsa_auth.db"),
    "history": ("BSA_HISTORY_DB", "/data/bsa_history.db"),
    "store": ("BSA_STORE_DB", "/data/bsa_store.db"),
    "jobs": ("BSA_JOBS_DB", "/data/bsa_jobs.db"),
}


def _paths() -> dict[str, Path]:
    return {
        name: Path(os.getenv(env, default))
        for name, (env, default) in _DB_ENV.items()
    }


def _sha256(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sqlite_snapshot(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    src=sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=15)
    dst=sqlite3.connect(destination, timeout=15)
    try:
        src.backup(dst)
        check=dst.execute("PRAGMA integrity_check").fetchone()
        if not check or str(check[0]).lower() != "ok":
            raise RuntimeError(f"integrity check failed for {source.name}")
    finally:
        dst.close()
        src.close()


def create_backup(output: str | Path) -> dict:
    output=Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    paths=_paths()
    missing=[name for name,path in paths.items() if not path.exists()]
    if missing:
        raise FileNotFoundError("missing database(s): " + ", ".join(sorted(missing)))

    with tempfile.TemporaryDirectory(prefix="bsa-backup-") as tmp:
        root=Path(tmp)
        files=[]
        for name,source in paths.items():
            snapshot=root/f"{name}.db"
            _sqlite_snapshot(source,snapshot)
            files.append({
                "name":name,
                "archive_path":f"databases/{name}.db",
                "source_name":source.name,
                "size":snapshot.stat().st_size,
                "sha256":_sha256(snapshot),
            })

        manifest={
            "format":"bsa-backup-v1",
            "created_at":int(time.time()),
            "files":files,
        }
        (root/"manifest.json").write_text(
            json.dumps(manifest,ensure_ascii=False,indent=2),
            encoding="utf-8",
        )
        with zipfile.ZipFile(output,"w",compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(root/"manifest.json","manifest.json")
            for item in files:
                zf.write(root/f"{item['name']}.db",item["archive_path"])
    return {**manifest,"output":str(output)}


def inspect_backup(archive: str | Path) -> dict:
    archive=Path(archive)
    with zipfile.ZipFile(archive,"r") as zf:
        names=set(zf.namelist())
        if "manifest.json" not in names:
            raise ValueError("backup manifest missing")
        manifest=json.loads(zf.read("manifest.json"))
        if manifest.get("format")!="bsa-backup-v1":
            raise ValueError("unsupported backup format")
        expected={"auth","history","store","jobs"}
        declared={str(x.get("name")) for x in manifest.get("files",[])}
        if declared != expected:
            raise ValueError("backup database set is incomplete")
        for item in manifest["files"]:
            archive_path=str(item.get("archive_path",""))
            if archive_path not in names or not archive_path.startswith("databases/"):
                raise ValueError("backup member missing")
            data=zf.read(archive_path)
            digest=hashlib.sha256(data).hexdigest()
            if digest != item.get("sha256"):
                raise ValueError(f"checksum mismatch: {item.get('name')}")
    return manifest


def restore_backup(archive: str | Path, *, force: bool=False) -> dict:
    manifest=inspect_backup(archive)
    paths=_paths()
    if not force:
        existing=[name for name,path in paths.items() if path.exists()]
        if existing:
            raise FileExistsError(
                "refusing to overwrite existing database(s): " + ", ".join(sorted(existing))
            )

    archive=Path(archive)
    with tempfile.TemporaryDirectory(prefix="bsa-restore-") as tmp:
        root=Path(tmp)
        with zipfile.ZipFile(archive,"r") as zf:
            for item in manifest["files"]:
                name=item["name"]
                extracted=root/f"{name}.db"
                extracted.write_bytes(zf.read(item["archive_path"]))
                conn=sqlite3.connect(extracted)
                try:
                    check=conn.execute("PRAGMA integrity_check").fetchone()
                    if not check or str(check[0]).lower()!="ok":
                        raise ValueError(f"sqlite integrity check failed: {name}")
                finally:
                    conn.close()

        for item in manifest["files"]:
            name=item["name"]
            destination=paths[name]
            destination.parent.mkdir(parents=True,exist_ok=True)
            source=root/f"{name}.db"
            staged=destination.with_suffix(destination.suffix+".restore")
            shutil.copy2(source,staged)
            os.replace(staged,destination)

    return {
        "format":manifest["format"],
        "created_at":manifest["created_at"],
        "restored":sorted(paths),
    }


def main() -> None:
    parser=argparse.ArgumentParser(prog="python -m app.backup")
    sub=parser.add_subparsers(dest="command",required=True)

    create=sub.add_parser("create")
    create.add_argument("output")

    inspect=sub.add_parser("inspect")
    inspect.add_argument("archive")

    restore=sub.add_parser("restore")
    restore.add_argument("archive")
    restore.add_argument("--force",action="store_true")

    args=parser.parse_args()
    if args.command=="create":
        result=create_backup(args.output)
    elif args.command=="inspect":
        result=inspect_backup(args.archive)
    else:
        result=restore_backup(args.archive,force=args.force)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
