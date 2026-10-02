"""Periodic backup scheduler for production pilots."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

from .backup import create_backup, inspect_backup


BACKUP_DIR=Path(os.getenv("BSA_BACKUP_DIR","/backups"))
INTERVAL_SECONDS=max(300,int(os.getenv("BSA_BACKUP_INTERVAL_SECONDS","86400")))
RETENTION_DAYS=max(1,int(os.getenv("BSA_BACKUP_RETENTION_DAYS","14")))


def backup_filename(now: datetime | None=None) -> str:
    now=now or datetime.now(timezone.utc)
    return f"bsa-{now.strftime('%Y%m%dT%H%M%SZ')}.zip"


def prune_backups(now_ts: int | None=None) -> list[str]:
    now_ts=int(now_ts or time.time())
    cutoff=now_ts-(RETENTION_DAYS*86400)
    removed=[]
    BACKUP_DIR.mkdir(parents=True,exist_ok=True)
    for path in BACKUP_DIR.glob("bsa-*.zip"):
        try:
            if int(path.stat().st_mtime)<cutoff:
                path.unlink()
                removed.append(path.name)
        except FileNotFoundError:
            continue
    return sorted(removed)


def run_backup_once() -> dict:
    BACKUP_DIR.mkdir(parents=True,exist_ok=True)
    target=BACKUP_DIR/backup_filename()
    result=create_backup(target)
    inspect_backup(target)
    removed=prune_backups()
    return {
        "backup":str(target),
        "format":result["format"],
        "created_at":result["created_at"],
        "retention_days":RETENTION_DAYS,
        "removed":removed,
    }


def main() -> None:
    while True:
        try:
            result=run_backup_once()
            print(result,flush=True)
        except Exception as exc:
            print({"status":"backup_failed","error":exc.__class__.__name__},flush=True)
        time.sleep(INTERVAL_SECONDS)


if __name__=="__main__":
    main()
