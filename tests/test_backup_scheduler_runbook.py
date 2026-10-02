from datetime import datetime, timezone
from pathlib import Path

from app import backup_scheduler


def test_backup_filename_is_utc_and_stable():
    now=datetime(2026,10,2,12,34,56,tzinfo=timezone.utc)
    assert backup_scheduler.backup_filename(now)=="bsa-20261002T123456Z.zip"


def test_prune_backups_respects_retention(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_scheduler,"BACKUP_DIR",tmp_path)
    monkeypatch.setattr(backup_scheduler,"RETENTION_DAYS",14)

    old=tmp_path/"bsa-old.zip"
    fresh=tmp_path/"bsa-fresh.zip"
    old.write_bytes(b"old")
    fresh.write_bytes(b"fresh")

    now=2_000_000_000
    old_ts=now-(15*86400)
    fresh_ts=now-(2*86400)
    old.touch()
    fresh.touch()
    import os
    os.utime(old,(old_ts,old_ts))
    os.utime(fresh,(fresh_ts,fresh_ts))

    removed=backup_scheduler.prune_backups(now)
    assert removed==["bsa-old.zip"]
    assert not old.exists()
    assert fresh.exists()


def test_production_compose_has_backup_scheduler_and_volume():
    compose=Path("docker-compose.production.yml").read_text(encoding="utf-8")
    assert "  backup:" in compose
    assert 'command: ["python", "-m", "app.backup_scheduler"]' in compose
    assert "BSA_BACKUP_INTERVAL_SECONDS" in compose
    assert "BSA_BACKUP_RETENTION_DAYS" in compose
    assert "bsa_backups:/backups" in compose
    assert "  bsa_backups:" in compose


def test_operations_runbook_documents_restore_and_worker_recovery():
    text=Path("docs/OPERATIONS_RUNBOOK.md").read_text(encoding="utf-8")
    assert "Worker parado ou stale" in text
    assert "Backup automático" in text
    assert "Restore" in text
    assert "release-readiness" in text
