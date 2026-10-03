import json
import sqlite3
import zipfile

import pytest

from app import backup


def _seed(path):
    conn=sqlite3.connect(path)
    conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO sample(value) VALUES('ok')")
    conn.commit()
    conn.close()


def _configure(tmp_path, monkeypatch):
    mapping={
        "BSA_AUTH_DB":tmp_path/"auth.db",
        "BSA_HISTORY_DB":tmp_path/"history.db",
        "BSA_STORE_DB":tmp_path/"store.db",
        "BSA_JOBS_DB":tmp_path/"jobs.db",
    }
    for env,path in mapping.items():
        monkeypatch.setenv(env,str(path))
        _seed(path)
    return mapping


def test_backup_round_trip_and_overwrite_guard(tmp_path, monkeypatch):
    paths=_configure(tmp_path,monkeypatch)
    archive=tmp_path/"backup.zip"

    created=backup.create_backup(archive)
    assert created["format"]=="bsa-backup-v1"
    assert {x["name"] for x in created["files"]}=={"auth","history","store","jobs"}
    assert backup.inspect_backup(archive)["format"]=="bsa-backup-v1"

    with pytest.raises(FileExistsError):
        backup.restore_backup(archive)

    for path in paths.values():
        path.unlink()

    restored=backup.restore_backup(archive)
    assert restored["restored"]==["auth","history","jobs","store"]

    for path in paths.values():
        conn=sqlite3.connect(path)
        assert conn.execute("SELECT value FROM sample").fetchone()[0]=="ok"
        conn.close()


def test_backup_rejects_invalid_checksum(tmp_path, monkeypatch):
    _configure(tmp_path,monkeypatch)
    archive=tmp_path/"backup.zip"
    backup.create_backup(archive)

    broken=tmp_path/"broken.zip"
    with zipfile.ZipFile(archive,"r") as src, zipfile.ZipFile(broken,"w") as dst:
        manifest=json.loads(src.read("manifest.json"))
        manifest["files"][0]["sha256"]="0"*64
        dst.writestr("manifest.json",json.dumps(manifest))
        for name in src.namelist():
            if name!="manifest.json":
                dst.writestr(name,src.read(name))

    with pytest.raises(ValueError,match="checksum mismatch"):
        backup.inspect_backup(broken)


def test_postgres_backup_round_trip_uses_verified_v2_bundle(tmp_path, monkeypatch):
    paths=_configure(tmp_path,monkeypatch)
    archive=tmp_path/"postgres-backup.zip"
    payload={"assets":[],"findings":[]}
    restored={}

    monkeypatch.setenv("BSA_ASSET_REPOSITORY_BACKEND","postgres")
    monkeypatch.setenv("BSA_DATABASE_URL","postgresql://bsa:secret@postgres:5432/bsa")
    monkeypatch.setattr(backup,"export_asset_state",lambda _dsn: payload)
    monkeypatch.setattr(
        backup,
        "restore_asset_state",
        lambda dsn,snapshot,force=False: restored.update(
            dsn=dsn,
            snapshot=snapshot,
            force=force,
        ) or {"assets":0,"findings":0},
    )

    created=backup.create_backup(archive)
    assert created["format"]=="bsa-backup-v2"
    assert created["postgres_asset_store"]["assets"]==0
    assert created["postgres_asset_store"]["findings"]==0
    inspected=backup.inspect_backup(archive)
    assert inspected["format"]=="bsa-backup-v2"

    for path in paths.values():
        path.unlink()

    result=backup.restore_backup(archive)
    assert result["postgres_asset_store"]=={"assets":0,"findings":0}
    assert restored=={
        "dsn":"postgresql://bsa:secret@postgres:5432/bsa",
        "snapshot":payload,
        "force":False,
    }
