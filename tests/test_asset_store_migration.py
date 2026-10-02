import json
import sqlite3
from datetime import datetime, timezone

import pytest

from app.migrate_asset_store import load_sqlite_state, migrate_state, state_summary
from app.models import Asset, AssetType, Finding, Severity
from app.repositories.assets_findings import AssetFindingRepository


def _asset(tenant_id="tenant-a", asset_id="asset-a"):
    now=datetime.now(timezone.utc).isoformat()
    return Asset(
        tenant_id=tenant_id,
        id=asset_id,
        value=f"{asset_id}.example.org",
        type=AssetType.DOMAIN,
        first_seen=now,
        last_seen=now,
    )


def _finding(tenant_id="tenant-a", finding_id="finding-a", asset_id="asset-a"):
    return Finding(
        tenant_id=tenant_id,
        id=finding_id,
        asset_id=asset_id,
        title="Migration finding",
        severity=Severity.HIGH,
        evidence="migration-test",
    )


def _source_sqlite(path, assets, findings):
    conn=sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE assets(
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id,id)
        )"""
    )
    conn.execute(
        """CREATE TABLE findings(
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id,id)
        )"""
    )
    for asset in assets:
        conn.execute(
            "INSERT INTO assets VALUES(?,?,?,?)",
            (
                asset.tenant_id,
                asset.id,
                json.dumps(asset.model_dump(mode="json")),
                "2026-10-02T00:00:00+00:00",
            ),
        )
    for finding in findings:
        conn.execute(
            "INSERT INTO findings VALUES(?,?,?,?,?)",
            (
                finding.tenant_id,
                finding.id,
                finding.asset_id,
                json.dumps(finding.model_dump(mode="json")),
                "2026-10-02T00:00:00+00:00",
            ),
        )
    conn.commit()
    conn.close()


def test_load_sqlite_state_and_summary_preserve_tenants(tmp_path):
    assets=[_asset("tenant-a","asset-a"),_asset("tenant-b","asset-b")]
    findings=[
        _finding("tenant-a","finding-a","asset-a"),
        _finding("tenant-b","finding-b","asset-b"),
    ]
    source=tmp_path/"store.db"
    _source_sqlite(source,assets,findings)

    loaded_assets,loaded_findings=load_sqlite_state(source)
    summary=state_summary(loaded_assets,loaded_findings)

    assert summary["assets"]==2
    assert summary["findings"]==2
    assert summary["tenants"]["tenant-a"]=={"assets":1,"findings":1}
    assert summary["tenants"]["tenant-b"]=={"assets":1,"findings":1}


def test_migration_dry_run_does_not_write():
    assets=[_asset()]
    findings=[_finding()]
    destination=AssetFindingRepository([],[])

    result=migrate_state(assets,findings,destination,dry_run=True)

    assert result["status"]=="validated"
    assert destination.all_assets()==[]
    assert destination.all_findings()==[]


def test_migration_refuses_non_empty_destination():
    existing=_asset("tenant-a","existing")
    destination=AssetFindingRepository([existing],[])

    with pytest.raises(RuntimeError,match="not empty"):
        migrate_state([_asset()],[ _finding() ],destination)


def test_migration_writes_and_reconciles_payloads(monkeypatch):
    assets=[_asset("tenant-a","asset-a"),_asset("tenant-b","asset-b")]
    findings=[
        _finding("tenant-a","finding-a","asset-a"),
        _finding("tenant-b","finding-b","asset-b"),
    ]
    destination=AssetFindingRepository([],[])
    monkeypatch.setattr(destination,"persist",lambda: None)

    result=migrate_state(assets,findings,destination)

    assert result["status"]=="migrated"
    assert result["verified"]=={"assets":2,"findings":2}
    assert state_summary(destination.all_assets(),destination.all_findings())==result["source"]


def test_migration_detects_reconciliation_mismatch(monkeypatch):
    asset=_asset()
    finding=_finding()
    destination=AssetFindingRepository([],[])

    def corrupt_persist():
        destination.all_assets()[0].value="tampered.example.org"

    monkeypatch.setattr(destination,"persist",corrupt_persist)

    with pytest.raises(RuntimeError,match="reconciliation failed"):
        migrate_state([asset],[finding],destination)
