import json
import sqlite3
from datetime import datetime, timezone

from app import job_queue, store
from app.models import Asset, AssetType, Finding, Severity


def test_legacy_job_queue_schema_upgrades_without_losing_jobs(tmp_path, monkeypatch):
    path=tmp_path/"jobs.db"
    conn=sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE assessment_jobs(
            job_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            profile TEXT NOT NULL,
            authorization_ref TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            started_at INTEGER,
            completed_at INTEGER,
            result_json TEXT,
            error TEXT,
            materialized INTEGER NOT NULL DEFAULT 0
        )"""
    )
    conn.execute(
        """INSERT INTO assessment_jobs(
            job_id,tenant_id,user_id,email,role,name,target,profile,
            authorization_ref,status,created_at,materialized
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "legacy-job","tenant-a","user-a","a@example.org","admin","Admin A",
            "legacy.example.org","rapid","AUTH-OLD","queued",100,0,
        ),
    )
    conn.commit(); conn.close()

    monkeypatch.setenv("BSA_JOBS_DB",str(path))
    migrated=job_queue._db()
    cols={r["name"] for r in migrated.execute("PRAGMA table_info(assessment_jobs)").fetchall()}
    row=migrated.execute(
        "SELECT job_id,tenant_id,target,status,attempts,max_attempts FROM assessment_jobs WHERE job_id=?",
        ("legacy-job",),
    ).fetchone()
    worker_table=migrated.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='worker_heartbeats'"
    ).fetchone()
    migrated.close()

    assert {"attempts","max_attempts","lease_expires_at","run_token","materialization_started_at"} <= cols
    assert row["job_id"]=="legacy-job"
    assert row["tenant_id"]=="tenant-a"
    assert row["target"]=="legacy.example.org"
    assert row["status"]=="queued"
    assert row["attempts"]==0
    assert row["max_attempts"]==3
    assert worker_table is not None


def test_persistent_asset_store_round_trip_preserves_tenant_boundaries(tmp_path, monkeypatch):
    path=tmp_path/"store.db"
    monkeypatch.setenv("BSA_STORE_DB",str(path))
    now=datetime.now(timezone.utc).isoformat()

    asset_a=Asset(
        tenant_id="tenant-a",id="asset-a",value="a.example.org",type=AssetType.DOMAIN,
        confidence=95,criticality=4,source="migration-test",first_seen=now,last_seen=now,
    )
    asset_b=Asset(
        tenant_id="tenant-b",id="asset-b",value="b.example.org",type=AssetType.DOMAIN,
        confidence=90,criticality=3,source="migration-test",first_seen=now,last_seen=now,
    )
    finding_a=Finding(
        tenant_id="tenant-a",id="finding-a",asset_id="asset-a",title="A",
        severity=Severity.HIGH,confidence=90,evidence="a",remediation="fix",
    )
    finding_b=Finding(
        tenant_id="tenant-b",id="finding-b",asset_id="asset-b",title="B",
        severity=Severity.MEDIUM,confidence=85,evidence="b",remediation="fix",
    )

    store.persist_state([asset_a,asset_b],[finding_a,finding_b])
    assets,findings=store._load_persisted()

    assert {(a.tenant_id,a.id) for a in assets}=={
        ("tenant-a","asset-a"),("tenant-b","asset-b"),
    }
    assert {(f.tenant_id,f.id,f.asset_id) for f in findings}=={
        ("tenant-a","finding-a","asset-a"),
        ("tenant-b","finding-b","asset-b"),
    }

    raw=sqlite3.connect(path)
    payloads=[json.loads(r[0]) for r in raw.execute(
        "SELECT payload_json FROM assets ORDER BY tenant_id,id"
    ).fetchall()]
    raw.close()
    assert [p["tenant_id"] for p in payloads]==["tenant-a","tenant-b"]
