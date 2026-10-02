"""Controlled migration of the asset/finding store from SQLite to PostgreSQL."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from collections import Counter
from pathlib import Path

from .models import Asset, Finding
from .repositories.postgres_assets_findings import PostgresAssetFindingRepository


def load_sqlite_state(path: str | Path) -> tuple[list[Asset], list[Finding]]:
    source=Path(path)
    if not source.exists():
        raise FileNotFoundError(f"SQLite asset store not found: {source}")
    conn=sqlite3.connect(f"file:{source}?mode=ro",uri=True,timeout=15)
    conn.row_factory=sqlite3.Row
    try:
        check=conn.execute("PRAGMA integrity_check").fetchone()
        if not check or str(check[0]).lower()!="ok":
            raise RuntimeError("SQLite integrity check failed")
        assets=[
            Asset.model_validate(json.loads(row["payload_json"]))
            for row in conn.execute(
                "SELECT payload_json FROM assets ORDER BY tenant_id,id"
            ).fetchall()
        ]
        findings=[
            Finding.model_validate(json.loads(row["payload_json"]))
            for row in conn.execute(
                "SELECT payload_json FROM findings ORDER BY tenant_id,id"
            ).fetchall()
        ]
    finally:
        conn.close()
    return assets,findings


def state_summary(assets: list[Asset], findings: list[Finding]) -> dict:
    asset_counts=Counter(asset.tenant_id for asset in assets)
    finding_counts=Counter(finding.tenant_id for finding in findings)
    tenants=sorted(set(asset_counts)|set(finding_counts))
    return {
        "assets":len(assets),
        "findings":len(findings),
        "tenants":{
            tenant_id:{
                "assets":asset_counts[tenant_id],
                "findings":finding_counts[tenant_id],
            }
            for tenant_id in tenants
        },
    }


def _payload_index(items) -> dict[tuple[str,str],dict]:
    return {
        (item.tenant_id,item.id):item.model_dump(mode="json")
        for item in items
    }


def migrate_state(
    assets: list[Asset],
    findings: list[Finding],
    destination,
    *,
    allow_existing: bool=False,
    dry_run: bool=False,
) -> dict:
    source_summary=state_summary(assets,findings)
    tenant_ids=sorted({
        *(asset.tenant_id for asset in assets),
        *(finding.tenant_id for finding in findings),
    })

    existing_assets=[]
    existing_findings=[]
    for tenant_id in tenant_ids:
        tenant_assets=list(destination.list_assets(tenant_id))
        existing_assets.extend(tenant_assets)
        existing_findings.extend(destination.list_findings(tenant_id))
    if (existing_assets or existing_findings) and not allow_existing:
        raise RuntimeError(
            "destination PostgreSQL repository is not empty; "
            "rerun only with --allow-existing after reviewing the target"
        )

    if dry_run:
        return {
            "status":"validated",
            "dry_run":True,
            "source":source_summary,
            "destination_before":state_summary(existing_assets,existing_findings),
        }

    for asset in assets:
        destination.add_asset(asset)
    for finding in findings:
        destination.add_finding(finding)
    destination.persist()

    migrated_assets=[]
    migrated_findings=[]
    for tenant_id in tenant_ids:
        tenant_assets=list(destination.list_assets(tenant_id))
        migrated_assets.extend(tenant_assets)
        migrated_findings.extend(destination.list_findings(tenant_id))

    source_assets=_payload_index(assets)
    source_findings=_payload_index(findings)
    target_assets=_payload_index(migrated_assets)
    target_findings=_payload_index(migrated_findings)

    asset_mismatches=[
        key for key,payload in source_assets.items()
        if target_assets.get(key)!=payload
    ]
    finding_mismatches=[
        key for key,payload in source_findings.items()
        if target_findings.get(key)!=payload
    ]
    if asset_mismatches or finding_mismatches:
        raise RuntimeError(
            "PostgreSQL reconciliation failed: "
            f"{len(asset_mismatches)} asset mismatch(es), "
            f"{len(finding_mismatches)} finding mismatch(es)"
        )

    return {
        "status":"migrated",
        "dry_run":False,
        "source":source_summary,
        "destination_after":state_summary(migrated_assets,migrated_findings),
        "verified":{
            "assets":len(source_assets),
            "findings":len(source_findings),
        },
    }


def main() -> None:
    parser=argparse.ArgumentParser(
        prog="python -m app.migrate_asset_store",
        description="Migrate BSA assets/findings from SQLite to PostgreSQL.",
    )
    parser.add_argument(
        "--sqlite",
        default=os.getenv("BSA_STORE_DB","/data/bsa_store.db"),
        help="source SQLite asset store",
    )
    parser.add_argument(
        "--dsn",
        default=os.getenv("BSA_DATABASE_URL",""),
        help="destination PostgreSQL DSN",
    )
    parser.add_argument("--allow-existing",action="store_true")
    parser.add_argument("--dry-run",action="store_true")
    args=parser.parse_args()

    if not args.dsn:
        raise SystemExit("BSA_DATABASE_URL or --dsn is required")

    assets,findings=load_sqlite_state(args.sqlite)
    destination=PostgresAssetFindingRepository(args.dsn)
    result=migrate_state(
        assets,
        findings,
        destination,
        allow_existing=args.allow_existing,
        dry_run=args.dry_run,
    )
    print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
