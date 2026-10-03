from __future__ import annotations

import json
from typing import Any

from .models import Asset, Finding


def _connect(dsn: str):
    import psycopg

    return psycopg.connect(dsn)


def export_asset_state(dsn: str, connect=None) -> dict[str, Any]:
    connect=connect or _connect
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT payload_json FROM assets ORDER BY tenant_id,id")
            assets=[row[0] if isinstance(row[0],dict) else json.loads(row[0]) for row in cur.fetchall()]
            cur.execute("SELECT payload_json FROM findings ORDER BY tenant_id,id")
            findings=[row[0] if isinstance(row[0],dict) else json.loads(row[0]) for row in cur.fetchall()]
    for payload in assets:
        Asset.model_validate(payload)
    for payload in findings:
        Finding.model_validate(payload)
    return {"assets":assets,"findings":findings}


def restore_asset_state(
    dsn: str,
    snapshot: dict[str, Any],
    *,
    force: bool=False,
    connect=None,
) -> dict[str, int]:
    connect=connect or _connect
    assets=[Asset.model_validate(item) for item in snapshot.get("assets",[])]
    findings=[Finding.model_validate(item) for item in snapshot.get("findings",[])]
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM assets")
            asset_count=int(cur.fetchone()[0])
            cur.execute("SELECT COUNT(*) FROM findings")
            finding_count=int(cur.fetchone()[0])
            if (asset_count or finding_count) and not force:
                raise FileExistsError("refusing to overwrite non-empty PostgreSQL asset store")
            if force:
                cur.execute("TRUNCATE TABLE findings, assets")
            for asset in assets:
                cur.execute(
                    """INSERT INTO assets(tenant_id,id,payload_json,updated_at)
                       VALUES(%s,%s,%s::jsonb,NOW())""",
                    (
                        asset.tenant_id,
                        asset.id,
                        json.dumps(asset.model_dump(mode="json"),ensure_ascii=False),
                    ),
                )
            for finding in findings:
                cur.execute(
                    """INSERT INTO findings(tenant_id,id,asset_id,payload_json,updated_at)
                       VALUES(%s,%s,%s,%s::jsonb,NOW())""",
                    (
                        finding.tenant_id,
                        finding.id,
                        finding.asset_id,
                        json.dumps(finding.model_dump(mode="json"),ensure_ascii=False),
                    ),
                )
    return {"assets":len(assets),"findings":len(findings)}
