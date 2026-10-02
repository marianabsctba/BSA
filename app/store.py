import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Asset, AssetType, Finding, Severity


def _store_path() -> str | None:
    configured = os.getenv("BSA_STORE_DB", "").strip()
    if configured:
        return configured
    if os.getenv("BSA_ENV", "development").lower() in {"production", "prod"}:
        return "/data/bsa_store.db"
    return None


def _connect():
    path = _store_path()
    if not path:
        return None
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS assets(
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id,id)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS findings(
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id,id)
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_tenant_asset ON findings(tenant_id,asset_id)")
    conn.commit()
    return conn


def _load_persisted() -> tuple[list[Asset], list[Finding]]:
    conn = _connect()
    if conn is None:
        return [], []
    try:
        assets = [Asset.model_validate(json.loads(r["payload_json"])) for r in conn.execute(
            "SELECT payload_json FROM assets ORDER BY tenant_id,id"
        ).fetchall()]
        findings = [Finding.model_validate(json.loads(r["payload_json"])) for r in conn.execute(
            "SELECT payload_json FROM findings ORDER BY tenant_id,id"
        ).fetchall()]
        return assets, findings
    finally:
        conn.close()


def persist_asset(asset: Asset) -> None:
    conn = _connect()
    if conn is None:
        return
    try:
        conn.execute(
            """INSERT INTO assets(tenant_id,id,payload_json,updated_at) VALUES(?,?,?,?)
               ON CONFLICT(tenant_id,id) DO UPDATE SET
                 payload_json=excluded.payload_json,
                 updated_at=excluded.updated_at""",
            (
                asset.tenant_id,
                asset.id,
                json.dumps(asset.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def persist_finding(finding: Finding) -> None:
    conn = _connect()
    if conn is None:
        return
    try:
        conn.execute(
            """INSERT INTO findings(tenant_id,id,asset_id,payload_json,updated_at) VALUES(?,?,?,?,?)
               ON CONFLICT(tenant_id,id) DO UPDATE SET
                 asset_id=excluded.asset_id,
                 payload_json=excluded.payload_json,
                 updated_at=excluded.updated_at""",
            (
                finding.tenant_id,
                finding.id,
                finding.asset_id,
                json.dumps(finding.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def persist_state(assets: list[Asset], findings: list[Finding]) -> None:
    conn = _connect()
    if conn is None:
        return
    now = datetime.now(timezone.utc).isoformat()
    try:
        for asset in assets:
            conn.execute(
                """INSERT INTO assets(tenant_id,id,payload_json,updated_at) VALUES(?,?,?,?)
                   ON CONFLICT(tenant_id,id) DO UPDATE SET
                     payload_json=excluded.payload_json,
                     updated_at=excluded.updated_at""",
                (asset.tenant_id, asset.id, json.dumps(asset.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")), now),
            )
        for finding in findings:
            conn.execute(
                """INSERT INTO findings(tenant_id,id,asset_id,payload_json,updated_at) VALUES(?,?,?,?,?)
                   ON CONFLICT(tenant_id,id) DO UPDATE SET
                     asset_id=excluded.asset_id,
                     payload_json=excluded.payload_json,
                     updated_at=excluded.updated_at""",
                (finding.tenant_id, finding.id, finding.asset_id, json.dumps(finding.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")), now),
            )
        conn.commit()
    finally:
        conn.close()


def _demo_state() -> tuple[list[Asset], list[Finding]]:
    now = datetime.now(timezone.utc).isoformat()
    assets = [
        Asset(
            id="ast-001", value="example.org", type=AssetType.DOMAIN,
            confidence=100, criticality=5, source="seed", owner="Security",
            business_unit="Corporate", environment="production",
            tags=["confirmed-owner", "internet-facing", "production"],
            first_seen=now, last_seen=now,
        ),
        Asset(
            id="ast-002", value="vpn.example.org", type=AssetType.SUBDOMAIN,
            confidence=92, criticality=5, source="dns", owner="Infra / IAM",
            business_unit="Corporate", environment="production",
            tags=["remote-access", "internet-facing", "production", "new"],
            first_seen=now, last_seen=now,
        ),
        Asset(
            id="ast-003", value="203.0.113.10:443", type=AssetType.SERVICE,
            confidence=90, criticality=4, source="tls-http", owner="AppSec / Infra",
            business_unit="Technology", environment="production",
            tags=["https", "internet-facing", "changed"],
            first_seen=now, last_seen=now,
        ),
        Asset(
            id="ast-004", value="legacy.example.org", type=AssetType.SUBDOMAIN,
            confidence=68, criticality=2, source="certificate-transparency",
            business_unit="Unknown", environment="unknown",
            tags=["candidate", "third-party"],
            first_seen=now, last_seen=now,
        ),
    ]
    findings = [
        Finding(
            id="fdg-001", asset_id="ast-002",
            title="Serviço administrativo exposto à Internet",
            severity=Severity.HIGH, confidence=88,
            evidence="Endpoint classificado como acesso remoto durante descoberta controlada.",
            remediation="Validar necessidade de exposição, MFA, allowlist e controles compensatórios.",
        ),
        Finding(
            id="fdg-002", asset_id="ast-003",
            title="Certificado próximo da expiração",
            severity=Severity.MEDIUM, confidence=96,
            evidence="Janela de validade observada no handshake TLS.",
            remediation="Planejar renovação antes da janela operacional de risco.",
        ),
        Finding(
            id="fdg-003", asset_id="ast-004",
            title="Ativo candidato sem ownership confirmado",
            severity=Severity.LOW, confidence=70,
            evidence="Ativo encontrado em fonte passiva, ainda sem evidência suficiente de propriedade.",
            remediation="Correlacionar DNS, certificados, ASN, CMDB e validação humana antes de promover o ativo.",
        ),
    ]
    return assets, findings


if _store_path():
    ASSETS, FINDINGS = _load_persisted()
else:
    ASSETS, FINDINGS = _demo_state()
