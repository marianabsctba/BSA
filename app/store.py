from datetime import datetime, timezone
from .models import Asset, AssetType, Finding, Severity

now = datetime.now(timezone.utc).isoformat()

ASSETS = [
    Asset(
        id="ast-001", value="example.org", type=AssetType.DOMAIN,
        confidence=100, criticality=5, source="seed", owner="Security", business_unit="Corporate", environment="production",
        tags=["confirmed-owner", "internet-facing", "production"],
        first_seen=now, last_seen=now
    ),
    Asset(
        id="ast-002", value="vpn.example.org", type=AssetType.SUBDOMAIN,
        confidence=92, criticality=5, source="dns", owner="Infra / IAM", business_unit="Corporate", environment="production",
        tags=["remote-access", "internet-facing", "production", "new"],
        first_seen=now, last_seen=now
    ),
    Asset(
        id="ast-003", value="203.0.113.10:443", type=AssetType.SERVICE,
        confidence=90, criticality=4, source="tls-http", owner="AppSec / Infra", business_unit="Technology", environment="production",
        tags=["https", "internet-facing", "changed"],
        first_seen=now, last_seen=now
    ),
    Asset(
        id="ast-004", value="legacy.example.org", type=AssetType.SUBDOMAIN,
        confidence=68, criticality=2, source="certificate-transparency", business_unit="Unknown", environment="unknown",
        tags=["candidate", "third-party"],
        first_seen=now, last_seen=now
    ),
]

FINDINGS = [
    Finding(
        id="fdg-001",
        asset_id="ast-002",
        title="Serviço administrativo exposto à Internet",
        severity=Severity.HIGH,
        confidence=88,
        evidence="Endpoint classificado como acesso remoto durante descoberta controlada.",
        remediation="Validar necessidade de exposição, MFA, allowlist e controles compensatórios.",
    ),
    Finding(
        id="fdg-002",
        asset_id="ast-003",
        title="Certificado próximo da expiração",
        severity=Severity.MEDIUM,
        confidence=96,
        evidence="Janela de validade observada no handshake TLS.",
        remediation="Planejar renovação antes da janela operacional de risco.",
    ),
    Finding(
        id="fdg-003",
        asset_id="ast-004",
        title="Ativo candidato sem ownership confirmado",
        severity=Severity.LOW,
        confidence=70,
        evidence="Ativo encontrado em fonte passiva, ainda sem evidência suficiente de propriedade.",
        remediation="Correlacionar DNS, certificados, ASN, CMDB e validação humana antes de promover o ativo.",
    ),
]
