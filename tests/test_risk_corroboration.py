from app.models import Asset, AssetType, Finding, Severity
from app.vulnerability_intelligence import vulnerability_intelligence


def _asset():
    return Asset(
        tenant_id="tenant-risk",
        id="asset-risk",
        value="api.example.org",
        type=AssetType.APPLICATION,
        confidence=90,
        criticality=4,
        tags=["internet-facing", "production"],
        first_seen="2026-10-01T00:00:00+00:00",
        last_seen="2026-10-01T00:00:00+00:00",
    )


def _finding(**overrides):
    data = {
        "tenant_id": "tenant-risk",
        "id": "finding-risk",
        "asset_id": "asset-risk",
        "title": "CVE exposure",
        "severity": Severity.HIGH,
        "confidence": 92,
        "status": "open",
        "evidence": "assessment evidence",
        "vulnerability_id": "CVE-2026-4242",
        "cvss": 8.8,
        "epss": 0.82,
        "kev": True,
        "validation_state": "confirmed",
        "evidence_quality": 80,
        "source_refs": ["ref-a", "ref-b", "ref-c"],
    }
    data.update(overrides)
    return Finding(**data)


def test_multiple_references_do_not_fake_independent_corroboration():
    finding = _finding(
        independent_source_count=1,
        independently_corroborated=False,
    )

    intel = vulnerability_intelligence(finding, _asset())

    assert "evidência corroborada por fontes independentes" not in intel.reasons
    assert "múltiplas referências sem independência comprovada" in intel.reasons


def test_independent_corroboration_increases_evidence_quality():
    single = _finding(
        independent_source_count=1,
        independently_corroborated=False,
    )
    corroborated = _finding(
        independent_source_count=3,
        independently_corroborated=True,
    )

    single_intel = vulnerability_intelligence(single, _asset())
    corroborated_intel = vulnerability_intelligence(corroborated, _asset())

    assert corroborated_intel.evidence_quality > single_intel.evidence_quality
    assert "evidência corroborada por fontes independentes" in corroborated_intel.reasons
