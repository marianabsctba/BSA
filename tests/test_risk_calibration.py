from app.models import Asset, AssetType, Finding, Severity
from app.risk_engine import assess_ctem_priority


def _asset(tags):
    return Asset(
        tenant_id="tenant-risk-cal",
        id="asset-risk-cal",
        value="api.example.org",
        type=AssetType.APPLICATION,
        confidence=90,
        criticality=4,
        tags=list(tags),
        first_seen="2026-10-01T00:00:00+00:00",
        last_seen="2026-10-01T00:00:00+00:00",
    )


def _finding(**overrides):
    data = {
        "tenant_id": "tenant-risk-cal",
        "id": "finding-risk-cal",
        "asset_id": "asset-risk-cal",
        "title": "Exposure",
        "severity": Severity.HIGH,
        "confidence": 90,
        "status": "open",
        "evidence": "assessment evidence",
        "vulnerability_id": "CVE-2026-9991",
        "validation_state": "confirmed",
        "evidence_quality": 85,
    }
    data.update(overrides)
    return Finding(**data)


def test_confirmed_exploitable_internet_exposure_outranks_cvss_only_signal():
    cvss_only = _finding(
        cvss=9.8,
        epss=None,
        kev=False,
        exploit_available=False,
        validation_state="observed",
        evidence_quality=60,
        confidence=78,
    )
    active_threat = _finding(
        cvss=7.5,
        epss=0.92,
        kev=True,
        exploit_available=True,
        validation_state="confirmed",
        evidence_quality=90,
        confidence=95,
        independent_source_count=2,
        independently_corroborated=True,
    )

    cvss_priority = assess_ctem_priority(cvss_only, _asset([]))
    threat_priority = assess_ctem_priority(
        active_threat,
        _asset(["internet-facing", "production"]),
    )

    assert threat_priority["priority"] > cvss_priority["priority"]
    assert threat_priority["action"] in {"immediate", "expedite"}
    assert threat_priority["known_exploited"] is True
    assert threat_priority["high_exploitation_probability"] is True


def test_unvalidated_signal_never_becomes_immediate_from_cvss_alone():
    pending = _finding(
        cvss=10.0,
        epss=0.95,
        kev=True,
        validation_state="needs_validation",
        evidence_quality=40,
        confidence=60,
    )

    priority = assess_ctem_priority(
        pending,
        _asset(["internet-facing", "production"]),
    )

    assert priority["priority"] <= 69
    assert priority["action"] == "validate"
