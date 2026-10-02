from types import SimpleNamespace

import app.main as main
from app.models import Asset, AssetType, Finding, Severity


def _asset(**overrides):
    data = {
        "tenant_id": "tenant-pilot",
        "id": "asset-pilot",
        "value": "example.org",
        "type": AssetType.DOMAIN,
        "status": "observed",
        "confidence": 100,
        "criticality": 5,
        "source": "manual",
        "tags": ["confirmed-owner", "internet-facing", "production"],
        "first_seen": "2026-10-01T00:00:00+00:00",
        "last_seen": "2026-10-01T00:00:00+00:00",
    }
    data.update(overrides)
    return Asset(**data)


def _finding(**overrides):
    data = {
        "tenant_id": "tenant-pilot",
        "id": "finding-pilot",
        "asset_id": "asset-pilot",
        "title": "Administrative service exposed",
        "severity": Severity.HIGH,
        "confidence": 90,
        "status": "open",
        "evidence": "pilot evidence",
        "validation_state": "confirmed",
        "evidence_quality": 90,
    }
    data.update(overrides)
    return Finding(**data)


def _principal():
    return SimpleNamespace(tenant_id="tenant-pilot", role="admin", user_id="user-pilot")


def test_easm_confirmed_owner_is_approved(monkeypatch):
    asset=_asset()
    monkeypatch.setattr(main, "require", lambda request, permission: _principal())
    monkeypatch.setattr(main, "tenant_scope", lambda principal, assets, findings: ([asset], []))

    result=main.easm_overview(None)

    assert result["summary"]["approved"] == 1
    assert result["summary"]["candidates"] == 0
    assert result["inventory"][0]["state"] == "approved"


def test_business_impact_is_bounded_to_100(monkeypatch):
    asset=_asset()
    finding=_finding()
    monkeypatch.setattr(main, "require", lambda request, permission: _principal())
    monkeypatch.setattr(main, "tenant_scope", lambda principal, assets, findings: ([asset], [finding]))

    result=main.exposure_business_impact(None)

    assert result["items"]
    assert 0 <= result["items"][0]["impact_index"] <= 100


def test_vulnerability_summary_counts_actual_finding_severity(monkeypatch):
    asset=_asset()
    finding=_finding()
    monkeypatch.setattr(main, "require", lambda request, permission: _principal())
    monkeypatch.setattr(main, "tenant_scope", lambda principal, assets, findings: ([asset], [finding]))

    result=main.vulnerability_intelligence_api(None)

    assert result["summary"]["findings"] == 1
    assert result["summary"]["high"] == 1


def test_graph_endpoint_never_uses_internal_tenant_identifier_as_root(monkeypatch):
    captured={}
    monkeypatch.setattr(main, "require", lambda request, permission: _principal())
    monkeypatch.setattr(main, "tenant_scope", lambda principal, assets, findings: ([], []))

    def fake_graph(target, *args, **kwargs):
        captured["target"]=target
        return {"nodes": [], "edges": [], "risk_summary": {}, "top_risk_paths": []}

    monkeypatch.setattr(main, "build_risk_graph", fake_graph)

    main.graph(None)

    assert captured["target"] == "External Surface"
    assert not captured["target"].startswith("tenant:")
