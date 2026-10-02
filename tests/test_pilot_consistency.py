from types import SimpleNamespace

import app.main as main
from app.api.routers import vulnerabilities as vulnerabilities_router
from app.api.routers import discovery_execution as discovery_execution_router
from app.api.routers import exposure as exposure_router
from app.api.routers import graph_assessment as graph_assessment_router
from app.api.routers import reporting as reporting_router
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
    monkeypatch.setattr(discovery_execution_router, "require", lambda request, permission: _principal())
    monkeypatch.setattr(discovery_execution_router, "tenant_scope", lambda principal: ([asset], []))

    result=discovery_execution_router.easm_overview(None)

    assert result["summary"]["approved"] == 1
    assert result["summary"]["candidates"] == 0
    assert result["inventory"][0]["state"] == "approved"


def test_business_impact_is_bounded_to_100(monkeypatch):
    asset=_asset()
    finding=_finding()
    monkeypatch.setattr(exposure_router, "require", lambda request, permission: _principal())
    monkeypatch.setattr(exposure_router, "tenant_scope", lambda principal: ([asset], [finding]))

    result=exposure_router.exposure_business_impact(None)

    assert result["items"]
    assert 0 <= result["items"][0]["impact_index"] <= 100


def test_vulnerability_summary_counts_actual_finding_severity(monkeypatch):
    asset=_asset()
    finding=_finding()
    monkeypatch.setattr(vulnerabilities_router, "require", lambda request, permission: _principal())
    monkeypatch.setattr(vulnerabilities_router, "tenant_scope", lambda principal, assets, findings: ([asset], [finding]))

    result=vulnerabilities_router.vulnerability_intelligence_api(None)

    assert result["summary"]["findings"] == 1
    assert result["summary"]["high"] == 1


def test_graph_endpoint_never_uses_internal_tenant_identifier_as_root(monkeypatch):
    captured={}
    monkeypatch.setattr(graph_assessment_router, "require", lambda request, permission: _principal())
    monkeypatch.setattr(graph_assessment_router, "tenant_scope", lambda principal: ([], []))

    def fake_graph(target, *args, **kwargs):
        captured["target"]=target
        return {"nodes": [], "edges": [], "risk_summary": {}, "top_risk_paths": []}

    monkeypatch.setattr(graph_assessment_router, "build_risk_graph", fake_graph)

    graph_assessment_router.graph(None)

    assert captured["target"] == "External Surface"
    assert not captured["target"].startswith("tenant:")



def test_report_summary_exposes_engine_private_operational_metrics(monkeypatch):
    asset=_asset()
    finding=_finding()
    principal=_principal()

    monkeypatch.setattr(reporting_router, "require", lambda request, permission: principal)
    monkeypatch.setattr(reporting_router, "tenant_scope", lambda p: ([asset], [finding]))
    monkeypatch.setattr(reporting_router, "public_engine_health", lambda: {
        "profiles":{
            "rapid":{"state":"ready","coverage_percent":100},
            "balanced":{"state":"partial","coverage_percent":80},
        }
    })
    monkeypatch.setattr(reporting_router, "queue_metrics", lambda tenant_id: {
        "total_jobs":4,"queued":1,"running":1,"succeeded":2,"failed":0,
        "cancelled":0,"retries":1,"success_rate_percent":100,
        "average_execution_seconds":5,"average_queue_wait_seconds":1,
    })
    monkeypatch.setattr(reporting_router, "list_ctem_items", lambda tenant_id: [])
    monkeypatch.setattr(reporting_router, "ctem_operational_summary", lambda items, *args, **kwargs: {
        "active_items":0,"overdue_items":0,"oldest_active_age_hours":0,
    })
    monkeypatch.setattr(reporting_router, "ctem_queue_view", lambda items: {
        "buckets":{
            "critical":{"count":0,"items":[]},
            "high":{"count":0,"items":[]},
            "medium":{"count":0,"items":[]},
            "low":{"count":0,"items":[]},
        }
    })

    result=reporting_router.report_summary(None)
    ops=result["operations"]

    assert ops["queue"]["queued"] == 1
    assert ops["coverage"]["rapid"] == {"state":"ready","coverage_percent":100}
    assert ops["coverage"]["balanced"] == {"state":"partial","coverage_percent":80}
    assert "provider" not in str(ops).lower()
    assert "nuclei" not in str(ops).lower()
