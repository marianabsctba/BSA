from app.auth import Principal
from app.api.routers import graph_assessment as graph_assessment_router


def test_same_cve_retains_multiple_observed_locations(monkeypatch):
    monkeypatch.setattr(graph_assessment_router, "STORE_ASSETS", [])
    monkeypatch.setattr(graph_assessment_router, "STORE_FINDINGS", [])
    monkeypatch.setattr(graph_assessment_router, "asset_in_scope", lambda principal, value: True)
    monkeypatch.setattr(graph_assessment_router, "persist_state", lambda assets, findings: None)
    monkeypatch.setattr(graph_assessment_router, "enrich_finding", lambda finding: finding)
    monkeypatch.setattr(
        graph_assessment_router,
        "assess_ctem_priority",
        lambda finding, asset: {"priority": 0, "action": "monitor", "drivers": []},
    )

    principal = Principal(
        user_id="u-components",
        tenant_id="tenant-components",
        email="components@example.org",
        role="admin",
        name="Components Admin",
    )

    def payload(path: str):
        return {
            "assessment_id": f"assessment-{path}",
            "findings": [
                {
                    "asset": "api.example.org",
                    "category": "vulnerability_validation",
                    "title": "CVE exposure",
                    "severity": "high",
                    "confidence": 92,
                    "evidence": {
                        "vulnerability_id": "CVE-2026-4242",
                        "matched_at": f"https://api.example.org/{path}",
                        "reference": [f"evidence-{path}"],
                        "validation_state": "confirmed_evidence",
                    },
                }
            ],
        }

    first = graph_assessment_router._materialize_assessment_result(principal, payload("login"))
    second = graph_assessment_router._materialize_assessment_result(principal, payload("admin"))

    assert first["findings_created"] == 1
    assert second["findings_created"] == 0
    assert len(graph_assessment_router.STORE_FINDINGS) == 1

    finding = graph_assessment_router.STORE_FINDINGS[0]
    assert set(finding.affected_components) == {
        "https://api.example.org/login",
        "https://api.example.org/admin",
    }
    assert finding.affected_component == "https://api.example.org/admin"
    assert set(finding.source_refs) == {"evidence-login", "evidence-admin"}
