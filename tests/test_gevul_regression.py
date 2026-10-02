from app.auth import Principal
from app.api.routers import graph_assessment as graph_assessment_router
from app.history import (
    list_ctem_items,
    update_ctem_state,
    ctem_verification_history,
)


def test_verified_finding_reappearance_reopens_gevul_and_ctem(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "history.db"))
    monkeypatch.setattr(graph_assessment_router, "STORE_ASSETS", [])
    monkeypatch.setattr(graph_assessment_router, "STORE_FINDINGS", [])
    monkeypatch.setattr(graph_assessment_router, "asset_in_scope", lambda principal, value: True)
    monkeypatch.setattr(graph_assessment_router, "persist_state", lambda assets, findings: None)
    monkeypatch.setattr(graph_assessment_router, "audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        graph_assessment_router,
        "assess_ctem_priority",
        lambda finding, asset: {
            "priority": 80,
            "action": "expedite",
            "drivers": ["evidence-backed exposure"],
        },
    )

    principal = Principal(
        user_id="u-regression",
        tenant_id="tenant-regression",
        email="regression@example.org",
        role="admin",
        name="Regression Admin",
    )

    result = {
        "assessment_id": "assessment-regression-1",
        "findings": [
            {
                "asset": "https://api.example.org",
                "category": "web_assessment",
                "title": "Administrative exposure",
                "severity": "high",
                "confidence": 92,
                "evidence": {
                    "url": "https://api.example.org",
                    "reference": ["evidence-before-remediation"],
                    "validation_state": "confirmed_evidence",
                },
            }
        ],
    }

    first = graph_assessment_router._materialize_assessment_result(principal, result)
    assert first["findings_created"] == 1
    assert first["regressions_reopened"] == 0

    finding = graph_assessment_router.STORE_FINDINGS[0]
    finding.status = "verified"

    item_id = f"assessment:{principal.tenant_id}:{finding.id}"
    update_ctem_state(item_id, principal.tenant_id, "acknowledged")
    update_ctem_state(item_id, principal.tenant_id, "in_progress")
    update_ctem_state(item_id, principal.tenant_id, "resolved")
    update_ctem_state(item_id, principal.tenant_id, "verified")

    result["assessment_id"] = "assessment-regression-2"
    result["findings"][0]["evidence"]["reference"] = ["evidence-after-remediation"]

    second = graph_assessment_router._materialize_assessment_result(principal, result)

    assert second["findings_created"] == 0
    assert second["regressions_reopened"] == 1
    assert second["ctem_regressions_reopened"] == 1
    assert finding.status == "open"
    assert "regression" in finding.evidence.lower()

    item = next(x for x in list_ctem_items(principal.tenant_id) if x["item_id"] == item_id)
    assert item["state"] == "in_progress"
    assert item["verified_at"] is None

    history = ctem_verification_history(item_id, principal.tenant_id)
    assert history
    assert history[-1]["result"] == "failed"
    assert "evidence-after-remediation" in history[-1]["evidence_refs"]
