import json
from types import SimpleNamespace

from app.auth import Principal
from app.models import Asset, AssetType
from app.history import upsert_ctem_item, update_ctem_state
import app.main as main


def test_ctem_retest_queues_authorized_assessment(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "history.db"))

    principal = Principal(
        user_id="u-retest",
        tenant_id="tenant-retest",
        email="retest@example.org",
        role="admin",
        name="Retest Admin",
    )
    now = "2026-10-01T00:00:00+00:00"
    asset = Asset(
        tenant_id=principal.tenant_id,
        id="asset-retest",
        value="api.example.org",
        type=AssetType.DOMAIN,
        first_seen=now,
        last_seen=now,
    )
    monkeypatch.setattr(main, "STORE_ASSETS", [asset])
    monkeypatch.setattr(main, "STORE_FINDINGS", [])
    monkeypatch.setattr(main, "require", lambda request, permission: principal)
    monkeypatch.setattr(main, "govern_active_scan", lambda request, principal, target, authorization_ref=None: "AUTH-RETEST")
    monkeypatch.setattr(main, "audit", lambda *args, **kwargs: None)

    item = upsert_ctem_item(
        {
            "item_id": "assessment:tenant-retest:finding-1",
            "asset_id": asset.id,
            "finding_id": "finding-1",
            "priority": 80,
            "action": "expedite",
            "title": "Retest finding",
            "drivers": [],
            "evidence_refs": ["before-remediation"],
        },
        principal.tenant_id,
    )
    update_ctem_state(item["item_id"], principal.tenant_id, "acknowledged")
    update_ctem_state(item["item_id"], principal.tenant_id, "in_progress")

    captured = {}

    def enqueue(principal, target, profile, authorization_ref):
        captured.update(
            target=target,
            profile=profile,
            authorization_ref=authorization_ref,
        )
        return {
            "job_id": "job-retest",
            "status": "queued",
            "target": target,
            "profile": profile,
        }

    monkeypatch.setattr(main, "enqueue_assessment", enqueue)

    request = SimpleNamespace(
        headers={"X-Authorization-Ref": "AUTH-RETEST"},
        method="POST",
        url=SimpleNamespace(path=f"/api/v1/ctem/{item['item_id']}/retest"),
    )
    response = main.ctem_retest(
        item["item_id"],
        request,
        {"profile": "rapid", "authorization_ref": "AUTH-RETEST"},
    )

    assert response.status_code == 202
    body = json.loads(response.body)
    assert body["job_id"] == "job-retest"
    assert body["verification_required"] is True
    assert captured == {
        "target": "api.example.org",
        "profile": "rapid",
        "authorization_ref": "AUTH-RETEST",
    }
