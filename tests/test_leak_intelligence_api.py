from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main
from app import digital_risk
from app.api.routers import digital_risk as digital_risk_router


client=TestClient(main.app)


def _principal():
    return SimpleNamespace(
        tenant_id="tenant-leak",
        user_id="admin-leak",
        email="admin@example.org",
        role="admin",
        name="Leak Admin",
    )


def test_specialized_drp_score_and_reasons_survive_generic_enrichment():
    item=digital_risk.enrich_event({
        "category":"credential_leak",
        "title":"Recurring stealer exposure",
        "indicator":"identity-fingerprint",
        "source":"verified",
        "severity":"high",
        "confidence":92,
        "evidence":{"sample_hash":"safe"},
        "status":"open",
        "risk_score":96,
        "risk_reasons":["recency:fresh","occurrences:3","source_reliability:90"],
    })

    assert item["risk_score"]>=96
    assert item["risk_band"]=="critical"
    assert "recency:fresh" in item["risk_reasons"]
    assert "occurrences:3" in item["risk_reasons"]
    assert "source_reliability:90" in item["risk_reasons"]


def test_leak_api_persists_recurrence_subtype_and_secret_hygiene(tmp_path,monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))
    principal=_principal()
    monkeypatch.setattr(
        digital_risk_router,
        "require",
        lambda request,permission:principal,
    )
    monkeypatch.setattr(
        digital_risk_router,
        "tenant_scope",
        lambda principal:([],[]),
    )
    monkeypatch.setattr(digital_risk_router,"audit",lambda *args,**kwargs:None)

    payload={
        "leak_type":"combo",
        "indicator":"user@example.org",
        "source":"verified",
        "account_count":12,
        "secret_count":2,
        "confidence":90,
        "evidence":{
            "sample_hash":"safe-hash",
            "password":"must-not-persist",
            "token":"must-not-persist",
        },
    }

    first=client.post("/api/v1/digital-risk/leaks",json=payload)
    second=client.post("/api/v1/digital-risk/leaks",json=payload)

    assert first.status_code==200
    assert second.status_code==200
    first_item=first.json()
    second_item=second.json()
    assert first_item["event_id"]==second_item["event_id"]
    assert first_item["leak_subtype"]=="combo_list"
    assert first_item["occurrence_count"]==1
    assert first_item["lifecycle_state"]=="new"
    assert second_item["occurrence_count"]==2
    assert second_item["recurring"] is True
    assert second_item["lifecycle_state"]=="recurring"
    assert second_item["source_reliability"]==90
    assert second_item["contains_raw_secret"] is False
    assert "password" not in second_item["evidence"]
    assert "token" not in second_item["evidence"]
    assert second_item["evidence"]["sample_hash"]=="safe-hash"
    assert "occurrences:2" in second_item["risk_reasons"]
