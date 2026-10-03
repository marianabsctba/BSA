from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main
from app import digital_risk
from app.api.routers import digital_risk as digital_risk_router
from app.brand_threat_intelligence import build_brand_threat


client=TestClient(main.app)


def _principal(tenant_id="tenant-a"):
    return SimpleNamespace(
        tenant_id=tenant_id,
        user_id=f"{tenant_id}-admin",
        email=f"{tenant_id}@example.org",
        role="admin",
        name="Admin",
    )


def test_brand_threat_marks_high_confidence_phishing_for_review():
    result=build_brand_threat(
        tenant_id="tenant-a",
        indicator="https://acme-login.invalid",
        brand="Acme",
        vip="CEO Acme",
        confidence=90,
        text_similarity=90,
        visual_similarity=85,
        evidence={"kind":"phishing"},
    )

    assert result["threat_type"]=="phishing"
    assert result["takedown_candidate"] is True
    assert result["human_review_required"] is True
    assert result["attribution"]=="unattributed"
    assert "vip_target" in result["signals"]


def test_brand_campaign_groups_same_brand_and_vip():
    first=build_brand_threat(
        tenant_id="tenant-a",
        indicator="acme-login.invalid",
        brand="Acme",
        vip="CEO Acme",
        confidence=85,
        evidence={"registrar":"reg-a"},
    )
    second=build_brand_threat(
        tenant_id="tenant-a",
        indicator="acme-support.invalid",
        brand="Acme",
        vip="CEO Acme",
        confidence=85,
        evidence={"registrar":"reg-a"},
        prior_events=[{
            "event_id":"evt-1",
            "brand":"Acme",
            "vip_target":"CEO Acme",
            "campaign_key":first["campaign_key"],
        }],
    )

    assert first["campaign_key"]==second["campaign_key"]
    assert second["campaign_event_count"]==2
    assert second["related_event_ids"]==["evt-1"]


def test_brand_correlation_api_persists_only_inside_tenant(tmp_path, monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))
    principal=_principal("tenant-a")
    monkeypatch.setattr(digital_risk_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(digital_risk_router,"audit",lambda *args,**kwargs:None)

    response=client.post("/api/v1/digital-risk/brand/correlate",json={
        "indicator":"https://acme-login.invalid",
        "brand":"Acme",
        "vip":"CEO Acme",
        "confidence":92,
        "text_similarity":95,
        "visual_similarity":90,
        "evidence":{"kind":"phishing","registrar":"reg-a"},
    })
    assert response.status_code==200
    body=response.json()
    assert body["event_id"]
    assert body["takedown_candidate"] is True

    tenant_a=digital_risk.list_events("tenant-a")
    tenant_b=digital_risk.list_events("tenant-b")
    assert len(tenant_a)==1
    assert tenant_a[0]["campaign_key"]==body["campaign_key"]
    assert tenant_b==[]
