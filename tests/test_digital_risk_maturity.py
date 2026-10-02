from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main
from app import auth
from app import digital_risk
from app.models import Asset, AssetType


client=TestClient(main.app)


def _principal(tenant_id):
    return SimpleNamespace(
        tenant_id=tenant_id,
        user_id=f"{tenant_id}-admin",
        email=f"{tenant_id}@example.org",
        role="admin",
        name=f"Admin {tenant_id}",
    )


def test_drp_deduplicates_correlated_events(tmp_path, monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))

    first=digital_risk.upsert_event("tenant-a",{
        "category":"phishing",
        "title":"Fake portal",
        "indicator":"login-example.invalid",
        "source":"feed-a",
        "severity":"high",
        "confidence":80,
        "evidence":{"dns":"observed"},
        "status":"open",
        "brand":"Example",
    })
    second=digital_risk.upsert_event("tenant-a",{
        "category":"phishing",
        "title":"Same fake portal",
        "indicator":"login-example.invalid",
        "source":"feed-b",
        "severity":"critical",
        "confidence":95,
        "evidence":{"tls":"observed"},
        "status":"open",
        "brand":"Example",
    })

    assert first["event_id"]==second["event_id"]
    rows=digital_risk.list_events("tenant-a")
    assert len(rows)==1
    assert rows[0]["risk_score"]>=70
    assert rows[0]["risk_reasons"]


def test_leak_analysis_never_returns_raw_secret():
    result=digital_risk.analyze_leak_signal(digital_risk.LeakSignal(
        leak_type="credential",
        indicator="breach-feed-1",
        domain="example.org",
        account_count=25,
        secret_count=4,
        confidence=90,
        evidence={
            "source_url":"feed://example",
            "password":"should-not-survive",
            "token":"should-not-survive",
            "sample_hash":"abc123",
        },
    ))

    assert result["category"]=="credential_leak"
    assert result["contains_raw_secret"] is False
    assert "password" not in result["evidence"]
    assert "token" not in result["evidence"]
    assert result["evidence"]["sample_hash"]=="abc123"
    assert result["risk_score"]>=70


def test_leak_api_links_only_same_tenant_assets(tmp_path, monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))
    tenant_a=_principal("tenant-a")
    now=datetime.now(timezone.utc).isoformat()
    asset_a=Asset(
        tenant_id="tenant-a",
        id="asset-a",
        value="portal.example.org",
        type=AssetType.SUBDOMAIN,
        confidence=95,
        criticality=4,
        source="test",
        first_seen=now,
        last_seen=now,
    )
    asset_b=Asset(
        tenant_id="tenant-b",
        id="asset-b",
        value="foreign.example.org",
        type=AssetType.SUBDOMAIN,
        confidence=95,
        criticality=4,
        source="test",
        first_seen=now,
        last_seen=now,
    )

    monkeypatch.setattr(main,"STORE_ASSETS",[asset_a,asset_b])
    monkeypatch.setattr(main,"STORE_FINDINGS",[])
    monkeypatch.setattr(main,"require",lambda request,permission:tenant_a)
    monkeypatch.setattr(main,"current_principal",lambda request:tenant_a)
    monkeypatch.setattr(main,"asset_in_scope",lambda principal,value:True)
    monkeypatch.setattr(main,"audit",lambda *args,**kwargs:None)

    linked=client.post("/api/v1/digital-risk/leaks",json={
        "leak_type":"credential",
        "indicator":"feed-a",
        "domain":"example.org",
        "account_count":8,
        "secret_count":0,
        "confidence":85,
        "evidence":{"sample_hash":"safe-hash"},
    })
    assert linked.status_code==200
    assert linked.json()["asset_id"]=="asset-a"

    foreign=client.post("/api/v1/digital-risk/leaks",json={
        "leak_type":"credential",
        "indicator":"feed-b",
        "asset_id":"asset-b",
        "account_count":3,
        "secret_count":0,
        "confidence":80,
        "evidence":{},
    })
    assert foreign.status_code==404


def test_drp_summary_tracks_risk_and_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))

    digital_risk.upsert_event("tenant-a",{
        "category":"phishing",
        "title":"Fake portal",
        "indicator":"phish.invalid",
        "severity":"high",
        "confidence":90,
        "evidence":{"dns":"observed"},
        "status":"open",
    })
    digital_risk.upsert_event("tenant-a",{
        "category":"credential_leak",
        "title":"Credential exposure",
        "indicator":"feed-1",
        "severity":"high",
        "confidence":90,
        "evidence":{"sample_hash":"abc"},
        "status":"open",
    })

    summary=digital_risk.summarize_events(digital_risk.list_events("tenant-a"))

    assert summary["credential_exposures"]==1
    assert summary["high_risk_open"]>=1
    assert summary["average_risk_score"]>0
    assert "takedown_candidates" not in summary
