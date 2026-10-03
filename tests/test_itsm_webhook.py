from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app import itsm_webhook
from app.api.routers import integrations as integrations_router
from app.models import Finding, Severity


def test_itsm_config_requires_https_in_production(monkeypatch):
    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setenv("BSA_ITSM_WEBHOOK_URL","http://itsm.example.org/hook")
    monkeypatch.setenv("BSA_ITSM_WEBHOOK_SECRET","secret")
    with pytest.raises(ValueError,match="HTTPS"):
        itsm_webhook.config_from_env()


def test_itsm_delivery_signs_and_reuses_idempotency_key(monkeypatch):
    cfg=itsm_webhook.ITSMWebhookConfig(
        url="https://itsm.example.org/hook",
        secret="top-secret",
        max_attempts=1,
    )
    event=itsm_webhook.build_mobilization_event(
        tenant_id="tenant-a",
        resource_type="finding",
        resource_id="finding-1",
        severity="high",
        title="Internet exposure",
        payload={"finding_id":"finding-1"},
    )
    captured={}

    class Response:
        status=202
        def __enter__(self): return self
        def __exit__(self,*args): return False

    class Opener:
        def open(self,req,timeout):
            captured["signature"]=req.headers["X-bsa-signature"]
            captured["idempotency"]=req.headers["Idempotency-key"]
            captured["body"]=req.data
            return Response()

    monkeypatch.setattr(itsm_webhook,"validate_external_target",lambda url:("itsm.example.org","https://itsm.example.org"))
    monkeypatch.setattr(itsm_webhook.request,"build_opener",lambda *args:Opener())
    result=itsm_webhook.deliver_event(event,cfg)

    assert result["delivered"] is True
    assert captured["idempotency"]==event["event_id"]
    assert captured["signature"].startswith("sha256=")
    assert captured["signature"]==itsm_webhook._signature(cfg.secret,captured["body"])


def test_itsm_retries_transient_failure_but_not_client_error(monkeypatch):
    cfg=itsm_webhook.ITSMWebhookConfig(
        url="https://itsm.example.org/hook",
        secret="secret",
        max_attempts=3,
    )
    event={"event_id":"evt-1"}
    monkeypatch.setattr(itsm_webhook,"validate_external_target",lambda url:("itsm.example.org","https://itsm.example.org"))
    monkeypatch.setattr(itsm_webhook.time,"sleep",lambda seconds:None)
    calls=[]

    def transient(*args,**kwargs):
        calls.append(1)
        if len(calls)==1:
            return {"delivered":False,"status_code":503}
        return {"delivered":True,"status_code":202}

    monkeypatch.setattr(itsm_webhook,"_send_once",transient)
    result=itsm_webhook.deliver_event(event,cfg)
    assert result["delivered"] is True
    assert result["attempts"]==2

    calls.clear()
    monkeypatch.setattr(itsm_webhook,"_send_once",lambda *args,**kwargs:(calls.append(1) or {"delivered":False,"status_code":400}))
    result=itsm_webhook.deliver_event(event,cfg)
    assert result["delivered"] is False
    assert result["attempts"]==1
    assert len(calls)==1


def test_itsm_mobilization_cannot_read_foreign_tenant_finding(monkeypatch):
    principal=SimpleNamespace(tenant_id="tenant-a",user_id="u-a",role="admin")
    own=Finding(
        tenant_id="tenant-a",
        id="finding-a",
        asset_id="asset-a",
        title="Own finding",
        severity=Severity.HIGH,
        evidence="safe",
    )
    foreign=Finding(
        tenant_id="tenant-b",
        id="finding-b",
        asset_id="asset-b",
        title="Foreign finding",
        severity=Severity.CRITICAL,
        evidence="safe",
    )
    monkeypatch.setattr(integrations_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(integrations_router,"tenant_scope",lambda principal:([],[own]))
    monkeypatch.setattr(integrations_router,"audit",lambda *args,**kwargs:None)
    monkeypatch.setattr(integrations_router,"deliver_itsm_event",lambda event:{"delivered":True,"attempts":1,"event_id":event["event_id"]})

    ok=integrations_router.integrations_itsm_mobilize("finding","finding-a",None)
    assert ok["delivered"] is True

    with pytest.raises(HTTPException) as exc:
        integrations_router.integrations_itsm_mobilize("finding",foreign.id,None)
    assert exc.value.status_code==404
