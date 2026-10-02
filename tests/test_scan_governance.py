from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.main as main
from app.api import active_scan


def test_active_scan_governance_requires_authorization_ref_in_production(monkeypatch):
    monkeypatch.setattr(active_scan,"IS_PRODUCTION",True)
    monkeypatch.setattr(active_scan,"rate_limit_action",lambda *args,**kwargs: True)
    events=[]
    monkeypatch.setattr(active_scan,"audit",lambda *args,**kwargs: events.append((args,kwargs)))
    request=SimpleNamespace(
        headers={},
        method="GET",
        url=SimpleNamespace(path="/api/v1/discovery/example.org/graph"),
    )
    principal=SimpleNamespace(tenant_id="tenant-a",user_id="user-a",role="superadmin")
    with pytest.raises(HTTPException) as exc:
        active_scan.govern_active_scan(request,principal,"example.org")
    assert exc.value.status_code==400
    assert events==[]


def test_active_scan_governance_audits_and_rate_limits(monkeypatch):
    monkeypatch.setattr(active_scan,"IS_PRODUCTION",True)
    calls=[]
    monkeypatch.setattr(active_scan,"rate_limit_action",lambda *args,**kwargs: calls.append(("rate",args,kwargs)) or True)
    monkeypatch.setattr(active_scan,"authorization_grant_valid",lambda principal,ref,target: True)
    monkeypatch.setattr(active_scan,"audit",lambda *args,**kwargs: calls.append(("audit",args,kwargs)))
    request=SimpleNamespace(
        headers={"X-Authorization-Ref":"AUTH-001"},
        method="GET",
        url=SimpleNamespace(path="/api/v1/discovery/example.org/graph"),
    )
    principal=SimpleNamespace(tenant_id="tenant-a",user_id="user-a",role="superadmin")
    ref=active_scan.govern_active_scan(request,principal,"example.org")
    assert ref=="AUTH-001"
    assert any(x[0]=="rate" for x in calls)
    assert any(x[0]=="audit" for x in calls)


def test_active_scan_governance_keeps_development_compatible(monkeypatch):
    monkeypatch.setattr(active_scan,"IS_PRODUCTION",False)
    monkeypatch.setattr(active_scan,"rate_limit_action",lambda *args,**kwargs: True)
    monkeypatch.setattr(active_scan,"audit",lambda *args,**kwargs: None)
    request=SimpleNamespace(headers={},method="GET",url=SimpleNamespace(path="/dev"))
    principal=SimpleNamespace(tenant_id="tenant-a",user_id="user-a",role="superadmin")
    assert active_scan.govern_active_scan(request,principal,"example.org")==""
