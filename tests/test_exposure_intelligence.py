from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def auth():
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"ChangeMe!123"})
    assert r.status_code==200
    return {"Authorization":"Bearer "+r.json()["access_token"]}

def test_exposure_reduction_and_attack_paths():
    h=auth()
    r=client.get("/api/v1/exposure/reduction",headers=h)
    assert r.status_code==200
    assert "aggregate_exposure" in r.json()
    r=client.get("/api/v1/attack-paths",headers=h)
    assert r.status_code==200
    assert "paths" in r.json()
    assert "summary" in r.json()


def test_asset_dna_and_radar():
    h=auth()
    r=client.get("/api/v1/assets/ast-002/dna",headers=h)
    assert r.status_code==200
    assert r.json()["fingerprint"]
    r=client.get("/api/v1/radar",headers=h)
    assert r.status_code==200
    assert any(x["asset_id"]=="ast-002" for x in r.json()["assets"])


def test_ctem_queue_and_business_impact():
    h=auth()
    r=client.get("/api/v1/exposure/ctem",headers=h)
    assert r.status_code==200
    assert "items" in r.json()
    r=client.get("/api/v1/exposure/business-impact",headers=h)
    assert r.status_code==200
    assert "items" in r.json()


def test_tenant_scoped_live_graph():
    h=auth()
    r=client.get("/api/v1/graph",headers=h)
    assert r.status_code==200
    data=r.json()
    assert "nodes" in data and "edges" in data and "top_risk_paths" in data


def test_graph_contains_exposure_and_finding_relationships():
    h=auth()
    data=client.get("/api/v1/graph",headers=h).json()
    assert any(n["kind"]=="internet" for n in data["nodes"])
    assert any(n["kind"]=="finding" for n in data["nodes"])


def test_ctem_plan_endpoint():
    h=auth()
    data=client.get("/api/v1/exposure/ctem",headers=h).json()
    item=(data.get("items") or [None])[0]
    payload={"asset_ids":[item["asset_id"]],"finding_ids":[]} if item else {"asset_ids":[],"finding_ids":[]}
    r=client.post("/api/v1/exposure/ctem/plan",headers={**h,"Content-Type":"application/json"},json=payload)
    assert r.status_code==200
    assert "items" in r.json()
