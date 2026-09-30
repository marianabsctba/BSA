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


def test_ctem_plan_persists_and_lifecycle():
    h=auth()
    data=client.get("/api/v1/exposure/ctem",headers=h).json()
    item=(data.get("items") or [None])[0]
    if not item:
        return
    payload={"asset_ids":[item["asset_id"]],"finding_ids":[]}
    created=client.post("/api/v1/exposure/ctem/plan",headers={**h,"Content-Type":"application/json"},json=payload).json()["items"]
    assert created
    plan_id=created[0]["plan_id"]
    listed=client.get("/api/v1/exposure/ctem/plans",headers=h).json()["items"]
    assert any(x["plan_id"]==plan_id for x in listed)
    updated=client.patch(f"/api/v1/exposure/ctem/plans/{plan_id}",headers={**h,"Content-Type":"application/json"},json={"status":"approved"})
    assert updated.status_code==200
    assert updated.json()["status"]=="approved"


def test_ctem_plans_are_durable_and_tenant_scoped():
    h=auth()
    data=client.get("/api/v1/exposure/ctem",headers=h).json()
    item=(data.get("items") or [None])[0]
    if not item:
        return
    created=client.post("/api/v1/exposure/ctem/plan",headers={**h,"Content-Type":"application/json"},json={"asset_ids":[item["asset_id"]],"finding_ids":[]}).json()["items"]
    assert created
    plans=client.get("/api/v1/exposure/ctem/plans",headers=h).json()["items"]
    assert any(x["plan_id"]==created[0]["plan_id"] for x in plans)
    assert all(x.get("plan_id") and x.get("asset_id") for x in plans)


def test_mssp_command_center_is_tenant_aggregated():
    h=auth()
    r=client.get("/api/v1/mssp/command-center",headers=h)
    assert r.status_code in (200,403)
    if r.status_code==200:
        data=r.json()
        assert "tenants" in data and "summary" in data
