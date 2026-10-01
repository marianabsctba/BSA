from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def auth():
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"Bsa-Test-Only-2026!"})
    assert r.status_code==200
    return {"Authorization":"Bearer "+r.json()["access_token"]}

def test_asset_detail_contains_operational_context():
    r=client.get("/api/v1/assets/ast-002",headers=auth())
    assert r.status_code==200
    data=r.json()
    assert data["asset"]["id"]=="ast-002"
    assert "ownership" in data
    assert "risk" in data
    assert "findings" in data
    assert "remediation" in data
    assert "history" in data
    assert "graph" in data
