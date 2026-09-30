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
