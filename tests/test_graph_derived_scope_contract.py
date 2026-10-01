from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def login():
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"Bsa-Test-Only-2026!"})
    assert r.status_code==200
    return r.cookies.get("bsa_session")

def test_graph_explain_cannot_expand_arbitrary_nodes():
    token=login()
    r=client.post("/api/v1/graph/attack-path/explain",
        cookies={"bsa_session":token},
        json={"path":["node-that-does-not-exist"]})
    assert r.status_code==200
    body=r.json()
    assert body.get("facts",[]) == []
    assert body.get("inference",[]) == []
