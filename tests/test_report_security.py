from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def test_report_summary_is_curated_and_authenticated():
    assert TestClient(app).get("/api/v1/reports/summary").status_code == 401
    login=client.post("/api/v1/auth/login",json={
        "email":"admin@besafe.local",
        "password":"Bsa-Test-Only-2026!",
    })
    assert login.status_code == 200
    response=client.get("/api/v1/reports/summary")
    assert response.status_code == 200
    body=response.json()
    assert set(body) == {"executive","exposure","vulnerabilities"}
    for row in body["exposure"]["items"]:
        assert set(row).issubset({"id","value","type","state","confidence","evidence_count"})
    for row in body["vulnerabilities"]["items"]:
        assert set(row).issubset({
            "id","vulnerability","asset","priority","exploitability",
            "impact","confidence","band","data_quality_gap",
        })
        forbidden={"evidence","description","cpe","raw","metadata","remediation","owner"}
        assert not forbidden.intersection(row)
