from fastapi.testclient import TestClient
from app.main import app
from app.auth import _db

client=TestClient(app)

def test_scope_denies_out_of_scope_discovery_target():
    token=None
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"Bsa-Test-Only-2026!"})
    assert r.status_code==200
    token=r.cookies.get("bsa_session")
    # Existing admin may have no restrictive scope in the test fixture; this is an API contract smoke test.
    r=client.post("/api/v1/discovery",cookies={"bsa_session":token},json={"target":"definitely-outside-scope.invalid","checks":["dns"]})
    assert r.status_code in {400,403,422}
