from fastapi.testclient import TestClient
from app.main import app
from app.auth import Principal, create_user, authenticate, principal_from_token
from app.scope import ensure_scope_schema, create_scope, assign_scope

client=TestClient(app)

def test_scope_denies_out_of_scope_discovery_target():
    login=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"Bsa-Test-Only-2026!"})
    assert login.status_code==200
    admin=principal_from_token(login.cookies.get("bsa_session"))
    user=create_user(admin,"scope-api-test@example.org","Scope API Test","Long-Test-Only-Password-2026!","analyst")
    ensure_scope_schema()
    scoped=create_scope(admin,"Only Example API","*.example.org")
    assign_scope(admin,user["id"],scoped["id"])
    user_token=authenticate(user["email"],"Long-Test-Only-Password-2026!")
    assert user_token
    r=client.post("/api/v1/discovery",cookies={"bsa_session":user_token},json={"target":"definitely-outside-scope.invalid","checks":["dns"]})
    assert r.status_code==403
