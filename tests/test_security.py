from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_security_headers_are_present():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_login_does_not_expose_session_token_in_json():
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "token" not in body
    assert "access_token" not in body
    assert body["token_type"] == "bearer"
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie


def test_production_session_cookie_is_secure(monkeypatch):
    monkeypatch.setenv("BSA_ENV", "production")
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"},
    )
    assert response.status_code == 200
    assert "secure" in response.headers["set-cookie"].lower()


def test_cors_never_reflects_an_arbitrary_origin():
    response = client.options(
        "/api/v1/assets",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in response.headers


def test_authenticated_session_cannot_be_reused_after_logout():
    isolated = TestClient(app)
    login = isolated.post(
        "/api/v1/auth/login",
        json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"},
    )
    assert login.status_code == 200
    session_cookie = login.cookies.get("bsa_session")
    assert session_cookie
    assert isolated.get("/api/v1/auth/me").status_code == 200

    logout = isolated.post("/api/v1/auth/logout")
    assert logout.status_code == 200

    replay = TestClient(app, cookies={"bsa_session": session_cookie})
    assert replay.get("/api/v1/auth/me").status_code == 401
