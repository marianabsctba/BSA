from fastapi.testclient import TestClient

from app.main import app


CORRECT_PASSWORD = "CorrectHorseBattery1!"
WRONG_PASSWORD = "WrongPassword123!"
EMAIL = "rate-limit@example.org"


def _seed_user(auth, monkeypatch, db_path):
    monkeypatch.setattr(auth, "DB_PATH", str(db_path))
    monkeypatch.setattr(auth, "JWT_SECRET", "j" * 48)
    monkeypatch.setattr(auth, "MFA_KEY", "m" * 48)
    conn = auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)", ("tenant-rate", "Rate Limit"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        (
            "rate-user",
            "tenant-rate",
            EMAIL,
            "Rate User",
            auth._hash(CORRECT_PASSWORD),
            "analyst",
            1,
        ),
    )
    conn.commit()
    conn.close()


def test_login_allows_correct_password_after_account_threshold(tmp_path, monkeypatch):
    from app import auth

    _seed_user(auth, monkeypatch, tmp_path / "auth.db")
    client = TestClient(app)

    for _ in range(8):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": EMAIL, "password": WRONG_PASSWORD},
        )
        assert response.status_code == 401

    blocked = client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": WRONG_PASSWORD},
    )
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0

    correct_while_blocked = client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": CORRECT_PASSWORD},
    )
    assert correct_while_blocked.status_code == 200
    assert correct_while_blocked.json()["user"]["email"] == EMAIL


def test_distributed_ips_cannot_bypass_account_throttle(tmp_path, monkeypatch):
    from app import auth
    from app.api.routers import auth as auth_router

    _seed_user(auth, monkeypatch, tmp_path / "auth-distributed.db")
    monkeypatch.setattr(
        auth_router,
        "_client_ip",
        lambda request: request.headers.get("X-Test-IP", "unknown"),
    )
    client = TestClient(app)

    for index in range(8):
        response = client.post(
            "/api/v1/auth/login",
            headers={"X-Test-IP": f"198.51.100.{index + 1}"},
            json={"email": EMAIL, "password": WRONG_PASSWORD},
        )
        assert response.status_code == 401

    blocked = client.post(
        "/api/v1/auth/login",
        headers={"X-Test-IP": "203.0.113.200"},
        json={"email": EMAIL, "password": WRONG_PASSWORD},
    )
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0

    correct_from_new_ip = client.post(
        "/api/v1/auth/login",
        headers={"X-Test-IP": "203.0.113.201"},
        json={"email": EMAIL, "password": CORRECT_PASSWORD},
    )
    assert correct_from_new_ip.status_code == 200
    assert correct_from_new_ip.json()["user"]["email"] == EMAIL
