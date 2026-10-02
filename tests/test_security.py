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
    assert "samesite=strict" in cookie


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


def test_login_rate_limit_is_bound_to_ip(tmp_path, monkeypatch):
    from app import auth
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    auth._db().close()
    ip="198.51.100.10"
    for i in range(20):
        assert auth.authenticate(f"missing-{i}@example.invalid","Wrong-Password-2026!",ip) is None
    assert auth.authenticate("another-missing@example.invalid","Wrong-Password-2026!",ip) is None
    conn=auth._db()
    row=conn.execute(
        "SELECT blocked_until FROM auth_rate_limits WHERE bucket=? AND identity=?",
        ("login-ip",ip),
    ).fetchone()
    conn.close()
    assert row is not None
    assert int(row["blocked_until"]) > 0


def test_totp_helpers_validate_codes():
    from app.auth import generate_mfa_secret, _totp, verify_totp
    import time
    secret=generate_mfa_secret()
    code=_totp(secret,int(time.time())//30)
    assert verify_totp(secret,code)
    assert not verify_totp(secret,"000000" if code!="000000" else "999999")


def test_client_ip_trusts_forwarded_header_only_from_internal_proxy(monkeypatch):
    from starlette.requests import Request
    from app.api.routers import auth as auth_router

    monkeypatch.setenv("BSA_TRUST_PROXY_HEADERS","1")

    internal=Request({
        "type":"http","method":"POST","path":"/api/v1/auth/login",
        "headers":[(b"x-real-ip",b"198.51.100.44")],
        "client":("172.18.0.5",12345),"server":("test",80),"scheme":"http","query_string":b"",
    })
    assert auth_router._client_ip(internal)=="198.51.100.44"

    direct=Request({
        "type":"http","method":"POST","path":"/api/v1/auth/login",
        "headers":[(b"x-real-ip",b"203.0.113.99")],
        "client":("8.8.8.8",12345),"server":("test",80),"scheme":"http","query_string":b"",
    })
    assert auth_router._client_ip(direct)=="8.8.8.8"


def test_distributed_failures_do_not_globally_lock_account(tmp_path, monkeypatch):
    from app import auth

    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setattr(auth,"JWT_SECRET","x"*48)
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("user-a","tenant-a","target@example.org","Target",auth._hash("CorrectHorseBattery1!"),"analyst",1),
    )
    conn.commit(); conn.close()

    for i in range(8):
        assert auth.authenticate(
            "target@example.org","WrongPassword123!",f"198.51.100.{i+1}"
        ) is None

    token=auth.authenticate(
        "target@example.org","CorrectHorseBattery1!","203.0.113.200"
    )
    assert token is not None


def test_shared_nat_failures_do_not_block_valid_password(tmp_path, monkeypatch):
    from app import auth

    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setattr(auth,"JWT_SECRET","n"*48)
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-nat","Tenant NAT"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("good-user","tenant-nat","good@example.org","Good",auth._hash("CorrectHorseBattery1!"),"analyst",1),
    )
    conn.commit(); conn.close()

    ip="198.51.100.200"
    for i in range(21):
        assert auth.authenticate(
            f"missing-{i}@example.invalid",
            "WrongPassword123!",
            ip,
        ) is None

    conn=auth._db()
    row=conn.execute(
        "SELECT blocked_until FROM auth_rate_limits WHERE bucket=? AND identity=?",
        ("login-ip",ip),
    ).fetchone()
    conn.close()
    assert row is not None and int(row["blocked_until"])>0

    token=auth.authenticate(
        "good@example.org",
        "CorrectHorseBattery1!",
        ip,
    )
    assert token is not None
