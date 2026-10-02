from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_and_me():
    response = client.post("/api/v1/auth/login", json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"})
    assert response.status_code == 200
    assert "bsa_session" in response.cookies
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "admin"
    assert me.json()["tenant_id"] == "tenant-demo"


def test_api_requires_authentication():
    unauthenticated = TestClient(app)
    response = unauthenticated.get("/api/v1/assets")
    assert response.status_code == 401


def test_admin_audit_is_tenant_scoped():
    response = client.post("/api/v1/auth/login", json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"})
    audit = client.get("/api/v1/audit")
    assert audit.status_code == 200
    assert any(item["action"] == "login" for item in audit.json())

def test_logout_revokes_session_cookie():
    response = client.post("/api/v1/auth/login", json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"})
    assert response.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200
    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_custom_role_cannot_escalate_beyond_caller(tmp_path, monkeypatch):
    from app import auth

    monkeypatch.setattr(auth, "DB_PATH", str(tmp_path / "auth.db"))
    auth._db().close()
    principal = auth.Principal("u1", "tenant-1", "admin@example.test", "analyst", "Analyst")
    try:
        auth.create_custom_role(principal, "too-powerful", ["assets:read", "users:write"])
    except PermissionError:
        return
    raise AssertionError("custom role escalation was accepted")


def test_missing_user_still_runs_password_verification(tmp_path, monkeypatch):
    from app import auth

    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    auth._db().close()
    calls=[]
    original=auth._verify

    def wrapped(password,encoded):
        calls.append((password,encoded))
        return original(password,encoded)

    monkeypatch.setattr(auth,"_verify",wrapped)
    token=auth.authenticate("missing@example.org","WrongPassword123!","198.51.100.10")

    assert token is None
    assert len(calls)==1
    assert calls[0][1]==auth._DUMMY_PASSWORD_HASH


def test_login_rate_limit_persists_in_database(tmp_path, monkeypatch):
    from app import auth

    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    auth._db().close()
    identity="persistent@example.org"

    for _ in range(5):
        assert auth.rate_limit_action("login-email",identity,limit=5,window_seconds=300) is True
    assert auth.rate_limit_action("login-email",identity,limit=5,window_seconds=300) is False

    # Persistence is proven by reopening the SQLite-backed limiter state.
    conn=auth._db()
    row=conn.execute(
        "SELECT count,blocked_until FROM auth_rate_limits WHERE bucket=? AND identity=?",
        ("login-email",identity),
    ).fetchone()
    conn.close()
    assert row is not None
    assert int(row["blocked_until"])>0
    assert auth.rate_limit_action("login-email",identity,limit=5,window_seconds=300) is False


def test_auth_permissions_support_custom_role_tenant_scope(tmp_path, monkeypatch):
    from app import auth
    from app.main import app
    from fastapi.testclient import TestClient

    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setattr(auth,"JWT_SECRET","j"*48)
    monkeypatch.setattr(auth,"MFA_KEY","m"*48)
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-x","Tenant X"))
    conn.execute(
        "INSERT INTO custom_roles(name,tenant_id,permissions,created_at) VALUES(?,?,?,?)",
        ("custom:auditor","tenant-x",'["assets:read","findings:read"]',1),
    )
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("u-custom","tenant-x","custom@example.org","Custom",auth._hash("CorrectHorseBattery1!"),"custom:auditor",1),
    )
    conn.commit(); conn.close()

    token=auth.authenticate("custom@example.org","CorrectHorseBattery1!","198.51.100.50")
    assert token
    client=TestClient(app,cookies={"bsa_session":token})
    response=client.get("/api/v1/auth/permissions")
    assert response.status_code==200
    assert response.json()["role"]=="custom:auditor"
    assert response.json()["permissions"]==["assets:read","findings:read"]


def test_session_idle_timeout_revokes_session(tmp_path, monkeypatch):
    from app import auth

    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setattr(auth,"JWT_SECRET","j"*48)
    monkeypatch.setattr(auth,"MFA_KEY","m"*48)
    monkeypatch.setattr(auth,"SESSION_IDLE_TIMEOUT",30)
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-idle","Idle"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("idle-user","tenant-idle","idle@example.org","Idle",auth._hash("CorrectHorseBattery1!"),"analyst",1),
    )
    conn.commit(); conn.close()

    now=int(auth.time.time())
    token=auth.authenticate("idle@example.org","CorrectHorseBattery1!","198.51.100.60")
    assert token
    monkeypatch.setattr(auth.time,"time",lambda: now+31)
    try:
        auth.principal_from_token(token)
    except ValueError as exc:
        assert "idle timeout" in str(exc)
    else:
        raise AssertionError("idle session remained valid")


def test_change_own_password_revokes_existing_sessions(tmp_path, monkeypatch):
    from app import auth

    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setattr(auth,"JWT_SECRET","j"*48)
    monkeypatch.setattr(auth,"MFA_KEY","m"*48)
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-pw","PW"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("pw-user","tenant-pw","pw@example.org","PW",auth._hash("CorrectHorseBattery1!"),"analyst",1),
    )
    conn.commit(); conn.close()

    token=auth.authenticate("pw@example.org","CorrectHorseBattery1!","198.51.100.61")
    principal=auth.principal_from_token(token)
    result=auth.change_own_password(principal,"CorrectHorseBattery1!","NewCorrectHorseBattery2!")
    assert result["sessions_revoked"] is True

    try:
        auth.principal_from_token(token)
    except ValueError:
        pass
    else:
        raise AssertionError("old session remained valid after password change")

    assert auth.authenticate("pw@example.org","NewCorrectHorseBattery2!","198.51.100.61")


def test_login_account_uses_progressive_backoff_without_account_lockout(tmp_path, monkeypatch):
    from app import auth

    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    auth._db().close()
    sleeps=[]
    monkeypatch.setattr(auth.time,"sleep",lambda seconds: sleeps.append(seconds))

    for _ in range(4):
        assert auth.authenticate("missing@example.org","WrongPassword123!","198.51.100.90") is None

    assert sleeps==[0.1,0.2,0.4,0.8]
    conn=auth._db()
    row=conn.execute(
        "SELECT count,blocked_until FROM auth_rate_limits WHERE bucket=? AND identity=?",
        ("login-account-backoff","missing@example.org:198.51.100.90"),
    ).fetchone()
    conn.close()
    assert row is not None
    assert int(row["count"])==4
    assert int(row["blocked_until"])==0
