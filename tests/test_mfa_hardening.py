from types import SimpleNamespace

from app import auth


def _principal():
    return auth.Principal(
        user_id="mfa-user",
        tenant_id="tenant-demo",
        email="mfa@example.org",
        role="admin",
        name="MFA User",
    )


def test_mfa_secret_is_encrypted_at_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setattr(auth, "JWT_SECRET", "x" * 48)
    principal=_principal()
    password="CorrectHorseBattery1!"
    conn=auth._db()
    conn.execute("INSERT OR IGNORE INTO tenants(id,name) VALUES(?,?)",(principal.tenant_id,"Demo"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        (principal.user_id,principal.tenant_id,principal.email,principal.name,auth._hash(password),principal.role,1),
    )
    conn.commit(); conn.close()

    enrolled=auth.mfa_enroll(principal,password)
    assert enrolled["secret"]

    conn=auth._db()
    row=conn.execute("SELECT secret FROM users_mfa WHERE user_id=?",(principal.user_id,)).fetchone()
    conn.close()

    assert row["secret"].startswith("fernet:")
    assert enrolled["secret"] not in row["secret"]


def test_legacy_plaintext_mfa_secret_is_migrated_on_read(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setattr(auth, "JWT_SECRET", "y" * 48)
    principal=_principal()
    secret=auth.generate_mfa_secret()

    conn=auth._db()
    conn.execute(
        "INSERT INTO users_mfa(user_id,secret,enabled,created_at) VALUES(?,?,1,?)",
        (principal.user_id,secret,1),
    )
    conn.commit(); conn.close()

    assert auth.mfa_secret_for_user(principal.user_id)==secret
    conn=auth._db()
    row=conn.execute("SELECT secret FROM users_mfa WHERE user_id=?",(principal.user_id,)).fetchone()
    conn.close()
    assert row["secret"].startswith("fernet:")


def test_mfa_login_attempts_are_throttled_after_valid_password(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setattr(auth, "JWT_SECRET", "z" * 48)

    conn=auth._db()
    conn.execute("INSERT OR IGNORE INTO tenants(id,name) VALUES(?,?)",("tenant-demo","Demo"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("user-1","tenant-demo","user@example.org","User",auth._hash("CorrectHorseBattery1!"),"admin",1),
    )
    secret=auth.generate_mfa_secret()
    conn.execute(
        "INSERT INTO users_mfa(user_id,secret,enabled,created_at) VALUES(?,?,1,?)",
        ("user-1",auth._encrypt_mfa_secret(secret),1),
    )
    conn.commit(); conn.close()

    for _ in range(6):
        assert auth.authenticate("user@example.org","CorrectHorseBattery1!","203.0.113.50","000000") is None

    conn=auth._db()
    row=conn.execute(
        "SELECT blocked_until FROM auth_rate_limits WHERE bucket=? AND identity=?",
        ("mfa-login","user-1:203.0.113.50"),
    ).fetchone()
    conn.close()
    assert row is not None
    assert int(row["blocked_until"]) > 0
