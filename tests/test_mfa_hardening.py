from app import auth


def _principal():
    return auth.Principal(
        user_id="mfa-user",
        tenant_id="tenant-demo",
        email="mfa@example.org",
        role="admin",
        name="MFA User",
    )


def _seed_user(tmp_path, monkeypatch, password="CorrectHorseBattery1!"):
    monkeypatch.setattr(auth, "DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setattr(auth, "JWT_SECRET", "x" * 48)
    principal=_principal()
    conn=auth._db()
    conn.execute("INSERT OR IGNORE INTO tenants(id,name) VALUES(?,?)",("tenant-demo","Demo"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        (principal.user_id,principal.tenant_id,principal.email,principal.name,auth._hash(password),principal.role,1),
    )
    conn.commit(); conn.close()
    return principal,password


def test_mfa_secret_is_encrypted_at_rest(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)

    enrolled=auth.mfa_enroll(principal,password)
    assert enrolled["secret"]

    conn=auth._db()
    row=conn.execute("SELECT secret,enabled,last_counter FROM users_mfa WHERE user_id=?",(principal.user_id,)).fetchone()
    conn.close()

    assert row["secret"].startswith("fernet:")
    assert enrolled["secret"] not in row["secret"]
    assert row["enabled"]==0
    assert row["last_counter"] is None


def test_mfa_enrollment_requires_current_password(tmp_path, monkeypatch):
    principal,_=_seed_user(tmp_path,monkeypatch)

    try:
        auth.mfa_enroll(principal,"WrongPassword123!")
    except PermissionError:
        return
    raise AssertionError("MFA enrollment accepted an invalid current password")


def test_legacy_plaintext_mfa_secret_is_migrated_on_read(tmp_path, monkeypatch):
    principal,_=_seed_user(tmp_path,monkeypatch)
    secret=auth.generate_mfa_secret()

    conn=auth._db()
    conn.execute(
        "INSERT INTO users_mfa(user_id,secret,enabled,created_at,last_counter) VALUES(?,?,1,?,NULL)",
        (principal.user_id,secret,1),
    )
    conn.commit(); conn.close()

    assert auth.mfa_secret_for_user(principal.user_id)==secret
    conn=auth._db()
    row=conn.execute("SELECT secret FROM users_mfa WHERE user_id=?",(principal.user_id,)).fetchone()
    conn.close()
    assert row["secret"].startswith("fernet:")


def test_mfa_replay_is_rejected(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)
    enrolled=auth.mfa_enroll(principal,password)
    secret=enrolled["secret"]
    counter=int(auth.time.time())//30
    code=auth._totp(secret,counter)

    assert auth.mfa_enable(principal,code) is True
    assert auth.verify_user_mfa_once(principal.user_id,code) is False


def test_mfa_login_attempts_are_persistently_throttled(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)
    enrolled=auth.mfa_enroll(principal,password)
    secret=enrolled["secret"]
    code=auth._totp(secret,int(auth.time.time())//30)
    assert auth.mfa_enable(principal,code) is True

    for _ in range(6):
        assert auth.authenticate(principal.email,password,"203.0.113.50","000000") is None

    conn=auth._db()
    row=conn.execute(
        "SELECT blocked_until FROM auth_rate_limits WHERE bucket=? AND identity=?",
        ("mfa-login",f"{principal.user_id}:203.0.113.50"),
    ).fetchone()
    conn.close()
    assert row is not None
    assert int(row["blocked_until"])>0
