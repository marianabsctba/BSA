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
    monkeypatch.setattr(auth, "MFA_SECRET_KEY", "m" * 48)
    monkeypatch.setattr(auth, "MFA_KEY", "m" * 48)
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


def test_mfa_reenrollment_requires_current_totp_when_enabled(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)
    enrolled=auth.mfa_enroll(principal,password)
    secret=enrolled["secret"]
    code=auth._totp(secret,int(auth.time.time())//30)
    assert auth.mfa_enable(principal,code) is True

    try:
        auth.mfa_enroll(principal,password)
    except PermissionError:
        pass
    else:
        raise AssertionError("MFA reenrollment did not require current factor")


def test_mfa_recovery_code_is_single_use(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)
    enrolled=auth.mfa_enroll(principal,password)
    secret=enrolled["secret"]
    code=auth._totp(secret,int(auth.time.time())//30)
    assert auth.mfa_enable(principal,code) is True

    recovery=auth.issue_mfa_recovery_codes(principal)[0]
    assert auth.verify_mfa_recovery_code(principal.user_id,recovery) is True
    assert auth.verify_mfa_recovery_code(principal.user_id,recovery) is False


def test_mfa_disable_requires_password_and_current_factor(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)
    enrolled=auth.mfa_enroll(principal,password)
    secret=enrolled["secret"]
    first=auth._totp(secret,int(auth.time.time())//30)
    assert auth.mfa_enable(principal,first) is True

    # Move to the next TOTP counter so replay protection is not the reason for rejection.
    now=int(auth.time.time())
    monkeypatch.setattr(auth.time,"time",lambda: now+31)
    second=auth._totp(secret,(now+31)//30)

    try:
        auth.mfa_disable(principal,"WrongPassword123!",second)
    except PermissionError:
        pass
    else:
        raise AssertionError("MFA disable accepted wrong password")

    assert auth.mfa_disable(principal,password,second) is True
    assert auth.mfa_status(principal)["enabled"] is False


def test_tenant_mfa_policy_requires_users_to_be_enrolled_first(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)

    try:
        auth.set_tenant_mfa_policy(principal,["admin"])
    except ValueError:
        pass
    else:
        raise AssertionError("tenant MFA policy accepted unenrolled required user")

    enrolled=auth.mfa_enroll(principal,password)
    code=auth._totp(enrolled["secret"],int(auth.time.time())//30)
    assert auth.mfa_enable(principal,code) is True
    policy=auth.set_tenant_mfa_policy(principal,["admin"])
    assert policy["mfa_required_roles"]==["admin"]


def test_production_mfa_requires_independent_key(monkeypatch):
    monkeypatch.setattr(auth,"ENVIRONMENT","production")
    monkeypatch.setattr(auth,"JWT_SECRET","j"*48)
    monkeypatch.setattr(auth,"MFA_KEY","")
    try:
        auth._require_security_config()
    except RuntimeError as exc:
        assert "BSA_MFA_KEY" in str(exc)
        return
    raise AssertionError("production accepted missing MFA encryption key")


def test_mfa_uses_dedicated_encryption_key(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)
    enrolled=auth.mfa_enroll(principal,password)
    secret=enrolled["secret"]

    conn=auth._db()
    stored=conn.execute("SELECT secret FROM users_mfa WHERE user_id=?",(principal.user_id,)).fetchone()["secret"]
    conn.close()

    old_jwt=auth.JWT_SECRET
    monkeypatch.setattr(auth,"JWT_SECRET","y"*48)
    assert auth._decrypt_mfa_secret(stored)==secret
    monkeypatch.setattr(auth,"JWT_SECRET",old_jwt)


def test_mfa_reenroll_requires_current_factor_when_enabled(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)
    enrolled=auth.mfa_enroll(principal,password)
    secret=enrolled["secret"]
    code=auth._totp(secret,int(auth.time.time())//30)
    assert auth.mfa_enable(principal,code) is True

    try:
        auth.mfa_enroll(principal,password)
    except PermissionError:
        pass
    else:
        raise AssertionError("enabled MFA was re-enrolled without current factor")


def test_recovery_code_is_single_use_for_mfa_disable(tmp_path, monkeypatch):
    principal,password=_seed_user(tmp_path,monkeypatch)
    enrolled=auth.mfa_enroll(principal,password)
    secret=enrolled["secret"]
    code=auth._totp(secret,int(auth.time.time())//30)
    assert auth.mfa_enable(principal,code) is True
    recovery=enrolled["recovery_codes"][0]

    assert auth.mfa_disable(principal,password,recovery) is True

    conn=auth._db()
    row=conn.execute("SELECT enabled FROM users_mfa WHERE user_id=?",(principal.user_id,)).fetchone()
    remaining=conn.execute("SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id=?",(principal.user_id,)).fetchone()["n"]
    conn.close()
    assert row["enabled"]==0
    assert remaining==0


def test_tenant_mfa_policy_can_require_discovery(tmp_path, monkeypatch):
    principal,_=_seed_user(tmp_path,monkeypatch)
    assert auth.set_tenant_mfa_required(principal,True)["mfa_required"] is True
    assert auth.tenant_mfa_required(principal.tenant_id) is True
    assert auth.mfa_required_for(principal,"discovery:run") is True
