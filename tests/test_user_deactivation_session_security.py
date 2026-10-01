def test_deactivated_user_sessions_are_revoked():
    from app.auth import _db, Principal, set_user_active, principal_from_token
    from app.auth import create_user
    p=Principal("admin","tenant-demo","admin@besafe.local","admin","Admin")
    user=create_user(p,"deactivation-test@example.org","Deactivation Test","Long-Test-Only-Password-2026!","analyst")
    row={"id":user["id"]}
    import time
    conn=_db()
    jti="security-test-session"
    conn.execute("INSERT OR REPLACE INTO sessions(jti,user_id,tenant_id,created_at,expires_at,revoked_at) VALUES(?,?,?,?,?,NULL)",(jti,row["id"],"tenant-demo",int(time.time()),int(time.time())+3600))
    conn.commit(); conn.close()
    set_user_active(p,row["id"],False)
    conn=_db()
    revoked=conn.execute("SELECT revoked_at FROM sessions WHERE jti=?",(jti,)).fetchone()
    conn.execute("DELETE FROM users WHERE id=?",(row["id"],))
    conn.execute("DELETE FROM sessions WHERE jti=?",(jti,))
    conn.commit(); conn.close()
    assert revoked and revoked["revoked_at"] is not None
