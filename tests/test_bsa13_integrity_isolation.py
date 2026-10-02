from app import auth, digital_risk


def test_audit_chain_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    principal=auth.Principal("u1","tenant-a","admin@example.test","admin","Admin")
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.commit(); conn.close()

    auth.audit(principal,"create","asset","a1",{"source":"test"})
    auth.audit(principal,"update","asset","a1",{"owner":"secops"})
    assert auth.verify_audit_chain(principal)["valid"] is True

    conn=auth._db()
    conn.execute("UPDATE audit_log SET metadata=? WHERE tenant_id=? AND id=(SELECT MIN(id) FROM audit_log WHERE tenant_id=?)",
                 ('{"source":"tampered"}',"tenant-a","tenant-a"))
    conn.commit(); conn.close()

    result=auth.verify_audit_chain(principal)
    assert result["valid"] is False
    assert result["broken_id"] is not None


def test_audit_chains_are_tenant_scoped(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    a=auth.Principal("u1","tenant-a","a@example.test","admin","A")
    b=auth.Principal("u2","tenant-b","b@example.test","admin","B")
    conn=auth._db()
    conn.executemany("INSERT INTO tenants(id,name) VALUES(?,?)",[("tenant-a","A"),("tenant-b","B")])
    conn.commit(); conn.close()

    auth.audit(a,"create","asset","same",{})
    auth.audit(b,"create","asset","same",{})

    assert auth.verify_audit_chain(a)["valid"] is True
    assert auth.verify_audit_chain(b)["valid"] is True


def test_drp_event_id_is_tenant_scoped(tmp_path, monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))
    shared_id="shared-event-id"
    a=digital_risk.upsert_event("tenant-a",{
        "event_id":shared_id,
        "category":"phishing",
        "title":"Tenant A signal",
        "indicator":"a.example",
        "severity":"high",
        "confidence":90,
    })
    b=digital_risk.upsert_event("tenant-b",{
        "event_id":shared_id,
        "category":"brand_abuse",
        "title":"Tenant B signal",
        "indicator":"b.example",
        "severity":"medium",
        "confidence":70,
    })

    assert a["event_id"]==shared_id
    assert b["event_id"]==shared_id
    events_a=digital_risk.list_events("tenant-a")
    events_b=digital_risk.list_events("tenant-b")
    assert len(events_a)==1 and events_a[0]["title"]=="Tenant A signal"
    assert len(events_b)==1 and events_b[0]["title"]=="Tenant B signal"
