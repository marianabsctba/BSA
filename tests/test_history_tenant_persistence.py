def test_history_is_tenant_scoped_and_persistent(tmp_path, monkeypatch):
    from app import history
    from app.models import Asset, AssetType
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path/"history.db"))
    a=Asset(id="a1",tenant_id="tenant-a",value="api.a.example",type=AssetType.SUBDOMAIN,first_seen="2026-10-01T00:00:00Z",last_seen="2026-10-01T00:00:00Z",fingerprint="same-fp",evidence_count=1)
    history.record_observations([a], "tenant-a")
    assert len(history.history_for("same-fp","tenant-a"))==1
    assert history.history_for("same-fp","tenant-b")==[]
    # Reopen through a fresh DB connection path; the row must survive module memory.
    history._HISTORY.clear()
    assert len(history.history_for("same-fp","tenant-a"))==1
