import app.auth as auth
import app.history as history
import app.job_queue as job_queue
import app.tenant_lifecycle as lifecycle


class _FailingRepository:
    def tenant_record_counts(self,tenant_id):
        return {"assets":2,"findings":1}

    def purge_tenant(self,tenant_id):
        raise RuntimeError("asset backend unavailable")


def _superadmin():
    return auth.Principal(
        "root","tenant-root","root@example.org","superadmin","Root"
    )


def test_tenant_identity_survives_when_asset_backend_purge_fails(tmp_path,monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    monkeypatch.setenv("BSA_JOBS_DB",str(tmp_path/"jobs.db"))
    monkeypatch.setattr(lifecycle,"asset_finding_repository",lambda:_FailingRepository())

    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-root","Root"))
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.commit(); conn.close()

    try:
        lifecycle.purge_tenant(_superadmin(),"tenant-a")
    except RuntimeError as exc:
        assert "asset backend unavailable" in str(exc)
    else:
        raise AssertionError("tenant purge ignored asset repository failure")

    conn=auth._db()
    assert conn.execute(
        "SELECT 1 FROM tenants WHERE id=?",("tenant-a",)
    ).fetchone() is not None
    conn.close()

    # Ensure the supporting databases can still be reopened after the failed purge.
    history._history_db().close()
    job_queue._db().close()
