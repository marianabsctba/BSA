from app import auth
from app.tenant_sla_policy import (
    TenantSLAPolicy,
    save_sla_policy,
    sla_policy_for,
    sla_threshold_hours,
)


def test_tenant_sla_policy_persists_and_isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    auth._db().close()

    policy=TenantSLAPolicy(
        tenant_id="tenant-a",
        version=3,
        critical_hours=8,
        high_hours=24,
        medium_hours=72,
        low_hours=240,
    )
    save_sla_policy(policy,updated_by="admin-a")

    assert sla_policy_for("tenant-a")==policy
    other=sla_policy_for("tenant-b")
    assert other.tenant_id=="tenant-b"
    assert other.critical_hours==24
    assert other.version==1


def test_sla_thresholds_follow_priority_band():
    policy=TenantSLAPolicy(
        tenant_id="tenant-a",
        critical_hours=8,
        high_hours=24,
        medium_hours=72,
        low_hours=240,
    )
    assert sla_threshold_hours(90,policy)==8
    assert sla_threshold_hours(75,policy)==24
    assert sla_threshold_hours(50,policy)==72
    assert sla_threshold_hours(20,policy)==240


def test_sla_policy_read_does_not_run_schema_ddl(tmp_path, monkeypatch):
    from app import tenant_sla_policy

    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    auth._db().close()
    save_sla_policy(TenantSLAPolicy(tenant_id="tenant-read"),updated_by="admin")

    monkeypatch.setattr(
        tenant_sla_policy,
        "_ensure_schema",
        lambda: (_ for _ in ()).throw(AssertionError("DDL helper called during read")),
    )
    assert sla_policy_for("tenant-read").tenant_id=="tenant-read"
