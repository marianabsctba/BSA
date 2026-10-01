from app.auth import Principal, create_user, authenticate, principal_from_token
from app.main import app, STORE_ASSETS, STORE_FINDINGS, tenant_scope
from app.scope import ensure_scope_schema, create_scope, assign_scope
from fastapi.testclient import TestClient

def test_derived_data_stays_within_scope():
    ensure_scope_schema()
    admin=Principal("agg-admin","tenant-demo","agg-admin@example.org","admin","Admin")
    user=create_user(admin,"agg-user@example.org","Agg User","Long-Test-Only-Password-2026!","analyst")
    scoped=create_scope(admin,"Scoped Asset","in-scope.example.org")
    assign_scope(admin,user["id"],scoped["id"])
    p=Principal(user["id"],"tenant-demo",user["email"],"analyst","Agg User")
    assets,findings=tenant_scope(p,STORE_ASSETS,STORE_FINDINGS)
    assert all("in-scope.example.org" in a.value for a in assets)
    assert all(f.asset_id in {a.id for a in assets} for f in findings)

def test_scoped_principal_has_no_unscoped_derived_assets():
    ensure_scope_schema()
    admin=Principal("agg-admin-2","tenant-demo","agg-admin-2@example.org","admin","Admin")
    user=create_user(admin,"agg-user-2@example.org","Agg User 2","Long-Test-Only-Password-2026!","analyst")
    scoped=create_scope(admin,"Only Other","only-other.example.org")
    assign_scope(admin,user["id"],scoped["id"])
    p=Principal(user["id"],"tenant-demo",user["email"],"analyst","Agg User 2")
    assets,findings=tenant_scope(p,STORE_ASSETS,STORE_FINDINGS)
    assert not any("out-of-scope" in a.value for a in assets)
