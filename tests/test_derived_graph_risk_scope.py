from app.auth import Principal, create_user
from app.main import tenant_scope, STORE_ASSETS, STORE_FINDINGS
from app.scope import ensure_scope_schema, create_scope, assign_scope

def scoped_principal():
    admin=Principal("derived-admin","tenant-demo","derived-admin@example.org","admin","Admin")
    user=create_user(admin,"derived-user@example.org","Derived User","Long-Test-Only-Password-2026!","analyst")
    scope=create_scope(admin,"Derived Scope","*.scoped.example.org")
    assign_scope(admin,user["id"],scope["id"])
    return Principal(user["id"],"tenant-demo",user["email"],"analyst","Derived User")

def test_graph_inputs_are_scope_bounded():
    p=scoped_principal()
    assets,findings=tenant_scope(p,STORE_ASSETS,STORE_FINDINGS)
    ids={a.id for a in assets}
    assert all(f.asset_id in ids for f in findings)

def test_remediation_inputs_are_scope_bounded():
    p=scoped_principal()
    assets,findings=tenant_scope(p,STORE_ASSETS,STORE_FINDINGS)
    ids={a.id for a in assets}
    assert all(f.asset_id in ids for f in findings)
