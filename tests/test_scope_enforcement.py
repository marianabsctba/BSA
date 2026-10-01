from app.auth import Principal, create_user
from app.scope import ensure_scope_schema, create_scope, assign_scope, asset_in_scope

def test_scope_enforcement_is_positive_and_negative():
    ensure_scope_schema()
    admin=Principal("scope-admin","tenant-demo","admin@besafe.local","admin","Admin")
    user=create_user(admin,"scope-user-enforcement@example.org","Scoped","Long-Test-Only-Password-2026!","analyst")
    scoped=create_scope(admin,"Only Example","*.example.org")
    assign_scope(admin,user["id"],scoped["id"])
    scoped_user=Principal(user["id"],"tenant-demo",user["email"],"analyst","Scoped")
    assert asset_in_scope(scoped_user,"api.example.org") is True
    assert asset_in_scope(scoped_user,"api.other.example") is False

def test_scope_cannot_cross_tenant():
    ensure_scope_schema()
    admin=Principal("scope-admin-a","tenant-a","a@example.org","admin","Admin")
    other=Principal("scope-user-b","tenant-b","b@example.org","analyst","User")
    user=create_user(admin,"scope-cross-a@example.org","A","Long-Test-Only-Password-2026!","analyst")
    scoped=create_scope(admin,"Tenant A","a.example.org")
    try:
        assign_scope(admin,other.user_id,scoped["id"])
    except ValueError:
        pass
    else:
        raise AssertionError("cross-tenant scope assignment must fail")
