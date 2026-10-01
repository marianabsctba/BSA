from app.auth import Principal
from app.scope import ensure_scope_schema, create_scope, assign_scope, asset_in_scope, scoped_patterns

def test_scope_enforcement_is_positive_and_negative():
    ensure_scope_schema()
    admin=Principal("scope-admin","tenant-demo","admin@besafe.local","admin","Admin")
    scoped=create_scope(admin,"Only Example","*.example.org")
    assign_scope(admin,"scope-user",scoped["id"])
    user=Principal("scope-user","tenant-demo","u@example.org","analyst","Scoped")
    assert asset_in_scope(user,"api.example.org") is True
    assert asset_in_scope(user,"api.other.example") is False

def test_scope_cannot_cross_tenant():
    ensure_scope_schema()
    admin=Principal("scope-admin-2","tenant-a","a@example.org","admin","Admin")
    other=Principal("scope-user-2","tenant-b","b@example.org","analyst","User")
    scoped=create_scope(admin,"Tenant A","a.example.org")
    try:
        assign_scope(admin,other.user_id,scoped["id"])
    except ValueError:
        pass
    else:
        raise AssertionError("cross-tenant scope assignment must fail")
