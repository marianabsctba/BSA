from app.auth import Principal
from app.main import tenant_scope, STORE_ASSETS, STORE_FINDINGS
from app.scope import asset_in_scope

def test_cross_tenant_derived_data_isolated():
    a=Principal("admin","tenant-demo","admin@besafe.local","admin","Admin")
    b=Principal("admin","other-tenant","other@example.org","admin","Admin")
    aa,af=tenant_scope(a,STORE_ASSETS,STORE_FINDINGS)
    ba,bf=tenant_scope(b,STORE_ASSETS,STORE_FINDINGS)
    assert {x.id for x in aa}.isdisjoint({x.id for x in ba})
    assert all(f.asset_id in {x.id for x in aa} for f in af)
    assert all(f.asset_id in {x.id for x in ba} for f in bf)

def test_cross_scope_target_is_not_allowed():
    p=Principal("admin","tenant-demo","admin@besafe.local","admin","Admin")
    assert asset_in_scope(p,"definitely-not-assigned.example.invalid") is False
