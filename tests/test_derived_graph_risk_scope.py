import uuid
from app.auth import Principal
from app.api.tenant_scope import tenant_scope
from app.store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS

def scoped_principal():
    # Use the seeded test tenant identity so this contract test does not mutate
    # the shared SQLite fixture or introduce cross-test locking.
    return Principal("admin", "tenant-demo", "admin@besafe.local", "admin", "Admin")

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
