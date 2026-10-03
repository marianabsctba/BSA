from types import SimpleNamespace

from app.infrastructure.workers import easm_executor


class _Repository:
    def __init__(self):
        self.asset_calls=[]
        self.finding_calls=[]
        self.assets=[
            SimpleNamespace(id="asset-a",tenant_id="tenant-a",value="a.example.org"),
            SimpleNamespace(id="asset-b",tenant_id="tenant-a",value="blocked.example.org"),
        ]
        self.findings=[
            SimpleNamespace(id="finding-a",tenant_id="tenant-a",asset_id="asset-a"),
            SimpleNamespace(id="finding-b",tenant_id="tenant-a",asset_id="asset-b"),
        ]

    def list_assets(self, tenant_id):
        self.asset_calls.append(tenant_id)
        return list(self.assets)

    def list_findings(self, tenant_id, asset_ids=None):
        allowed=set(asset_ids or ())
        self.finding_calls.append((tenant_id,allowed))
        return [item for item in self.findings if item.asset_id in allowed]


def test_tenant_state_uses_repository_boundary_and_scope(monkeypatch):
    repository=_Repository()
    principal=SimpleNamespace(tenant_id="tenant-a")
    monkeypatch.setattr(easm_executor,"asset_finding_repository",lambda: repository)
    monkeypatch.setattr(
        easm_executor,
        "asset_in_scope",
        lambda _principal,value: value=="a.example.org",
    )

    assets,findings=easm_executor._tenant_state(principal)

    assert [item.id for item in assets]==["asset-a"]
    assert [item.id for item in findings]==["finding-a"]
    assert repository.asset_calls==["tenant-a"]
    assert repository.finding_calls==[("tenant-a",{"asset-a"})]
