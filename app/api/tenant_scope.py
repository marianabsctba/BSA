from ..repositories.assets_findings import asset_finding_repository
from ..scope import asset_in_scope


def tenant_scope(principal, assets=None, findings=None, scope_check=None):
    repository=asset_finding_repository(assets=assets,findings=findings)
    check=scope_check or asset_in_scope
    scoped_assets=[
        asset
        for asset in repository.list_assets(principal.tenant_id)
        if check(principal,asset.value)
    ]
    scoped_ids={asset.id for asset in scoped_assets}
    scoped_findings=repository.list_findings(
        principal.tenant_id,
        scoped_ids,
    )
    return scoped_assets,scoped_findings
