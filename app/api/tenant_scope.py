from ..scope import asset_in_scope
from ..store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS


def tenant_scope(principal, assets=None, findings=None):
    source_assets=STORE_ASSETS if assets is None else assets
    source_findings=STORE_FINDINGS if findings is None else findings
    scoped_assets=[
        asset
        for asset in source_assets
        if getattr(asset,"tenant_id","tenant-demo")==principal.tenant_id
        and asset_in_scope(principal,asset.value)
    ]
    scoped_ids={asset.id for asset in scoped_assets}
    scoped_findings=[
        finding
        for finding in source_findings
        if getattr(finding,"tenant_id","tenant-demo")==principal.tenant_id
        and finding.asset_id in scoped_ids
    ]
    return scoped_assets,scoped_findings
