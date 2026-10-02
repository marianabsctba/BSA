from ...history import (
    ctem_next_action,
    ctem_operational_summary,
    ctem_queue_filter,
    ctem_queue_page,
    ctem_queue_view,
    ctem_remediation_coverage,
    list_ctem_items,
)
from ...tenant_sla_policy import sla_policy_for


def build_ctem_operations(tenant_id: str) -> dict:
    items=list_ctem_items(tenant_id)
    summary=ctem_operational_summary(
        items,
        sla_policy=sla_policy_for(tenant_id),
    )
    summary["remediation_coverage"]=ctem_remediation_coverage(items)
    summary["queue"]=ctem_queue_view(items)
    return {"summary":summary,"items":items}


def build_ctem_queue_page(
    tenant_id: str,
    *,
    state: str | None=None,
    bucket: str | None=None,
    min_leverage: int | None=None,
    page: int=1,
    page_size: int=50,
) -> dict:
    items=list_ctem_items(tenant_id)
    filtered=ctem_queue_filter(
        items,
        state=state,
        bucket=bucket,
        min_leverage=min_leverage,
    )
    result=ctem_queue_page(filtered,page=page,page_size=page_size)
    result["items"]=[
        {**item,"next_action":ctem_next_action(item)}
        for item in result["items"]
    ]
    return result


def list_ctem_queue(tenant_id: str, state: str | None=None) -> dict:
    states={state} if state else None
    return {"items":list_ctem_items(tenant_id,states)}
