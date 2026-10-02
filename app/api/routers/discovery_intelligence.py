from fastapi import APIRouter, HTTPException, Request

from ...cve_correlation import CVERange, match_cve
from ...local_ai import (
    OLLAMA_MODEL,
    analyze_attack_paths,
    enabled as local_ai_enabled,
)
from ...risk_engine import normalize_cpe
from ...scope import asset_in_scope
from ..dependencies import require
from ..tenant_scope import tenant_scope
from ..operation_queue import queue_active_operation


router=APIRouter()



@router.post("/api/v1/discovery/adaptive/{target}")
def discovery_adaptive(
    target: str,
    request: Request,
    max_rounds: int=3,
    max_assets: int=40,
):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    if max_rounds<1 or max_rounds>3 or max_assets<1 or max_assets>100:
        raise HTTPException(status_code=400,detail="invalid discovery bounds")
    return queue_active_operation(
        request,
        principal,
        target,
        "discovery.adaptive",
        {"max_rounds":max_rounds,"max_assets":max_assets},
    )


@router.post("/api/v1/discovery/ip-intelligence/{target}")
def discovery_ip_intelligence(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    return queue_active_operation(
        request,
        principal,
        target,
        "discovery.ip_intelligence",
    )


@router.post("/api/v1/discovery/ai-attack-paths")
def discovery_ai_attack_paths(request: Request, payload: dict):
    principal=require(request,"assets:read")
    graph=payload.get("graph") if isinstance(payload,dict) else None
    if not isinstance(graph,dict):
        raise HTTPException(status_code=400,detail="graph required")
    target=str(payload.get("target","")).strip()
    if target and not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    result=analyze_attack_paths(graph)
    return {
        "target":target or None,
        "ai_enabled":local_ai_enabled(),
        "model":OLLAMA_MODEL if local_ai_enabled() else None,
        "analysis":result,
        "fallback":"deterministic graph only" if result is None else None,
    }


def _queue_discovery(request: Request, target: str, operation: str):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    return queue_active_operation(request,principal,target,operation)


@router.post("/api/v1/discovery/ai-identity/{target}")
def discovery_ai_identity(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.ai_identity")


@router.post("/api/v1/discovery/ai-prioritize/{target}")
def discovery_ai_prioritize(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.ai_prioritize")


@router.post("/api/v1/discovery/ai-api-surface/{target}")
def discovery_ai_api_surface(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.ai_api_surface")


@router.post("/api/v1/discovery/ai-correlate/{target}")
def discovery_ai_correlate(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.ai_correlate")


@router.post("/api/v1/discovery/signals/{target}")
def discovery_signals(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.signals")


@router.post("/api/v1/discovery/ai-judge/{target}")
def discovery_ai_judge(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.ai_judge")


@router.post("/api/v1/discovery/ai-plan/{target}")
def discovery_ai_plan(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.ai_plan")


@router.post("/api/v1/technologies/intelligence/{target}")
def technology_intelligence_api(target: str, request: Request):
    return _queue_discovery(request,target,"technology.intelligence")


@router.post("/api/v1/vulnerabilities/correlate")
async def correlate_vulnerabilities(request: Request):
    principal=require(request,"assets:read")
    tenant_scope(principal)
    body=await request.json()
    candidates=[]
    for item in body.get("candidates",[]):
        try:
            candidates.append(CVERange(
                vulnerability_id=str(item["vulnerability_id"]),
                vendor=str(item.get("vendor","")),
                product=str(item["product"]),
                version_start=item.get("version_start"),
                version_end=item.get("version_end"),
                exact_versions=tuple(item.get("exact_versions",[])),
                source=str(item.get("source","catalog")),
            ))
        except (KeyError,TypeError):
            continue
    results=[]
    for item in body.get("observations",[]):
        product=str(item.get("product",""))
        version=item.get("version")
        cpe=normalize_cpe(item.get("cpe"))
        matches=match_cve(product,version,cpe,candidates)
        results.append({
            "product":product,
            "version":version,
            "cpe":cpe,
            "matches":[match.__dict__ for match in matches],
        })
    return {
        "results":results,
        "summary":{
            "observations":len(results),
            "confirmed":sum(
                1
                for result in results
                for match in result["matches"]
                if match["state"]=="confirmed_affected"
            ),
            "potential":sum(
                1
                for result in results
                for match in result["matches"]
                if match["state"]=="potential"
            ),
            "not_affected":sum(
                1
                for result in results
                for match in result["matches"]
                if match["state"]=="not_affected"
            ),
        },
    }
