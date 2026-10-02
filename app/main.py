from datetime import datetime, timezone
from dataclasses import asdict
from fastapi.responses import JSONResponse
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from urllib.parse import urlparse
import os
from hashlib import sha256

from .changes import seed_changes
from .graph import RELATIONSHIPS, build_attack_surface_graph, build_risk_graph, simulate_remediation
from .intelligence import ownership_confidence, blast_radius, finding_context_score
from .models import Dashboard, Asset, AssetType, Finding, Severity
from .scoring import exposure_score
from .exposure import exposure_breakdown, exposure_band
from .discovery import collect_target, discover_surface, adaptive_discovery
from fastapi import HTTPException
from pydantic import BaseModel, Field
from .store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS, persist_state
from .correlation import correlate_evidence
from .history import record_observations, list_ctem_items, update_ctem_state, upsert_ctem_item, verify_ctem_item, reopen_ctem_item, ctem_leverage_summary, ctem_operational_summary, ctem_remediation_coverage, ctem_verification_history, ctem_audit_timeline, ctem_audit_integrity, ctem_audit_diff, ctem_audit_outcome, ctem_queue_view, ctem_queue_filter, ctem_queue_page, ctem_next_action, ctem_action_transition, ctem_action_idempotency_key, ctem_claim_operation, ctem_operation_result, ctem_store_operation_result, change_summary, record_lifecycle, lifecycle_for
from .prioritization import prioritize_finding
from .remediation import build_remediation_plan
from .auth import authenticate, rate_limit_action, bootstrap, can, role_permissions, list_custom_roles, create_custom_role, create_user, list_users, update_user, set_user_active, reset_user_password, principal_from_token, create_tenant, list_tenants, tenant_settings, update_tenant_locale, audit, list_audit, revoke_session, mfa_status, mfa_enroll, mfa_enable
from .ctem_store import list_plans, get_plan, upsert_plan, history
from .discovery_orchestrator import plan_candidate_collection
from .scope import bootstrap_scope, asset_in_scope, active_scan_in_scope, create_scope, list_scopes, assign_scope, create_scan_scope, list_scan_scopes, assign_scan_scope, create_group, list_groups, list_user_scopes, list_user_scan_scopes, assign_scope_to_user, assign_scan_scope_to_user
from .asset_view import asset_detail
from .asset_identity import normalize_asset_value
from .exposure_dna import build_exposure_dna
from .local_ai import analyze_exposure, explain_attack_path, analyze_brand_context, analyze_infrastructure_cluster, plan_discovery, judge_correlation, correlate_exposure, analyze_api_surface, prioritize_collection, validate_asset_identity, analyze_attack_paths, enabled as local_ai_enabled, OLLAMA_MODEL
from .vulnerability_intelligence import vulnerability_intelligence, enrich_finding
from .vulnerability_evidence import normalize_vulnerability_evidence, vulnerability_identity_key
from .technology_intelligence import extract_technologies, technology_match_quality, fingerprint_technology
from .risk_engine import assess_risk, assess_ctem_priority, normalize_cpe, cpe_product
from .cve_correlation import CVERange, match_cve
from .risk_policy import calculate_risk, DEFAULT_POLICY
from .tenant_risk_policy import policy_for, serialize_policy, validate_policy, TenantRiskPolicy
from .digital_risk import DigitalRiskEvent, TakedownRequest, BrandAnalysis, InfrastructureIndicator, analyze_brand_impersonation, build_infrastructure_links, build_infrastructure_graph, upsert_event, list_events, create_takedown, list_takedowns
from .exposure_signals import cloud_signals, takeover_signals, summarize_signals
from .ip_intelligence import ip_exposure_signal
from .dast import run_safe_web_assessment
from .nuclei_engine import NucleiEngineError, run_nuclei, normalize_findings
from .assessment_orchestrator import run_public_assessment
from .engine_health import public_engine_health
from .release_readiness import release_readiness
from .assessment_registry import registry
from .job_queue import enqueue_assessment, get_job, cancel_job, claim_materialization, finish_materialization
from .auth import Principal
from .tenant_lifecycle import retire_tenant, tenant_purge_preview, purge_tenant
from .scan_authorization import create_authorization_grant, list_authorization_grants, revoke_authorization_grant, authorization_grant_valid

bootstrap()
bootstrap_scope()

IS_PRODUCTION=os.getenv("BSA_ENV","development").lower() in {"production","prod"}

app = FastAPI(
    title="BSA — Be Safe ASM API",
    version="0.3.0",
    description="Attack Surface Management defensivo, rastreável e orientado a evidências.",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)

ALLOWED_HOSTS=[x.strip() for x in os.getenv("BSA_ALLOWED_HOSTS","").split(",") if x.strip()]
if ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

ALLOWED_ORIGINS=[x.strip() for x in os.getenv("BSA_ALLOWED_ORIGINS","").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["Authorization","Content-Type","X-Requested-With","X-Authorization-Ref"],
)

@app.middleware("http")
async def csrf_origin_guard(request: Request, call_next):
    cookie_auth = bool(request.cookies.get("bsa_session")) and not request.headers.get("Authorization")
    mutating = request.method in {"POST","PUT","PATCH","DELETE"}
    login_path = request.url.path == "/api/v1/auth/login"
    if mutating and cookie_auth and not login_path:
        origin=request.headers.get("origin")
        if origin:
            allowed=set(ALLOWED_ORIGINS)
            if origin not in allowed:
                return JSONResponse(status_code=403, content={"detail":"origin not allowed"})
        if os.getenv("BSA_ENV","development").lower() in {"production","prod"}:
            if request.headers.get("X-Requested-With") != "BeSafeASM":
                return JSONResponse(status_code=403, content={"detail":"csrf request marker required"})
    return await call_next(request)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-XSS-Protection"]="0"
    response.headers["Cross-Origin-Resource-Policy"]="same-origin"
    response.headers["Cross-Origin-Opener-Policy"]="same-origin"
    response.headers["Cache-Control"]="no-store"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"]="default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    if request.url.scheme=="https":
        response.headers["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
    return response


def govern_active_scan(http_request: Request, principal, target: str, authorization_ref: str | None = None):
    ref=(authorization_ref or http_request.headers.get("X-Authorization-Ref","")).strip()
    if IS_PRODUCTION and not ref:
        raise HTTPException(status_code=400,detail="authorization_ref is required for active scans")
    if IS_PRODUCTION and not authorization_grant_valid(principal,ref,target):
        raise HTTPException(status_code=403,detail="authorization_ref is expired, revoked, or not valid for target")
    if not active_scan_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target not authorized for active scanning")
    rate_key=f"{principal.tenant_id}:{principal.user_id}"
    if not rate_limit_action("active-scan",rate_key,limit=30,window_seconds=300):
        raise HTTPException(status_code=429,detail="active scan rate limit exceeded")
    audit(
        principal,"request","active_scan",target,
        {
            "authorization_ref":ref or "development",
            "method":http_request.method,
            "path":http_request.url.path,
        },
    )
    return ref


@app.post("/api/v1/auth/logout")
def auth_logout(request: Request):
    principal=current_principal(request)
    auth=request.headers.get("Authorization","")
    token=auth.split(" ",1)[1] if auth.lower().startswith("bearer ") else request.cookies.get("bsa_session","")
    try:
        claims=__import__("app.auth",fromlist=["_decode"])._decode(token)
        revoke_session(principal,claims.get("jti"))
    except Exception:
        revoke_session(principal)
    response=JSONResponse({"ok":True})
    response.delete_cookie("bsa_session",path="/")
    return response

@app.get("/health")
def health():
    return {"status": "ok", "product": "BSA", "version": "0.3.0", "powered_by": "Mariana BS"}


@app.get("/api/v1/exposure/engines/health")
def exposure_engines_health(request: Request):
    require(request, "assets:read")
    return public_engine_health()


@app.get("/api/v1/operations/release-readiness")
def operations_release_readiness(request: Request):
    principal = require(request, "assets:read")
    if principal.role not in {"superadmin", "admin", "manager"}:
        raise HTTPException(status_code=403, detail="manager role required")
    return release_readiness()


@app.get("/api/v1/mssp/command-center/trend")
def mssp_command_center_trend(request: Request):
    principal=require(request,"assets:read")
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403, detail="MSSP role required")
    from .auth import _db
    conn=_db()
    if principal.role == "superadmin":
        tenants=[dict(x) for x in conn.execute("SELECT id,name FROM tenants ORDER BY name").fetchall()]
    else:
        tenants=[dict(x) for x in conn.execute("SELECT id,name FROM tenants WHERE id=?",(principal.tenant_id,)).fetchall()]
    conn.close()
    out=[]
    for t in tenants:
        events=history(t["id"],90)
        out.append({"tenant_id":t["id"],"tenant":t["name"],"events":events})
    return {"days":90,"tenants":out}

@app.get("/api/v1/mssp/command-center")
def mssp_command_center(request: Request):
    principal = require(request, "assets:read")
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403, detail="MSSP role required")
    from .auth import _db
    conn=_db()
    if principal.role == "superadmin":
        tenants=[dict(x) for x in conn.execute("SELECT id,name,active FROM tenants ORDER BY name").fetchall()]
    else:
        tenants=[dict(x) for x in conn.execute("SELECT id,name,active FROM tenants WHERE id=?",(principal.tenant_id,)).fetchall()]
    conn.close()
    rows=[]
    for t in tenants:
        scoped=type("P",(),{"tenant_id":t["id"]})()
        assets=[a for a in STORE_ASSETS if getattr(a,"tenant_id","tenant-demo")==t["id"]]
        findings=[f for f in STORE_FINDINGS if getattr(f,"tenant_id","tenant-demo")==t["id"] and f.status=="open"]
        scores=[exposure_breakdown(a,findings).score for a in assets]
        plans=list_plans(t["id"])
        overdue=sum(1 for p in plans if p.get("status") in {"planned","approved","in_progress"} and p.get("effort")=="alto")
        risk=round(sum(scores)/len(scores)) if scores else 0
        critical=sum(1 for f in findings if getattr(f,"severity",None) and str(f.severity).lower().endswith("critical"))
        approved=sum(1 for p in plans if p.get("status")=="approved")
        in_progress=sum(1 for p in plans if p.get("status")=="in_progress")
        remediated=sum(1 for p in plans if p.get("status") in {"remediated","retest","closed"})
        now_ts=datetime.now(timezone.utc)
        active_plans=[p for p in plans if p.get("status") not in {"closed","remediated"}]
        aging_days=[]
        for p in active_plans:
            try:
                created=datetime.fromisoformat(p.get("created_at","").replace("Z","+00:00"))
                aging_days.append(max(0,(now_ts-created).days))
            except Exception:
                pass
        sla_target=7
        sla_breaches=sum(1 for d in aging_days if d>sla_target)
        sla_compliance=round((len(aging_days)-sla_breaches)/len(aging_days)*100) if aging_days else 100
        residual=round(sum(p.get("residual_score",0) for p in active_plans)/len(active_plans)) if active_plans else 0
        risk_reduction=sum(max(0,p.get("risk_reduction",0)) for p in plans)
        rows.append({"tenant_id":t["id"],"tenant":t["name"],"active":t["active"],"risk":risk,
                     "assets":len(assets),"open_findings":len(findings),"critical_findings":critical,
                     "ctem":len(plans),"approved":approved,"in_progress":in_progress,"remediated":remediated,
                     "overdue":overdue,"ctem_aging":len(active_plans),"avg_ctem_age_days":round(sum(aging_days)/len(aging_days)) if aging_days else 0,
                     "sla_compliance":sla_compliance,"sla_breaches":sla_breaches,"risk_residual":residual,
                     "risk_reduction_30d":risk_reduction})
    rows.sort(key=lambda x:x["risk"],reverse=True)
    return {"tenants":rows,"summary":{"tenants":len(rows),"critical_tenants":sum(x["risk"]>=80 for x in rows),
        "open_findings":sum(x["open_findings"] for x in rows),"ctem_plans":sum(x["ctem"] for x in rows),
        "overdue":sum(x["overdue"] for x in rows),"remediated":sum(x["remediated"] for x in rows),"in_progress":sum(x["in_progress"] for x in rows),
        "sla_compliance":round(sum(x["sla_compliance"] for x in rows)/len(rows)) if rows else 100,
        "sla_breaches":sum(x["sla_breaches"] for x in rows),"risk_residual":round(sum(x["risk_residual"] for x in rows)) if rows else 0,
        "risk_reduction_30d":sum(x["risk_reduction_30d"] for x in rows)}}

@app.get("/api/v1/assets")
def list_assets(request: Request):
    principal = require(request, "assets:read")
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    result = []
    for asset in ASSETS:
        item = asset.model_dump()
        ownership = ownership_confidence(asset)
        item["ownership"] = {
            "score": ownership.score,
            "state": ownership.state,
            "reasons": ownership.reasons,
        }
        item["blast_radius"] = blast_radius(asset)
        result.append(item)
    return result




@app.get("/api/v1/assets/{asset_id}")
def asset_detail_view(asset_id: str, request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    asset = next((a for a in assets if a.id == asset_id), None)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")
    audit(principal, "read", "asset", asset.id)
    return asset_detail(asset, findings, assets, principal.tenant_id)


@app.get("/api/v1/discovery/adaptive/{target}")
def discovery_adaptive(target: str, request: Request, max_rounds: int = 3, max_assets: int = 40):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    result=adaptive_discovery(target,max_rounds=max_rounds,max_assets=max_assets)
    candidates=[{"kind":"hostname","value":x["value"],"confidence":x["confidence"],
                 "evidence_refs":x["evidence_refs"],"reasons":x["reasons"]} for x in result.get("candidates",[])]
    plans=plan_candidate_collection(candidates, max_jobs=max_assets)
    authorized=[p for p in plans if asset_in_scope(principal,p.target)]
    return {"target":result["seed"],"rounds":result["rounds"],"candidates":candidates,
            "collection_plan":[{"collector":p.collector,"target_kind":p.target_kind,"target":p.target,
                                "priority":p.priority,"reason":p.reason} for p in authorized],
            "summary":{"candidate_count":len(candidates),"planned_jobs":len(authorized),
                       "max_assets":max_assets,"scope_filtered_jobs":len(plans)-len(authorized)}}

@app.get("/api/v1/discovery/ip-intelligence/{target}")
def discovery_ip_intelligence(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct","ports","rdap","ip_intel"])
    ips=sorted({str(e.get("value")) for e in data["evidence"] if e.get("kind") in {"a_record","aaaa"}})
    return {"target":data["target"],"ips":[ip_exposure_signal(x) for x in ips],
            "evidence_count":data["evidence_count"]}





@app.post("/api/v1/discovery/ai-attack-paths")
def discovery_ai_attack_paths(request: Request, payload: dict):
    principal=require(request,"assets:read")
    graph=payload.get("graph") if isinstance(payload,dict) else None
    if not isinstance(graph,dict):
        raise HTTPException(status_code=400,detail="graph required")
    target=str(payload.get("target","")).strip()
    if target and not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    result=analyze_attack_paths(graph)
    return {"target":target or None,"ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "analysis":result,"fallback":"deterministic graph only" if result is None else None}

@app.get("/api/v1/discovery/ai-identity/{target}")
def discovery_ai_identity(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct","rdap"])
    assets=correlate_evidence(target,data["evidence"])
    payload=[{"fingerprint":a.fingerprint,"value":a.value,"asset_type":a.asset_type,
              "confidence":a.confidence,"sources":list(a.sources),"evidence_count":a.evidence_count,
              "tags":list(a.tags)} for a in assets]
    result=validate_asset_identity(payload,data["evidence"])
    return {"target":data["target"],"ai_enabled":local_ai_enabled(),"model":OLLAMA_MODEL if local_ai_enabled() else None,
            "assets":payload,"evidence_count":data["evidence_count"],"identity_validation":result}

@app.get("/api/v1/discovery/ai-prioritize/{target}")
def discovery_ai_prioritize(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct"])
    signals=[]
    for e in data["evidence"]:
        if e.get("kind") in {"http_status","certificate_name","a_record","aaaa","openapi_endpoint"}:
            signals.append({"kind":e.get("kind"),"value":e.get("value"),"confidence":e.get("confidence")})
    candidate_checks=["dns","http","tls","ct","ports","rdap","ip_intel"]
    result=prioritize_collection(target,data["evidence"],signals,candidate_checks)
    return {"target":data["target"],"ai_enabled":local_ai_enabled(),"model":OLLAMA_MODEL if local_ai_enabled() else None,
            "evidence_count":data["evidence_count"],"candidate_checks":candidate_checks,
            "prioritization":result,"fallback":"deterministic collector order" if result is None else None}

@app.get("/api/v1/discovery/ai-api-surface/{target}")
def discovery_ai_api_surface(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["http"])
    endpoints=[e for e in data["evidence"] if e.get("kind")=="openapi_endpoint"]
    technologies=[e for e in data["evidence"] if str(e.get("kind","")).startswith("technology:")]
    result=analyze_api_surface(target,endpoints,technologies)
    return {"target":data["target"],"ai_enabled":local_ai_enabled(),"model":OLLAMA_MODEL if local_ai_enabled() else None,
            "endpoint_count":len(endpoints),"evidence_count":data["evidence_count"],
            "analysis":result,"fallback":"deterministic evidence only" if result is None else None}

@app.get("/api/v1/discovery/ai-correlate/{target}")
def discovery_ai_correlate(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct","ports","rdap"])
    result=correlate_exposure(target,data["evidence"])
    return {"target":data["target"],"ai_enabled":local_ai_enabled(),"model":OLLAMA_MODEL if local_ai_enabled() else None,
            "evidence_count":data["evidence_count"],"correlation":result}

@app.get("/api/v1/discovery/signals/{target}")
def discovery_signals(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct","ports","rdap"])
    values=[str(e.get("value","")) for e in data["evidence"]]
    http_values=[str(e.get("value","")) for e in data["evidence"] if str(e.get("kind","")).startswith("http_") or str(e.get("kind","")).startswith("page_")]
    signals=cloud_signals(values)+takeover_signals(http_values)
    return {"target":data["target"],"evidence_count":data["evidence_count"],**summarize_signals(signals)}

@app.get("/api/v1/discovery/ai-judge/{target}")
def discovery_ai_judge(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct","ports","rdap"])
    grouped={}
    for e in data["evidence"]:
        subject=str(e.get("subject",target))
        grouped.setdefault(subject,[]).append(e)
    decisions=[]
    for subject,items in grouped.items():
        if len(items)<2: continue
        decision=judge_correlation(subject,items)
        if decision: decisions.append({"subject":subject,"decision":decision})
    return {"target":data["target"],"evidence_count":data["evidence_count"],"ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,"decisions":decisions}
    
@app.get("/api/v1/discovery/ai-plan/{target}")
def discovery_ai_plan(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct"])
    plan=plan_discovery(target,data)
    return {"target":data["target"],"ai_enabled":local_ai_enabled(),"model":OLLAMA_MODEL if local_ai_enabled() else None,
            "evidence_count":data["evidence_count"],"plan":plan,
            "fallback":"deterministic discovery only" if plan is None else None}

@app.get("/api/v1/technologies/intelligence/{target}")
def technology_intelligence_api(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["http","tls"])
    observations=extract_technologies(data["evidence"])
    fingerprints=fingerprint_technology(data["evidence"])
    items=[]
    for o in observations:
        item={"product":o.product,"version":o.version,"confidence":o.confidence,"source":o.source,
              "evidence":o.evidence,"version_confirmed":o.version_confirmed}
        item["matching"]=technology_match_quality(o)
        items.append(item)
    return {"target":data["target"],"technologies":items,"fingerprints":fingerprints,
            "summary":{"products":len(items),"version_confirmed":sum(x["version_confirmed"] for x in items),
                       "product_only":sum(not x["version_confirmed"] for x in items),
                       "fingerprint_candidates":len(fingerprints),
                       "cve_matching":sum(x["matching"]["matching_allowed"] for x in items)}}

@app.post("/api/v1/vulnerabilities/correlate")
async def correlate_vulnerabilities(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    body=await request.json()
    candidates=[]
    for x in body.get("candidates",[]):
        try: candidates.append(CVERange(vulnerability_id=str(x["vulnerability_id"]),vendor=str(x.get("vendor","")),product=str(x["product"]),version_start=x.get("version_start"),version_end=x.get("version_end"),exact_versions=tuple(x.get("exact_versions",[])),source=str(x.get("source","catalog"))))
        except (KeyError,TypeError): continue
    results=[]
    for x in body.get("observations",[]):
        product=str(x.get("product","")); version=x.get("version"); cpe=normalize_cpe(x.get("cpe"))
        matches=match_cve(product,version,cpe,candidates)
        results.append({"product":product,"version":version,"cpe":cpe,"matches":[m.__dict__ for m in matches]})
    return {"results":results,"summary":{"observations":len(results),"confirmed":sum(1 for r in results for m in r["matches"] if m["state"]=="confirmed_affected"),"potential":sum(1 for r in results for m in r["matches"] if m["state"]=="potential"),"not_affected":sum(1 for r in results for m in r["matches"] if m["state"]=="not_affected")}}

@app.get("/api/v1/risk/policy")
def get_risk_policy(request: Request):
    principal=require(request,"assets:read")
    policy=policy_for(principal.tenant_id)
    return {"policy":serialize_policy(policy),"validation":validate_policy(policy)}

@app.put("/api/v1/risk/policy")
async def update_risk_policy(request: Request):
    principal=require(request,"remediation:write")
    body=await request.json()
    base=policy_for(principal.tenant_id)
    allowed={"likelihood_weight","impact_weight","confidence_weight","internet_multiplier","production_multiplier","remote_access_multiplier","compensating_control_reduction","stale_evidence_days","stale_confidence_penalty","name"}
    values={k:body[k] for k in allowed if k in body}
    candidate=TenantRiskPolicy(**{**base.__dict__,**values,"tenant_id":principal.tenant_id,"version":base.version+1})
    errors=validate_policy(candidate)
    if errors: raise HTTPException(status_code=400,detail={"errors":errors})
    audit(principal,"risk_policy_update","risk_policy",metadata=serialize_policy(candidate))
    return {"policy":serialize_policy(candidate),"validation":[],"note":"policy validated; persistence wiring is isolated from the scoring contract"}

@app.get("/api/v1/risk/register")
def risk_register(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    amap={a.id:a for a in assets}
    items=[]
    for f in findings:
        if f.status!="open": continue
        a=amap.get(f.asset_id)
        risk=calculate_risk(f,a)
        items.append({"finding_id":f.id,"asset_id":f.asset_id,"asset":a.value if a else None,
                      "title":f.title,"risk":risk})
    items.sort(key=lambda x:(x["risk"]["residual_score"],x["risk"]["score"]),reverse=True)
    return {"policy":asdict(DEFAULT_POLICY),"summary":{
        "findings":len(items),
        "critical":sum(x["risk"]["band"]=="critical" for x in items),
        "high":sum(x["risk"]["band"]=="high" for x in items),
        "medium":sum(x["risk"]["band"]=="medium" for x in items),
        "low":sum(x["risk"]["band"]=="low" for x in items),
        "validation_required":sum(x["risk"]["validation_required"] for x in items),
        "average_inherent":round(sum(x["risk"]["inherent_score"] for x in items)/len(items)) if items else 0,
        "average_residual":round(sum(x["risk"]["residual_score"] for x in items)/len(items)) if items else 0,
    },"items":items}

@app.get("/api/v1/risk/overview")
def risk_overview(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    amap={a.id:a for a in assets}
    items=[]
    for f in findings:
        if f.status!="open": continue
        a=amap.get(f.asset_id)
        risk=assess_risk(f,a)
        items.append({"finding_id":f.id,"asset_id":f.asset_id,"asset":a.value if a else None,
                      "vulnerability_id":f.vulnerability_id,"cpe":normalize_cpe(f.cpe),
                      "cpe_product":cpe_product(f.cpe)[0],"cpe_version":cpe_product(f.cpe)[1],
                      "risk":asdict(risk)})
    items.sort(key=lambda x:x["risk"]["score"],reverse=True)
    return {"summary":{"findings":len(items),
        "critical":sum(x["risk"]["band"]=="critical" for x in items),
        "high":sum(x["risk"]["band"]=="high" for x in items),
        "medium":sum(x["risk"]["band"]=="medium" for x in items),
        "low":sum(x["risk"]["band"]=="low" for x in items),
        "average":round(sum(x["risk"]["score"] for x in items)/len(items)) if items else 0},"items":items}

@app.get("/api/v1/vulnerabilities/intelligence")
def vulnerability_intelligence_api(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    amap={a.id:a for a in assets}
    rows=[]
    for f in findings:
        if f.status!="open": continue
        intel=vulnerability_intelligence(f,amap.get(f.asset_id))
        rows.append({"finding":f.model_dump(),"asset":amap.get(f.asset_id).value if amap.get(f.asset_id) else None,"intelligence":asdict(intel)})
    rows.sort(key=lambda x:x["intelligence"]["priority_score"],reverse=True)
    return {"summary":{"findings":len(rows),"critical":sum(x["intelligence"]["band"]=="critical" for x in rows),"high":sum(x["intelligence"]["band"]=="high" for x in rows),"data_quality_gaps":sum(bool(x["intelligence"]["data_quality"]) for x in rows)},"items":rows}

@app.get("/api/v1/vulnerabilities/{finding_id}/intelligence")
def vulnerability_finding_intelligence(finding_id: str, request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    f=next((x for x in findings if x.id==finding_id),None)
    if not f: raise HTTPException(status_code=404,detail="finding not found")
    a=next((x for x in assets if x.id==f.asset_id),None)
    return {"finding":f.model_dump(),"asset":a.model_dump() if a else None,"intelligence":asdict(vulnerability_intelligence(f,a))}

@app.get("/api/v1/findings")
def list_findings(request: Request):
    principal = require(request, "assets:read")
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    asset_map = {a.id: a for a in ASSETS}
    result = []
    for finding in FINDINGS:
        item = finding.model_dump()
        asset = asset_map.get(finding.asset_id)
        item["context_score"] = finding_context_score(finding, asset) if asset else None
        result.append(item)
    return result


@app.get("/api/v1/changes")
def list_changes(request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    return seed_changes(assets)


class RemediationSimulationRequest(BaseModel):
    path: list[str] = Field(default_factory=list)
    finding_node_ids: list[str] = Field(default_factory=list)

@app.post("/api/v1/graph/simulate")
def graph_simulate(payload: RemediationSimulationRequest, request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    graph = build_risk_graph(f"tenant:{principal.tenant_id}", assets, [], source_assets=assets, findings=findings)
    nodes = {n["id"]: type("Node", (), n)() for n in graph["nodes"]}
    edges = [type("Edge", (), e)() for e in graph["edges"]]
    return simulate_remediation(nodes, edges, payload.path, payload.finding_node_ids)

@app.post("/api/v1/graph/attack-path/explain")
def explain_attack_path_api(payload: dict, request: Request):
    principal=require(request,"assets:read")
    path=payload.get("path") or []
    if not path or len(path)>30:
        raise HTTPException(status_code=400,detail="Invalid attack path")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    allowed={a.id for a in assets}
    graph=build_risk_graph(f"tenant:{principal.tenant_id}",assets,[],source_assets=assets,findings=findings)
    graph_nodes={n["id"]:n for n in graph["nodes"]}
    selected=[graph_nodes[n] for n in path if n in graph_nodes]
    evidence={"nodes":selected,"paths":[p for p in graph.get("top_risk_paths",[]) if any(n in path for n in p.get("nodes",[]))]}
    result=explain_attack_path(path,evidence)
    if not result:
        return {"ai":{"enabled":local_ai_enabled(),"provider":"ollama-local","grounded":False},"summary":"Local AI unavailable.","facts":[],"inference":[],"unknowns":["AI unavailable; use graph evidence directly."],"validation":[],"confidence":0}
    result["ai"]={"enabled":True,"provider":"ollama-local","model":OLLAMA_MODEL,"grounded":True}
    return result

@app.get("/api/v1/risk/remediation-options")
def risk_remediation_options(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    graph=build_risk_graph(f"tenant:{principal.tenant_id}",assets,[],source_assets=assets,findings=findings)
    nodes={n["id"]:type("Node",(),n)() for n in graph["nodes"]}
    edges=[type("Edge",(),e)() for e in graph["edges"]]
    from .graph import remediation_options
    options=remediation_options(nodes,edges,graph.get("top_risk_paths",[]))
    return {"summary":{"options":len(options),"total_risk_reduction":sum(x["risk_reduction"] for x in options)},"options":options}

@app.get("/api/v1/risk/attack-paths")
def risk_attack_paths(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    graph=build_risk_graph(f"tenant:{principal.tenant_id}",assets,[],source_assets=assets,findings=findings)
    paths=graph.get("top_risk_paths",[])
    for p in paths:
        p["risk_model"]="contextual-residual"
        p["decision_factors"]={
            "highest_node_risk":max((graph_node.get("risk_score",0) for graph_node in graph["nodes"] if graph_node["id"] in p.get("nodes",[])),default=0),
            "weakest_link_confidence":p.get("explanation",{}).get("weakest_link",{}).get("confidence",0),
            "choke_points":len(p.get("choke_points",[])),
            "control_unknowns":p.get("control_summary",{}).get("unknown",0)
        }
    return {"summary":graph["risk_summary"],"paths":paths}

@app.get("/api/v1/graph/control-coverage")
def graph_control_coverage(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    graph=build_risk_graph(f"tenant:{principal.tenant_id}",assets,[],source_assets=assets,findings=findings)
    covered=[n for n in graph["nodes"] if n.get("control_coverage")=="covered"]
    unknown=[n for n in graph["nodes"] if n.get("control_coverage")=="unknown" and n.get("kind") not in {"internet","finding","threat","certificate","ip"}]
    controls={}
    for n in covered:
        for control in n.get("security_controls",[]):
            controls.setdefault(control["type"],{"count":0,"providers":set()})
            controls[control["type"]]["count"]+=1
            controls[control["type"]]["providers"].add(control["provider"])
    return {"coverage":{"covered_assets":len(covered),"unknown_assets":len(unknown),"coverage_percent":round(len(covered)/(len(covered)+len(unknown))*100) if covered or unknown else 0},
            "controls":[{"type":k,"count":v["count"],"providers":sorted(v["providers"])} for k,v in controls.items()],
            "choke_points":sorted([{"node_id":n["id"],"label":n["label"],"score":n.get("choke_point_score",0)} for n in graph["nodes"] if n.get("choke_point_score",0)>0],key=lambda x:x["score"],reverse=True)[:10]}
 
@app.get("/api/v1/graph")
def graph(request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    result = build_risk_graph(
        f"tenant:{principal.tenant_id}",
        assets,
        [],
        source_assets=assets,
        findings=findings,
    )
    return result




class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=256)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=6)

class ScopeCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    pattern: str = Field(min_length=1, max_length=253)

class ScopeAssignRequest(BaseModel):
    user_id: str
    scope_id: str

class GroupCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    pattern: str = Field(min_length=1, max_length=253)

class UserCreateRequest(BaseModel):
    email: str
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)
    role: str


def tenant_scope(principal, assets, findings):
    scoped_assets = [a for a in assets if getattr(a, "tenant_id", "tenant-demo") == principal.tenant_id and asset_in_scope(principal, a.value)]
    scoped_ids = {a.id for a in scoped_assets}
    scoped_findings = [f for f in findings if getattr(f, "tenant_id", "tenant-demo") == principal.tenant_id and f.asset_id in scoped_ids]
    return scoped_assets, scoped_findings


def current_principal(request: Request):
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else request.cookies.get("bsa_session", "")
    if not token:
        raise HTTPException(status_code=401, detail="authentication required")
    try:
        return principal_from_token(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="invalid or expired token") from exc


def require(request: Request, permission: str):
    principal = current_principal(request)
    if not can(principal, permission):
        raise HTTPException(status_code=403, detail="permission denied")
    return principal


@app.get("/api/v1/auth/mfa")
def auth_mfa_status(request: Request):
    p=current_principal(request)
    return mfa_status(p)

@app.post("/api/v1/auth/mfa/enroll")
def auth_mfa_enroll(request: Request):
    p=current_principal(request)
    try: return mfa_enroll(p)
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc))
    
class MFAEnableRequest(BaseModel):
    code: str = Field(min_length=6,max_length=6)

@app.post("/api/v1/auth/mfa/enable")
def auth_mfa_enable(request: Request, payload: MFAEnableRequest):
    p=current_principal(request)
    if not rate_limit_action("mfa-enable", p.user_id, limit=5, window_seconds=300):
        raise HTTPException(status_code=429, detail="too many MFA attempts")
    try:
        if not mfa_enable(p,payload.code): raise HTTPException(status_code=400,detail="invalid MFA code")
        audit(p,"enable","mfa")
        return {"enabled":True}
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc))
    
@app.post("/api/v1/auth/login")
def login(payload: LoginRequest, request: Request):
    token = authenticate(payload.email, payload.password, request.client.host if request.client else "", payload.mfa_code)
    if not token:
        raise HTTPException(status_code=401, detail="invalid credentials")
    principal = principal_from_token(token)
    audit(principal, "login", "session")
    response = JSONResponse({"token_type": "bearer", "expires_in": 28800,
                             "user": {"id": principal.user_id, "email": principal.email, "name": principal.name, "role": principal.role, "tenant_id": principal.tenant_id}})
    response.set_cookie("bsa_session", token, httponly=True, secure=os.getenv("BSA_ENV","development").lower() in {"production","prod"}, samesite="strict", max_age=28800, path="/")
    return response


@app.get("/api/v1/auth/me")
def me(request: Request):
    p = current_principal(request)
    tenant=tenant_settings(p)
    return {"id": p.user_id, "email": p.email, "name": p.name, "role": p.role, "tenant_id": p.tenant_id, "tenant_name":tenant["name"], "locale":tenant["locale"]}




class TenantCreateRequest(BaseModel):
    id: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]+$")
    name: str = Field(min_length=1, max_length=120)
    locale: str = Field(default="pt-BR", pattern=r"^(pt-BR|en|es)$")

class TenantLocaleRequest(BaseModel):
    locale: str = Field(pattern=r"^(pt-BR|en|es)$")


class TenantPurgeRequest(BaseModel):
    execute: bool = False
    preserve_audit: bool = True


class ScanGrantCreateRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    authorization_ref: str = Field(min_length=1, max_length=200)
    pattern: str = Field(min_length=1, max_length=253)
    ttl_seconds: int = Field(default=3600, ge=60, le=2592000)






@app.get("/api/v1/scopes")
def scopes(request: Request):
    p=require(request,"users:read")
    return list_scopes(p)

@app.post("/api/v1/scopes")
def scopes_create(request: Request, payload: ScopeCreateRequest):
    p=current_principal(request)
    try:
        result=create_scope(p,payload.name,payload.pattern)
        audit(p,"create","scope",result["id"],{"pattern":payload.pattern})
        return result
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc)) from exc

@app.post("/api/v1/scopes/assign")
def scopes_assign(request: Request, payload: ScopeAssignRequest):
    p=current_principal(request)
    try:
        assign_scope(p,payload.user_id,payload.scope_id)
        audit(p,"assign","scope",payload.scope_id,{"user_id":payload.user_id})
        return {"ok":True}
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc)) from exc


@app.get("/api/v1/scan-scopes")
def scan_scopes(request: Request):
    p=require(request,"users:read")
    return list_scan_scopes(p)

@app.post("/api/v1/scan-scopes")
def scan_scopes_create(request: Request, payload: ScopeCreateRequest):
    p=current_principal(request)
    try:
        result=create_scan_scope(p,payload.name,payload.pattern)
        audit(p,"create","scan_scope",result["id"],{"pattern":payload.pattern})
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc

@app.post("/api/v1/scan-scopes/assign")
def scan_scopes_assign(request: Request, payload: ScopeAssignRequest):
    p=current_principal(request)
    try:
        assign_scan_scope(p,payload.user_id,payload.scope_id)
        audit(p,"assign","scan_scope",payload.scope_id,{"user_id":payload.user_id})
        return {"ok":True}
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc

@app.get("/api/v1/scan-authorizations")
def scan_authorizations(request: Request):
    p=require(request,"users:read")
    try:
        return list_authorization_grants(p)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@app.post("/api/v1/scan-authorizations")
def scan_authorizations_create(request: Request, payload: ScanGrantCreateRequest):
    p=current_principal(request)
    try:
        result=create_authorization_grant(
            p,payload.user_id,payload.authorization_ref,payload.pattern,payload.ttl_seconds
        )
        audit(p,"create","scan_authorization",result["grant_id"],{
            "user_id":payload.user_id,"pattern":payload.pattern,"expires_at":result["expires_at"],
        })
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@app.post("/api/v1/scan-authorizations/{grant_id}/revoke")
def scan_authorizations_revoke(grant_id: str, request: Request):
    p=current_principal(request)
    try:
        result=revoke_authorization_grant(p,grant_id)
        audit(p,"revoke","scan_authorization",grant_id,{})
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404,detail=str(exc)) from exc


@app.get("/api/v1/groups")
def groups(request: Request):
    p=require(request,"users:read")
    return list_groups(p)

@app.post("/api/v1/groups")
def groups_create(request: Request, payload: GroupCreateRequest):
    p=current_principal(request)
    try:
        result=create_group(p,payload.name,payload.pattern)
        audit(p,"create","asset_group",result["id"],{"pattern":payload.pattern})
        return result
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc)) from exc

@app.get("/api/v1/audit")
def audit_events(request: Request, limit: int = 100):
    p = current_principal(request)
    try:
        return list_audit(p, limit)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.get("/api/v1/tenant/settings")
def tenant_settings_get(request: Request):
    p=current_principal(request)
    return tenant_settings(p)

@app.patch("/api/v1/tenant/settings")
def tenant_settings_update(request: Request, payload: TenantLocaleRequest):
    p=current_principal(request)
    try:
        result=update_tenant_locale(p,payload.locale)
        audit(p,"update","tenant_settings",p.tenant_id,{"locale":payload.locale})
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@app.post("/api/v1/tenants/{tenant_id}/retire")
def tenant_retire(tenant_id: str, request: Request):
    principal=current_principal(request)
    try:
        result=retire_tenant(principal,tenant_id)
        audit(principal,"retire","tenant",tenant_id,{})
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@app.post("/api/v1/tenants/{tenant_id}/purge")
def tenant_purge(tenant_id: str, request: Request, payload: TenantPurgeRequest):
    principal=current_principal(request)
    if principal.role!="superadmin":
        raise HTTPException(status_code=403,detail="superadmin required")
    try:
        if not payload.execute:
            return {"dry_run":True,**tenant_purge_preview(tenant_id,preserve_audit=payload.preserve_audit)}
        result=purge_tenant(principal,tenant_id,preserve_audit=payload.preserve_audit)
        audit(principal,"purge","tenant",tenant_id,{"preserve_audit":payload.preserve_audit})
        return {"dry_run":False,**result}
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc

@app.get("/api/v1/tenants")
def tenants(request: Request):
    p = current_principal(request)
    if p.role != "superadmin":
        raise HTTPException(status_code=403, detail="superadmin required")
    return list_tenants(p)


@app.post("/api/v1/tenants")
def tenants_create(request: Request, payload: TenantCreateRequest):
    p = current_principal(request)
    if p.role != "superadmin":
        raise HTTPException(status_code=403, detail="superadmin required")
    try:
        result = create_tenant(p, payload.id, payload.name, payload.locale)
        audit(p, "create", "tenant", payload.id)
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=409, detail="tenant already exists or invalid data") from exc


@app.get("/api/v1/users")
def users(request: Request):
    p = require(request, "users:read")
    try:
        return list_users(p)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/v1/users")
def users_create(request: Request, payload: UserCreateRequest):
    p = current_principal(request)
    if p.role not in {"admin", "superadmin"}:
        raise HTTPException(status_code=403, detail="admin required")
    try:
        result = create_user(p, payload.email, payload.name, payload.password, payload.role)
        audit(p, "create", "user", result["id"], {"role": payload.role})
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=409, detail="user already exists or invalid data") from exc


@app.get("/api/v1/auth/permissions")
def auth_permissions(request: Request):
    p=current_principal(request)
    return {"role":p.role,"permissions":role_permissions(p.role)}

@app.get("/api/v1/rbac/permissions")
def rbac_permissions():
    from .auth import PERMISSION_CATALOG
    return {"permissions": PERMISSION_CATALOG}

class UserScopeRequest(BaseModel):
    scope_id: str = Field(min_length=1, max_length=120)
    active: bool = True

@app.get("/api/v1/users/{user_id}/scopes")
def users_scopes_list(user_id: str, request: Request):
    p=current_principal(request)
    try: return list_user_scopes(p,user_id)
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc))

@app.post("/api/v1/users/{user_id}/scopes")
def users_scopes_set(user_id: str, request: Request, payload: UserScopeRequest):
    p=current_principal(request)
    try:
        result=assign_scope_to_user(p,user_id,payload.scope_id)
        audit(p,"scope_change","user",user_id,result)
        return result
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc))
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))


@app.get("/api/v1/users/{user_id}/scan-scopes")
def users_scan_scopes_list(user_id: str, request: Request):
    p=current_principal(request)
    try:
        return list_user_scan_scopes(p,user_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc))

@app.post("/api/v1/users/{user_id}/scan-scopes")
def users_scan_scopes_set(user_id: str, request: Request, payload: UserScopeRequest):
    p=current_principal(request)
    try:
        result=assign_scan_scope_to_user(p,user_id,payload.scope_id)
        audit(p,"scan_scope_change","user",user_id,result)
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc))

class CustomRoleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    permissions: list[str] = Field(min_length=1, max_length=50)

@app.get("/api/v1/rbac/custom-roles")
def custom_roles_list(request: Request):
    p=current_principal(request)
    try: return list_custom_roles(p)
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc))

@app.post("/api/v1/rbac/custom-roles")
def custom_roles_create(request: Request, payload: CustomRoleRequest):
    p=current_principal(request)
    try:
        result=create_custom_role(p,payload.name,payload.permissions)
        audit(p,"create","custom_role",result["name"],{"permissions":result["permissions"]})
        return result
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc))
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))

class UserUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: str | None = None

class UserActiveRequest(BaseModel):
    active: bool

class UserPasswordResetRequest(BaseModel):
    password: str = Field(min_length=12, max_length=256)

@app.patch("/api/v1/users/{user_id}")
def users_update(user_id: str, request: Request, payload: UserUpdateRequest):
    p=current_principal(request)
    try:
        result=update_user(p,user_id,payload.name,payload.role)
        audit(p,"update","user",user_id,{"role":payload.role} if payload.role else {})
        return result
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc))
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))

@app.patch("/api/v1/users/{user_id}/active")
def users_active(user_id: str, request: Request, payload: UserActiveRequest):
    p=current_principal(request)
    try:
        result=set_user_active(p,user_id,payload.active)
        audit(p,"activate" if payload.active else "deactivate","user",user_id)
        return result
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc))
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))

@app.post("/api/v1/users/{user_id}/reset-password")
def users_reset_password(user_id: str, request: Request, payload: UserPasswordResetRequest):
    p=current_principal(request)
    if not rate_limit_action("password-reset", p.user_id, limit=5, window_seconds=300):
        raise HTTPException(status_code=429, detail="too many password reset attempts")
    try:
        result=reset_user_password(p,user_id,payload.password)
        audit(p,"reset_password","user",user_id)
        return result
    except PermissionError as exc: raise HTTPException(status_code=403,detail=str(exc))
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))

class DiscoveryRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    checks: list[str] = Field(default_factory=lambda: ["dns", "http", "tls", "ct"])
    authorization_ref: str = Field(default="", max_length=200)

class DASTRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    authorization_ref: str = Field(min_length=1, max_length=200)
    profile: str = Field(default="safe", max_length=20)


class AssessmentRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    authorization_ref: str = Field(min_length=1, max_length=200)
    profile: str = Field(default="rapid", pattern="^(surface|rapid|network|balanced)$")


def _materialize_assessment_result(principal, result: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    created_assets = 0
    created_findings = 0
    created_ctem = 0
    regressions_reopened = 0
    ctem_regressions_reopened = 0
    skipped_out_of_scope = 0

    scoped_assets, _ = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    by_value = {a.value.lower(): a for a in scoped_assets}

    for row in result.get("findings", []):
        value = str(row.get("asset") or "").strip()
        if not value:
            continue
        if not asset_in_scope(principal, value):
            skipped_out_of_scope += 1
            continue

        evidence = row.get("evidence") or {}
        validation_required = bool(evidence.get("validation_required")) if isinstance(evidence, dict) else False
        if validation_required or str(row.get("category") or "") == "candidate_discovery":
            continue

        confidence = max(0, min(100, int(row.get("confidence", 50) or 50)))
        if "://" in value:
            kind = AssetType.APPLICATION
        elif value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit():
            kind = AssetType.SERVICE
        else:
            kind = AssetType.SUBDOMAIN if value.count(".") >= 2 else AssetType.DOMAIN
        canonical_value = normalize_asset_value(kind.value, value) or value.lower()
        asset = by_value.get(canonical_value)

        if asset is None:
            digest = sha256(f"{principal.tenant_id}|{kind.value}|{canonical_value}".encode()).hexdigest()[:16]
            asset = Asset(
                tenant_id=principal.tenant_id,
                id=f"ast-{digest}",
                value=canonical_value,
                type=kind,
                status="observed",
                confidence=confidence,
                criticality=3,
                source="assessment-intelligence",
                tags=["assessment-observed"],
                first_seen=now,
                last_seen=now,
                fingerprint=f"fp-{digest}",
                evidence_count=1,
                sources=["assessment-intelligence"],
            )
            STORE_ASSETS.append(asset)
            by_value[canonical_value] = asset
            created_assets += 1
        else:
            asset.last_seen = now
            asset.confidence = max(asset.confidence, confidence)
            asset.evidence_count += 1
            if "assessment-intelligence" not in asset.sources:
                asset.sources.append("assessment-intelligence")

        try:
            severity = Severity(str(row.get("severity") or "info").lower())
        except ValueError:
            severity = Severity.INFO

        vuln_ctx = normalize_vulnerability_evidence(row)
        vulnerability_id = vuln_ctx["vulnerability_id"]
        cvss = vuln_ctx["cvss"]
        cpe = vuln_ctx["cpe"]

        title = str(row.get("title") or "Exposure evidence")
        finding_key = vulnerability_identity_key(row, canonical_value)
        finding_identity = f"{principal.tenant_id}|{asset.id}|{repr(finding_key)}"
        finding_digest = sha256(finding_identity.encode()).hexdigest()[:16]
        finding_id = f"fdg-{finding_digest}"
        finding = next((x for x in STORE_FINDINGS if x.tenant_id == principal.tenant_id and x.id == finding_id), None)
        regression_reopened = False

        if finding is None:
            finding = Finding(
                tenant_id=principal.tenant_id,
                id=finding_id,
                asset_id=asset.id,
                title=title,
                severity=severity,
                confidence=confidence,
                status="open",
                evidence="Evidence confirmed by assessment intelligence.",
                remediation="Review the exposure and validate remediation.",
                vulnerability_id=vulnerability_id,
                cpe=cpe,
                cvss=cvss,
                detected_at=now,
                source_refs=vuln_ctx["references"],
                false_positive_confidence=vuln_ctx["false_positive_confidence"],
                validation_state=vuln_ctx["validation_state"],
                evidence_quality=vuln_ctx["evidence_quality"],
                affected_component=vuln_ctx["affected_component"],
                affected_components=[vuln_ctx["affected_component"]] if vuln_ctx["affected_component"] else [],
            )
            if finding.vulnerability_id:
                finding = enrich_finding(finding)
            STORE_FINDINGS.append(finding)
            created_findings += 1
        else:
            if finding.status in {"resolved", "verified", "closed", "remediated"}:
                finding.status = "open"
                finding.detected_at = now
                finding.evidence = "Exposure re-observed after remediation; regression requires retest."
                regressions_reopened += 1
                regression_reopened = True
            finding.confidence = max(finding.confidence, confidence)
            severity_rank = {
                Severity.INFO: 0,
                Severity.LOW: 1,
                Severity.MEDIUM: 2,
                Severity.HIGH: 3,
                Severity.CRITICAL: 4,
            }
            if severity_rank.get(severity, 0) > severity_rank.get(finding.severity, 0):
                finding.severity = severity
            if vulnerability_id and not finding.vulnerability_id:
                finding.vulnerability_id = vulnerability_id
            if cpe and not finding.cpe:
                finding.cpe = cpe
            if cvss is not None and finding.cvss is None:
                finding.cvss = cvss
            finding.false_positive_confidence = min(
                finding.false_positive_confidence or 100,
                vuln_ctx["false_positive_confidence"],
            )
            if vuln_ctx["evidence_quality"] >= finding.evidence_quality:
                finding.validation_state = vuln_ctx["validation_state"]
                finding.evidence_quality = vuln_ctx["evidence_quality"]
            if vuln_ctx["references"]:
                finding.source_refs = sorted(set(finding.source_refs + vuln_ctx["references"]))[:20]
            if vuln_ctx["affected_component"]:
                finding.affected_component = vuln_ctx["affected_component"]
                if vuln_ctx["affected_component"] not in finding.affected_components:
                    finding.affected_components.append(vuln_ctx["affected_component"])
                finding.affected_components = finding.affected_components[:50]
            if finding.vulnerability_id:
                enriched = enrich_finding(finding)
                finding.cvss = enriched.cvss
                finding.epss = enriched.epss
                finding.kev = enriched.kev
                finding.cpe = enriched.cpe
                finding.published_at = enriched.published_at

        ctem_item_id = f"assessment:{principal.tenant_id}:{finding.id}"
        if regression_reopened:
            regression_refs = list(finding.source_refs) or [
                f"assessment:{result.get('assessment_id') or finding.id}"
            ]
            try:
                reopened = reopen_ctem_item(
                    ctem_item_id,
                    principal.tenant_id,
                    regression_refs,
                    notes="assessment evidence re-observed after verified remediation",
                )
                if reopened.get("reopened"):
                    ctem_regressions_reopened += 1
            except KeyError:
                pass
            audit(
                principal,
                "reopen",
                "finding_regression",
                finding.id,
                {"asset_id": asset.id, "evidence_refs": regression_refs[:20]},
            )

        priority_data = assess_ctem_priority(finding, asset)
        priority = int(priority_data["priority"])
        if priority >= 45:
            upsert_ctem_item({
                "item_id": ctem_item_id,
                "asset_id": asset.id,
                "finding_id": finding.id,
                "priority": priority,
                "action": priority_data["action"],
                "title": "Exposure requiring remediation attention",
                "drivers": priority_data["drivers"],
                "evidence_refs": list(finding.source_refs),
            }, principal.tenant_id)
            created_ctem += 1

    persist_state(STORE_ASSETS, STORE_FINDINGS)
    return {
        "assets_created": created_assets,
        "findings_created": created_findings,
        "ctem_items": created_ctem,
        "regressions_reopened": regressions_reopened,
        "ctem_regressions_reopened": ctem_regressions_reopened,
        "skipped_out_of_scope": skipped_out_of_scope,
    }

@app.get("/api/v1/exposure/assessment/capabilities")
def exposure_assessment_capabilities(request: Request, target: str | None = None):
    principal = require(request, "assets:read")
    if target and not asset_in_scope(principal, target):
        raise HTTPException(status_code=403, detail="target outside assigned scope")
    return {
        "bundle": os.getenv("BSA_ENGINE_BUNDLE", "core"),
        "capabilities": registry.capability_health(target),
    }


@app.post("/api/v1/exposure/assessment")
def exposure_assessment(payload: AssessmentRequest, request: Request):
    principal = require(request, "discovery:run")
    if not asset_in_scope(principal, payload.target):
        raise HTTPException(status_code=403, detail="target outside assigned scope")
    if not rate_limit_action("exposure-assessment", principal.user_id, limit=8, window_seconds=300):
        raise HTTPException(status_code=429, detail="assessment rate limit exceeded")

    if IS_PRODUCTION:
        if not authorization_grant_valid(principal,payload.authorization_ref,payload.target):
            raise HTTPException(status_code=403,detail="authorization_ref is expired, revoked, or not valid for target")
        job=enqueue_assessment(principal,payload.target,payload.profile,payload.authorization_ref)
        audit(
            principal,"queue","exposure_assessment",payload.target,
            {"profile":payload.profile,"authorization_ref":payload.authorization_ref,"job_id":job["job_id"]},
        )
        return JSONResponse(
            status_code=202,
            content={
                "job_id":job["job_id"],
                "status":job["status"],
                "target":job["target"],
                "profile":job["profile"],
            },
        )

    try:
        result = run_public_assessment(
            payload.target,
            profile=payload.profile,
            authorize=lambda target: asset_in_scope(principal, target),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        principal,
        "run",
        "exposure_assessment",
        payload.target,
        {
            "profile": payload.profile,
            "authorization_ref": payload.authorization_ref,
            "finding_count": result.get("finding_count", 0),
            "partial_coverage": result.get("partial_coverage", False),
        },
    )
    result["materialization"] = _materialize_assessment_result(principal, result)
    return result


@app.post("/api/v1/exposure/assessment/jobs/{job_id}/cancel")
def exposure_assessment_job_cancel(job_id: str, request: Request):
    principal=require(request,"discovery:run")
    job=cancel_job(job_id,principal.tenant_id)
    if not job:
        raise HTTPException(status_code=404,detail="assessment job not found")
    if job["status"]!="cancelled":
        raise HTTPException(status_code=409,detail="assessment job can no longer be cancelled")
    audit(principal,"cancel","exposure_assessment",job["target"],{"job_id":job_id})
    return {"job_id":job_id,"status":"cancelled"}


@app.get("/api/v1/exposure/assessment/jobs/{job_id}")
def exposure_assessment_job(job_id: str, request: Request):
    principal=require(request,"discovery:run")
    job=get_job(job_id,principal.tenant_id)
    if not job:
        raise HTTPException(status_code=404,detail="assessment job not found")
    result=job.get("result")
    if job["status"]=="succeeded" and result is not None and not job.get("materialized"):
        if claim_materialization(job_id,principal.tenant_id):
            job_principal=Principal(
                user_id=job["user_id"],
                tenant_id=job["tenant_id"],
                email=job["email"],
                role=job["role"],
                name=job["name"],
            )
            try:
                result["materialization"]=_materialize_assessment_result(job_principal,result)
                finish_materialization(job_id,principal.tenant_id,True)
                audit(
                    job_principal,"complete","exposure_assessment",job["target"],
                    {
                        "profile":job["profile"],
                        "authorization_ref":job["authorization_ref"],
                        "job_id":job_id,
                        "finding_count":result.get("finding_count",0),
                        "partial_coverage":result.get("partial_coverage",False),
                    },
                )
                job["materialized"]=True
            except Exception:
                finish_materialization(job_id,principal.tenant_id,False)
                raise
        else:
            job=get_job(job_id,principal.tenant_id) or job
    return {
        "job_id":job["job_id"],
        "status":job["status"],
        "target":job["target"],
        "profile":job["profile"],
        "created_at":job["created_at"],
        "started_at":job.get("started_at"),
        "completed_at":job.get("completed_at"),
        "error":job.get("error"),
        "materialized":bool(job.get("materialized")),
        "result":result,
    }






@app.get("/api/v1/assets/{asset_id}/dna")
def asset_dna(asset_id: str, request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    asset = next((a for a in assets if a.id == asset_id), None)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")
    dna = build_exposure_dna(asset, findings)
    return asdict(dna)


@app.get("/api/v1/radar")
def exposure_radar(request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    rows = []
    for asset in assets:
        dna = build_exposure_dna(asset, findings)
        rows.append({
            "asset_id": asset.id,
            "value": asset.value,
            "type": asset.type.value,
            "owner": asset.owner,
            "environment": asset.environment,
            "confidence": asset.confidence,
            "criticality": asset.criticality,
            "dna": dna.fingerprint,
            "change_type": dna.change_type,
            "signals": dna.signals,
        })
    return {"assets": sorted(rows, key=lambda x: (x["change_type"] != "material-change", -x["criticality"], -x["confidence"]))}


@app.get("/api/v1/assets/{asset_id}/timeline")
def asset_timeline(asset_id: str, request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    asset = next((a for a in assets if a.id == asset_id), None)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")
    return {
        "asset_id": asset.id,
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
        "change_summary": change_summary(asset.fingerprint, principal.tenant_id),
        "history": [h.__dict__ for h in history_for(asset.fingerprint,principal.tenant_id)],
    }



@app.post("/api/v1/digital-risk/infrastructure/analyze")
def digital_risk_infrastructure(payload: InfrastructureIndicator, request: Request):
    principal=require(request,"assets:read")
    result=build_infrastructure_links(payload)
    ai=analyze_infrastructure_cluster(payload.indicator,result["links"])
    if ai:
        result["ai_analysis"]=ai
    event=upsert_event(principal.tenant_id,{
        "category":"infrastructure_cluster","title":f"Infrastructure correlation for {payload.indicator}",
        "indicator":payload.indicator,"source":payload.source,"severity":"medium" if result["cluster_strength"]>=60 else "low",
        "confidence":result["cluster_strength"],"evidence":result,"status":"open"})
    result["event_id"]=event["event_id"]
    return result

@app.post("/api/v1/digital-risk/brand/analyze")
def digital_risk_brand_analyze(payload: BrandAnalysis, request: Request):
    principal=require(request,"assets:read")
    result=analyze_brand_impersonation(principal.tenant_id,payload)
    ai=analyze_brand_context(payload.brand,payload.indicator,result["evidence"])
    if ai:
        result["ai_analysis"]=ai
    if result["verdict"]=="likely_impersonation":
        event=upsert_event(principal.tenant_id,{
            "category":"brand_abuse","title":f"Possible {payload.brand} impersonation",
            "indicator":payload.indicator,"source":"bsa_brand_engine","severity":"high" if result["score"]>=85 else "medium",
            "confidence":result["score"],"evidence":result["evidence"],"status":"open","brand":payload.brand})
        result["event_id"]=event["event_id"]
    return result

@app.get("/api/v1/digital-risk")
def digital_risk(request: Request, category: str|None=None):
    principal=require(request,"assets:read")
    events=list_events(principal.tenant_id,category)
    by={}
    for e in events: by[e["category"]]=by.get(e["category"],0)+1
    return {"events":events,"summary":{"total":len(events),"by_category":by,"critical":sum(1 for e in events if e.get("severity")=="critical"),
        "open":sum(1 for e in events if e.get("status")=="open"),"takedown_candidates":sum(1 for e in events if e.get("category") in {"phishing","brand_abuse","fake_profile","fake_app","malware"} and e.get("status")=="open")}}

@app.post("/api/v1/digital-risk/events")
def digital_risk_ingest(payload: DigitalRiskEvent, request: Request):
    principal=require(request,"assets:write")
    item=upsert_event(principal.tenant_id,payload.model_dump())
    audit(principal,"create","digital_risk",item["event_id"],{"category":item["category"],"source":item["source"]})
    return item

@app.get("/api/v1/digital-risk/takedowns")
def digital_risk_takedowns(request: Request):
    principal=require(request,"assets:read")
    return {"items":list_takedowns(principal.tenant_id)}

@app.post("/api/v1/digital-risk/takedowns")
def digital_risk_takedown(payload: TakedownRequest, request: Request):
    principal=require(request,"assets:write")
    events=list_events(principal.tenant_id)
    if not any(e["event_id"]==payload.event_id for e in events):
        raise HTTPException(status_code=404,detail="digital risk event not found")
    item=create_takedown(principal.tenant_id,payload.event_id,payload.provider,payload.reason,payload.priority)
    audit(principal,"create","takedown",item["takedown_id"],{"event_id":payload.event_id,"provider":item["provider"]})
    return item

@app.get("/api/v1/exposure/storyline")
def exposure_storyline(request: Request, limit: int = 50):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    events = []
    for asset in assets:
        dna = build_exposure_dna(asset, findings)
        if dna.change_type != "stable":
            events.append({"asset_id": asset.id, "asset": asset.value, "timestamp": asset.last_seen,
                           "event": dna.change_type, "signals": dna.signals,
                           "confidence": dna.confidence, "explainability": dna.explainability})
    return {"events": sorted(events, key=lambda x: x["timestamp"], reverse=True)[:max(1, min(limit, 500))]}

@app.get("/api/v1/exposure/copilot")
def exposure_copilot(request: Request, question: str):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    q = question.lower()
    if "owner" in q or "respons" in q:
        rows = [a for a in assets if not a.owner]
        fallback = "Ativos sem owner informado."
    elif "mudou" in q or "change" in q or "novo" in q:
        rows = [a for a in assets if build_exposure_dna(a, findings).change_type != "stable"]
        fallback = "Ativos com sinais materiais de mudança."
    else:
        rows = sorted(assets, key=lambda a: exposure_breakdown(a, findings).score, reverse=True)[:10]
        fallback = "Ativos ordenados por exposição contextual."
    evidence=[{"asset_id":a.id,"asset":a.value,"type":getattr(a.type,"value",a.type),"confidence":a.confidence,
               "owner":a.owner,"exposure_score":exposure_breakdown(a,findings).score,
               "signals":build_exposure_dna(a,findings).signals} for a in rows]
    ai=analyze_exposure(question,evidence)
    return {"answer":ai or fallback,"ai":{"enabled":local_ai_enabled(),"provider":"ollama-local","model":OLLAMA_MODEL if local_ai_enabled() else None,"grounded":bool(ai),"fallback":not bool(ai)},"evidence":evidence}

@app.get("/api/v1/exposure/ai/status")
def exposure_ai_status(request: Request):
    require(request, "assets:read")
    return {"enabled":local_ai_enabled(),"provider":"ollama-local","model":OLLAMA_MODEL if local_ai_enabled() else None,"privacy":"local-server","internet_required":False}


@app.get("/api/v1/exposure/ctem/plans")
def exposure_ctem_plans(request: Request):
    principal = require(request, "assets:read")
    return {"items": list_plans(principal.tenant_id)}

class CTEMStatusRequest(BaseModel):
    status: str = Field(pattern="^(planned|approved|in_progress|remediated|retest|closed)$")

@app.patch("/api/v1/exposure/ctem/plans/{plan_id}")
def update_ctem_plan(plan_id: str, payload: CTEMStatusRequest, request: Request):
    principal = require(request, "assets:read")
    item = get_plan(principal.tenant_id, plan_id)
    if item:
        item["status"] = payload.status
        item["updated_at"] = datetime.now(timezone.utc).isoformat()
        upsert_plan(principal.tenant_id, item)
        audit(principal, "update", "ctem.plan", plan_id, {"status": payload.status})
        return item
    raise HTTPException(status_code=404, detail="CTEM plan not found")

@app.get("/api/v1/exposure/ctem")
def exposure_ctem(request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    queue = []
    for asset in assets:
        af = [f for f in findings if f.asset_id == asset.id and f.status == "open"]
        score = exposure_breakdown(asset, findings).score
        dna = build_exposure_dna(asset, findings)
        if score >= 60 or af:
            queue.append({
                "asset_id": asset.id, "asset": asset.value,
                "priority_score": score, "criticality": asset.criticality,
                "owner": asset.owner, "finding_count": len(af),
                "dna": dna.fingerprint, "signals": dna.signals,
                "stage": "prioritize" if af else "validate",
                "next_action": "validate-exposure" if not af else "mobilize-remediation",
            })
    return {"items": sorted(queue, key=lambda x: x["priority_score"], reverse=True)}

@app.post("/api/v1/exposure/ctem/plan")
def exposure_ctem_plan(payload: dict, request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    asset_ids = set(payload.get("asset_ids", []))
    finding_ids = set(payload.get("finding_ids", []))
    selected = [a for a in assets if a.id in asset_ids]
    selected_findings = [f for f in findings if f.id in finding_ids or f.asset_id in asset_ids]
    items = list_plans(principal.tenant_id)
    created = []
    now = datetime.now(timezone.utc).isoformat()
    for a in selected:
        af = [f for f in selected_findings if f.asset_id == a.id and f.status == "open"]
        score = exposure_breakdown(a, findings).score
        for f in af or [None]:
            plan_id = f"ctp-{principal.tenant_id[:8]}-{a.id}-{f.id if f else 'asset'}"
            existing = next((x for x in items if x["plan_id"] == plan_id), None)
            if existing:
                created.append(existing)
                continue
            plan = build_remediation_plan(f, a) if f else None
            item = {"plan_id": plan_id, "asset_id": a.id, "asset": a.value, "owner": (plan.owner if plan else a.owner),
                    "priority_score": score, "finding_ids": [f.id] if f else [], "status": "planned",
                    "current_score": plan.current_score if plan else score, "residual_score": plan.residual_score if plan else score,
                    "risk_reduction": plan.risk_reduction if plan else 0, "action": plan.action if plan else "validar exposição e ownership",
                    "validation": plan.validation if plan else "reexecutar discovery e confirmar evidência", "effort": plan.effort if plan else "médio",
                    "created_at": now, "updated_at": now, "reason": "Selected from Exposure/Attack Path Planner"}
            upsert_plan(principal.tenant_id, item); items.append(item); created.append(item)
    audit(principal, "create", "ctem.plan", None, {"count": len(created)})
    return {"items": created, "count": len(created)}

@app.get("/api/v1/exposure/business-impact")
def exposure_business_impact(request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    rows=[]
    for a in assets:
        score=exposure_breakdown(a,findings).score
        rows.append({"asset_id":a.id,"asset":a.value,"business_unit":a.business_unit,
                     "environment":a.environment,"criticality":a.criticality,
                     "exposure":score,"owner":a.owner or "unowned",
                     "impact_index":round(score*(1+a.criticality/5),1)})
    return {"items":sorted(rows,key=lambda x:x["impact_index"],reverse=True)}

@app.get("/api/v1/exposure/reduction")
def exposure_reduction(request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    current = sum(exposure_breakdown(a, findings).score for a in assets)
    open_findings = sum(1 for f in findings if f.status == "open")
    internet_assets = sum(1 for a in assets if "internet-facing" in a.tags)
    unmanaged = sum(1 for a in assets if ownership_confidence(a).state == "candidate")
    return {
        "assets": len(assets),
        "open_findings": open_findings,
        "internet_facing_assets": internet_assets,
        "unmanaged_or_unconfirmed_assets": unmanaged,
        "aggregate_exposure": round(current / len(assets)) if assets else 0,
        "risk_reduction_model": "baseline-vs-current",
        "note": "A redução real é calculada quando snapshots históricos comparáveis estiverem disponíveis.",
    }


@app.get("/api/v1/attack-paths")
def attack_paths(request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    graph = build_risk_graph(
        "tenant-surface",
        assets,
        [],
        source_assets=assets,
        findings=findings,
    )
    return {
        "paths": graph["top_risk_paths"],
        "summary": graph["risk_summary"],
    }


@app.get("/api/v1/score")
def score(request: Request):
    principal = require(request, "assets:read")
    assets, findings = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    result = exposure_score(findings, assets)
    breakdowns = []
    for asset in assets:
        item = exposure_breakdown(asset, findings)
        breakdowns.append({
            "asset_id": asset.id,
            "asset": asset.value,
            "score": item.score,
            "band": exposure_band(item.score),
            "rationale": item.rationale,
            "dimensions": {
                "internet": item.internet,
                "exploitability": item.exploitability,
                "criticality": item.criticality,
                "intelligence": item.intelligence,
                "confidence": item.confidence,
                "shadow": item.shadow,
            },
        })
    return {
        "score": result.score,
        "penalty": result.penalty,
        "rationale": result.rationale,
        "assets": breakdowns,
    }


@app.post("/api/v1/dast/nuclei")
def dast_nuclei(payload: DASTRequest, request: Request):
    principal=require(request, "discovery:run")
    if not payload.authorization_ref.strip():
        raise HTTPException(status_code=400, detail="authorization_ref is required")
    if payload.profile not in {"safe", "standard"}:
        raise HTTPException(status_code=400, detail="unsupported DAST profile")
    if not asset_in_scope(principal, payload.target):
        raise HTTPException(status_code=403, detail="target outside assigned scope")
    govern_active_scan(request,principal,payload.target,payload.authorization_ref)
    try:
        scan = run_nuclei(payload.target, profile=payload.profile)
        scan["bsa_findings"] = normalize_findings(scan, asset_id=f"unresolved:{urlparse(payload.target).hostname}")
        return scan
    except NucleiEngineError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@app.post("/api/v1/dast/safe-web")
def dast_safe_web(payload: DASTRequest, request: Request):
    principal=require(request, "discovery:run")
    if not payload.authorization_ref.strip():
        raise HTTPException(status_code=400, detail="authorization_ref is required")
    if not asset_in_scope(principal, payload.target):
        raise HTTPException(status_code=403, detail="target outside assigned scope")
    govern_active_scan(request,principal,payload.target,payload.authorization_ref)
    try:
        return run_safe_web_assessment(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/discovery")
def discovery(request: DiscoveryRequest, http_request: Request):
    principal=require(http_request, "discovery:run")
    if not asset_in_scope(principal, request.target):
        raise HTTPException(status_code=403, detail="target outside assigned scope")
    govern_active_scan(http_request,principal,request.target,request.authorization_ref)
    allowed = {"dns", "http", "tls", "ct"}
    checks = list(dict.fromkeys(request.checks))
    if not checks or any(check not in allowed for check in checks):
        raise HTTPException(status_code=400, detail="checks deve conter apenas dns, http, tls e ct")
    try:
        return collect_target(request.target, checks)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/discovery/{target}/changes")
def discovery_changes(target: str, request: Request):
    principal = require(request, "discovery:run")
    if not asset_in_scope(principal, target):
        raise HTTPException(status_code=403, detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    record_observations(assets, principal.tenant_id)
    return {
        "target": data["target"],
        "changes": [
            {
                "fingerprint": asset.fingerprint,
                "asset": asset.value,
                "type": asset.asset_type,
                "change": change_summary(asset.fingerprint, principal.tenant_id),
            }
            for asset in assets
        ],
    }


@app.get("/api/v1/discovery/{target}/graph")
def discovery_graph(target: str, request: Request):
    principal = require(request, "discovery:run")
    if not asset_in_scope(principal, target):
        raise HTTPException(status_code=403, detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    return build_risk_graph(data["target"], assets, data["evidence"], source_assets=ASSETS, findings=FINDINGS)

@app.get("/api/v1/discovery/{target}/correlation")
def discovery_correlation(target: str, request: Request):
    principal = require(request, "discovery:run")
    if not asset_in_scope(principal, target):
        raise HTTPException(status_code=403, detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    """Return normalized asset identities for an explicit discovery target."""
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    observations = record_observations(assets, principal.tenant_id)
    return {
        "target": data["target"],
        "evidence_count": data["evidence_count"],
        "confidence": data["confidence"],
        "assets": [
            {
                "fingerprint": asset.fingerprint,
                "value": asset.value,
                "type": asset.asset_type,
                "confidence": asset.confidence,
                "sources": list(asset.sources),
                "evidence_count": asset.evidence_count,
                "tags": list(asset.tags),
                "evidence_refs": list(asset.evidence_refs),
                "independent_source_count": len(asset.sources),
                "identity_quality": (
                    "corroborated" if len(asset.sources) >= 2 and asset.evidence_count >= 2
                    else "single-source" if len(asset.sources) == 1
                    else "unverified"
                ),
                "history": change_summary(asset.fingerprint, principal.tenant_id),
            }
            for asset in assets
        ],
        "observation_count": len(observations),
    }


@app.get("/api/v1/easm/discover/{target}")
def easm_discover(target: str, request: Request, max_depth: int = 2, max_assets: int = 40):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    if max_depth < 0 or max_depth > 3 or max_assets < 1 or max_assets > 100:
        raise HTTPException(status_code=400,detail="invalid discovery bounds")
    result=discover_surface(target,max_depth=max_depth,max_assets=max_assets,scope_validator=lambda candidate: asset_in_scope(principal,candidate))
    return result

@app.get("/api/v1/easm/lifecycle/{target}")
def easm_lifecycle(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct"])
    assets=correlate_evidence(data["target"],data["evidence"])
    lifecycle=record_lifecycle(assets,data["evidence"],principal.tenant_id)
    changed=[x for x in lifecycle if x["state"]=="changed"]
    new=[x for x in lifecycle if x["state"]=="new"]
    return {
        "target":data["target"],"observed_at":datetime.now(timezone.utc).isoformat(),
        "summary":{"assets":len(lifecycle),"new":len(new),"changed":len(changed),"stable":len(lifecycle)-len(new)-len(changed),
                   "evidence":data["evidence_count"],"confidence":data["confidence"]},
        "assets":lifecycle,
    }

@app.get("/api/v1/easm/lifecycle/{target}/{fingerprint}")
def easm_asset_lifecycle(target: str, fingerprint: str, request: Request):
    principal=require(request,"assets:read")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    return lifecycle_for(fingerprint,principal.tenant_id)

@app.get("/api/v1/easm/overview")
def easm_overview(request: Request):
    principal=require(request,"assets:read")
    scoped_assets,scoped_findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    def state(a):
        if a.status in {"approved","owned","managed"}: return "approved"
        if a.status in {"dependency","third_party"}: return "dependency"
        if a.status in {"monitor","monitor_only"}: return "monitor_only"
        if a.status in {"requires_investigation","investigate"}: return "requires_investigation"
        return "candidate"
    inventory=[{"id":a.id,"value":a.value,"type":a.type.value,"state":state(a),"confidence":a.confidence,"criticality":a.criticality,
               "first_seen":a.first_seen,"last_seen":a.last_seen,"sources":a.sources,"evidence_count":a.evidence_count,
               "owner":a.owner,"environment":a.environment,"cloud_provider":a.cloud_provider} for a in scoped_assets]
    by_state={}
    by_type={}
    for x in inventory:
        by_state[x["state"]]=by_state.get(x["state"],0)+1
        by_type[x["type"]]=by_type.get(x["type"],0)+1
    exposed=[x for x in inventory if x["type"] in {"service","application","ip","domain","subdomain"}]
    return {"summary":{"total_assets":len(inventory),"exposed_assets":len(exposed),"approved":by_state.get("approved",0),
        "candidates":by_state.get("candidate",0),"requires_investigation":by_state.get("requires_investigation",0),
        "dependencies":by_state.get("dependency",0),"monitor_only":by_state.get("monitor_only",0),
        "by_type":by_type,"by_state":by_state},
        "inventory":inventory,"changes":{"recent":sum(1 for a in scoped_assets if a.status=="observed"),
        "unowned":sum(1 for a in scoped_assets if not a.owner),"low_confidence":sum(1 for a in scoped_assets if a.confidence<70)},
        "risk":{"critical_findings":sum(1 for f in scoped_findings if f.status=="open" and f.severity.value=="critical"),
        "high_findings":sum(1 for f in scoped_findings if f.status=="open" and f.severity.value=="high")}}

@app.get("/api/v1/exposure")
def exposure(request: Request):
    principal = require(request, "assets:read")
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    items = []
    for asset in ASSETS:
        item = exposure_breakdown(asset, FINDINGS)
        items.append({
            "asset_id": asset.id,
            "asset": asset.value,
            "score": item.score,
            "band": exposure_band(item.score),
            "rationale": item.rationale,
            "dimensions": {
                "internet": item.internet,
                "exploitability": item.exploitability,
                "criticality": item.criticality,
                "intelligence": item.intelligence,
                "confidence": item.confidence,
                "shadow": item.shadow,
            },
        })
    return sorted(items, key=lambda x: x["score"], reverse=True)


@app.get("/api/v1/reports/summary")
def report_summary(request: Request):
    """Return only the curated fields required by the tenant report UI."""
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    open_findings=[f for f in findings if f.status=="open"]
    ownership=[ownership_confidence(a) for a in assets]
    score=exposure_score(findings,assets)

    def state(a):
        if a.status in {"approved","owned","managed"}: return "approved"
        if a.status in {"dependency","third_party"}: return "dependency"
        if a.status in {"monitor","monitor_only"}: return "monitor_only"
        if a.status in {"requires_investigation","investigate"}: return "requires_investigation"
        return "candidate"

    exposure_rows=[{
        "id":a.id,"value":a.value,"type":a.type.value,"state":state(a),
        "confidence":a.confidence,"evidence_count":a.evidence_count
    } for a in assets[:40]]

    amap={a.id:a for a in assets}
    vuln_rows=[]
    for f in open_findings:
        intel=vulnerability_intelligence(f,amap.get(f.asset_id))
        vuln_rows.append({
            "id":f.id,
            "vulnerability":f.vulnerability_id or f.title,
            "asset":amap.get(f.asset_id).value if amap.get(f.asset_id) else None,
            "priority":intel.priority_score,
            "exploitability":intel.exploitability,
            "impact":intel.business_impact,
            "confidence":intel.confidence,
            "band":intel.band,
            "data_quality_gap":bool(intel.data_quality),
        })
    vuln_rows.sort(key=lambda x:x["priority"],reverse=True)

    states=[state(a) for a in assets]
    return {
        "executive":{
            "total_assets":len(assets),
            "exposed_services":sum(1 for a in assets if a.type.value=="service"),
            "open_findings":len(open_findings),
            "critical_findings":sum(1 for f in open_findings if f.severity.value=="critical"),
            "exposure_score":score.score,
            "approved":sum(x=="approved" for x in states),
            "candidates":sum(x=="candidate" for x in states),
            "unowned":sum(1 for a in assets if not a.owner),
            "low_confidence":sum(1 for a in assets if a.confidence<70),
            "confirmed_assets":sum(1 for o in ownership if o.state=="confirmed"),
        },
        "exposure":{"summary":{"total_assets":len(assets),"exposed_assets":sum(1 for a in assets if a.type.value in {"service","application","ip","domain","subdomain"}),"approved":sum(x=="approved" for x in states),"candidates":sum(x=="candidate" for x in states)},"items":exposure_rows},
        "vulnerabilities":{"summary":{"findings":len(vuln_rows),"critical":sum(x["band"]=="critical" for x in vuln_rows),"high":sum(x["band"]=="high" for x in vuln_rows),"data_quality_gaps":sum(x["data_quality_gap"] for x in vuln_rows)},"items":vuln_rows[:40]},
    }

@app.get("/api/v1/dashboard", response_model=Dashboard)
def dashboard(request: Request):
    principal = require(request, "assets:read")
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    changes = seed_changes(ASSETS)
    ownership = [ownership_confidence(a) for a in ASSETS]
    score = exposure_score(FINDINGS, ASSETS)

    return Dashboard(
        total_assets=len(ASSETS),
        exposed_services=sum(1 for a in ASSETS if a.type.value == "service"),
        open_findings=sum(1 for f in FINDINGS if f.status == "open"),
        critical_findings=sum(1 for f in FINDINGS if f.status == "open" and f.severity.value == "critical"),
        exposure_score=score.score,
        confirmed_assets=sum(1 for o in ownership if o.state == "confirmed"),
        candidate_assets=sum(1 for o in ownership if o.state == "candidate"),
        changes_24h=len(changes),
        attack_paths=len(RELATIONSHIPS),
    )

@app.get("/api/v1/discovery/{target}/infrastructure/graph")
def discovery_infrastructure_graph(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct"])
    item=InfrastructureIndicator(indicator=data["target"],source="bsa_discovery",confidence=data["confidence"])
    for e in data["evidence"]:
        kind=e.get("kind",""); value=e.get("value")
        if kind=="a_record" and not item.ip: item.ip=value
        elif kind=="certificate_name" and value and value!=data["target"]: item.related_domains.append(value)
    graph=build_infrastructure_graph(item)
    graph["discovery"]={"target":data["target"],"evidence_count":data["evidence_count"],"confidence":data["confidence"]}
    return graph

@app.get("/api/v1/discovery/{target}/infrastructure")
def discovery_infrastructure(target: str, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    data=collect_target(target,["dns","http","tls","ct"])
    item=InfrastructureIndicator(indicator=data["target"],source="bsa_discovery",confidence=data["confidence"])
    for e in data["evidence"]:
        kind=e.get("kind",""); value=e.get("value")
        if kind=="a_record" and not item.ip: item.ip=value
        elif kind=="certificate_cn" and not item.certificate_sha256: item.certificate_sha256=value
        elif kind=="certificate_name" and value and value!=data["target"]: item.related_domains.append(value)
        elif kind=="http_header:server": item.registrar=value
    result=build_infrastructure_links(item)
    result["discovery"]={"target":data["target"],"evidence_count":data["evidence_count"],"confidence":data["confidence"]}
    result["evidence"]=data["evidence"]
    return result

@app.get("/api/v1/discovery/{target}/risk-paths")
def discovery_risk_paths(target: str, request: Request):
    principal = require(request, "discovery:run")
    if not asset_in_scope(principal, target):
        raise HTTPException(status_code=403, detail="target outside assigned scope")
    govern_active_scan(request,principal,target)
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    data = collect_target(target, ["dns", "http", "tls", "ct"])
    assets = correlate_evidence(data["target"], data["evidence"])
    graph = build_risk_graph(data["target"], assets, data["evidence"], source_assets=ASSETS, findings=FINDINGS)
    return {
        "target": data["target"],
        "paths": graph["top_risk_paths"],
        "summary": graph["risk_summary"],
    }


@app.get("/api/v1/ctem/operations")
def ctem_operations(request: Request):
    principal=require(request,"findings:read")
    items=list_ctem_items(principal.tenant_id)
    summary=ctem_operational_summary(items)
    summary["remediation_coverage"]=ctem_remediation_coverage(items)
    summary["queue"]=ctem_queue_view(items)
    return {"summary":summary,"items":items}

@app.get("/api/v1/ctem/{item_id}/audit")
def ctem_audit(item_id: str, request: Request):
    principal=require(request,"findings:read")
    items=list_ctem_items(principal.tenant_id)
    item=next((x for x in items if x.get("item_id")==item_id),None)
    if item is None:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    verifications=ctem_verification_history(item_id,principal.tenant_id)
    timeline=ctem_audit_timeline(item,verifications)
    return {"item_id":item_id,"outcome":ctem_audit_outcome(item,verifications),"timeline":timeline}

@app.get("/api/v1/ctem/{item_id}/audit/export")
def ctem_audit_export(item_id: str, request: Request):
    principal=require(request,"findings:read")
    items=list_ctem_items(principal.tenant_id)
    item=next((x for x in items if x.get("item_id")==item_id),None)
    if item is None:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    verifications=ctem_verification_history(item_id,principal.tenant_id)
    timeline=ctem_audit_timeline(item,verifications)
    integrity=ctem_audit_integrity(item,verifications)
    outcome=ctem_audit_outcome(item,verifications)
    diffs=[]
    for current in timeline[1:]:
        if current.get("event")=="verification":
            diffs.append({"event":"verification","timestamp":current.get("timestamp"),
                          "result":current.get("result"),
                          "diff":ctem_audit_diff(timeline[0],current)})
    return {"format":"ctem-audit-v1","tenant_id":principal.tenant_id,
            "item_id":item_id,"generated_at":datetime.now(timezone.utc).isoformat(),
            "integrity":integrity,"outcome":outcome,"timeline":timeline,"diffs":diffs}

@app.get("/api/v1/ctem/queue")
def ctem_queue_page_api(request: Request, state: str | None = None, bucket: str | None = None,
                        min_leverage: int | None = None, page: int = 1, page_size: int = 50):
    principal=require(request,"findings:read")
    items=list_ctem_items(principal.tenant_id)
    filtered=ctem_queue_filter(items,state=state,bucket=bucket,min_leverage=min_leverage)
    result=ctem_queue_page(filtered,page=page,page_size=page_size)
    result["items"]=[{**item,"next_action":ctem_next_action(item)} for item in result["items"]]
    return result

@app.get("/api/v1/ctem")
def ctem_queue(request: Request, state: str | None = None):
    principal=require(request,"findings:read")
    states={state} if state else None
    return {"items":list_ctem_items(principal.tenant_id,states)}

@app.post("/api/v1/ctem/{item_id}/retest")
def ctem_retest(item_id: str, request: Request, payload: dict):
    principal=require(request,"remediation:write")
    item=next(
        (x for x in list_ctem_items(principal.tenant_id) if x.get("item_id")==item_id),
        None,
    )
    if item is None:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    if item.get("state") not in {"in_progress","resolved"}:
        raise HTTPException(status_code=400,detail="CTEM item is not ready for retest")

    asset_id=str(item.get("asset_id") or "")
    assets,_=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    asset=next((x for x in assets if x.id==asset_id),None)
    if asset is None:
        raise HTTPException(status_code=404,detail="CTEM asset not found")

    profile=str(payload.get("profile") or "rapid")
    if profile not in {"rapid","network","balanced"}:
        raise HTTPException(status_code=400,detail="invalid retest profile")
    authorization_ref=govern_active_scan(
        request,
        principal,
        asset.value,
        str(payload.get("authorization_ref") or ""),
    )
    job=enqueue_assessment(
        principal,
        asset.value,
        profile,
        authorization_ref or "development-retest",
    )
    audit(
        principal,
        "queue",
        "ctem_retest",
        item_id,
        {
            "job_id":job["job_id"],
            "asset_id":asset.id,
            "profile":profile,
            "authorization_ref":authorization_ref or "development",
        },
    )
    return JSONResponse(
        status_code=202,
        content={
            "item_id":item_id,
            "job_id":job["job_id"],
            "status":job["status"],
            "profile":job["profile"],
            "verification_required":True,
        },
    )


@app.post("/api/v1/ctem/{item_id}/verify")
def ctem_verify(item_id: str, request: Request, payload: dict):
    principal=require(request,"remediation:write")
    try:
        result=verify_ctem_item(
            item_id, principal.tenant_id,
            str(payload.get("result","")),
            list(payload.get("evidence_refs") or []),
            str(payload.get("notes","")),
        )
        audit(principal,"ctem_verification","ctem",item_id,{"result":str(payload.get("result","")),"evidence_count":len(list(payload.get("evidence_refs") or []))})
        return result

    except KeyError:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc))

@app.post("/api/v1/ctem/{item_id}/state")
def ctem_state(item_id: str, request: Request, payload: dict):
    principal=require(request,"remediation:write")
    new_state=str(payload.get("state",""))
    request_id=str(payload.get("request_id") or request.headers.get("Idempotency-Key") or "")
    items=list_ctem_items(principal.tenant_id)
    item=next((x for x in items if x.get("item_id")==item_id),None)
    if item is None:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    transitions={"acknowledged":"acknowledge","in_progress":"start_remediation",
                 "resolved":"submit_for_verification","verified":"verify"}
    action=transitions.get(new_state)
    if not action:
        raise HTTPException(status_code=400,detail="invalid CTEM target state")
    try:
        target=ctem_action_transition(item,action)
        operation_key=ctem_action_idempotency_key(item_id,action,request_id)
        if not ctem_claim_operation(principal.tenant_id,operation_key,action,item_id):
            previous=ctem_operation_result(principal.tenant_id,operation_key)
            return previous or {"status":"already_processed","operation_key":operation_key}
        result=update_ctem_state(item_id,principal.tenant_id,target)
        audit(principal,"ctem_state_transition","ctem",item_id,{"action":action,"from":item.get("state"),"to":target})
        ctem_store_operation_result(principal.tenant_id,operation_key,result)
        return result
    except KeyError:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc))

@app.get("/api/v1/prioritization")
def prioritization(request: Request):
    principal = require(request, "findings:read")
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    asset_map = {a.id: a for a in ASSETS}
    result = []
    for finding in FINDINGS:
        asset = asset_map.get(finding.asset_id)
        item = prioritize_finding(finding, asset)
        result.append({
            "finding_id": finding.id,
            "finding": finding.title,
            "asset": asset.value if asset else None,
            "priority": item.priority,
            "score": item.score,
            "impact": item.impact,
            "urgency": item.urgency,
            "confidence": item.confidence,
            "reasons": item.reasons,
            "recommended_action": item.action,
        })
    return sorted(result, key=lambda x: (-x["score"], x["priority"]))


@app.get("/api/v1/remediation")
def remediation(request: Request):
    principal = require(request, "remediation:write")
    ASSETS, FINDINGS = tenant_scope(principal, STORE_ASSETS, STORE_FINDINGS)
    asset_map = {a.id: a for a in ASSETS}
    result = []
    for finding in FINDINGS:
        asset = asset_map.get(finding.asset_id)
        if not asset or finding.status != "open":
            continue
        plan = build_remediation_plan(finding, asset)
        result.append({
            "finding_id": plan.finding_id,
            "asset_id": plan.asset_id,
            "asset": asset.value,
            "priority": plan.priority,
            "current_score": plan.current_score,
            "residual_score": plan.residual_score,
            "risk_reduction": plan.risk_reduction,
            "action": plan.action,
            "validation": plan.validation,
            "owner": plan.owner,
            "effort": plan.effort,
            "rationale": plan.rationale,
        })
    return sorted(result, key=lambda x: (-x["risk_reduction"], x["residual_score"]))
