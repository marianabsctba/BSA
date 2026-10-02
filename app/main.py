from datetime import datetime, timezone
from dataclasses import asdict
from fastapi.responses import JSONResponse, Response
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from urllib.parse import urlparse
import os
import ipaddress
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
from .history import record_observations, list_ctem_items, update_ctem_state, upsert_ctem_item, verify_ctem_item, reopen_ctem_item, ctem_leverage_summary, ctem_operational_summary, ctem_remediation_coverage, ctem_verification_history, ctem_transition_history, record_ctem_transition, record_ctem_retest, ctem_retest_for_job, complete_ctem_retest, ctem_audit_timeline, ctem_audit_integrity, ctem_audit_diff, ctem_audit_outcome, ctem_queue_view, ctem_queue_filter, ctem_queue_page, ctem_next_action, ctem_action_transition, ctem_action_idempotency_key, ctem_claim_operation, ctem_operation_result, ctem_store_operation_result, change_summary, history_for, record_lifecycle, lifecycle_for, recent_change_events
from .prioritization import prioritize_finding
from .remediation import build_remediation_plan
from .auth import authenticate, rate_limit_action, bootstrap, can, role_permissions, list_custom_roles, create_custom_role, create_user, list_users, update_user, set_user_active, reset_user_password, change_own_password, principal_from_token, create_tenant, list_tenants, tenant_settings, update_tenant_locale, audit, list_audit, verify_audit_chain, revoke_session, mfa_status, mfa_enroll, mfa_enable, mfa_disable, issue_mfa_recovery_codes, generate_mfa_recovery_codes, tenant_mfa_policy, set_tenant_mfa_policy, TOKEN_TTL
from .ctem_store import list_plans, get_plan, upsert_plan, history
from .ctem_retest import reconcile_ctem_retest_job
from .discovery_orchestrator import plan_candidate_collection
from .scope import bootstrap_scope, asset_in_scope, active_scan_in_scope, create_scope, list_scopes, assign_scope, create_scan_scope, list_scan_scopes, assign_scan_scope, create_group, list_groups, list_user_scopes, list_user_scan_scopes, assign_scope_to_user, assign_scan_scope_to_user, create_domain_ownership_proof, verify_domain_ownership_proof, create_ip_ownership_approval
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
from .tenant_risk_policy import policy_for, serialize_policy
from .tenant_sla_policy import sla_policy_for, serialize_sla_policy, sla_threshold_hours
from .application.services.ctem_service import build_ctem_operations, build_ctem_queue_page, list_ctem_queue
from .digital_risk import DigitalRiskEvent, BrandAnalysis, InfrastructureIndicator, LeakSignal, analyze_brand_impersonation, analyze_leak_signal, build_infrastructure_links, build_infrastructure_graph, upsert_event, list_events, summarize_events
from .exposure_signals import cloud_signals, takeover_signals, summarize_signals
from .ip_intelligence import ip_exposure_signal
from .dast import run_safe_web_assessment
from .nuclei_engine import NucleiEngineError, run_nuclei, normalize_findings
from .assessment_orchestrator import run_public_assessment
from .engine_health import public_engine_health
from .release_readiness import release_readiness
from .assessment_registry import registry
from .job_queue import enqueue_assessment, enqueue_operation, get_job, cancel_job, claim_materialization, finish_materialization, queue_metrics, queue_health, worker_health
from .auth import Principal
from .tenant_lifecycle import retire_tenant, tenant_purge_preview, purge_tenant
from .scan_authorization import create_authorization_grant, list_authorization_grants, revoke_authorization_grant, authorization_grant_valid
from .retention import get_retention_policy, set_retention_policy, retention_preview, apply_retention
from .integration_export import siem_events, unified_siem_events, audit_siem_events
from .syslog_export import config_from_env, send_event, send_events
from .observability import request_id_from_header, identity_from_request, log_http_event, monotonic_ms
from .runtime_health import runtime_health
from .metrics import record_http_metric, prometheus_metrics, operational_alerts
from .version import __version__
from .api.routers.risk import router as risk_router
from .api.routers.vulnerabilities import router as vulnerabilities_router
from .api.routers.ctem import router as ctem_router
from .api.routers.integrations import router as integrations_router
from .api.routers.admin import router as admin_router
from .api.routers.auth import router as auth_router
from .api.routers.operations import router as operations_router
from .api.routers.scopes import router as scopes_router
from .api.routers.governance import router as governance_router
from .api.routers.digital_risk import router as digital_risk_router
from .api.routers.mssp import router as mssp_router
from .api.routers.reporting import router as reporting_router
from .api.routers.assets import router as assets_router
from .api.routers.remediation import router as remediation_router
from .api.routers.discovery_intelligence import router as discovery_intelligence_router
from .api.routers.graph_assessment import router as graph_assessment_router
from .api.routers.exposure import router as exposure_router
from .api.routers.discovery_execution import router as discovery_execution_router
from .api.active_scan import govern_active_scan

bootstrap()
bootstrap_scope()

IS_PRODUCTION=os.getenv("BSA_ENV","development").lower() in {"production","prod"}

app = FastAPI(
    title="BSA — Be Safe ASM API",
    version=__version__,
    description="Attack Surface Management defensivo, rastreável e orientado a evidências.",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)


app.include_router(risk_router)
app.include_router(vulnerabilities_router)
app.include_router(ctem_router)
app.include_router(integrations_router)
app.include_router(admin_router)
app.include_router(auth_router)
app.include_router(operations_router)
app.include_router(scopes_router)
app.include_router(governance_router)
app.include_router(digital_risk_router)
app.include_router(mssp_router)
app.include_router(reporting_router)
app.include_router(assets_router)
app.include_router(remediation_router)
app.include_router(discovery_intelligence_router)
app.include_router(graph_assessment_router)
app.include_router(exposure_router)
app.include_router(discovery_execution_router)

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
async def request_observability(request: Request, call_next):
    request_id=request_id_from_header(request.headers.get("X-Request-ID"))
    request.state.request_id=request_id
    request.state.authenticated_principal=None
    started=monotonic_ms()
    status_code=500
    try:
        response=await call_next(request)
        status_code=response.status_code
        return response
    finally:
        duration_ms=max(0,monotonic_ms()-started)
        route_obj=request.scope.get("route")
        route_path=getattr(route_obj,"path",None) or request.url.path
        principal=getattr(request.state,"authenticated_principal",None)
        log_http_event(
            request_id=request_id,
            method=request.method,
            path=route_path,
            status_code=status_code,
            duration_ms=duration_ms,
            tenant_id=getattr(principal,"tenant_id",None),
            user_id=getattr(principal,"user_id",None),
        )
        record_http_metric(request.method,route_path,status_code,duration_ms)
        if "response" in locals():
            response.headers["X-Request-ID"]=request_id

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


def _client_ip(request: Request) -> str:
    peer=(request.client.host if request.client else "") or "unknown"
    if os.getenv("BSA_TRUST_PROXY_HEADERS","0") != "1":
        return peer
    try:
        peer_ip=ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not (peer_ip.is_private or peer_ip.is_loopback):
        return peer
    forwarded=(request.headers.get("X-Real-IP") or "").strip()
    try:
        return str(ipaddress.ip_address(forwarded)) if forwarded else peer
    except ValueError:
        return peer
