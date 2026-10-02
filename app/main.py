import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .auth import bootstrap
from .metrics import record_http_metric
from .observability import log_http_event, monotonic_ms, request_id_from_header
from .scope import bootstrap_scope
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
