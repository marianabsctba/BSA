from app.architecture import BOUNDED_CONTEXTS, LAYERS


def test_modular_architecture_declares_expected_layers():
    assert LAYERS==("api","application","domain","repositories","infrastructure")
    assert {"identity","discovery","risk","ctem","digital_risk","integrations","operations"} <= set(BOUNDED_CONTEXTS)


def test_risk_router_routes_policy_use_cases_through_application_layer():
    from pathlib import Path

    source=Path("app/api/routers/risk.py").read_text(encoding="utf-8")
    assert "from ...application.services.policy_service import" in source
    assert "from ...policy_service import" not in source


def test_application_layer_does_not_import_infrastructure():
    import ast
    from pathlib import Path

    offenders=[]
    for path in Path("app/application").rglob("*.py"):
        tree=ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                modules=[alias.name for alias in node.names]
            elif isinstance(node,ast.ImportFrom):
                modules=[node.module or ""]
            else:
                continue
            if any("infrastructure" in module.split(".") for module in modules):
                offenders.append(str(path))
                break
    assert offenders==[], f"application layer imports infrastructure: {offenders}"


def test_worker_composes_operation_executor_from_infrastructure():
    from pathlib import Path

    source=Path("app/worker.py").read_text(encoding="utf-8")
    assert "from .infrastructure.workers.operation_dispatcher import run_operation" in source
    assert "application.services.operation_dispatcher" not in source


def test_risk_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/risk.py").read_text(encoding="utf-8")
    assert "app.include_router(risk_router)" in main_source
    assert '@app.get("/api/v1/risk/policy")' not in main_source
    assert '@app.get("/api/v1/risk/register")' not in main_source
    assert '@router.get("/api/v1/risk/policy")' in router_source
    assert '@router.get("/api/v1/risk/register")' in router_source


def test_vulnerability_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/vulnerabilities.py").read_text(encoding="utf-8")
    assert "app.include_router(vulnerabilities_router)" in main_source
    assert '@app.get("/api/v1/vulnerabilities/intelligence")' not in main_source
    assert '@app.get("/api/v1/findings")' not in main_source
    assert '@router.get("/api/v1/vulnerabilities/intelligence")' in router_source
    assert '@router.get("/api/v1/findings")' in router_source


def test_ctem_read_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/ctem.py").read_text(encoding="utf-8")
    assert "app.include_router(ctem_router)" in main_source
    assert '@app.get("/api/v1/ctem/operations")' not in main_source
    assert '@app.get("/api/v1/ctem/queue")' not in main_source
    assert '@router.get("/api/v1/ctem/operations")' in router_source
    assert '@router.get("/api/v1/ctem/queue")' in router_source


def test_ctem_mutation_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/ctem.py").read_text(encoding="utf-8")
    assert '@app.post("/api/v1/ctem/{item_id}/verify")' not in main_source
    assert '@app.post("/api/v1/ctem/{item_id}/state")' not in main_source
    assert '@router.post("/api/v1/ctem/{item_id}/verify")' in router_source
    assert '@router.post("/api/v1/ctem/{item_id}/state")' in router_source


def test_ctem_retest_route_lives_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/ctem.py").read_text(encoding="utf-8")
    assert '@app.post("/api/v1/ctem/{item_id}/retest")' not in main_source
    assert '@router.post("/api/v1/ctem/{item_id}/retest")' in router_source


def test_siem_integration_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/integrations.py").read_text(encoding="utf-8")
    assert "app.include_router(integrations_router)" in main_source
    assert '@app.get("/api/v1/integrations/siem/export")' not in main_source
    assert '@app.get("/api/v1/integrations/siem/status")' not in main_source
    assert '@app.post("/api/v1/integrations/siem/syslog/test")' not in main_source
    assert '@app.post("/api/v1/integrations/siem/syslog/push")' not in main_source
    assert '@router.get("/api/v1/integrations/siem/export")' in router_source


def test_admin_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/admin.py").read_text(encoding="utf-8")
    assert "app.include_router(admin_router)" in main_source
    for route in (
        "/api/v1/tenants",
        "/api/v1/users",
        "/api/v1/rbac/custom-roles",
        "/api/v1/users/{user_id}/scopes",
        "/api/v1/users/{user_id}/scan-scopes",
    ):
        assert f'@app.get("{route}")' not in main_source
        assert f'@app.post("{route}")' not in main_source
    assert '@router.get("/api/v1/users")' in router_source
    assert '@router.post("/api/v1/tenants")' in router_source


def test_auth_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/auth.py").read_text(encoding="utf-8")
    assert "app.include_router(auth_router)" in main_source
    for route in (
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/auth/permissions",
        "/api/v1/auth/mfa",
        "/api/v1/auth/mfa/enroll",
        "/api/v1/auth/mfa/enable",
        "/api/v1/auth/mfa/recovery-codes",
        "/api/v1/auth/mfa/disable",
    ):
        assert f'@app.get("{route}")' not in main_source
        assert f'@app.post("{route}")' not in main_source
    assert '@router.post("/api/v1/auth/login")' in router_source
    assert '@router.get("/api/v1/auth/me")' in router_source


def test_operations_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/operations.py").read_text(encoding="utf-8")
    assert "app.include_router(operations_router)" in main_source
    for route in (
        "/health",
        "/ready",
        "/metrics",
        "/api/v1/operations/jobs/{job_id}",
        "/api/v1/operations/alerts",
        "/api/v1/operations/assessment-queue",
        "/api/v1/operations/release-readiness",
    ):
        assert f'@app.get("{route}")' not in main_source
    assert '@router.get("/ready")' in router_source
    assert '@router.get("/api/v1/operations/release-readiness")' in router_source


def test_scope_authorization_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/scopes.py").read_text(encoding="utf-8")
    assert "app.include_router(scopes_router)" in main_source
    for route in (
        "/api/v1/scopes",
        "/api/v1/scopes/assign",
        "/api/v1/scan-scopes",
        "/api/v1/scan-scopes/assign",
        "/api/v1/domain-ownership/proofs",
        "/api/v1/ip-ownership/approvals",
        "/api/v1/scan-authorizations",
    ):
        assert f'@app.get("{route}")' not in main_source
        assert f'@app.post("{route}")' not in main_source
    assert '@router.post("/api/v1/ip-ownership/approvals")' in router_source
    assert '@router.post("/api/v1/scan-authorizations")' in router_source


def test_tenant_governance_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/governance.py").read_text(encoding="utf-8")
    assert "app.include_router(governance_router)" in main_source
    for route in (
        "/api/v1/groups",
        "/api/v1/audit",
        "/api/v1/audit/integrity",
        "/api/v1/audit/export",
        "/api/v1/audit/syslog/push",
        "/api/v1/tenant/retention",
        "/api/v1/tenant/retention/apply",
        "/api/v1/tenant/settings",
    ):
        assert f'@app.get("{route}")' not in main_source
        assert f'@app.post("{route}")' not in main_source
        assert f'@app.patch("{route}")' not in main_source
    assert '@router.get("/api/v1/audit/integrity")' in router_source
    assert '@router.patch("/api/v1/tenant/settings")' in router_source


def test_digital_risk_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/digital_risk.py").read_text(encoding="utf-8")
    assert "app.include_router(digital_risk_router)" in main_source
    for route in (
        "/api/v1/digital-risk",
        "/api/v1/digital-risk/events",
        "/api/v1/digital-risk/leaks",
        "/api/v1/digital-risk/brand/analyze",
        "/api/v1/digital-risk/infrastructure/analyze",
    ):
        assert f'@app.get("{route}")' not in main_source
        assert f'@app.post("{route}")' not in main_source
    assert '@router.get("/api/v1/digital-risk")' in router_source
    assert '@router.post("/api/v1/digital-risk/leaks")' in router_source


def test_mssp_routes_live_outside_main():
    from pathlib import Path

    main_source=Path("app/main.py").read_text(encoding="utf-8")
    router_source=Path("app/api/routers/mssp.py").read_text(encoding="utf-8")
    assert "app.include_router(mssp_router)" in main_source
    assert '@app.get("/api/v1/mssp/command-center")' not in main_source
    assert '@app.get("/api/v1/mssp/command-center/trend")' not in main_source
    assert '@router.get("/api/v1/mssp/command-center")' in router_source
    assert '@router.get("/api/v1/mssp/command-center/trend")' in router_source
