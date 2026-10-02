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
