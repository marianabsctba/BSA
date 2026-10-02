from app.architecture import BOUNDED_CONTEXTS, LAYERS


def test_modular_architecture_declares_expected_layers():
    assert LAYERS==("api","application","domain","repositories","infrastructure")
    assert {"identity","discovery","risk","ctem","digital_risk","integrations","operations"} <= set(BOUNDED_CONTEXTS)


def test_main_routes_policy_use_cases_through_application_layer():
    from pathlib import Path
    source=Path("app/main.py").read_text()
    assert "from .application.services.policy_service import" in source
    assert "from .policy_service import" not in source


def test_application_layer_does_not_import_infrastructure():
    from pathlib import Path

    offenders=[]
    for path in Path("app/application").rglob("*.py"):
        source=path.read_text(encoding="utf-8")
        if "infrastructure" in source:
            offenders.append(str(path))
    assert offenders==[], f"application layer imports infrastructure: {offenders}"


def test_worker_composes_operation_executor_from_infrastructure():
    from pathlib import Path

    source=Path("app/worker.py").read_text(encoding="utf-8")
    assert "from .infrastructure.workers.operation_dispatcher import run_operation" in source
    assert "application.services.operation_dispatcher" not in source
