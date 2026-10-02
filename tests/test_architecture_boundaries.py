from app.architecture import BOUNDED_CONTEXTS, LAYERS


def test_modular_architecture_declares_expected_layers():
    assert LAYERS==("api","application","domain","repositories","infrastructure")
    assert {"identity","discovery","risk","ctem","digital_risk","integrations","operations"} <= set(BOUNDED_CONTEXTS)


def test_main_routes_policy_use_cases_through_application_layer():
    from pathlib import Path
    source=Path("app/main.py").read_text()
    assert "from .application.services.policy_service import" in source
    assert "from .policy_service import" not in source
