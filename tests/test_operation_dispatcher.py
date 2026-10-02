import pytest

from app.application.services import operation_dispatcher


def test_dispatcher_routes_migrated_discovery_operation(monkeypatch):
    calls=[]
    monkeypatch.setattr(
        operation_dispatcher,
        "supports_discovery_operation",
        lambda operation: operation=="discovery.basic",
    )
    monkeypatch.setattr(
        operation_dispatcher,
        "run_discovery_operation",
        lambda operation,target,payload,principal: calls.append(("new",operation,target,payload)) or {"source":"new"},
    )
    result=operation_dispatcher.run_operation("discovery.basic","example.com",{"checks":["dns"]},object())

    assert result=={"source":"new"}
    assert calls==[("new","discovery.basic","example.com",{"checks":["dns"]})]


def test_dispatcher_rejects_unknown_operation(monkeypatch):
    monkeypatch.setattr(operation_dispatcher,"supports_assessment_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_intelligence_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_technology_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_easm_operation",lambda operation: False)

    with pytest.raises(ValueError,match="unsupported active operation"):
        operation_dispatcher.run_operation("legacy.operation","example.com",{},object())


def test_dispatcher_routes_discovery_intelligence_operation(monkeypatch):
    calls=[]
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_operation",lambda operation: False)
    monkeypatch.setattr(
        operation_dispatcher,
        "supports_discovery_intelligence_operation",
        lambda operation: operation=="discovery.correlation",
    )
    monkeypatch.setattr(
        operation_dispatcher,
        "run_discovery_intelligence_operation",
        lambda operation,target,payload,principal: calls.append(("intel",operation,target)) or {"source":"intel"},
    )
    result=operation_dispatcher.run_operation("discovery.correlation","example.com",{},object())

    assert result=={"source":"intel"}
    assert calls==[("intel","discovery.correlation","example.com")]


def test_dispatcher_routes_assessment_operation(monkeypatch):
    calls=[]
    monkeypatch.setattr(operation_dispatcher,"supports_assessment_operation",lambda operation: operation=="dast.safe_web")
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_intelligence_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_technology_operation",lambda operation: False)
    monkeypatch.setattr(
        operation_dispatcher,
        "run_assessment_operation",
        lambda operation,target,payload,principal: calls.append(("assessment",operation,target)) or {"source":"assessment"},
    )
    result=operation_dispatcher.run_operation("dast.safe_web","https://example.com",{},object())
    assert result=={"source":"assessment"}
    assert calls==[("assessment","dast.safe_web","https://example.com")]


def test_dispatcher_routes_technology_operation(monkeypatch):
    calls=[]
    monkeypatch.setattr(operation_dispatcher,"supports_assessment_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_intelligence_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_technology_operation",lambda operation: operation=="technology.intelligence")
    monkeypatch.setattr(
        operation_dispatcher,
        "run_technology_operation",
        lambda operation,target,payload,principal: calls.append(("technology",operation,target)) or {"source":"technology"},
    )
    result=operation_dispatcher.run_operation("technology.intelligence","example.com",{},object())
    assert result=={"source":"technology"}
    assert calls==[("technology","technology.intelligence","example.com")]


def test_dispatcher_routes_easm_operation(monkeypatch):
    calls=[]
    monkeypatch.setattr(operation_dispatcher,"supports_assessment_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_intelligence_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_technology_operation",lambda operation: False)
    monkeypatch.setattr(operation_dispatcher,"supports_easm_operation",lambda operation: operation=="discovery.graph")
    monkeypatch.setattr(
        operation_dispatcher,
        "run_easm_operation",
        lambda operation,target,payload,principal: calls.append(("easm",operation,target)) or {"source":"easm"},
    )

    result=operation_dispatcher.run_operation("discovery.graph","example.com",{},object())

    assert result=={"source":"easm"}
    assert calls==[("easm","discovery.graph","example.com")]
