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
    monkeypatch.setattr(
        operation_dispatcher,
        "run_legacy_operation",
        lambda operation,target,payload,principal: calls.append(("legacy",operation,target,payload)) or {"source":"legacy"},
    )

    result=operation_dispatcher.run_operation("discovery.basic","example.com",{"checks":["dns"]},object())

    assert result=={"source":"new"}
    assert calls==[("new","discovery.basic","example.com",{"checks":["dns"]})]


def test_dispatcher_keeps_legacy_fallback(monkeypatch):
    calls=[]
    monkeypatch.setattr(operation_dispatcher,"supports_discovery_operation",lambda operation: False)
    monkeypatch.setattr(
        operation_dispatcher,
        "run_legacy_operation",
        lambda operation,target,payload,principal: calls.append(operation) or {"source":"legacy"},
    )

    result=operation_dispatcher.run_operation("discovery.graph","example.com",{},object())

    assert result=={"source":"legacy"}
    assert calls==["discovery.graph"]
