from app.assessment_orchestrator import _provider_failure_scope, _record_capability_call
from app.history import provider_reliability, record_provider_execution


def test_provider_telemetry_separates_target_and_engine_failures():
    telemetry = {}

    _record_capability_call(
        {},
        "httpx",
        elapsed_ms=0,
        error=True,
        provider_error_scope=_provider_failure_scope(TimeoutError("target timed out")),
        provider_telemetry=telemetry,
    )

    row = telemetry["httpx"]
    assert row["calls"] == 1
    assert row["target_errors"] == 1
    assert row["engine_errors"] == 0
    assert row["errors"] == 0

    _record_capability_call(
        {},
        "httpx",
        elapsed_ms=0,
        error=True,
        provider_error_scope=_provider_failure_scope(RuntimeError("adapter crashed")),
        provider_telemetry=telemetry,
    )

    row = telemetry["httpx"]
    assert row["calls"] == 2
    assert row["target_errors"] == 1
    assert row["engine_errors"] == 1
    assert row["errors"] == 1


def test_target_failures_do_not_poison_global_provider_reliability(monkeypatch, tmp_path):
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "history.db"))

    record_provider_execution(
        {
            "httpx": {
                "calls": 3,
                "errors": 0,
                "engine_errors": 0,
                "target_errors": 3,
            }
        }
    )

    reliability = provider_reliability(("httpx",), min_calls=3)["httpx"]
    assert reliability["status"] == "stable"
    assert reliability["success_rate_percent"] == 100
    assert reliability["consecutive_failures"] == 0
