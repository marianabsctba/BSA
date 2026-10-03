import json

from fastapi.testclient import TestClient

from app import observability, runtime_health
from app.main import app
from app.api.routers import operations as operations_router


def test_request_id_validation_and_generation():
    assert observability.request_id_from_header("req-12345678")=="req-12345678"
    generated=observability.request_id_from_header("bad request id with spaces")
    assert generated!="bad request id with spaces"
    assert len(generated)>=16


def test_structured_http_event_contains_safe_context(monkeypatch):
    captured=[]
    monkeypatch.setattr(observability.logger,"info",lambda message: captured.append(message))
    event=observability.log_http_event(
        request_id="req-12345678",
        method="GET",
        path="/api/v1/assets",
        status_code=200,
        duration_ms=12.34,
        tenant_id="tenant-a",
        user_id="user-a",
    )
    parsed=json.loads(captured[0])
    assert parsed==event
    assert parsed["tenant_id"]=="tenant-a"
    assert parsed["user_id"]=="user-a"
    serialized=captured[0].lower()
    assert "authorization" not in serialized
    assert "cookie" not in serialized
    assert "password" not in serialized


def test_runtime_health_degrades_when_required_component_fails(monkeypatch):
    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setattr(runtime_health.auth,"DB_PATH","/does/not/exist/auth.db")
    monkeypatch.setattr(runtime_health,"_store_path",lambda:"/does/not/exist/store.db")
    monkeypatch.setattr(runtime_health,"queue_health",lambda:{
        "status":"unavailable","queued":0,"running":0,
    })
    monkeypatch.setattr(runtime_health,"worker_health",lambda:{
        "status":"unknown","active_workers":0,
    })
    monkeypatch.setattr(runtime_health,"privileged_mfa_readiness",lambda:{"status":"healthy"})
    data=runtime_health.runtime_health()
    assert data["status"]=="degraded"
    assert data["components"]["auth_db"]["status"]=="unavailable"
    assert data["components"]["queue"]["status"]=="unavailable"


def test_health_response_has_request_id_header(monkeypatch):
    monkeypatch.setattr(operations_router,"runtime_health",lambda:{
        "status":"healthy",
        "components":{
            "auth_db":{"status":"healthy"},
            "asset_store":{"status":"healthy"},
            "queue":{"status":"healthy","queued":0,"running":0},
            "workers":{"status":"healthy","active_workers":1},
        },
    })
    client=TestClient(app)
    response=client.get("/health",headers={"X-Request-ID":"req-health-1234"})
    assert response.status_code==200
    assert response.headers["X-Request-ID"]=="req-health-1234"
    assert response.json()=={"status":"ok"}


def test_ready_returns_503_with_component_detail_when_degraded(monkeypatch):
    monkeypatch.setattr(operations_router,"runtime_health",lambda:{
        "status":"degraded",
        "components":{
            "auth_db":{"status":"unavailable"},
            "asset_store":{"status":"healthy"},
            "queue":{"status":"healthy","queued":0,"running":0},
            "workers":{"status":"healthy","active_workers":1},
        },
    })
    client=TestClient(app)
    response=client.get("/ready")
    assert response.status_code==503
    assert response.json()["status"]=="degraded"
    assert response.json()["components"]["auth_db"]["status"]=="unavailable"


def test_observability_identity_is_not_taken_from_unvalidated_token(monkeypatch):
    captured=[]
    monkeypatch.setattr("app.main.log_http_event",lambda **kwargs: captured.append(kwargs))
    client=TestClient(app)
    response=client.get(
        "/health",
        headers={"Authorization":"Bearer invalid-but-shaped-token"},
    )
    assert response.status_code==200
    assert captured[-1]["tenant_id"] is None
    assert captured[-1]["user_id"] is None


def test_runtime_health_checks_postgres_when_repository_backend_is_postgres(monkeypatch):
    import psycopg

    class Cursor:
        def __enter__(self): return self
        def __exit__(self,*args): return False
        def execute(self,sql): assert sql=="SELECT 1"
        def fetchone(self): return (1,)

    class Connection:
        def __enter__(self): return self
        def __exit__(self,*args): return False
        def cursor(self): return Cursor()

    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setenv("BSA_ASSET_REPOSITORY_BACKEND","postgres")
    monkeypatch.setenv("BSA_DATABASE_URL","postgresql://safe-redacted/db")
    monkeypatch.setattr(psycopg,"connect",lambda dsn,connect_timeout=2: Connection())
    monkeypatch.setattr(runtime_health.auth,"DB_PATH","/data/auth.db")
    monkeypatch.setattr(runtime_health,"_sqlite_readable",lambda path: {"status":"healthy"})
    monkeypatch.setattr(runtime_health,"queue_health",lambda: {"status":"healthy","queued":0,"running":0})
    monkeypatch.setattr(runtime_health,"worker_health",lambda: {"status":"healthy","active_workers":1})
    monkeypatch.setattr(runtime_health,"privileged_mfa_readiness",lambda:{"status":"healthy"})

    data=runtime_health.runtime_health()

    assert data["status"]=="healthy"
    assert data["components"]["asset_store"]=={
        "status":"healthy",
        "backend":"postgres",
    }
