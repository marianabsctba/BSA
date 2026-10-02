from fastapi.testclient import TestClient

from app import metrics
from app.main import app


def test_prometheus_export_contains_http_and_queue_metrics(monkeypatch):
    metrics.record_http_metric("GET","/api/v1/assets",200,42.5)
    monkeypatch.setattr(metrics,"queue_health",lambda tenant_id=None:{
        "status":"healthy","queued":2,"running":1,"oldest_queued_age_seconds":15,
        "expired_running_leases":0,
    })
    monkeypatch.setattr(metrics,"queue_metrics",lambda tenant_id:{
        "total_jobs":5,"retries":1,"success_rate_percent":80,
        "average_execution_seconds":3.5,
    })
    monkeypatch.setattr(metrics,"worker_health",lambda:{
        "status":"healthy","active_workers":2,"stale_workers":0,
    })

    text=metrics.prometheus_metrics("tenant-a")
    assert "bsa_http_requests_total" in text
    assert 'route="/api/v1/assets"' in text
    assert "bsa_queue_queued_jobs 2" in text
    assert "bsa_queue_retries_total 1" in text
    assert "bsa_worker_active 2" in text


def test_operational_alerts_detect_worker_backlog(monkeypatch):
    monkeypatch.setattr(metrics,"queue_health",lambda tenant_id=None:{
        "status":"warn","queued":4,"running":0,"oldest_queued_age_seconds":1200,
        "expired_running_leases":0,
    })
    monkeypatch.setattr(metrics,"queue_metrics",lambda tenant_id:{
        "total_jobs":10,"success_rate_percent":70,
    })
    monkeypatch.setattr(metrics,"worker_health",lambda:{
        "status":"degraded","active_workers":0,"stale_workers":1,
    })

    data=metrics.operational_alerts("tenant-a")
    codes={x["code"] for x in data["alerts"]}
    assert data["status"]=="alerting"
    assert "queue_backlog_age" in codes
    assert "no_active_worker_with_backlog" in codes
    assert "stale_worker" in codes
    assert "queue_success_rate_low" in codes


def test_metrics_endpoint_requires_auth():
    client=TestClient(app)
    response=client.get("/metrics")
    assert response.status_code==401
