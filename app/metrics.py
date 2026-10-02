import math
import threading
from collections import defaultdict

from .job_queue import queue_health, queue_metrics, worker_health

_LOCK=threading.Lock()
_HTTP_REQUESTS=defaultdict(int)
_HTTP_ERRORS=defaultdict(int)
_HTTP_DURATION_COUNT=defaultdict(int)
_HTTP_DURATION_SUM=defaultdict(float)
_HTTP_DURATION_BUCKETS=(10,25,50,100,250,500,1000,2500,5000,10000)
_HTTP_BUCKET_COUNTS=defaultdict(lambda:[0 for _ in _HTTP_DURATION_BUCKETS])


def record_http_metric(method: str, route: str, status_code: int, duration_ms: float) -> None:
    method=str(method or "UNKNOWN").upper()
    route=str(route or "unknown")
    status_class=f"{int(status_code)//100}xx"
    key=(method,route,status_class)
    base=(method,route)
    value=max(0.0,float(duration_ms))
    with _LOCK:
        _HTTP_REQUESTS[key]+=1
        if int(status_code)>=500:
            _HTTP_ERRORS[base]+=1
        _HTTP_DURATION_COUNT[base]+=1
        _HTTP_DURATION_SUM[base]+=value
        buckets=_HTTP_BUCKET_COUNTS[base]
        for idx,bound in enumerate(_HTTP_DURATION_BUCKETS):
            if value<=bound:
                buckets[idx]+=1


def _escape(value: str) -> str:
    return str(value).replace("\\","\\\\").replace('"','\\"').replace("\n","\\n")


def _labels(**items) -> str:
    return "{" + ",".join(f'{k}="{_escape(v)}"' for k,v in items.items()) + "}"


def prometheus_metrics(tenant_id: str | None=None) -> str:
    lines=[
        "# HELP bsa_http_requests_total Total HTTP requests.",
        "# TYPE bsa_http_requests_total counter",
    ]
    with _LOCK:
        requests=dict(_HTTP_REQUESTS)
        errors=dict(_HTTP_ERRORS)
        counts=dict(_HTTP_DURATION_COUNT)
        sums=dict(_HTTP_DURATION_SUM)
        buckets={k:list(v) for k,v in _HTTP_BUCKET_COUNTS.items()}

    for (method,route,status_class),value in sorted(requests.items()):
        lines.append(f"bsa_http_requests_total{_labels(method=method,route=route,status_class=status_class)} {value}")

    lines += [
        "# HELP bsa_http_server_errors_total HTTP 5xx responses.",
        "# TYPE bsa_http_server_errors_total counter",
    ]
    for (method,route),value in sorted(errors.items()):
        lines.append(f"bsa_http_server_errors_total{_labels(method=method,route=route)} {value}")

    lines += [
        "# HELP bsa_http_request_duration_ms HTTP request duration in milliseconds.",
        "# TYPE bsa_http_request_duration_ms histogram",
    ]
    for (method,route),count in sorted(counts.items()):
        cumulative=buckets.get((method,route),[])
        for idx,bound in enumerate(_HTTP_DURATION_BUCKETS):
            value=cumulative[idx] if idx<len(cumulative) else 0
            lines.append(f'bsa_http_request_duration_ms_bucket{_labels(method=method,route=route,le=str(bound))} {value}')
        lines.append(f'bsa_http_request_duration_ms_bucket{_labels(method=method,route=route,le="+Inf")} {count}')
        lines.append(f"bsa_http_request_duration_ms_count{_labels(method=method,route=route)} {count}")
        lines.append(f"bsa_http_request_duration_ms_sum{_labels(method=method,route=route)} {round(sums.get((method,route),0.0),3)}")

    qh=queue_health(tenant_id)
    qm=queue_metrics(tenant_id) if tenant_id else None
    wh=worker_health()
    lines += [
        "# HELP bsa_queue_queued_jobs Current queued jobs.",
        "# TYPE bsa_queue_queued_jobs gauge",
        f"bsa_queue_queued_jobs {int(qh.get('queued',0))}",
        "# HELP bsa_queue_running_jobs Current running jobs.",
        "# TYPE bsa_queue_running_jobs gauge",
        f"bsa_queue_running_jobs {int(qh.get('running',0))}",
        "# HELP bsa_queue_oldest_queued_age_seconds Age of oldest queued job.",
        "# TYPE bsa_queue_oldest_queued_age_seconds gauge",
        f"bsa_queue_oldest_queued_age_seconds {int(qh.get('oldest_queued_age_seconds',0))}",
        "# HELP bsa_worker_active Current active workers.",
        "# TYPE bsa_worker_active gauge",
        f"bsa_worker_active {int(wh.get('active_workers',0))}",
        "# HELP bsa_worker_stale Current stale workers.",
        "# TYPE bsa_worker_stale gauge",
        f"bsa_worker_stale {int(wh.get('stale_workers',0))}",
    ]
    if qm is not None:
        lines += [
            "# HELP bsa_queue_retries_total Tenant queue retry count.",
            "# TYPE bsa_queue_retries_total gauge",
            f"bsa_queue_retries_total {int(qm.get('retries',0))}",
            "# HELP bsa_queue_success_rate_percent Tenant queue success rate.",
            "# TYPE bsa_queue_success_rate_percent gauge",
            f"bsa_queue_success_rate_percent {float(qm.get('success_rate_percent',100))}",
            "# HELP bsa_queue_average_execution_seconds Average job execution duration.",
            "# TYPE bsa_queue_average_execution_seconds gauge",
            f"bsa_queue_average_execution_seconds {float(qm.get('average_execution_seconds',0))}",
        ]
    return "\n".join(lines)+"\n"


def operational_alerts(tenant_id: str | None=None) -> dict:
    qh=queue_health(tenant_id)
    qm=queue_metrics(tenant_id) if tenant_id else {}
    wh=worker_health()
    alerts=[]
    if int(qh.get("expired_running_leases",0))>0:
        alerts.append({"severity":"high","code":"queue_expired_lease","value":qh["expired_running_leases"]})
    if int(qh.get("oldest_queued_age_seconds",0))>900:
        alerts.append({"severity":"medium","code":"queue_backlog_age","value":qh["oldest_queued_age_seconds"]})
    if int(wh.get("active_workers",0))==0 and int(qh.get("queued",0))>0:
        alerts.append({"severity":"high","code":"no_active_worker_with_backlog","value":qh.get("queued",0)})
    if int(wh.get("stale_workers",0))>0:
        alerts.append({"severity":"medium","code":"stale_worker","value":wh["stale_workers"]})
    if qm and int(qm.get("total_jobs",0))>=5 and float(qm.get("success_rate_percent",100))<80:
        alerts.append({"severity":"medium","code":"queue_success_rate_low","value":qm["success_rate_percent"]})
    return {"status":"alerting" if alerts else "healthy","alerts":alerts}
