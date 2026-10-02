from pathlib import Path


ACTIVE_CALLS=(
    "collect_target(",
    "adaptive_discovery(",
    "discover_surface(",
    "run_safe_web_assessment(",
    "run_nuclei(",
)


def test_network_active_post_routes_queue_in_production():
    source=Path("app/main.py").read_text(encoding="utf-8")
    offenders=[]
    for chunk in source.split("\n@app."):
        if not chunk.startswith('post("'):
            continue
        body=chunk.split("\n@app.",1)[0]
        if not any(marker in body for marker in ACTIVE_CALLS):
            continue
        header=body.splitlines()[0]
        if "if IS_PRODUCTION:" not in body or "queue_active_operation(" not in body:
            offenders.append(header)
    assert offenders==[], f"active POST routes execute synchronously in production: {offenders}"


def test_active_operation_queue_has_worker_dispatch():
    queue=Path("app/job_queue.py").read_text(encoding="utf-8")
    worker=Path("app/worker.py").read_text(encoding="utf-8")
    dispatcher=Path("app/active_operations.py").read_text(encoding="utf-8")

    assert "def enqueue_operation(" in queue
    assert 'job_type TEXT NOT NULL DEFAULT \'assessment\'' in queue
    assert '=="operation"' in worker
    assert "run_active_operation(" in worker
    assert "def run_active_operation(" in dispatcher
