from pathlib import Path


ACTIVE_MARKERS = (
    "collect_target(",
    "adaptive_discovery(",
    "discover_surface(",
    "run_safe_web_assessment(",
    "run_nuclei(",
    "run_public_assessment(",
)


def test_no_get_route_performs_active_network_collection():
    source = Path("app/main.py").read_text(encoding="utf-8")
    chunks = source.split("@app.")
    offenders = []
    for chunk in chunks:
        if not chunk.startswith('get("'):
            continue
        header = chunk.split("\n", 1)[0]
        body = chunk.split("@app.", 1)[0]
        if any(marker in body for marker in ACTIVE_MARKERS):
            offenders.append(header)
    assert offenders == [], f"active network collection exposed through GET: {offenders}"


def test_active_post_routes_queue_in_production():
    source = Path("app/main.py").read_text(encoding="utf-8")
    chunks = source.split("@app.")
    offenders = []
    for chunk in chunks:
        if not chunk.startswith('post("'):
            continue
        header = chunk.split("\n", 1)[0]
        body = chunk.split("@app.", 1)[0]
        if not any(marker in body for marker in ACTIVE_MARKERS):
            continue
        queued = "queue_active_operation(" in body or "enqueue_assessment(" in body
        if "if IS_PRODUCTION:" not in body or not queued:
            offenders.append(header)
    assert offenders == [], f"active POST route executes synchronously in production: {offenders}"


def test_no_post_route_executes_active_collection_inline():
    source=Path("app/main.py").read_text(encoding="utf-8")
    chunks=source.split("@app.")
    offenders=[]
    for chunk in chunks:
        if not chunk.startswith('post("'):
            continue
        header=chunk.split("\n",1)[0]
        body=chunk.split("@app.",1)[0]
        if any(marker in body for marker in ACTIVE_MARKERS):
            offenders.append(header)
    assert offenders==[], f"active collection executed inline in POST handlers: {offenders}"
