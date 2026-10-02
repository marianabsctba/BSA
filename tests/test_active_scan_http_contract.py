from pathlib import Path


ACTIVE_MARKERS = (
    "govern_active_scan(",
    "collect_target(",
    "adaptive_discovery(",
    "discover_surface(",
    "run_safe_web_assessment(",
    "run_nuclei(",
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
