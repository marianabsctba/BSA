from pathlib import Path
import re


def test_nginx_enforces_edge_security_headers_and_forwarded_scheme():
    conf=Path("frontend/nginx.conf").read_text(encoding="utf-8")
    assert 'Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' in conf
    assert "proxy_set_header X-Forwarded-Proto https;" in conf
    assert "proxy_set_header X-Forwarded-Proto $scheme;" not in conf


def test_ci_actions_are_pinned_and_supply_chain_scans_exist():
    workflow=Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    for line in workflow.splitlines():
        stripped=line.strip()
        if stripped.startswith("uses:"):
            ref=stripped.split("@",1)[1].split()[0]
            assert re.fullmatch(r"[0-9a-f]{40}",ref), f"unpinned action: {stripped}"

    assert "bandit -q -r app" in workflow
    assert "aquasecurity/trivy-action@" in workflow
    assert "severity: HIGH,CRITICAL" in workflow
    assert "format: cyclonedx" in workflow
    assert "output: sbom.cdx.json" in workflow


def test_container_images_are_digest_pinned():
    backend=Path("Dockerfile").read_text(encoding="utf-8")
    frontend=Path("frontend/Dockerfile").read_text(encoding="utf-8")
    compose=Path("docker-compose.production.yml").read_text(encoding="utf-8")

    for line in backend.splitlines():
        if line.startswith("FROM "):
            assert "@sha256:" in line
    for line in frontend.splitlines():
        if line.startswith("FROM "):
            assert "@sha256:" in line
    ollama_line=next(line.strip() for line in compose.splitlines() if "image: ollama/ollama:" in line)
    assert "@sha256:" in ollama_line
