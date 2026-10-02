from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from urllib.parse import urlparse

from .security import validate_external_target


class NucleiEngineError(RuntimeError):
    pass


def validate_nuclei_target(target: str) -> str:
    value = target if "://" in target else f"https://{target}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("invalid web target")
    if os.getenv("BSA_ENV","development").lower() in {"production","prod"}:
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:
            raise ValueError(
                "nuclei hostname targets are disabled in production; use an explicit public IP"
            ) from exc
    validate_external_target(value)
    return value


def _normalized_target(target: str) -> str:
    return validate_nuclei_target(target)


def _result(item: dict) -> dict:
    info = item.get("info") or {}
    classification = info.get("classification") or {}
    return {
        "template_id": item.get("template-id") or item.get("templateID"),
        "name": info.get("name") or item.get("template-id"),
        "severity": str(info.get("severity") or "info").lower(),
        "type": info.get("type"),
        "matched_at": item.get("matched-at") or item.get("matchedAt") or item.get("host"),
        "host": item.get("host"),
        "url": item.get("url"),
        "matcher_name": item.get("matcher-name") or item.get("matcher_name"),
        "extracted_results": item.get("extracted-results") or item.get("extractedResults") or [],
        "cve_id": classification.get("cve-id") or classification.get("cve_id"),
        "cwe_id": classification.get("cwe-id") or classification.get("cwe_id"),
        "references": info.get("reference") or info.get("references") or [],
        "raw": item,
    }


def run_nuclei(target: str, profile: str = "safe", timeout_seconds: int = 120) -> dict:
    """Run Nuclei as an external detection engine under a bounded, validated scope."""
    normalized = _normalized_target(target)
    if profile not in {"safe", "standard"}:
        raise ValueError("unsupported nuclei profile")
    timeout = max(10, min(int(timeout_seconds), 300))
    binary = os.getenv("NUCLEI_BIN") or shutil.which("nuclei")
    if not binary:
        raise NucleiEngineError("nuclei engine is not installed")

    command = [
        binary, "-u", normalized, "-jsonl", "-silent", "-no-interactsh",
        "-timeout", "5", "-retries", "1", "-rate-limit", "25",
    ]
    if profile == "safe":
        command.extend(["-tags", "safe"])
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")},
        )
    except subprocess.TimeoutExpired as exc:
        raise NucleiEngineError("nuclei scan timed out") from exc
    if completed.returncode not in {0, 1}:
        detail = (completed.stderr or "nuclei failed").strip()[-1000:]
        raise NucleiEngineError(detail)

    findings = []
    invalid_lines = 0
    for line in (completed.stdout or "").splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                findings.append(_result(item))
        except json.JSONDecodeError:
            invalid_lines += 1
    return {
        "engine": "nuclei",
        "profile": profile,
        "target": normalized,
        "destructive_tests": profile != "safe",
        "exit_code": completed.returncode,
        "finding_count": len(findings),
        "findings": findings,
        "invalid_output_lines": invalid_lines,
    }


def normalize_findings(scan: dict, asset_id: str) -> list[dict]:
    """Map Nuclei detections to the BSA finding contract without persisting them."""
    severity_map = {"info":"info", "low":"low", "medium":"medium", "high":"high", "critical":"critical"}
    normalized = []
    for item in scan.get("findings", []):
        severity = severity_map.get(str(item.get("severity", "info")).lower(), "info")
        cve = item.get("cve_id")
        normalized.append({
            "asset_id": asset_id,
            "title": item.get("name") or item.get("template_id") or "Nuclei detection",
            "severity": severity,
            "confidence": 90,
            "evidence": json.dumps({"engine":"nuclei","template_id":item.get("template_id"),"matched_at":item.get("matched_at"),"matcher_name":item.get("matcher_name"),"extracted_results":item.get("extracted_results",[])}, ensure_ascii=False, sort_keys=True),
            "vulnerability_id": cve,
            "source_refs": item.get("references", []),
            "affected_component": item.get("host") or item.get("url"),
        })
    return normalized
