"""Be Safe ASM assessment orchestration layer.

Security engines are internal implementation details. Public exports contain
only normalized exposure intelligence, evidence and confidence.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import uuid
import re


@dataclass
class AssessmentFinding:
    asset: str
    engine: str
    category: str
    title: str
    severity: str
    confidence: int
    evidence: dict[str, Any]


class AssessmentEngine:
    """Coordinates multiple internal assessment providers."""

    PROVIDERS = {
        "nuclei": "vulnerability_validation",
        "openvas": "vulnerability_assessment",
        "zap": "dast",
        "nmap": "service_discovery",
        "dns": "external_discovery",
        "ct": "certificate_intelligence",
        "cti": "threat_intelligence",
        "leak": "credential_exposure",
        "httpx": "surface_validation",
        "subfinder": "external_discovery",
        "amass": "external_discovery",
        "assetfinder": "external_discovery",
        "alterx": "candidate_discovery",
        "puredns": "dns_intelligence",
        "safeweb": "web_assessment",
        "dnsx": "dns_intelligence",
        "naabu": "service_exposure",
        "tlsx": "certificate_intelligence",
        "gau": "historical_surface",
        "katana": "web_surface",
        "asnmap": "network_intelligence",
        "trufflehog": "credential_exposure",
        "cloud": "cloud_intelligence",
        "threatfox": "threat_intelligence",
        "hibp": "credential_exposure",
        "hudsonrock": "credential_exposure",
        "whatweb": "technology_intelligence",
        "testssl": "tls_assessment",
    }

    def __init__(self):
        self.findings: list[AssessmentFinding] = []

    def register_finding(self, finding: AssessmentFinding):
        self.findings.append(finding)

    def add_provider_result(self, provider: str, asset: str, result: dict):
        category = self.PROVIDERS.get(provider, "assessment")
        self.register_finding(
            AssessmentFinding(
                asset=asset,
                engine=provider,
                category=category,
                title=result.get("title", "assessment finding"),
                severity=result.get("severity", "info"),
                confidence=max(0, min(100, int(result.get("confidence", 50)))),
                evidence=result.get("evidence") or result,
            )
        )

    def export_public(self) -> dict:
        """Product-safe output: provider/tool identities are intentionally removed."""
        findings = []
        for item in self.findings:
            findings.append(
                {
                    "asset": item.asset,
                    "category": item.category,
                    "title": item.title,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "evidence": self._sanitize_evidence(item.evidence),
                }
            )
        return {
            "assessment_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "finding_count": len(findings),
        }

    def export_internal(self) -> dict:
        """Internal diagnostics only. Never expose this payload through tenant APIs."""
        return {
            "assessment_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": [asdict(item) for item in self.findings],
            "finding_count": len(self.findings),
        }

    def export(self) -> dict:
        # Backwards-compatible default is the safe product boundary.
        return self.export_public()

    @classmethod
    def _sanitize_evidence(cls, evidence: dict[str, Any]) -> dict[str, Any]:
        blocked = {
            "engine",
            "provider",
            "scanner",
            "command",
            "binary",
            "template",
            "template_id",
            "tool",
            "tool_name",
        }
        return {
            k: cls._mask_value(k, v)
            for k, v in (evidence or {}).items()
            if str(k).lower() not in blocked
        }

    @classmethod
    def _mask_value(cls, key: str, value: Any) -> Any:
        sensitive_keys = {
            "authorization",
            "cookie",
            "set-cookie",
            "password",
            "passwd",
            "pwd",
            "secret",
            "secret_value",
            "token",
            "access_token",
            "refresh_token",
            "api_key",
            "apikey",
            "private_key",
            "client_secret",
            "credential",
            "credentials",
        }
        key_l = str(key).lower().replace("_", "-")
        normalized = key_l.replace("-", "_")
        if normalized in {x.replace("-", "_") for x in sensitive_keys}:
            return "[REDACTED]"

        if isinstance(value, dict):
            blocked_nested = {
                "engine", "provider", "scanner", "command", "binary",
                "template", "template_id", "template-id", "tool", "tool_name",
                "tool-name", "provider_name", "provider-name", "adapter", "executor",
            }
            return {
                k: cls._mask_value(k, v)
                for k, v in value.items()
                if str(k).lower() not in blocked_nested
            }
        if isinstance(value, list):
            return [cls._mask_value(key, item) for item in value]
        if isinstance(value, tuple):
            return [cls._mask_value(key, item) for item in value]
        if not isinstance(value, str):
            return value

        text = value
        text = re.sub(
            r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}",
            lambda m: m.group(1) + " [REDACTED]",
            text,
        )
        text = re.sub(
            r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|client[_-]?secret)\s*[:=]\s*[^\s,;]+",
            lambda m: m.group(1) + "=[REDACTED]",
            text,
        )
        text = re.sub(
            r"\b([A-Za-z0-9._%+-]{1,3})[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
            r"\1***@\2",
            text,
        )
        return text


def mask_public_data(value: Any) -> Any:
    """Reusable public-boundary masking for normalized product payloads."""
    return AssessmentEngine._mask_value("payload", value)
