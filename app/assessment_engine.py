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

    @classmethod
    def _evidence_classification(
        cls,
        category: str,
        confidence: int,
        evidence: dict[str, Any],
    ) -> tuple[str, str]:
        """Return product-safe evidence state and quality without changing severity."""
        normalized = dict(evidence or {})
        existing = str(normalized.get("validation_state") or "").strip().lower()
        allowed = {"needs_validation", "observed", "confirmed_evidence", "confirmed"}
        independently_corroborated = bool(normalized.get("independently_corroborated"))

        if independently_corroborated:
            state = "confirmed_evidence"
        elif existing in allowed:
            state = "confirmed_evidence" if existing == "confirmed" else existing
        elif bool(normalized.get("validation_required")):
            state = "needs_validation"
        elif category in {
            "vulnerability_validation",
            "vulnerability_assessment",
            "dast",
            "web_assessment",
        }:
            state = "needs_validation"
        else:
            state = "observed"

        evidence_present = bool(normalized)
        if state == "confirmed_evidence" and confidence >= 80:
            quality = "strong"
        elif independently_corroborated or (evidence_present and confidence >= 80):
            quality = "strong"
        elif evidence_present and confidence >= 60:
            quality = "moderate"
        else:
            quality = "limited"
        return state, quality

    def _public_row(self, item: AssessmentFinding, *, include_backend: bool = False) -> dict:
        evidence = self._sanitize_evidence(item.evidence)
        evidence_state, evidence_quality = self._evidence_classification(
            item.category,
            item.confidence,
            evidence,
        )
        row = {
            "asset": item.asset,
            "category": item.category,
            "title": item.title,
            "severity": item.severity,
            "confidence": item.confidence,
            "evidence_state": evidence_state,
            "evidence_quality": evidence_quality,
            "evidence": evidence,
        }
        if include_backend:
            row["_source_backend"] = item.engine
        return row

    def export_public(self) -> dict:
        """Product-safe output: provider/tool identities are intentionally removed."""
        findings = [self._public_row(item) for item in self.findings]
        return {
            "assessment_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "finding_count": len(findings),
        }

    def export_orchestration_rows(self) -> list[dict]:
        """Sanitized rows for internal orchestration.

        Provider identity is carried only in a private transient field so the
        orchestrator can measure independent corroboration. The field must be
        removed before crossing the public API boundary.
        """
        return [self._public_row(item, include_backend=True) for item in self.findings]

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
