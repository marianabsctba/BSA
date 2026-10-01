"""Internal provider contracts for Be Safe ASM assessment engines.

Provider names are private implementation details and must not cross the
product/API boundary.
"""

from dataclasses import dataclass
from typing import Protocol, Callable
import json
import os
import shutil
import subprocess
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .dast import run_safe_web_assessment
from .exposure_signals import cloud_signals
from .intelligence_sources import SOURCES


@dataclass
class ProviderResult:
    title: str
    severity: str = "info"
    confidence: int = 50
    evidence: dict | None = None


class AssessmentProvider(Protocol):
    name: str

    def execute(self, target: str) -> list[ProviderResult]:
        ...


class CommandProvider:
    """Bounded adapter for optional local engines already installed on the worker."""

    name = "internal"
    binary = ""
    timeout = 60
    build_command: Callable[[str], list[str]] | None = None

    def available(self) -> bool:
        return bool(self.binary and shutil.which(self.binary))

    def execute(self, target: str) -> list[ProviderResult]:
        if not self.available():
            return []
        command = self._command(target)
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        return self.parse(proc.stdout or "", proc.stderr or "", proc.returncode)

    def _command(self, target: str) -> list[str]:
        if self.build_command:
            return self.build_command(target)
        raise NotImplementedError

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ProviderResult]:
        return []


class JsonLinesProvider(CommandProvider):
    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ProviderResult]:
        results = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                continue
            normalized = self.normalize(item)
            if normalized:
                results.append(normalized)
        return results

    def normalize(self, item: dict) -> ProviderResult | None:
        return None


class NucleiProvider(JsonLinesProvider):
    name = "nuclei"
    binary = "nuclei"
    timeout = 120

    def _command(self, target: str) -> list[str]:
        return [self.binary, "-u", target, "-jsonl", "-silent", "-timeout", "8", "-retries", "1"]

    def normalize(self, item: dict) -> ProviderResult | None:
        info = item.get("info") or {}
        severity = str(info.get("severity") or "info").lower()
        title = str(info.get("name") or item.get("matcher-name") or "Exposure evidence")
        evidence = {
            "matched_at": item.get("matched-at") or item.get("host"),
            "type": item.get("type"),
            "severity": severity,
            "reference": info.get("reference") or [],
            "classification": info.get("classification") or {},
        }
        return ProviderResult(title=title, severity=severity, confidence=92, evidence=evidence)


class HttpProbeProvider(JsonLinesProvider):
    name = "httpx"
    binary = "httpx"
    timeout = 60

    def _command(self, target: str) -> list[str]:
        return [self.binary, "-u", target, "-json", "-silent", "-title", "-tech-detect", "-status-code"]

    def normalize(self, item: dict) -> ProviderResult | None:
        evidence = {
            "url": item.get("url"),
            "status_code": item.get("status_code"),
            "title": item.get("title"),
            "technologies": item.get("tech") or [],
        }
        return ProviderResult(
            title="External service validated",
            severity="info",
            confidence=95,
            evidence=evidence,
        )


class SubdomainProvider(CommandProvider):
    name = "subfinder"
    binary = "subfinder"
    timeout = 90

    def _command(self, target: str) -> list[str]:
        return [self.binary, "-d", target, "-silent"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ProviderResult]:
        seen = set()
        out = []
        for value in stdout.splitlines():
            value = value.strip().lower()
            if value and value not in seen:
                seen.add(value)
                out.append(
                    ProviderResult(
                        title="External asset discovered",
                        severity="info",
                        confidence=85,
                        evidence={"asset": value, "relationship": "subdomain"},
                    )
                )
        return out


class NmapProvider(CommandProvider):
    name = "nmap"
    binary = "nmap"
    timeout = 90

    def _command(self, target: str) -> list[str]:
        # Bounded service discovery only: common ports, no NSE scripts or intrusive probes.
        return [self.binary, "-Pn", "-T3", "--top-ports", "100", "-sV", "--version-light", target]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ProviderResult]:
        open_lines = [line.strip() for line in stdout.splitlines() if "/tcp" in line and " open " in line]
        return [
            ProviderResult(
                title="Externally reachable service",
                severity="info",
                confidence=90,
                evidence={"service": line},
            )
            for line in open_lines
        ]


class AmassProvider(CommandProvider):
    name = "amass"
    binary = "amass"
    timeout = 120

    def _command(self, target: str) -> list[str]:
        return [self.binary, "enum", "-passive", "-d", target]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ProviderResult]:
        seen = set()
        out = []
        for value in stdout.splitlines():
            value = value.strip().lower()
            if value and value not in seen:
                seen.add(value)
                out.append(
                    ProviderResult(
                        title="External asset discovered",
                        severity="info",
                        confidence=82,
                        evidence={"asset": value, "relationship": "subdomain"},
                    )
                )
        return out


class SafeWebProvider:
    name = "safeweb"

    def available(self) -> bool:
        return True

    def execute(self, target: str) -> list[ProviderResult]:
        data = run_safe_web_assessment(target)
        out = []
        for item in data.get("findings", []):
            out.append(
                ProviderResult(
                    title=str(item.get("title") or "Web exposure evidence"),
                    severity=str(item.get("severity") or "info"),
                    confidence=max(0, min(100, int(item.get("confidence", 80) or 80))),
                    evidence={
                        "url": data.get("target") or target,
                        "check": item.get("check"),
                        "evidence": item.get("evidence"),
                    },
                )
            )
        return out


class DnsValidationProvider(JsonLinesProvider):
    name = "dnsx"
    binary = "dnsx"
    timeout = 75

    def _command(self, target: str) -> list[str]:
        return [self.binary, "-d", target, "-json", "-silent", "-a", "-aaaa", "-cname"]

    def normalize(self, item: dict) -> ProviderResult | None:
        host = item.get("host") or item.get("input")
        if not host:
            return None
        evidence = {
            "asset": host,
            "a": item.get("a") or [],
            "aaaa": item.get("aaaa") or [],
            "cname": item.get("cname") or [],
            "relationship": "dns-validated",
        }
        return ProviderResult("DNS asset validated", "info", 94, evidence)


class PortExposureProvider(JsonLinesProvider):
    name = "naabu"
    binary = "naabu"
    timeout = 90

    def _command(self, target: str) -> list[str]:
        return [self.binary, "-host", target, "-top-ports", "100", "-json", "-silent", "-rate", "300"]

    def normalize(self, item: dict) -> ProviderResult | None:
        host = item.get("host") or item.get("ip")
        port = item.get("port")
        if not host or not port:
            return None
        service = f"{host}:{port}"
        return ProviderResult(
            "Externally reachable service",
            "info",
            92,
            {"asset": service, "host": host, "port": port, "relationship": "reachable-service"},
        )


class TlsIntelligenceProvider(JsonLinesProvider):
    name = "tlsx"
    binary = "tlsx"
    timeout = 75

    def _command(self, target: str) -> list[str]:
        return [self.binary, "-u", target, "-json", "-silent"]

    def normalize(self, item: dict) -> ProviderResult | None:
        host = item.get("host") or item.get("input") or item.get("url")
        if not host:
            return None
        evidence = {
            "asset": host,
            "subject_cn": item.get("subject_cn"),
            "issuer_cn": item.get("issuer_cn"),
            "not_before": item.get("not_before"),
            "not_after": item.get("not_after"),
            "san": item.get("san") or [],
            "tls_version": item.get("version") or item.get("tls_version"),
            "relationship": "tls-observed",
        }
        return ProviderResult("TLS exposure intelligence", "info", 95, evidence)


class HistoricalUrlProvider(CommandProvider):
    name = "gau"
    binary = "gau"
    timeout = 90

    def _command(self, target: str) -> list[str]:
        return [self.binary, "--subs", target]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ProviderResult]:
        seen = set()
        out = []
        for value in stdout.splitlines():
            value = value.strip()
            if value and value not in seen and len(seen) < 500:
                seen.add(value)
                out.append(
                    ProviderResult(
                        "Historical web surface discovered",
                        "info",
                        72,
                        {"url": value, "relationship": "historical-url"},
                    )
                )
        return out


class WebCrawlProvider(JsonLinesProvider):
    name = "katana"
    binary = "katana"
    timeout = 90

    def _command(self, target: str) -> list[str]:
        return [self.binary, "-u", target, "-jsonl", "-silent", "-d", "2", "-jc"]

    def normalize(self, item: dict) -> ProviderResult | None:
        request = item.get("request") or {}
        endpoint = request.get("endpoint") or item.get("url")
        if not endpoint:
            return None
        return ProviderResult(
            "Web surface discovered",
            "info",
            80,
            {"url": endpoint, "relationship": "web-surface"},
        )


class AsnIntelligenceProvider(JsonLinesProvider):
    name = "asnmap"
    binary = "asnmap"
    timeout = 75

    def _command(self, target: str) -> list[str]:
        return [self.binary, "-d", target, "-json", "-silent"]

    def normalize(self, item: dict) -> ProviderResult | None:
        asset = item.get("domain") or item.get("ip") or item.get("input")
        if not asset:
            return None
        evidence = {
            "asset": asset,
            "asn": item.get("asn"),
            "org": item.get("org"),
            "country": item.get("country"),
            "cidr": item.get("cidr"),
            "relationship": "network-intelligence",
        }
        return ProviderResult("Network ownership intelligence", "info", 90, evidence)


class SecretExposureProvider(JsonLinesProvider):
    name = "trufflehog"
    binary = "trufflehog"
    timeout = 150

    def supports(self, target: str) -> bool:
        return target.startswith(("https://github.com/", "https://gitlab.com/", "http://github.com/", "http://gitlab.com/"))

    def available(self) -> bool:
        return bool(shutil.which(self.binary))

    def _command(self, target: str) -> list[str]:
        if not (
            target.startswith("https://github.com/")
            or target.startswith("https://gitlab.com/")
            or target.startswith("http://github.com/")
            or target.startswith("http://gitlab.com/")
        ):
            raise ValueError("repository URL required")
        return [
            self.binary,
            "--json",
            "--no-update",
            "--no-verification",
            "git",
            target,
            "--max-depth",
            "100",
        ]

    def normalize(self, item: dict) -> ProviderResult | None:
        detector = str(item.get("DetectorName") or item.get("DetectorType") or "credential")
        verified = bool(item.get("Verified"))
        source = item.get("SourceMetadata") or {}
        data = source.get("Data") if isinstance(source, dict) else {}
        git = data.get("Git") if isinstance(data, dict) else {}
        path = git.get("file") if isinstance(git, dict) else None
        evidence = {
            "asset": item.get("SourceName") or "repository",
            "detector": detector,
            "verified": verified,
            "path": path,
            "redacted": True,
            "relationship": "secret-exposure",
        }
        return ProviderResult(
            "Potential credential exposure",
            "high" if verified else "medium",
            95 if verified else 78,
            evidence,
        )


class WhatWebProvider(CommandProvider):
    name = "whatweb"
    binary = "whatweb"
    timeout = 75

    def _command(self, target: str) -> list[str]:
        return [self.binary, "--no-errors", "--log-json=-", target]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ProviderResult]:
        try:
            rows = json.loads(stdout or "[]")
        except ValueError:
            return []
        if isinstance(rows, dict):
            rows = [rows]
        out = []
        for row in rows[:50] if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            plugins = row.get("plugins") or {}
            technologies = sorted(str(k) for k in plugins.keys())[:100] if isinstance(plugins, dict) else []
            target = row.get("target") or row.get("url")
            if not target:
                continue
            out.append(
                ProviderResult(
                    "Technology fingerprint observed",
                    "info",
                    82,
                    {
                        "url": target,
                        "technologies": technologies,
                        "relationship": "technology-fingerprint",
                    },
                )
            )
        return out


class TestSslProvider(CommandProvider):
    name = "testssl"
    binary = "testssl.sh"
    timeout = 120

    def available(self) -> bool:
        return bool(shutil.which(self.binary) or shutil.which("testssl"))

    def _command(self, target: str) -> list[str]:
        binary = shutil.which(self.binary) or shutil.which("testssl") or self.binary
        return [
            binary,
            "--quiet",
            "--warnings",
            "off",
            "--jsonfile",
            "/dev/stdout",
            target,
        ]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ProviderResult]:
        try:
            data = json.loads(stdout or "[]")
        except ValueError:
            return []
        rows = data if isinstance(data, list) else [data]
        out = []
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
            "OK": "info",
        }
        for row in rows[:250]:
            if not isinstance(row, dict):
                continue
            finding = str(row.get("finding") or row.get("id") or "").strip()
            if not finding:
                continue
            raw_severity = str(row.get("severity") or "INFO").upper()
            out.append(
                ProviderResult(
                    str(row.get("id") or "TLS posture evidence"),
                    severity_map.get(raw_severity, "info"),
                    90,
                    {
                        "asset": target if (target := row.get("ip") or row.get("fqdn")) else "tls-endpoint",
                        "finding": finding[:500],
                        "cve": row.get("cve"),
                        "cwe": row.get("cwe"),
                        "relationship": "tls-assessment",
                    },
                )
            )
        return out


class CloudExposureProvider:
    name = "cloud"

    def available(self) -> bool:
        return True

    def execute(self, target: str) -> list[ProviderResult]:
        signals = cloud_signals([target])
        return [
            ProviderResult(
                "Cloud exposure signal",
                "info",
                signal.confidence,
                {
                    "asset": target,
                    "cloud_provider": signal.value,
                    "relationship": "cloud-attribution",
                    "validation_required": signal.validation_required,
                },
            )
            for signal in signals
        ]


class _ConfiguredJsonIntelProvider:
    endpoint_env = ""
    token_env = ""
    timeout = 8

    def available(self) -> bool:
        endpoint = os.getenv(self.endpoint_env, "").strip()
        return endpoint.startswith("https://")

    def _post(self, payload: dict) -> dict:
        endpoint = os.getenv(self.endpoint_env, "").strip()
        if not endpoint.startswith("https://"):
            return {}
        token = os.getenv(self.token_env, "").strip()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(
            endpoint,
            data=json.dumps(payload, separators=(",", ":")).encode(),
            headers=headers,
            method="POST",
        )
        with urlopen(req, timeout=self.timeout) as response:
            raw = response.read(262144)
        data = json.loads(raw.decode("utf-8", "ignore"))
        return data if isinstance(data, dict) else {}


class ThreatIntelProvider(_ConfiguredJsonIntelProvider):
    name = "cti"
    endpoint_env = "BSA_CTI_URL"
    token_env = "BSA_CTI_TOKEN"

    def execute(self, target: str) -> list[ProviderResult]:
        data = self._post({"indicator": target})
        hits = max(0, int(data.get("hits", data.get("match_count", 0)) or 0))
        if hits == 0:
            return []
        score = max(0, min(100, int(data.get("score", data.get("confidence", 70)) or 70)))
        severity = str(data.get("severity") or ("high" if score >= 80 else "medium")).lower()
        evidence = {
            "asset": target,
            "match_count": hits,
            "threat_score": score,
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "categories": list(data.get("categories") or [])[:20],
            "relationship": "threat-intelligence",
        }
        return [ProviderResult("Threat intelligence correlation", severity, score, evidence)]


class CredentialExposureProvider(_ConfiguredJsonIntelProvider):
    name = "leak"
    endpoint_env = "BSA_LEAK_INTEL_URL"
    token_env = "BSA_LEAK_INTEL_TOKEN"

    def supports(self, target: str) -> bool:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        return bool(parsed.hostname)

    def execute(self, target: str) -> list[ProviderResult]:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = (parsed.hostname or "").lower()
        if not domain:
            return []
        data = self._post({"domain": domain, "aggregate_only": True})
        exposed = max(0, int(data.get("exposed_accounts", data.get("count", 0)) or 0))
        stealer = max(0, int(data.get("stealer_log_count", 0) or 0))
        sources = max(0, int(data.get("source_count", 0) or 0))
        if exposed == 0 and stealer == 0:
            return []
        confidence = max(0, min(100, int(data.get("confidence", 85) or 85)))
        severity = "high" if stealer > 0 or exposed >= 10 else "medium"
        evidence = {
            "asset": domain,
            "exposed_account_count": exposed,
            "stealer_log_count": stealer,
            "source_count": sources,
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "redacted": True,
            "relationship": "credential-exposure",
        }
        return [ProviderResult("Credential exposure detected", severity, confidence, evidence)]


class ThreatFoxProvider(_ConfiguredJsonIntelProvider):
    name = "threatfox"
    endpoint_env = "BSA_THREATFOX_URL"
    token_env = "BSA_THREATFOX_AUTH_KEY"

    def available(self) -> bool:
        return bool(os.getenv(self.token_env, "").strip())

    def _post(self, payload: dict) -> dict:
        endpoint = os.getenv(self.endpoint_env, "").strip() or SOURCES["threatfox"].endpoint
        token = os.getenv(self.token_env, "").strip()
        if not token:
            return {}
        req = Request(
            endpoint,
            data=json.dumps(payload, separators=(",", ":")).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Auth-Key": token,
            },
            method="POST",
        )
        with urlopen(req, timeout=self.timeout) as response:
            raw = response.read(262144)
        data = json.loads(raw.decode("utf-8", "ignore"))
        return data if isinstance(data, dict) else {}

    def execute(self, target: str) -> list[ProviderResult]:
        data = self._post({"query": "search_ioc", "search_term": target})
        rows = data.get("data") or []
        if not isinstance(rows, list) or not rows:
            return []
        rows = rows[:50]
        malware = sorted({str(x.get("malware_printable") or x.get("malware") or "") for x in rows if isinstance(x, dict)})
        malware = [x for x in malware if x][:20]
        return [ProviderResult(
            "Threat intelligence correlation",
            "high",
            90,
            {
                "asset": target,
                "match_count": len(rows),
                "malware_families": malware,
                "relationship": "threat-intelligence",
            },
        )]


class OpenVASProvider(_ConfiguredJsonIntelProvider):
    name = "openvas"
    endpoint_env = "BSA_OPENVAS_URL"
    token_env = "BSA_OPENVAS_TOKEN"
    timeout = 120

    def execute(self, target: str) -> list[ProviderResult]:
        data = self._post({
            "target": target,
            "profile": "safe",
            "max_findings": 250,
        })
        rows = data.get("findings") or data.get("results") or []
        out = []
        for row in rows[:250] if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            severity = str(row.get("severity") or "info").lower()
            confidence = max(0, min(100, int(row.get("confidence", 85) or 85)))
            evidence = {
                "asset": row.get("asset") or target,
                "vulnerability_id": row.get("cve") or row.get("vulnerability_id"),
                "cvss": row.get("cvss"),
                "port": row.get("port"),
                "protocol": row.get("protocol"),
                "summary": row.get("summary") or row.get("description"),
                "relationship": "vulnerability-assessment",
            }
            out.append(
                ProviderResult(
                    str(row.get("title") or "Vulnerability assessment finding"),
                    severity,
                    confidence,
                    evidence,
                )
            )
        return out


class ZAPProvider(_ConfiguredJsonIntelProvider):
    name = "zap"
    endpoint_env = "BSA_ZAP_URL"
    token_env = "BSA_ZAP_TOKEN"
    timeout = 120

    def supports(self, target: str) -> bool:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname)

    def execute(self, target: str) -> list[ProviderResult]:
        data = self._post({
            "target": target,
            "mode": "baseline",
            "active_scan": False,
            "max_findings": 250,
        })
        rows = data.get("findings") or data.get("alerts") or []
        out = []
        for row in rows[:250] if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            severity = str(row.get("severity") or row.get("risk") or "info").lower()
            confidence = max(0, min(100, int(row.get("confidence", 80) or 80)))
            evidence = {
                "url": row.get("url") or target,
                "parameter": row.get("parameter"),
                "evidence": row.get("evidence"),
                "cwe": row.get("cwe"),
                "wasc": row.get("wasc"),
                "relationship": "web-assessment",
            }
            out.append(
                ProviderResult(
                    str(row.get("title") or row.get("alert") or "Web assessment finding"),
                    severity,
                    confidence,
                    evidence,
                )
            )
        return out


DEFAULT_PROVIDERS = [
    SubdomainProvider,
    AmassProvider,
    HttpProbeProvider,
    NucleiProvider,
    NmapProvider,
    SafeWebProvider,
    DnsValidationProvider,
    PortExposureProvider,
    TlsIntelligenceProvider,
    HistoricalUrlProvider,
    WebCrawlProvider,
    WhatWebProvider,
    TestSslProvider,
    AsnIntelligenceProvider,
    SecretExposureProvider,
    OpenVASProvider,
    ZAPProvider,
    ThreatIntelProvider,
    CredentialExposureProvider,
]
