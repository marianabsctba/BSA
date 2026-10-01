"""Internal provider contracts for Be Safe ASM assessment engines.

Provider names are private implementation details and must not cross the
product/API boundary.
"""

from dataclasses import dataclass
from typing import Protocol, Callable
import json
import shutil
import subprocess

from .dast import run_safe_web_assessment


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


class OpenVASProvider:
    name = "openvas"


class ZAPProvider:
    name = "zap"


class ThreatIntelProvider:
    name = "cti"


class CredentialExposureProvider:
    name = "leak"


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
    OpenVASProvider,
    ZAPProvider,
    ThreatIntelProvider,
    CredentialExposureProvider,
]
