"""Internal provider contracts for Be Safe ASM assessment engines.

Provider names are private implementation details and must not cross the
product/API boundary.
"""

from dataclasses import dataclass
from typing import Protocol, Callable
import json
import shutil
import subprocess


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
    HttpProbeProvider,
    NucleiProvider,
    NmapProvider,
    OpenVASProvider,
    ZAPProvider,
    ThreatIntelProvider,
    CredentialExposureProvider,
]
