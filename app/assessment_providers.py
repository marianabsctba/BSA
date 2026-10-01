"""Provider contracts for Be Safe ASM assessment engines."""

from dataclasses import dataclass
from typing import Protocol


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


class NucleiProvider:
    name = "nuclei"


class OpenVASProvider:
    name = "openvas"


class ZAPProvider:
    name = "zap"


class NmapProvider:
    name = "nmap"


class ThreatIntelProvider:
    name = "cti"


class CredentialExposureProvider:
    name = "leak"


DEFAULT_PROVIDERS = [
    NucleiProvider,
    OpenVASProvider,
    ZAPProvider,
    NmapProvider,
    ThreatIntelProvider,
    CredentialExposureProvider,
]
