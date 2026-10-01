"""Assessment provider registry.

Keeps Be Safe ASM independent from individual assessment tools. Provider
identities stay internal; product/API consumers work with generic capabilities.
"""

from dataclasses import dataclass
from typing import Dict, Type

from .assessment_providers import (
    AssessmentProvider,
    AmassProvider,
    CredentialExposureProvider,
    DnsValidationProvider,
    HistoricalUrlProvider,
    HttpProbeProvider,
    NmapProvider,
    NucleiProvider,
    PortExposureProvider,
    OpenVASProvider,
    SafeWebProvider,
    SubdomainProvider,
    ThreatIntelProvider,
    TlsIntelligenceProvider,
    WebCrawlProvider,
    ZAPProvider,
)


@dataclass(frozen=True)
class EngineCapability:
    name: str
    category: str
    description: str
    enabled: bool = True


class AssessmentRegistry:
    def __init__(self):
        self.providers: Dict[str, Type[AssessmentProvider]] = {}
        self.capabilities = {
            "discovery": EngineCapability("discovery", "surface", "External asset discovery and enumeration"),
            "fingerprint": EngineCapability("fingerprint", "technology", "Technology and service identification"),
            "vulnerability": EngineCapability("vulnerability", "security", "Evidence-based vulnerability assessment"),
            "service_exposure": EngineCapability("service_exposure", "network", "Externally reachable service validation"),
            "web_assessment": EngineCapability("web_assessment", "application", "Safe web exposure assessment"),
            "intelligence": EngineCapability("intelligence", "cti", "Threat intelligence correlation"),
            "credential_exposure": EngineCapability("credential_exposure", "identity", "Credential exposure intelligence"),
        }
        self._register_defaults()

    def _register_defaults(self):
        for provider in (
            SubdomainProvider,
            AmassProvider,
            DnsValidationProvider,
            HttpProbeProvider,
            TlsIntelligenceProvider,
            HistoricalUrlProvider,
            WebCrawlProvider,
            NucleiProvider,
            NmapProvider,
            PortExposureProvider,
            SafeWebProvider,
            OpenVASProvider,
            ZAPProvider,
            ThreatIntelProvider,
            CredentialExposureProvider,
        ):
            self.register(provider.name, provider)

    def register(self, name: str, provider: Type[AssessmentProvider]):
        self.providers[name] = provider

    def provider(self, name: str):
        provider_cls = self.providers.get(name)
        if provider_cls is None:
            raise ValueError(f"assessment provider unavailable: {name}")
        return provider_cls()

    def execute(self, name: str, *, target: str):
        return self.provider(name).execute(target)

    def available(self, name: str) -> bool:
        provider = self.provider(name)
        check = getattr(provider, "available", None)
        return bool(check()) if callable(check) else True

    def list_capabilities(self):
        return [
            {
                "name": item.name,
                "category": item.category,
                "description": item.description,
                "enabled": item.enabled,
            }
            for item in self.capabilities.values()
        ]

    def list_engines(self):
        # Backwards compatibility. Deliberately returns product capabilities,
        # never private provider/tool names.
        return self.list_capabilities()


registry = AssessmentRegistry()
