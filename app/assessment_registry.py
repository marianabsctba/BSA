"""Assessment provider registry.

Keeps Be Safe ASM independent from individual assessment tools. Provider
identities stay internal; product/API consumers work with generic capabilities.
"""

from dataclasses import dataclass
from typing import Dict, Type

from .assessment_providers import (
    AssessmentProvider,
    AmassProvider,
    PureDnsProvider,
    AlterXProvider,
    AssetfinderProvider,
    AsnIntelligenceProvider,
    CredentialExposureProvider,
    CloudExposureProvider,
    DnsValidationProvider,
    HistoricalUrlProvider,
    HIBPProvider,
    HttpProbeProvider,
    HudsonRockProvider,
    NmapProvider,
    NucleiProvider,
    PortExposureProvider,
    OpenVASProvider,
    SafeWebProvider,
    SubdomainProvider,
    ThreatIntelProvider,
    ThreatFoxProvider,
    TlsIntelligenceProvider,
    WebCrawlProvider,
    WhatWebProvider,
    TestSslProvider,
    SecretExposureProvider,
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
            "cloud_intelligence": EngineCapability("cloud_intelligence", "cloud", "Cloud footprint and exposure intelligence"),
            "network_intelligence": EngineCapability("network_intelligence", "network", "ASN and network ownership intelligence"),
        }
        self._register_defaults()

    def _register_defaults(self):
        for provider in (
            SubdomainProvider,
            AmassProvider,
            AssetfinderProvider,
            AlterXProvider,
            PureDnsProvider,
            AsnIntelligenceProvider,
            DnsValidationProvider,
            HttpProbeProvider,
            TlsIntelligenceProvider,
            HistoricalUrlProvider,
            WebCrawlProvider,
            WhatWebProvider,
            TestSslProvider,
            CloudExposureProvider,
            NucleiProvider,
            NmapProvider,
            PortExposureProvider,
            SafeWebProvider,
            SecretExposureProvider,
            OpenVASProvider,
            ZAPProvider,
            ThreatFoxProvider,
            HIBPProvider,
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

    def available(self, name: str, target: str | None = None) -> bool:
        provider = self.provider(name)
        supports = getattr(provider, "supports", None)
        if callable(supports) and target is not None and not supports(target):
            return False
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

    def capability_health(self, target: str | None = None) -> list[dict]:
        mapping = {
            "discovery": ("subfinder", "amass", "assetfinder", "alterx", "puredns", "dnsx"),
            "fingerprint": ("httpx", "whatweb"),
            "vulnerability": ("nuclei", "openvas"),
            "service_exposure": ("naabu", "nmap"),
            "web_assessment": ("safeweb", "zap", "katana"),
            "intelligence": ("cti", "threatfox"),
            "credential_exposure": ("leak", "trufflehog"),
            "cloud_intelligence": ("cloud",),
            "network_intelligence": ("asnmap",),
        }
        rows = []
        for capability, providers in mapping.items():
            states = []
            for provider in providers:
                try:
                    states.append(self.available(provider, target))
                except Exception:
                    states.append(False)
            available = sum(1 for state in states if state)
            rows.append({
                "name": capability,
                "status": "ready" if available == len(states) else "partial" if available else "unavailable",
                "available_backends": available,
                "backend_count": len(states),
            })
        return rows

    def list_engines(self):
        # Backwards compatibility. Deliberately returns product capabilities,
        # never private provider/tool names.
        return self.list_capabilities()


registry = AssessmentRegistry()
