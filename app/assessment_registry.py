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
            "dns_intelligence": EngineCapability("dns_intelligence", "surface", "DNS validation and relationship intelligence"),
            "network_intelligence": EngineCapability("network_intelligence", "network", "ASN and network ownership intelligence"),
            "fingerprint": EngineCapability("fingerprint", "technology", "Technology and service identification"),
            "certificate_intelligence": EngineCapability("certificate_intelligence", "certificate", "Certificate and TLS identity intelligence"),
            "tls_assessment": EngineCapability("tls_assessment", "security", "TLS posture assessment"),
            "technology_intelligence": EngineCapability("technology_intelligence", "technology", "Technology fingerprint intelligence"),
            "historical_surface": EngineCapability("historical_surface", "surface", "Historical web exposure intelligence"),
            "web_surface": EngineCapability("web_surface", "application", "Bounded web surface discovery"),
            "web_assessment": EngineCapability("web_assessment", "application", "Safe web exposure assessment"),
            "cloud_exposure": EngineCapability("cloud_exposure", "cloud", "Cloud exposure validation"),
            "vulnerability": EngineCapability("vulnerability", "security", "Evidence-based vulnerability assessment"),
            "service_exposure": EngineCapability("service_exposure", "network", "Externally reachable service validation"),
            "cloud_intelligence": EngineCapability("cloud_intelligence", "cloud", "Cloud footprint and attribution intelligence"),
            "credential_exposure": EngineCapability("credential_exposure", "identity", "Credential exposure intelligence"),
            "intelligence": EngineCapability("intelligence", "cti", "Threat intelligence correlation"),
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
            ThreatIntelProvider,
            CredentialExposureProvider,
            HIBPProvider,
            HudsonRockProvider,
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

    CAPABILITY_PROVIDERS = {
        "discovery": ("subfinder", "amass", "assetfinder", "alterx"),
        "dns_intelligence": ("puredns", "dnsx"),
        "network_intelligence": ("asnmap",),
        "fingerprint": ("httpx",),
        "certificate_intelligence": ("tlsx",),
        "tls_assessment": ("testssl",),
        "technology_intelligence": ("whatweb",),
        "historical_surface": ("gau",),
        "web_surface": ("katana",),
        "web_assessment": ("safeweb", "zap"),
        "cloud_exposure": ("cloud",),
        "vulnerability": ("nuclei", "openvas"),
        "service_exposure": ("naabu", "nmap"),
        "cloud_intelligence": ("cloud",),
        "credential_exposure": ("leak", "hibp", "hudsonrock", "trufflehog"),
        "intelligence": ("cti", "threatfox"),
    }

    def capability_health(
        self,
        target: str | None = None,
        capabilities: tuple[str, ...] | list[str] | None = None,
    ) -> list[dict]:
        requested = list(capabilities) if capabilities is not None else list(self.CAPABILITY_PROVIDERS)
        rows = []
        for capability in requested:
            providers = self.CAPABILITY_PROVIDERS.get(capability, ())
            states = []
            for provider in providers:
                try:
                    states.append(self.available(provider, target))
                except Exception:
                    states.append(False)
            available = sum(1 for state in states if state)
            operational = available > 0
            rows.append({
                "name": capability,
                "status": "ready" if providers and available == len(states) else "partial" if operational else "unavailable",
                "operational": operational,
                "available_backends": available,
                "backend_count": len(states),
            })
        return rows

    def list_engines(self):
        # Backwards compatibility. Deliberately returns product capabilities,
        # never private provider/tool names.
        return self.list_capabilities()


registry = AssessmentRegistry()
