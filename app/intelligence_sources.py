"""Trusted intelligence source catalog for Be Safe ASM.

Source identities are internal implementation details. Product APIs should
surface normalized evidence, confidence and provenance class, not credentials
or raw feed payloads.
"""

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class IntelligenceSource:
    key: str
    category: str
    trust: str
    purpose: str
    endpoint: str
    auth_env: str | None = None
    enabled_by_default: bool = True


SOURCES: Mapping[str, IntelligenceSource] = {
    "cisa_kev": IntelligenceSource(
        key="cisa_kev",
        category="vulnerability",
        trust="authoritative",
        purpose="Known exploited vulnerability confirmation",
        endpoint="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    "nvd": IntelligenceSource(
        key="nvd",
        category="vulnerability",
        trust="authoritative",
        purpose="CVE, CVSS and CPE enrichment",
        endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        auth_env="BSA_NVD_API_KEY",
    ),
    "first_epss": IntelligenceSource(
        key="first_epss",
        category="vulnerability",
        trust="authoritative",
        purpose="Exploit probability enrichment",
        endpoint="https://api.first.org/data/v1/epss",
    ),
    "threatfox": IntelligenceSource(
        key="threatfox",
        category="threat_intelligence",
        trust="community_verified",
        purpose="Malware and IOC correlation",
        endpoint="https://threatfox-api.abuse.ch/api/v1/",
        auth_env="BSA_THREATFOX_AUTH_KEY",
    ),
    "urlhaus": IntelligenceSource(
        key="urlhaus",
        category="threat_intelligence",
        trust="community_verified",
        purpose="Malicious URL and host correlation",
        endpoint="https://urlhaus-api.abuse.ch/v1/",
        auth_env="BSA_URLHAUS_AUTH_KEY",
    ),
    "hibp": IntelligenceSource(
        key="hibp",
        category="credential_exposure",
        trust="established_commercial",
        purpose="Domain-scoped breach exposure intelligence",
        endpoint="https://haveibeenpwned.com/api/v3/",
        auth_env="BSA_HIBP_API_KEY",
        enabled_by_default=False,
    ),
}


def sources_for(category: str) -> list[IntelligenceSource]:
    return [x for x in SOURCES.values() if x.category == category]


def public_source_health() -> list[dict]:
    """Return product-safe metadata without endpoints, keys or vendor secrets."""
    return [
        {
            "category": source.category,
            "trust": source.trust,
            "purpose": source.purpose,
            "enabled_by_default": source.enabled_by_default,
        }
        for source in SOURCES.values()
    ]
