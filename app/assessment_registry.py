"""Assessment provider registry.

Keeps the ASM independent from specific scanners. Engines can be enabled
per tenant without exposing vendor/tool details in the product UI.
"""

from dataclasses import dataclass
from typing import Callable, Dict, Any


@dataclass(frozen=True)
class EngineCapability:
    name: str
    category: str
    description: str
    enabled: bool = True


class AssessmentRegistry:
    def __init__(self):
        self.providers: Dict[str, Callable[..., Any]] = {}
        self.capabilities = {
            "discovery": EngineCapability("discovery", "surface", "External asset discovery and enumeration"),
            "fingerprint": EngineCapability("fingerprint", "technology", "Technology and service identification"),
            "vulnerability": EngineCapability("vulnerability", "security", "Evidence based vulnerability assessment"),
            "web_assessment": EngineCapability("web_assessment", "application", "Safe web exposure assessment"),
            "intelligence": EngineCapability("intelligence", "cti", "Threat intelligence correlation"),
        }

    def register(self, name: str, provider: Callable[..., Any]):
        self.providers[name] = provider

    def list_engines(self):
        return [
            {"name": x.name, "category": x.category, "description": x.description, "enabled": x.enabled}
            for x in self.capabilities.values()
        ]

    def execute(self, name: str, **kwargs):
        if name not in self.providers:
            raise ValueError(f"assessment provider unavailable: {name}")
        return self.providers[name](**kwargs)


registry = AssessmentRegistry()
