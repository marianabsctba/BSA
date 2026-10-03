"""Hardened Nuclei adapter used by the assessment registry.

Keeps HTTP redirects disabled so a validated external target cannot steer the
scanner toward an unvalidated destination through a redirect chain.
"""

from .assessment_providers import NucleiProvider as BaseNucleiProvider


class SafeNucleiProvider(BaseNucleiProvider):
    """Nuclei provider with redirects disabled by policy."""

    name = "nuclei"

    def _command(self, target: str) -> list[str]:
        command = super()._command(target)
        if "-dr" not in command and "-disable-redirects" not in command:
            command.extend(["-dr"])
        return command
