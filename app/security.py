import ipaddress, os, socket
import tldextract
from urllib.parse import urlparse
from dataclasses import dataclass

_TLD_EXTRACT=tldextract.TLDExtract(suffix_list_urls=None)

_CGNAT=ipaddress.ip_network("100.64.0.0/10")

def _public_ip(ip):
    obj=ipaddress.ip_address(ip)
    if obj.version==4 and obj in _CGNAT:
        return False
    if obj.is_loopback or obj.is_private or obj.is_link_local or obj.is_multicast or obj.is_reserved or obj.is_unspecified:
        return False
    return obj.is_global

def resolve_public(hostname: str) -> list[str]:
    host=hostname.strip().rstrip(".")
    try:
        infos=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("target could not be resolved") from exc
    ips=sorted({item[4][0] for item in infos})
    if not ips:
        raise ValueError("target could not be resolved")
    if any(not _public_ip(ip) for ip in ips):
        raise ValueError("target resolves to non-public address")
    return ips

def validate_external_target(target: str) -> tuple[str,str]:
    raw=target.strip()
    if not raw: raise ValueError("target vazio")
    if ":" in raw.split("/")[0] and "://" not in raw:
        raise ValueError("target inválido")
    candidate=raw if "://" in raw else "https://"+raw
    parsed=urlparse(candidate)
    if parsed.scheme not in {"http","https"} or not parsed.hostname:
        raise ValueError("target inválido")
    host=parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        if not _public_ip(host):
            raise ValueError("private or reserved target blocked")
    except ValueError as exc:
        if "blocked" in str(exc):
            raise
        extracted=_TLD_EXTRACT(host)
        if not extracted.domain or not extracted.suffix:
            raise ValueError("target must use a registrable public domain")
        resolve_public(host)
    return host, f"{parsed.scheme}://{host}"

def validate_redirect(url: str) -> None:
    host=urlparse(url).hostname
    if not host: raise ValueError("redirect inválido")
    try:
        ipaddress.ip_address(host)
        if not _public_ip(host): raise ValueError("redirect to non-public address blocked")
    except ValueError as exc:
        if "blocked" in str(exc): raise
        resolve_public(host)


def validated_external_binding(target: str) -> dict:
    """Resolve an external target once and return the exact approved IP set."""
    host, origin=validate_external_target(target)
    try:
        ip=ipaddress.ip_address(host)
        ips=[str(ip)]
    except ValueError:
        ips=resolve_public(host)
    return {"host":host,"origin":origin,"approved_ips":tuple(ips)}


@dataclass(frozen=True)
class ResolvedExternalTarget:
    host: str
    url: str
    ips: tuple[str, ...]


def resolve_external_target(target: str) -> ResolvedExternalTarget:
    """Resolve once, reject non-public destinations, and retain the approved IP set."""
    host, base_url = validate_external_target(target)
    try:
        ip = ipaddress.ip_address(host)
        ips = (str(ip),)
    except ValueError:
        ips = tuple(resolve_public(host))
    return ResolvedExternalTarget(host=host, url=base_url, ips=ips)


def revalidate_external_resolution(snapshot: ResolvedExternalTarget) -> tuple[str, ...]:
    """Reject DNS rebinding to private/reserved space after an external engine call."""
    try:
        ipaddress.ip_address(snapshot.host)
        current = snapshot.ips
    except ValueError:
        current = tuple(resolve_public(snapshot.host))
    if not current:
        raise ValueError("target resolution disappeared during assessment")
    return current
