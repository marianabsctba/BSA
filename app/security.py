import ipaddress, os, socket
from urllib.parse import urlparse

def _public_ip(ip):
    obj=ipaddress.ip_address(ip)
    if obj.is_loopback or obj.is_private or obj.is_link_local or obj.is_multicast or obj.is_reserved or obj.is_unspecified:
        return False
    return obj.is_global

def resolve_public(hostname: str) -> list[str]:
    host=hostname.strip().rstrip(".")
    try:
        infos=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
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
    host=parsed.hostname
    try:
        ipaddress.ip_address(host)
        if not _public_ip(host): raise ValueError("private or reserved target blocked")
    except ValueError as exc:
        if "blocked" in str(exc): raise
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
