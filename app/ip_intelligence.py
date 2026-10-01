import ipaddress
from dataclasses import dataclass

def classify_ip(value):
    try:
        ip=ipaddress.ip_address(value)
    except ValueError:return None
    if ip.is_loopback:return "loopback"
    if ip.is_private:return "private"
    if ip.is_reserved:return "reserved"
    if ip.is_multicast:return "multicast"
    if ip.is_global:return "global"
    return "other"

def ip_exposure_signal(value):
    kind=classify_ip(value)
    return {"ip":value,"scope":kind,"externally_routable":kind=="global"}


@dataclass(frozen=True)
class IPExposure:
    ip: str
    scope: str
    externally_routable: bool
    routability_reason: str

def explain_ip_exposure(value: str) -> IPExposure:
    kind=classify_ip(value)
    if kind is None:
        return IPExposure(value,"invalid",False,"IP inválido")
    if kind=="global":
        return IPExposure(value,kind,True,"endereço globalmente roteável")
    return IPExposure(value,kind,False,f"endereço não globalmente roteável: {kind}")
