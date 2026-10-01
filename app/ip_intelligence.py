import ipaddress

def classify_ip(value):
    try:
        ip=ipaddress.ip_address(value)
    except ValueError:return None
    if ip.is_private:return "private"
    if ip.is_loopback:return "loopback"
    if ip.is_reserved:return "reserved"
    if ip.is_multicast:return "multicast"
    if ip.is_global:return "global"
    return "other"

def ip_exposure_signal(value):
    kind=classify_ip(value)
    return {"ip":value,"scope":kind,"externally_routable":kind=="global"}
