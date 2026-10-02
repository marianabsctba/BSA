"""SIEM/Syslog outbound delivery for Be Safe ASM.

The transport is intentionally small and vendor-neutral:
- JSON event envelope
- RFC5424-style framing
- UDP, TCP or TLS
- no secret payloads
"""
from __future__ import annotations

import json
import os
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class SyslogConfig:
    host: str
    port: int = 6514
    transport: str = "tls"
    facility: int = 16
    app_name: str = "be-safe-asm"
    timeout: float = 5.0
    ca_file: str | None = None
    server_name: str | None = None


def config_from_env() -> SyslogConfig | None:
    host=os.getenv("BSA_SYSLOG_HOST","").strip()
    if not host:
        return None
    transport=os.getenv("BSA_SYSLOG_TRANSPORT","tls").strip().lower()
    if transport not in {"udp","tcp","tls"}:
        raise ValueError("BSA_SYSLOG_TRANSPORT must be udp, tcp or tls")
    port=int(os.getenv("BSA_SYSLOG_PORT","6514" if transport=="tls" else "514"))
    if not 1 <= port <= 65535:
        raise ValueError("BSA_SYSLOG_PORT out of range")
    return SyslogConfig(
        host=host,
        port=port,
        transport=transport,
        facility=max(0,min(23,int(os.getenv("BSA_SYSLOG_FACILITY","16")))),
        app_name=(os.getenv("BSA_SYSLOG_APP_NAME","be-safe-asm").strip() or "be-safe-asm")[:48],
        timeout=max(1.0,min(30.0,float(os.getenv("BSA_SYSLOG_TIMEOUT","5")))),
        ca_file=os.getenv("BSA_SYSLOG_CA_FILE") or None,
        server_name=os.getenv("BSA_SYSLOG_SERVER_NAME") or None,
    )


def _severity(event: dict) -> int:
    value=str(
        event.get("finding",{}).get("severity")
        or event.get("severity")
        or event.get("risk",{}).get("band")
        or event.get("risk_band")
        or "info"
    ).lower()
    return {
        "critical":2,
        "high":3,
        "medium":4,
        "low":5,
        "info":6,
    }.get(value,6)


def _safe_event(event: dict) -> dict:
    blocked={"password","secret","token","credential","raw_secret","raw_value"}
    def clean(value):
        if isinstance(value,dict):
            return {k:clean(v) for k,v in value.items() if str(k).lower() not in blocked}
        if isinstance(value,list):
            return [clean(v) for v in value]
        return value
    return clean(event)


def rfc5424_message(event: dict, config: SyslogConfig, hostname: str | None=None) -> bytes:
    safe=_safe_event(event)
    severity=_severity(safe)
    pri=config.facility*8+severity
    ts=str(safe.get("observed_at") or datetime.now(timezone.utc).isoformat())
    host=(hostname or socket.gethostname() or "bsa")[:255]
    msgid=str(safe.get("event_type") or "bsa.event").replace(" ","_")[:32]
    payload=json.dumps(safe,ensure_ascii=False,separators=(",",":"),sort_keys=True)
    return f"<{pri}>1 {ts} {host} {config.app_name} - {msgid} - {payload}\n".encode("utf-8")


def send_event(event: dict, config: SyslogConfig | None=None) -> dict:
    cfg=config or config_from_env()
    if cfg is None:
        return {"enabled":False,"delivered":False,"reason":"not_configured"}

    payload=rfc5424_message(event,cfg)
    if cfg.transport=="udp":
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(cfg.timeout)
            sent=sock.sendto(payload,(cfg.host,cfg.port))
        return {"enabled":True,"delivered":sent==len(payload),"transport":"udp","bytes":sent}

    raw=socket.create_connection((cfg.host,cfg.port),timeout=cfg.timeout)
    try:
        if cfg.transport=="tls":
            context=ssl.create_default_context(cafile=cfg.ca_file)
            server_name=cfg.server_name or cfg.host
            stream=context.wrap_socket(raw,server_hostname=server_name)
        else:
            stream=raw
        try:
            stream.sendall(payload)
        finally:
            if stream is not raw:
                stream.close()
    finally:
        try:
            raw.close()
        except Exception:
            pass
    return {"enabled":True,"delivered":True,"transport":cfg.transport,"bytes":len(payload)}


def send_events(events: list[dict], config: SyslogConfig | None=None, limit: int=500) -> dict:
    cfg=config or config_from_env()
    if cfg is None:
        return {"enabled":False,"delivered":0,"failed":0,"reason":"not_configured"}
    delivered=0
    failures=[]
    for event in events[:max(1,min(1000,int(limit or 500)))]:
        try:
            result=send_event(event,cfg)
            delivered+=1 if result.get("delivered") else 0
        except Exception as exc:
            failures.append({"event_id":event.get("event_id"),"error":type(exc).__name__})
    return {
        "enabled":True,
        "transport":cfg.transport,
        "host":cfg.host,
        "port":cfg.port,
        "delivered":delivered,
        "failed":len(failures),
        "failures":failures[:20],
    }
