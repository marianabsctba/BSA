from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import time
from typing import Any
from urllib import error, request
from urllib.parse import urlparse

from .security import validate_external_target


class ITSMWebhookError(RuntimeError):
    pass


@dataclass(frozen=True)
class ITSMWebhookConfig:
    url: str
    secret: str
    timeout_seconds: int = 8
    max_attempts: int = 3


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def config_from_env() -> ITSMWebhookConfig | None:
    url=str(os.getenv("BSA_ITSM_WEBHOOK_URL") or "").strip()
    secret=str(os.getenv("BSA_ITSM_WEBHOOK_SECRET") or "").strip()
    if not url and not secret:
        return None
    if not url or not secret:
        raise ValueError("ITSM webhook requires URL and secret")
    parsed=urlparse(url)
    env=str(os.getenv("BSA_ENV") or "development").lower()
    if env in {"production","prod"} and parsed.scheme!="https":
        raise ValueError("ITSM webhook must use HTTPS in production")
    validate_external_target(url)
    timeout=max(2,min(int(os.getenv("BSA_ITSM_WEBHOOK_TIMEOUT","8")),30))
    attempts=max(1,min(int(os.getenv("BSA_ITSM_WEBHOOK_ATTEMPTS","3")),5))
    return ITSMWebhookConfig(url=url,secret=secret,timeout_seconds=timeout,max_attempts=attempts)


def build_mobilization_event(
    *,
    tenant_id: str,
    resource_type: str,
    resource_id: str,
    severity: str,
    title: str,
    payload: dict[str,Any],
) -> dict[str,Any]:
    observed_at=datetime.now(timezone.utc).isoformat()
    event_id=hashlib.sha256(
        f"{tenant_id}|{resource_type}|{resource_id}".encode()
    ).hexdigest()[:32]
    return {
        "schema_version":"1.0",
        "event_type":"mobilization.requested",
        "event_id":event_id,
        "observed_at":observed_at,
        "tenant_id":tenant_id,
        "resource_type":resource_type,
        "resource_id":resource_id,
        "severity":str(severity or "medium").lower(),
        "title":str(title or resource_id),
        "payload":payload,
    }


def _canonical_body(event: dict[str,Any]) -> bytes:
    return json.dumps(event,ensure_ascii=False,separators=(",",":"),sort_keys=True).encode()


def _signature(secret: str, body: bytes) -> str:
    return "sha256="+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()


def _send_once(event: dict[str,Any], cfg: ITSMWebhookConfig) -> dict[str,Any]:
    body=_canonical_body(event)
    req=request.Request(
        cfg.url,
        data=body,
        method="POST",
        headers={
            "Content-Type":"application/json",
            "User-Agent":"Be-Safe-ASM/ITSM",
            "X-BSA-Signature":_signature(cfg.secret,body),
            "Idempotency-Key":str(event["event_id"]),
        },
    )
    opener=request.build_opener(_NoRedirect())
    try:
        with opener.open(req,timeout=cfg.timeout_seconds) as response:
            status=int(getattr(response,"status",200))
            return {"delivered":200<=status<300,"status_code":status}
    except error.HTTPError as exc:
        return {"delivered":False,"status_code":int(exc.code)}
    except (error.URLError,TimeoutError,OSError) as exc:
        raise ITSMWebhookError("ITSM webhook delivery failed") from exc


def deliver_event(event: dict[str,Any], cfg: ITSMWebhookConfig | None=None) -> dict[str,Any]:
    cfg=cfg or config_from_env()
    if cfg is None:
        raise ITSMWebhookError("ITSM webhook not configured")
    validate_external_target(cfg.url)
    last: dict[str,Any] | None=None
    for attempt in range(1,cfg.max_attempts+1):
        try:
            result=_send_once(event,cfg)
        except ITSMWebhookError:
            result={"delivered":False,"status_code":None}
        last=result
        status=result.get("status_code")
        if result.get("delivered"):
            return {**result,"attempts":attempt,"event_id":event["event_id"]}
        if status is not None and int(status)<500:
            break
        if attempt<cfg.max_attempts:
            time.sleep(min(0.25*(2**(attempt-1)),1.0))
    return {
        **(last or {"delivered":False,"status_code":None}),
        "attempts":attempt,
        "event_id":event["event_id"],
    }
