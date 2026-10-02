import json

from app.integration_export import unified_siem_events
from app.syslog_export import SyslogConfig, rfc5424_message
from app.models import Asset, AssetType, Finding, Severity


def test_unified_siem_stream_contains_findings_and_drp():
    asset=Asset(
        tenant_id="tenant-a",
        id="asset-a",
        value="a.example.org",
        type=AssetType.DOMAIN,
        confidence=95,
        criticality=4,
        source="test",
        first_seen="2026-10-02T09:00:00+00:00",
        last_seen="2026-10-02T10:00:00+00:00",
    )
    finding=Finding(
        tenant_id="tenant-a",
        id="finding-a",
        asset_id="asset-a",
        title="Exposure",
        severity=Severity.HIGH,
        confidence=90,
        evidence="observed",
        detected_at="2026-10-02T10:00:00+00:00",
    )

    stream=unified_siem_events(
        "tenant-a",
        [asset],
        [finding],
        [{
            "event_id":"drp-1",
            "category":"credential_leak",
            "indicator":"feed-1",
            "severity":"high",
            "confidence":88,
            "risk_score":82,
            "risk_band":"high",
            "risk_reasons":["credential_exposure"],
            "status":"open",
            "source":"feed-a",
            "asset_id":"asset-a",
            "last_seen":"2026-10-02T10:01:00+00:00",
            "evidence":{"sample_hash":"abc"},
        }],
        limit=10,
    )

    assert stream["count"]==2
    assert set(stream["event_types"])=={"exposure.finding","digital_risk.credential_leak"}
    assert all(x["tenant_id"]=="tenant-a" for x in stream["events"])

def test_rfc5424_payload_filters_secrets_and_hardens_header():
    cfg=SyslogConfig(host="siem.example.org",transport="tls",app_name="bad app\nname")
    raw=rfc5424_message({
        "event_type":"digital_risk.credential_leak\nattack",
        "event_id":"drp:1",
        "observed_at":"2026-10-02T10:00:00Z\nBAD",
        "tenant_id":"tenant-a",
        "severity":"high",
        "evidence":{
            "sample_hash":"abc",
            "password":"never-send",
            "token":"never-send",
        },
    },cfg,hostname="bsa host\nattack").decode("utf-8")

    header,payload=raw.rsplit(" - ",1)
    assert "\n" not in header
    assert "bad_app_name" in header
    assert "bsa_host_attack" in header
    parsed=json.loads(payload)
    assert parsed["evidence"]["sample_hash"]=="abc"
    assert "password" not in parsed["evidence"]
    assert "token" not in parsed["evidence"]


def test_syslog_config_defaults_to_tls(monkeypatch):
    from app.syslog_export import config_from_env

    monkeypatch.setenv("BSA_SYSLOG_HOST","siem.example.org")
    monkeypatch.delenv("BSA_SYSLOG_TRANSPORT",raising=False)
    monkeypatch.delenv("BSA_SYSLOG_PORT",raising=False)
    cfg=config_from_env()

    assert cfg.transport=="tls"
    assert cfg.port==6514
