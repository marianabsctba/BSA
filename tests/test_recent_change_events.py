import json
from datetime import datetime, timedelta, timezone

from app import history


def test_recent_changes_are_derived_from_persisted_history(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    conn=history._history_db()
    now=datetime.now(timezone.utc)
    first=(now-timedelta(hours=2)).isoformat()
    second=(now-timedelta(hours=1)).isoformat()

    conn.execute(
        """INSERT INTO asset_observations(
           tenant_id,fingerprint,observed_at,confidence,evidence_count,
           sources_json,tags_json,evidence_refs_json
           ) VALUES(?,?,?,?,?,?,?,?)""",
        ("tenant-a","fp-1",first,70,1,json.dumps(["dns"]),json.dumps([]),json.dumps(["ev-1"])),
    )
    conn.execute(
        """INSERT INTO asset_observations(
           tenant_id,fingerprint,observed_at,confidence,evidence_count,
           sources_json,tags_json,evidence_refs_json
           ) VALUES(?,?,?,?,?,?,?,?)""",
        ("tenant-a","fp-1",second,90,2,json.dumps(["dns","tls"]),json.dumps([]),json.dumps(["ev-2"])),
    )
    conn.commit()
    conn.close()

    events=history.recent_change_events("tenant-a",hours=24)
    assert [event["kind"] for event in events]==["asset_changed","new_asset"]
    changed=events[0]
    fields={item["field"] for item in changed["details"]["changes"]}
    assert {"confidence","evidence_count","sources_added"} <= fields
    assert changed["evidence_refs"]==["ev-2"]


def test_recent_changes_do_not_fabricate_tag_events_without_history(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    assert history.recent_change_events("tenant-a",hours=24)==[]
