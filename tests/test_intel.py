from datetime import datetime, timezone
import json

from signalf0rge.intel import load_stix_bundle, enrich_events
from signalf0rge.models import Event


def test_stix_ip_indicator_matches_event(tmp_path):
    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--test",
                "name": "Known bad IP",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '203.0.113.50']",
                "confidence": 90,
                "labels": ["malicious-activity"],
            }
        ],
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    indicators = load_stix_bundle(path)
    event = Event(
        timestamp=datetime(2026, 8, 17, tzinfo=timezone.utc),
        source_type="network",
        src_ip="10.0.0.5",
        dst_ip="203.0.113.50",
        raw={"source_type": "network", "dst_ip": "203.0.113.50"},
    )
    matches = enrich_events([event], indicators)
    assert len(matches) == 1
    assert matches[0].field == "dst_ip"
    assert matches[0].indicator.confidence == 90


def test_unsupported_stix_pattern_is_skipped(tmp_path):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--complex",
                "name": "Complex pattern",
                "pattern": "[file:hashes.'SHA-256' = 'abc']",
            }
        ],
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert load_stix_bundle(path) == []


def test_domain_indicator_matches_raw_event_field(tmp_path):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--domain",
                "name": "Known bad domain",
                "pattern": "[domain-name:value = 'payload.example']",
                "labels": [],
            }
        ],
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    event = Event(
        timestamp=datetime(2026, 8, 17, tzinfo=timezone.utc),
        source_type="dns",
        raw={"source_type": "dns", "dns_query": "payload.example"},
    )
    matches = enrich_events([event], load_stix_bundle(path))
    assert len(matches) == 1
    assert matches[0].field == "dns_query"
