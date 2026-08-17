from datetime import datetime, timezone, timedelta
from pathlib import Path
from signalf0rge.models import Event
from signalf0rge.rules import Rule, load_rules
from signalf0rge.engine import analyze
from signalf0rge.parser import load_jsonl


def test_threshold_rule():
    start = datetime(2026, 8, 17, 10, 0, tzinfo=timezone.utc)
    events = []
    for i in range(5):
        timestamp = start + timedelta(minutes=i)
        events.append(
            Event(
                timestamp=timestamp,
                source_type="auth",
                src_ip="203.0.113.10",
                action="login_failed",
                raw={
                    "timestamp": timestamp.isoformat(),
                    "source_type": "auth",
                    "src_ip": "203.0.113.10",
                    "action": "login_failed",
                },
            )
        )

    rule = Rule(
        {
            "id": "AUTH-001",
            "title": "Repeated failed authentication",
            "description": "",
            "kind": "threshold",
            "source_type": "auth",
            "match": {"action": "login_failed"},
            "group_by": "src_ip",
            "threshold": 5,
            "window_minutes": 10,
            "severity": "medium",
            "mitre": ["T1110"],
        }
    )

    findings = analyze(events, [rule])
    assert len(findings) == 1
    assert findings[0].evidence_count == 5
    assert findings[0].entity == "src_ip:203.0.113.10"


def test_success_after_failures_sequence():
    start = datetime(2026, 8, 17, 10, 0, tzinfo=timezone.utc)
    events = []
    for i in range(5):
        timestamp = start + timedelta(minutes=i)
        events.append(Event(timestamp=timestamp, source_type="auth", user="arin", action="login_failed", raw={"timestamp": timestamp.isoformat(), "source_type": "auth", "user": "arin", "action": "login_failed"}))

    success_time = start + timedelta(minutes=6)
    events.append(Event(timestamp=success_time, source_type="auth", user="arin", action="login_success", raw={"timestamp": success_time.isoformat(), "source_type": "auth", "user": "arin", "action": "login_success"}))

    rule = Rule({"id":"AUTH-002","title":"Success after failures","description":"","kind":"sequence","source_type":"auth","sequence":{"first":{"action":"login_failed"},"second":{"action":"login_success"}},"group_by":"user","threshold":5,"window_minutes":15,"severity":"high","mitre":["T1110","T1078"]})

    findings = analyze(events, [rule])
    assert len(findings) == 1
    assert findings[0].evidence_count == 6


def test_phase1_detection_samples_cover_new_rules():
    root = Path(__file__).resolve().parents[1]
    events = load_jsonl(root / "samples" / "phase1_events.jsonl")
    rules = load_rules(root / "rules.yml")
    findings = analyze(events, rules)
    detected = {finding.rule_id for finding in findings}

    expected = {
        "AUTH-003",
        "ENDPOINT-005",
        "ENDPOINT-006",
        "ENDPOINT-007",
        "ENDPOINT-008",
        "ENDPOINT-009",
        "ENDPOINT-010",
        "ENDPOINT-011",
        "ENDPOINT-012",
        "ENDPOINT-013",
        "ENDPOINT-014",
    }

    assert expected <= detected
    assert "AUTH-001" not in detected
