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


def test_threshold_rule_expires_events_outside_window():
    start = datetime(2026, 8, 17, 10, 0, tzinfo=timezone.utc)
    events = []
    for minutes in (0, 1, 2, 3, 14):
        timestamp = start + timedelta(minutes=minutes)
        events.append(
            Event(
                timestamp=timestamp,
                source_type="auth",
                src_ip="203.0.113.11",
                action="login_failed",
                raw={
                    "timestamp": timestamp.isoformat(),
                    "source_type": "auth",
                    "src_ip": "203.0.113.11",
                    "action": "login_failed",
                },
            )
        )

    rule = Rule(
        {
            "id": "AUTH-WINDOW",
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

    assert analyze(events, [rule]) == []


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


def test_distinct_count_rule():
    start = datetime(2026, 8, 17, 11, 0, tzinfo=timezone.utc)
    users = ["alice", "bob", "carol", "dave", "erin"]
    events = []
    for i, user in enumerate(users):
        timestamp = start + timedelta(seconds=i * 30)
        events.append(Event(timestamp=timestamp, source_type="auth", user=user, src_ip="198.51.100.90", action="login_failed", raw={"timestamp": timestamp.isoformat(), "source_type": "auth", "user": user, "src_ip": "198.51.100.90", "action": "login_failed"}))

    rule = Rule({"id":"AUTH-SPRAY","title":"Password spray","description":"","kind":"distinct_count","source_type":"auth","match":{"action":"login_failed"},"group_by":"src_ip","distinct_field":"user","threshold":5,"window_minutes":10,"severity":"high","mitre":["T1110.003"]})
    findings = analyze(events, [rule])

    assert len(findings) == 1
    assert findings[0].evidence_count == 5
    assert findings[0].entity == "src_ip:198.51.100.90"


def test_multi_sequence_rule():
    start = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)
    events = [
        Event(timestamp=start, source_type="endpoint", host="ws-01", command="powershell.exe -nop", raw={"timestamp": start.isoformat(), "source_type": "endpoint", "host": "ws-01", "command": "powershell.exe -nop"}),
        Event(timestamp=start + timedelta(minutes=2), source_type="endpoint", host="ws-01", message="Suspicious access to LSASS detected", raw={"timestamp": (start + timedelta(minutes=2)).isoformat(), "source_type": "endpoint", "host": "ws-01", "message": "Suspicious access to LSASS detected"}),
    ]
    rule = Rule({"id":"BEHAVIOR-TEST","title":"PowerShell then LSASS","description":"","kind":"multi_sequence","group_by":"host","window_minutes":10,"steps":[{"source_type":"endpoint","contains":{"command":["powershell"]}},{"source_type":"endpoint","contains":{"message":["lsass"]}}],"severity":"critical","mitre":["T1059.001","T1003.001"]})

    findings = analyze(events, [rule])
    assert len(findings) == 1
    assert findings[0].evidence_count == 2
    assert findings[0].entity == "host:ws-01"


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


def test_advanced_samples_cover_phase2_and_phase3():
    root = Path(__file__).resolve().parents[1]
    events = load_jsonl(root / "samples" / "advanced_events.jsonl")
    rules = load_rules(root / "rules.yml")
    findings = analyze(events, rules)
    detected = {finding.rule_id for finding in findings}

    expected = {"AUTH-004", "BEHAVIOR-001", "NET-003", "NET-004", "INCIDENT-001"}
    assert expected <= detected

    incident = next(finding for finding in findings if finding.rule_id == "INCIDENT-001")
    assert incident.entity == "user:alex"
    assert incident.evidence_count == 4
    assert incident.score == 100
