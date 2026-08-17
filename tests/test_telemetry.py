from pathlib import Path

from signalf0rge.engine import analyze
from signalf0rge.rules import load_rules
from signalf0rge.telemetry import load_windows_jsonl


def test_windows_sysmon_adapter_normalizes_security_events():
    root = Path(__file__).resolve().parents[1]
    events = load_windows_jsonl(root / "samples" / "windows_sysmon_events.jsonl")

    assert len(events) == 15

    failed = next(event for event in events if event.action == "login_failed")
    assert failed.source_type == "auth"
    assert failed.user == "finance1"
    assert failed.src_ip == "198.51.100.77"
    assert failed.get("windows_event_id") == 4625

    powershell = next(event for event in events if event.command and "-enc " in event.command)
    assert powershell.source_type == "endpoint"
    assert powershell.user == "alex"
    assert powershell.host == "WS22.corp.local"

    network = next(event for event in events if event.dst_port == 4444)
    assert network.source_type == "network"
    assert network.user == "alex"
    assert network.dst_ip == "203.0.113.200"


def test_windows_sysmon_sample_drives_detection_and_incident_correlation():
    root = Path(__file__).resolve().parents[1]
    events = load_windows_jsonl(root / "samples" / "windows_sysmon_events.jsonl")
    rules = load_rules(root / "rules.yml")
    findings = analyze(events, rules)
    detected = {finding.rule_id for finding in findings}

    expected = {
        "AUTH-004",
        "ENDPOINT-002",
        "ENDPOINT-004",
        "BEHAVIOR-001",
        "NET-001",
        "INCIDENT-001",
        "ENDPOINT-005",
        "ENDPOINT-010",
        "ENDPOINT-013",
    }
    assert expected <= detected

    incident = next(finding for finding in findings if finding.rule_id == "INCIDENT-001")
    assert incident.entity == "user:alex"
    assert incident.evidence_count == 4
    assert incident.score == 100
    assert all("correlation_id" not in evidence for evidence in incident.evidence)
