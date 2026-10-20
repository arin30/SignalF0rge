from datetime import datetime

from signalf0rge.agent import investigate
from signalf0rge.agent_runner import run_investigation
from signalf0rge.investigation_tools import search_events
from signalf0rge.models import Event, Finding


def _finding(entity="alice", severity="high"):
    return Finding(
        rule_id="PS-1",
        title="Suspicious PowerShell",
        description="test",
        severity=severity,
        entity=entity,
        mitre=["T1059.001"],
        first_seen="2026-10-20T10:00:00",
        last_seen="2026-10-20T10:01:00",
        evidence_count=1,
        evidence=[{"event": "test"}],
        score=80,
    )


def test_search_events_matches_requested_field():
    events = [
        Event(datetime(2026, 10, 20, 10), "auth", user="alice", host="ws-1"),
        Event(datetime(2026, 10, 20, 11), "auth", user="bob", host="ws-2"),
    ]

    result = search_events(events, user="alice")

    assert result.tool == "search_events"
    assert len(result.results) == 1
    assert result.results[0]["host"] == "ws-1"


def test_agent_runs_evidence_tools_and_escalates_high_case():
    findings = [_finding()]
    events = [Event(datetime(2026, 10, 20, 10), "endpoint", user="alice", host="ws-1")]
    case = investigate(findings)[0]

    report = run_investigation(case, events, findings)

    assert report.verdict == "escalate"
    assert report.entity == "alice"
    assert [step.tool for step in report.steps] == [
        "get_related_findings",
        "get_entity_links",
        "map_attack",
        "search_events",
    ]
    assert "Conclusions are limited" in report.evidence_summary
