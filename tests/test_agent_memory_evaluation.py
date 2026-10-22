from datetime import datetime

from signalf0rge.agent import investigate
from signalf0rge.agent_evaluate import evaluate_agent_report
from signalf0rge.agent_runner import run_llm_investigation
from signalf0rge.models import Event, Finding


def _finding(severity="medium"):
    return Finding(
        rule_id="AUTH-TEST", title="Test finding", description="test",
        severity=severity, entity="alice", mitre=["T1078"],
        first_seen="2026-10-22T10:00:00", last_seen="2026-10-22T10:01:00",
        evidence_count=1, evidence=[{"event": "test"}], score=50,
    )


def test_misleading_memory_cannot_change_current_verdict(monkeypatch):
    findings = [_finding("medium")]
    case = investigate(findings)[0]
    events = [Event(datetime(2026, 10, 22, 10), "auth", user="alice", host="ws-1")]
    seen = {}

    def planner(case, previous, api_key, model, prior_cases=None, **kwargs):
        seen["memory"] = prior_cases
        return None

    monkeypatch.setattr("signalf0rge.llm_agent.choose_tool", planner)
    history = [{
        "entity": "alice",
        "verdict": "escalate",
        "severity": "critical",
        "confidence": "high",
        "tool_calls": ["get_related_findings"],
        "evidence_items": 99,
    }]

    report = run_llm_investigation(
        case, events, findings, "test-key", "test-model", case_history=history
    )
    metrics = evaluate_agent_report(report, expected_verdict="review")

    assert seen["memory"] == history
    assert report.verdict == "review"
    assert report.severity == "medium"
    assert metrics["verdict_grounded"] is True


def test_other_entity_memory_is_not_exposed_to_planner(monkeypatch):
    findings = [_finding("high")]
    case = investigate(findings)[0]
    seen = {}

    def planner(case, previous, api_key, model, prior_cases=None, **kwargs):
        seen["memory"] = prior_cases
        return None

    monkeypatch.setattr("signalf0rge.llm_agent.choose_tool", planner)
    run_llm_investigation(
        case, [], findings, "test-key", "test-model",
        case_history=[{"entity": "bob", "verdict": "escalate", "severity": "critical"}],
    )

    assert seen["memory"] == []
