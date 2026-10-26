import json

import pytest

from signalf0rge.agent import Investigation
from signalf0rge.incident_narrative import generate_narrative
from signalf0rge.models import Finding


def fixtures():
    case = Investigation(
        entity="host-1", severity="high", confidence="medium",
        finding_count=1, finding_ids=["ENDPOINT-001"], mitre_techniques=["T1059.001"],
        first_seen="2026-10-20T10:00:00", last_seen="2026-10-20T10:01:00",
        evidence_count=1, summary="Suspicious execution",
        recommended_actions=["Review host"],
    )
    finding = Finding(
        rule_id="ENDPOINT-001", title="Suspicious PowerShell", description="Detected",
        severity="high", entity="host-1", mitre=["T1059.001"],
        first_seen="2026-10-20T10:00:00", last_seen="2026-10-20T10:01:00",
        evidence_count=1, evidence=[], score=80,
    )
    return case, [finding]


def narrative():
    return {
        "summary": "A PowerShell detection requires review.",
        "timeline": [{"timestamp": "2026-10-20T10:00:00",
                      "description": "PowerShell detection recorded",
                      "finding_ids": ["ENDPOINT-001"]}],
        "gaps": ["Process ancestry not available"],
        "next_steps": ["Review endpoint telemetry"],
        "cited_finding_ids": ["ENDPOINT-001"],
    }


def mock_response(monkeypatch, data):
    monkeypatch.setattr(
        "signalf0rge.incident_narrative._request_json",
        lambda *args: {"choices": [{"message": {"content": json.dumps(data)}}]},
    )


def test_grounded_narrative_preserves_deterministic_severity(monkeypatch):
    mock_response(monkeypatch, narrative())
    case, findings = fixtures()
    result = generate_narrative(case, findings, "key", "model")
    assert result.severity == "high"
    assert result.cited_finding_ids == ["ENDPOINT-001"]
    assert result.timeline[0]["timestamp"] == case.first_seen


def test_rejects_hallucinated_finding(monkeypatch):
    data = narrative()
    data["cited_finding_ids"] = ["FAKE-999"]
    mock_response(monkeypatch, data)
    with pytest.raises(ValueError, match="unsupported finding citations"):
        generate_narrative(*fixtures(), "key", "model")


def test_rejects_invented_timeline_timestamp(monkeypatch):
    data = narrative()
    data["timeline"][0]["timestamp"] = "2026-10-21T12:00:00"
    mock_response(monkeypatch, data)
    with pytest.raises(ValueError, match="timestamp is not supported"):
        generate_narrative(*fixtures(), "key", "model")


def test_rejects_uncited_timeline(monkeypatch):
    data = narrative()
    data["timeline"][0]["finding_ids"] = []
    mock_response(monkeypatch, data)
    with pytest.raises(ValueError, match="unsupported finding citations"):
        generate_narrative(*fixtures(), "key", "model")
