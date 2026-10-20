import json

import pytest

from signalf0rge.llm_agent import LLMDecision, execute_decision
from signalf0rge.models import Event, Finding
from datetime import datetime


def _finding():
    return Finding(
        rule_id="AUTH-1", title="Login", description="test", severity="medium",
        entity="alice", mitre=["T1078"], first_seen="2026-10-20T10:00:00",
        last_seen="2026-10-20T10:01:00", evidence_count=1,
        evidence=[{"event": "test"}], score=50,
    )


def test_execute_llm_search_decision_is_allowlisted():
    events = [Event(datetime(2026, 10, 20, 10), "auth", user="alice")]
    decision = LLMDecision("search_events", {"field": "user", "value": "alice"}, "pivot user")

    result = execute_decision(decision, events, [_finding()], "alice")

    assert len(result.results) == 1


def test_execute_llm_search_rejects_arbitrary_fields():
    decision = LLMDecision("search_events", {"field": "raw", "value": "x"}, "bad pivot")

    with pytest.raises(RuntimeError, match="Invalid search_events arguments"):
        execute_decision(decision, [], [_finding()], "alice")
