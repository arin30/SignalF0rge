from signalf0rge.correlate import entity_for, severity_score


def test_entity_for_prefers_requested_field_then_falls_back():
    event = {"user": "alice", "host": "ws-01", "src_ip": "192.0.2.10"}

    assert entity_for(event, "host") == "host:ws-01"
    assert entity_for(event, "missing") == "user:alice"


def test_severity_score_increases_with_evidence_and_caps_at_100():
    assert severity_score("high", 1) == 75
    assert severity_score("high", 4) == 81
    assert severity_score("critical", 10) == 100
