from signalf0rge.correlate import entity_for, severity_score


def test_entity_for_prefers_requested_field_then_falls_back():
    event = {"user": "alice", "host": "ws-01", "src_ip": "192.0.2.10"}

    assert entity_for(event, "host") == "host:ws-01"
    assert entity_for(event, "missing") == "user:alice"


def test_entity_for_skips_empty_identity_values():
    event = {"user": "", "host": None, "src_ip": "192.0.2.10"}

    assert entity_for(event) == "src_ip:192.0.2.10"


def test_entity_for_returns_unknown_when_no_identity_fields_exist():
    assert entity_for({"event_type": "process_start"}) == "event:unknown"


def test_severity_score_increases_with_evidence_and_caps_at_100():
    assert severity_score("high", 1) == 75
    assert severity_score("high", 4) == 81
    assert severity_score("critical", 10) == 100


def test_severity_score_normalizes_case_and_ignores_nonpositive_evidence():
    assert severity_score(" HIGH ", 2) == 77
    assert severity_score("low", 0) == 25
    assert severity_score("low", -3) == 25
    assert severity_score("unrecognized", 1) == 25


def test_entity_for_uses_fallback_when_preferred_value_is_missing():
    event = {"host": "", "user": "alice", "src_ip": "192.0.2.10"}

    assert entity_for(event, "host") == "user:alice"
    assert entity_for(event, "not_present") == "user:alice"


def test_entity_for_fallback_respects_identity_priority():
    event = {"dst_ip": "203.0.113.8", "src_ip": "192.0.2.4", "host": "ws-02"}

    assert entity_for(event, "missing") == "host:ws-02"
    assert entity_for({"dst_ip": "203.0.113.8", "src_ip": "192.0.2.4"}) == "src_ip:192.0.2.4"


def test_severity_score_saturates_without_wrapping_for_large_evidence_counts():
    # Large correlation batches must not produce scores above the documented cap.
    assert severity_score("critical", 1_000_000) == 100
    assert severity_score("high", 1_000_000) == 100
    assert severity_score("low", 1_000_000) == 100


def test_severity_score_uses_distinct_info_and_medium_baselines():
    assert severity_score("info", 1) == 10
    assert severity_score("info", 3) == 14
    assert severity_score("medium", 1) == 50
    assert severity_score("medium", 3) == 54
