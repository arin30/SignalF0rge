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


def test_entity_for_explicit_preference_overrides_default_identity_order():
    event = {"user": "alice", "host": "ws-01", "src_ip": "192.0.2.10"}

    assert entity_for(event, "src_ip") == "src_ip:192.0.2.10"
    assert entity_for(event) == "user:alice"


def test_entity_for_uses_destination_ip_as_last_available_identity():
    event = {"user": "", "host": None, "src_ip": "", "dst_ip": "203.0.113.42"}

    assert entity_for(event) == "dst_ip:203.0.113.42"
    assert entity_for(event, "host") == "dst_ip:203.0.113.42"


def test_entity_for_prefers_destination_when_explicitly_requested():
    event = {"user": "alice", "host": "ws-01", "dst_ip": "203.0.113.9"}

    assert entity_for(event, "dst_ip") == "dst_ip:203.0.113.9"
    assert entity_for(event, "src_ip") == "user:alice"


def test_entity_for_unknown_when_preferred_and_fallbacks_are_unavailable():
    event = {"user": "", "host": None, "src_ip": "", "dst_ip": None}

    assert entity_for(event, "missing") == "event:unknown"
    assert entity_for(event) == "event:unknown"


def test_critical_severity_with_no_evidence_keeps_baseline():
    assert severity_score("critical", 0) == 95
    assert severity_score("critical", -10) == 95


def test_entity_for_supports_custom_preferred_identity_without_changing_fallback():
    event = {"user": "alice", "session_id": "session-42"}

    assert entity_for(event, "session_id") == "session_id:session-42"
    assert entity_for(event, "missing_session") == "user:alice"
    assert entity_for(event) == "user:alice"


def test_entity_for_does_not_use_falsey_preferred_identity():
    event = {"user": "alice", "session_id": 0, "host": "ws-01"}

    assert entity_for(event, "session_id") == "user:alice"
    assert entity_for({"session_id": 0}, "session_id") == "event:unknown"


def test_severity_score_caps_at_exact_evidence_threshold():
    # High severity reaches 99 before saturating; the next item caps at 100.
    assert severity_score("high", 13) == 99
    assert severity_score("high", 14) == 100
    # Critical severity reaches the cap sooner because its baseline is 95.
    assert severity_score("critical", 3) == 99
    assert severity_score("critical", 4) == 100


def test_severity_score_normalizes_mixed_case_and_whitespace_for_all_levels():
    # Normalization must not silently downgrade recognized alert severities.
    for level, baseline in (("INFO", 10), ("LoW", 25), ("MeDiUm", 50),
                            ("HiGh", 75), ("CrItIcAl", 95)):
        assert severity_score(f"  {level}\t", 1) == baseline


def test_severity_scores_are_monotonic_across_evidence_counts():
    # Additional correlated evidence must never lower an alert's score.
    for severity in ("info", "low", "medium", "high", "critical"):
        scores = [severity_score(severity, count) for count in range(0, 51)]
        assert scores == sorted(scores)
        assert all(0 <= score <= 100 for score in scores)


def test_severity_score_first_evidence_does_not_inflate_baseline():
    # A single observation establishes the baseline; only additional evidence adds weight.
    for level, baseline in (("info", 10), ("low", 25), ("medium", 50),
                            ("high", 75), ("critical", 95)):
        assert severity_score(level, 0) == baseline
        assert severity_score(level, 1) == baseline
        assert severity_score(level, 2) == min(100, baseline + 2)


def test_unrecognized_severity_uses_low_baseline_with_evidence_weight():
    # Unknown levels retain the low-severity fallback even with multiple observations.
    assert severity_score("unknown", 1) == 25
    assert severity_score(" UNKNOWN ", 3) == 29
    assert severity_score("unknown", 100) == 100


def test_entity_for_prefers_host_over_network_addresses_without_user():
    # Host correlation must win over IP addresses when no user is present.
    event = {"host": "server-7", "src_ip": "192.0.2.7", "dst_ip": "203.0.113.7"}
    assert entity_for(event) == "host:server-7"
    assert entity_for(event, "unavailable") == "host:server-7"
    assert entity_for(event, "dst_ip") == "dst_ip:203.0.113.7"
