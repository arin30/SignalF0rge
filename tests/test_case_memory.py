from types import SimpleNamespace

from signalf0rge.case_memory import append_case_history, load_case_history, prior_cases


def _report(entity="alice"):
    return SimpleNamespace(
        entity=entity,
        verdict="escalate",
        severity="high",
        confidence="high",
        steps=[
            SimpleNamespace(tool="get_related_findings", result_count=2),
            SimpleNamespace(tool="traverse_entity_graph", result_count=3),
        ],
    )


def test_case_history_persists_compact_report_without_raw_evidence(tmp_path):
    path = tmp_path / "cases.json"
    append_case_history(path, _report())

    history = load_case_history(path)

    assert history[0]["entity"] == "alice"
    assert history[0]["evidence_items"] == 5
    assert history[0]["tool_calls"] == ["get_related_findings", "traverse_entity_graph"]
    assert "evidence" not in history[0]


def test_prior_cases_filters_entity_and_limits_results(tmp_path):
    path = tmp_path / "cases.json"
    append_case_history(path, _report("alice"))
    append_case_history(path, _report("bob"))
    append_case_history(path, _report("alice"))

    matches = prior_cases(load_case_history(path), "alice", limit=1)

    assert len(matches) == 1
    assert matches[0]["entity"] == "alice"


def test_case_history_enforces_retention_bound(tmp_path):
    path = tmp_path / "cases.json"
    append_case_history(path, _report("first"), max_entries=2)
    append_case_history(path, _report("second"), max_entries=2)
    append_case_history(path, _report("third"), max_entries=2)

    history = load_case_history(path)

    assert [item["entity"] for item in history] == ["second", "third"]
