from types import SimpleNamespace

import pytest

from signalf0rge import case_memory
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


def test_serialization_failure_preserves_history(tmp_path):
    path = tmp_path / "cases.json"
    append_case_history(path, _report("first"))
    original = path.read_bytes()

    with pytest.raises(TypeError):
        append_case_history(path, _report(object()))

    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_replace_failure_preserves_history_and_removes_temporary_file(tmp_path, monkeypatch):
    path = tmp_path / "cases.json"
    append_case_history(path, _report("first"))
    original = path.read_bytes()

    def fail_replace(source, destination):
        assert source.parent == path.parent
        assert destination == path
        raise OSError("simulated replacement failure")

    monkeypatch.setattr(case_memory.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replacement failure"):
        append_case_history(path, _report("second"))

    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_sync_failure_preserves_history_and_removes_temporary_file(tmp_path, monkeypatch):
    path = tmp_path / "cases.json"
    append_case_history(path, _report("first"))
    original = path.read_bytes()

    def fail_sync(fd):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(case_memory.os, "fsync", fail_sync)
    with pytest.raises(OSError, match="simulated disk failure"):
        append_case_history(path, _report("second"))

    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]



@pytest.mark.parametrize("max_entries", [0, -1, 1001])
def test_invalid_retention_bound_does_not_modify_history(tmp_path, max_entries):
    path = tmp_path / "cases.json"
    append_case_history(path, _report("original"))
    original = path.read_bytes()

    with pytest.raises(ValueError, match="max_entries"):
        append_case_history(path, _report("new"), max_entries=max_entries)

    assert path.read_bytes() == original
    assert [item["entity"] for item in load_case_history(path)] == ["original"]


def test_atomic_save_creates_missing_parent_directories(tmp_path):
    path = tmp_path / "nested" / "cases.json"
    append_case_history(path, _report())
    assert load_case_history(path)[0]["entity"] == "alice"
    assert list(path.parent.iterdir()) == [path]
