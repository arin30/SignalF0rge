from types import SimpleNamespace

from signalf0rge.agent_evaluate import aggregate_agent_evaluations, evaluate_agent_report


def _report(tools, verdict="escalate"):
    return SimpleNamespace(
        verdict=verdict,
        steps=[SimpleNamespace(tool=tool) for tool in tools],
    )


def test_agent_evaluation_scores_useful_pivots_and_redundancy():
    result = evaluate_agent_report(
        _report(["get_related_findings", "map_attack", "map_attack"]),
        expected_tools={"get_related_findings", "map_attack", "search_events"},
        max_steps=5,
        expected_verdict="escalate",
    )
    assert result["useful_pivot_rate"] == 2 / 3
    assert result["redundant_calls"] == 1
    assert result["missing_expected_pivots"] == ["search_events"]
    assert result["within_budget"] is True
    assert result["verdict_grounded"] is True


def test_agent_evaluation_detects_budget_and_verdict_failures():
    result = evaluate_agent_report(
        _report(["a", "b", "c"], verdict="escalate"),
        expected_tools={"a"},
        max_steps=2,
        expected_verdict="review",
    )
    assert result["within_budget"] is False
    assert result["verdict_grounded"] is False


def test_agent_evaluation_aggregates_cases():
    results = [
        evaluate_agent_report(_report(["a"]), {"a"}, expected_verdict="escalate"),
        evaluate_agent_report(_report(["a", "a"], verdict="review"), {"a"}, expected_verdict="review"),
    ]
    summary = aggregate_agent_evaluations(results)
    assert summary["cases"] == 2
    assert summary["mean_useful_pivot_rate"] == 1.0
    assert summary["total_redundant_calls"] == 1
    assert summary["budget_compliance_rate"] == 1.0
    assert summary["grounded_verdict_rate"] == 1.0
