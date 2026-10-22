from __future__ import annotations

from typing import Any


def evaluate_agent_report(report: Any, expected_tools=None, max_steps: int = 5, expected_verdict=None):
    if max_steps < 1:
        raise ValueError("max_steps must be positive")
    steps = list(report.steps)
    calls = [step.tool for step in steps]
    unique = set(calls)
    expected = set(expected_tools or set())
    useful = unique & expected
    missing = expected - unique
    return {
        "tool_calls": len(calls),
        "unique_tools": len(unique),
        "useful_pivots": len(useful),
        "missing_expected_pivots": sorted(missing),
        "useful_pivot_rate": len(useful) / len(expected) if expected else 1.0,
        "redundant_calls": max(0, len(calls) - len(unique)),
        "within_budget": len(calls) <= max_steps,
        "verdict_grounded": expected_verdict is None or report.verdict == expected_verdict,
    }


def aggregate_agent_evaluations(results):
    if not results:
        return {
            "cases": 0,
            "mean_useful_pivot_rate": 0.0,
            "total_redundant_calls": 0,
            "budget_compliance_rate": 0.0,
            "grounded_verdict_rate": 0.0,
        }
    count = len(results)
    return {
        "cases": count,
        "mean_useful_pivot_rate": sum(r["useful_pivot_rate"] for r in results) / count,
        "total_redundant_calls": sum(r["redundant_calls"] for r in results),
        "budget_compliance_rate": sum(bool(r["within_budget"]) for r in results) / count,
        "grounded_verdict_rate": sum(bool(r["verdict_grounded"]) for r in results) / count,
    }
