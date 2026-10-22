from __future__ import annotations

import json
from pathlib import Path

from .agent import investigate
from .agent_evaluate import aggregate_agent_evaluations, evaluate_agent_report
from .agent_runner import run_investigation
from .engine import analyze
from .evaluate import evaluate_findings
from .parser import load_jsonl
from .rules import load_rules


def benchmark(events_path, rules_path, labels, agent_expectations):
    events = load_jsonl(events_path)
    findings = analyze(events, load_rules(rules_path))
    detection = evaluate_findings(findings, labels)
    cases = {case.entity: case for case in investigate(findings)}
    agent_results = []

    for entity, expectation in agent_expectations.items():
        case = cases.get(entity)
        if case is None:
            agent_results.append({
                "entity": entity,
                "missing_case": True,
                "useful_pivot_rate": 0.0,
                "redundant_calls": 0,
                "within_budget": True,
                "verdict_grounded": False,
            })
            continue
        report = run_investigation(case, events, findings)
        result = evaluate_agent_report(
            report,
            expected_tools=set(expectation.get("expected_tools", [])),
            max_steps=expectation.get("max_steps", 5),
            expected_verdict=expectation.get("expected_verdict"),
        )
        result["entity"] = entity
        result["missing_case"] = False
        agent_results.append(result)

    return {
        "events": len(events),
        "findings": len(findings),
        "detection": detection,
        "investigation": {
            "summary": aggregate_agent_evaluations(agent_results),
            "cases": agent_results,
        },
    }


def write_benchmark(result, path):
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return output
