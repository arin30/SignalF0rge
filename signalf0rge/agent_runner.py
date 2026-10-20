"""Simple tool-calling investigation planner.

This module provides the agent loop without binding SignalF0rge to an LLM vendor.
A future model adapter only needs to choose among the same audited read-only tools.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .agent import Investigation
from .models import Event, Finding
from .investigation_tools import get_related_findings, map_attack, search_events


@dataclass
class AgentStep:
    tool: str
    reason: str
    result_count: int
    evidence: list[dict[str, Any]]


@dataclass
class AgentReport:
    entity: str
    verdict: str
    severity: str
    confidence: str
    steps: list[AgentStep]
    evidence_summary: str
    recommended_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


def run_investigation(
    case: Investigation,
    events: list[Event],
    findings: list[Finding],
) -> AgentReport:
    """Run an auditable investigation plan using read-only evidence tools."""
    steps: list[AgentStep] = []

    related = get_related_findings(findings, case.entity)
    steps.append(
        AgentStep(
            tool=related.tool,
            reason="Establish which deterministic detections belong to this entity.",
            result_count=len(related.results),
            evidence=related.results,
        )
    )

    attack = map_attack(findings, case.entity)
    steps.append(
        AgentStep(
            tool=attack.tool,
            reason="Identify ATT&CK techniques already supported by detection evidence.",
            result_count=len(attack.results),
            evidence=attack.results,
        )
    )

    # Entity values in SignalF0rge are commonly users or hosts. Try both pivots
    # and keep only evidence that actually exists.
    for field in ("user", "host"):
        event_result = search_events(events, **{field: case.entity})
        if event_result.results:
            steps.append(
                AgentStep(
                    tool=event_result.tool,
                    reason=f"Pivot through telemetry where {field} matches the case entity.",
                    result_count=len(event_result.results),
                    evidence=event_result.results,
                )
            )

    evidence_items = sum(step.result_count for step in steps)
    verdict = "escalate" if case.severity in {"critical", "high"} else "review"
    return AgentReport(
        entity=case.entity,
        verdict=verdict,
        severity=case.severity,
        confidence=case.confidence,
        steps=steps,
        evidence_summary=(
            f"Investigation used {len(steps)} tool call(s) and returned "
            f"{evidence_items} evidence item(s). Conclusions are limited to "
            "SignalF0rge detections and matching local telemetry."
        ),
        recommended_actions=case.recommended_actions,
    )
