"""Deterministic investigation layer for SignalF0rge findings.

The investigator is intentionally provider-neutral: it builds an evidence-grounded
case summary from SignalF0rge findings. An LLM can later consume the structured
output, but severity and evidence remain traceable to deterministic detections.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .models import Finding


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Investigation:
    entity: str
    severity: str
    confidence: str
    finding_count: int
    finding_ids: list[str]
    mitre_techniques: list[str]
    first_seen: str
    last_seen: str
    evidence_count: int
    summary: str
    recommended_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _severity(findings: list[Finding]) -> str:
    return max(
        (f.severity.lower() for f in findings),
        key=lambda value: _SEVERITY_RANK.get(value, -1),
        default="info",
    )


def _confidence(findings: list[Finding], techniques: list[str]) -> str:
    # Multiple independent detections and ATT&CK context increase confidence.
    if len(findings) >= 3 and len(techniques) >= 2:
        return "high"
    if len(findings) >= 2 or techniques:
        return "medium"
    return "low"


def _actions(severity: str, techniques: list[str]) -> list[str]:
    actions = ["Review the supporting events and validate the activity with the asset owner."]
    if severity in {"critical", "high"}:
        actions.append("Consider isolating the affected host or account while the activity is investigated.")
    if techniques:
        actions.append("Pivot on the mapped ATT&CK techniques for related activity across the same time window.")
    actions.append("Search for the same indicators and behavior on other users and hosts.")
    return actions


def investigate(findings: Iterable[Finding]) -> list[Investigation]:
    """Group findings by entity and turn them into investigation-ready cases."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.entity or "unknown", []).append(finding)

    investigations: list[Investigation] = []
    for entity, entity_findings in grouped.items():
        entity_findings.sort(key=lambda finding: finding.first_seen)
        techniques = sorted({tech for finding in entity_findings for tech in finding.mitre})
        severity = _severity(entity_findings)
        titles = Counter(finding.title for finding in entity_findings)
        title_summary = ", ".join(
            f"{title} ({count})" if count > 1 else title for title, count in titles.items()
        )
        evidence_count = sum(finding.evidence_count for finding in entity_findings)

        investigations.append(
            Investigation(
                entity=entity,
                severity=severity,
                confidence=_confidence(entity_findings, techniques),
                finding_count=len(entity_findings),
                finding_ids=[finding.rule_id for finding in entity_findings],
                mitre_techniques=techniques,
                first_seen=min(finding.first_seen for finding in entity_findings),
                last_seen=max(finding.last_seen for finding in entity_findings),
                evidence_count=evidence_count,
                summary=(
                    f"{entity} produced {len(entity_findings)} security finding(s): "
                    f"{title_summary}. The case contains {evidence_count} supporting "
                    f"event(s) and maps to {len(techniques)} ATT&CK technique(s)."
                ),
                recommended_actions=_actions(severity, techniques),
            )
        )

    return sorted(
        investigations,
        key=lambda case: (_SEVERITY_RANK.get(case.severity, -1), case.evidence_count),
        reverse=True,
    )
