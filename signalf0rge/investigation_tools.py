"""Read-only investigation tools for the SignalF0rge agent.

Tools operate on local evidence only. Keeping them small and deterministic makes
agent decisions auditable and easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .models import Event, Finding
from .entity_linking import link_entities


@dataclass
class ToolResult:
    tool: str
    query: dict[str, Any]
    results: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "query": self.query, "results": self.results}


def search_events(events: list[Event], **query: Any) -> ToolResult:
    """Return events whose populated fields match every supplied query value."""
    matches: list[dict[str, Any]] = []
    for event in events:
        if all(str(event.get(key) or "").lower() == str(value).lower() for key, value in query.items()):
            matches.append(
                {
                    "timestamp": event.timestamp.isoformat(),
                    "source_type": event.source_type,
                    "host": event.host,
                    "user": event.user,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "dst_port": event.dst_port,
                    "action": event.action,
                    "command": event.command,
                    "message": event.message,
                }
            )
    return ToolResult("search_events", query, matches)


def get_related_findings(findings: list[Finding], entity: str) -> ToolResult:
    results = [
        {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "mitre": finding.mitre,
            "first_seen": finding.first_seen,
            "last_seen": finding.last_seen,
            "evidence_count": finding.evidence_count,
        }
        for finding in findings
        if finding.entity == entity
    ]
    return ToolResult("get_related_findings", {"entity": entity}, results)


def map_attack(findings: list[Finding], entity: str) -> ToolResult:
    techniques = sorted(
        {technique for finding in findings if finding.entity == entity for technique in finding.mitre}
    )
    return ToolResult(
        "map_attack",
        {"entity": entity},
        [{"technique": technique} for technique in techniques],
    )


Tool = Callable[..., ToolResult]


def get_entity_links(events: list[Event], entity: str) -> ToolResult:
    """Return directly observed user/host/IP relationships for an entity."""
    links = [link.to_dict() for link in link_entities(events, entity)]
    return ToolResult("get_entity_links", {"entity": entity}, links)
