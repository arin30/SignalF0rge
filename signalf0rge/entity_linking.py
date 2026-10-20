"""Entity linking for investigation pivots.

Builds a small relationship graph from normalized telemetry so an investigation can
move from a user to the hosts and IP addresses observed with that user, and then
to neighboring entities seen in the same events.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Event


_FIELDS = ("user", "host", "src_ip", "dst_ip")


@dataclass
class EntityLink:
    source: str
    target: str
    relationship: str
    observations: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "observations": self.observations,
        }


def link_entities(events: list[Event], entity: str) -> list[EntityLink]:
    """Return directly observed relationships involving an entity."""
    counts: dict[tuple[str, str, str], int] = {}
    for event in events:
        values = {field: getattr(event, field) for field in _FIELDS if getattr(event, field)}
        matching_fields = [field for field, value in values.items() if str(value) == str(entity)]
        if not matching_fields:
            continue
        for source_field in matching_fields:
            for target_field, target in values.items():
                if target_field == source_field or str(target) == str(entity):
                    continue
                key = (str(entity), str(target), f"{source_field}->{target_field}")
                counts[key] = counts.get(key, 0) + 1

    links = [
        EntityLink(source, target, relationship, observations)
        for (source, target, relationship), observations in counts.items()
    ]
    return sorted(links, key=lambda link: (-link.observations, link.relationship, link.target))


def traverse_entities(
    events: list[Event],
    entity: str,
    max_depth: int = 2,
    max_nodes: int = 25,
) -> list[EntityLink]:
    """Traverse observed entity relationships with strict depth and node bounds."""
    if max_depth < 1 or max_depth > 3:
        raise ValueError("max_depth must be between 1 and 3")
    if max_nodes < 2 or max_nodes > 100:
        raise ValueError("max_nodes must be between 2 and 100")

    seen = {str(entity)}
    frontier = [str(entity)]
    collected: dict[tuple[str, str, str], EntityLink] = {}

    for _ in range(max_depth):
        next_frontier: list[str] = []
        for current in frontier:
            for link in link_entities(events, current):
                key = (link.source, link.target, link.relationship)
                collected[key] = link
                if link.target not in seen and len(seen) < max_nodes:
                    seen.add(link.target)
                    next_frontier.append(link.target)
            if len(seen) >= max_nodes:
                break
        if not next_frontier or len(seen) >= max_nodes:
            break
        frontier = next_frontier

    return sorted(
        collected.values(),
        key=lambda link: (link.source, -link.observations, link.relationship, link.target),
    )
