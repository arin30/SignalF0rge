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
