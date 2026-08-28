import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

from .models import Event

_PATTERN = re.compile(
    r"\[(?P<type>ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'(?P<value>[^']+)'\]",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Indicator:
    id: str
    name: str
    observable_type: str
    value: str
    labels: list[str]
    confidence: int | None = None
    valid_from: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class IntelMatch:
    event_index: int
    field: str
    observed_value: str
    indicator: Indicator

    def to_dict(self) -> dict:
        data = asdict(self)
        return data


def _parse_indicator(obj: dict) -> Indicator | None:
    if obj.get("type") != "indicator":
        return None
    pattern = obj.get("pattern", "")
    match = _PATTERN.fullmatch(pattern.strip())
    if not match:
        return None
    return Indicator(
        id=obj.get("id", "indicator--unknown"),
        name=obj.get("name") or obj.get("description") or "Unnamed indicator",
        observable_type=match.group("type").lower(),
        value=match.group("value"),
        labels=list(obj.get("labels", []) or []),
        confidence=obj.get("confidence"),
        valid_from=obj.get("valid_from"),
        description=obj.get("description"),
    )


def load_stix_bundle(path: str | Path) -> list[Indicator]:
    """Load simple STIX 2.x Indicator objects from a bundle.

    SignalF0rge currently supports exact-value indicator patterns for IP addresses,
    domains, and URLs. Unsupported STIX patterns are skipped rather than guessed.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("type") != "bundle" or not isinstance(data.get("objects"), list):
        raise ValueError("Expected a STIX bundle with an objects list")

    indicators = []
    for obj in data["objects"]:
        if isinstance(obj, dict):
            indicator = _parse_indicator(obj)
            if indicator:
                indicators.append(indicator)
    return indicators


def _event_observables(event: Event) -> Iterable[tuple[str, str, str]]:
    if event.src_ip:
        yield "src_ip", "ipv4-addr" if ":" not in event.src_ip else "ipv6-addr", event.src_ip
    if event.dst_ip:
        yield "dst_ip", "ipv4-addr" if ":" not in event.dst_ip else "ipv6-addr", event.dst_ip

    for field in ("domain", "hostname", "dns_query"):
        value = event.raw.get(field)
        if value:
            yield field, "domain-name", str(value)

    for field in ("url", "request_url"):
        value = event.raw.get(field)
        if value:
            yield field, "url", str(value)


def enrich_events(events: list[Event], indicators: list[Indicator]) -> list[IntelMatch]:
    index: dict[tuple[str, str], list[Indicator]] = {}
    for indicator in indicators:
        key = (indicator.observable_type, indicator.value.lower())
        index.setdefault(key, []).append(indicator)

    matches = []
    for event_index, event in enumerate(events):
        for field, observable_type, value in _event_observables(event):
            for indicator in index.get((observable_type, value.lower()), []):
                matches.append(
                    IntelMatch(
                        event_index=event_index,
                        field=field,
                        observed_value=value,
                        indicator=indicator,
                    )
                )
    return matches


def write_intel_matches(matches: list[IntelMatch], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([m.to_dict() for m in matches], indent=2), encoding="utf-8")
    return path
