from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any

@dataclass
class Event:
    timestamp: datetime
    source_type: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    action: str | None = None
    command: str | None = None
    message: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    def get(self, field_name: str):
        if hasattr(self, field_name): return getattr(self, field_name)
        return self.raw.get(field_name)

@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str
    entity: str
    mitre: list[str]
    first_seen: str
    last_seen: str
    evidence_count: int
    evidence: list[dict[str, Any]]
    score: int
    def to_dict(self): return asdict(self)
