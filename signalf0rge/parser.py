import json
from datetime import datetime, timezone
from pathlib import Path
from .models import Event

REQUIRED_FIELDS = {"timestamp", "source_type"}

def parse_port(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("dst_port must be an integer from 0 to 65535")
    if isinstance(value, str) and "_" in value:
        raise ValueError("dst_port must be an integer from 0 to 65535")
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError("dst_port must be an integer from 0 to 65535") from exc
    if not 0 <= port <= 65535:
        raise ValueError("dst_port must be an integer from 0 to 65535")
    return port

def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string")
    value = value.strip()
    if value.endswith(("Z", "z")): value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def normalize_record(record: dict) -> Event:
    missing = REQUIRED_FIELDS - set(record)
    if missing: raise ValueError(f"Missing required fields: {sorted(missing)}")
    source_type = record["source_type"]
    if not isinstance(source_type, str) or not source_type.strip():
        raise ValueError("source_type must be a non-empty string")
    return Event(timestamp=parse_timestamp(record["timestamp"]), source_type=source_type.strip().lower(), host=record.get("host"), user=record.get("user"), src_ip=record.get("src_ip"), dst_ip=record.get("dst_ip"), dst_port=parse_port(record.get("dst_port")), action=record.get("action"), command=record.get("command"), message=record.get("message"), raw=dict(record))

def load_jsonl(path: str | Path) -> list[Event]:
    events = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line: continue
            try: events.append(normalize_record(json.loads(line)))
            except Exception as exc: raise ValueError(f"{path}:{line_no}: {exc}") from exc
    events.sort(key=lambda e: e.timestamp)
    return events
