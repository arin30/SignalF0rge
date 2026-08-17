import json
from datetime import datetime, timezone
from pathlib import Path
from .models import Event

REQUIRED_FIELDS = {"timestamp", "source_type"}

def parse_timestamp(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"): value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def normalize_record(record: dict) -> Event:
    missing = REQUIRED_FIELDS - set(record)
    if missing: raise ValueError(f"Missing required fields: {sorted(missing)}")
    return Event(timestamp=parse_timestamp(str(record["timestamp"])), source_type=str(record["source_type"]).strip().lower(), host=record.get("host"), user=record.get("user"), src_ip=record.get("src_ip"), dst_ip=record.get("dst_ip"), dst_port=int(record["dst_port"]) if record.get("dst_port") is not None else None, action=record.get("action"), command=record.get("command"), message=record.get("message"), raw=dict(record))

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
