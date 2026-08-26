import json
from pathlib import Path
from .models import Event
from .parser import parse_timestamp, normalize_record


def _first(record: dict, *names):
    for name in names:
        value = record.get(name)
        if value not in (None, "", "-"):
            return value
    return None


def _int_or_none(value):
    if value in (None, "", "-"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_windows_record(record: dict) -> Event:
    event_id = _int_or_none(_first(record, "EventID", "event_id", "Id"))
    provider = str(_first(record, "ProviderName", "Provider", "provider") or "").lower()
    timestamp = _first(record, "UtcTime", "TimeCreated", "timestamp", "@timestamp")
    if timestamp is None:
        raise ValueError("Missing Windows event timestamp")

    host = _first(record, "Computer", "ComputerName", "Hostname", "host")
    user = _first(record, "TargetUserName", "User", "SubjectUserName", "user")
    src_ip = _first(record, "IpAddress", "SourceIp", "SourceIP", "src_ip")
    dst_ip = _first(record, "DestinationIp", "DestinationIP", "dst_ip")
    dst_port = _int_or_none(_first(record, "DestinationPort", "dst_port"))
    command = _first(record, "CommandLine", "command")
    image = _first(record, "Image", "SourceImage")
    message = str(_first(record, "Message", "message") or "")

    source_type = "endpoint"
    action = None

    if event_id in {4624, 4625} or "security-auditing" in provider:
        source_type = "auth"
        if event_id == 4624:
            action = "login_success"
        elif event_id == 4625:
            action = "login_failed"
    elif event_id == 3:
        source_type = "network"
        action = "allowed"
    elif event_id == 1:
        source_type = "endpoint"
        action = "process_start"
    elif event_id == 10:
        source_type = "endpoint"
        action = "process_access"

    if event_id == 10:
        target_image = str(_first(record, "TargetImage") or "")
        if "lsass.exe" in target_image.lower():
            message = (message + " Suspicious access to LSASS detected").strip()

    if command is None and event_id == 1:
        command = image

    normalized = {
        "timestamp": str(timestamp),
        "source_type": source_type,
        "host": host,
        "user": user,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "action": action,
        "command": command,
        "message": message,
        "windows_event_id": event_id,
        "provider": provider,
        "raw_event": record,
    }
    return normalize_record(normalized)


def load_windows_jsonl(path: str | Path) -> list[Event]:
    events = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(normalize_windows_record(json.loads(line)))
            except Exception as exc:
                raise ValueError(f"{path}:{line_no}: {exc}") from exc
    events.sort(key=lambda event: event.timestamp)
    return events


def load_events(path: str | Path, format_name: str = "normalized") -> list[Event]:
    format_name = format_name.strip().lower()
    if format_name == "normalized":
        from .parser import load_jsonl
        return load_jsonl(path)
    if format_name == "windows":
        return load_windows_jsonl(path)
    raise ValueError(f"Unsupported telemetry format: {format_name}")
