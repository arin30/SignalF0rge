import tempfile
from pathlib import Path
from signalf0rge.parser import load_jsonl


def test_load_jsonl():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "events.jsonl"
        p.write_text('{"timestamp":"2026-08-17T10:00:00Z","source_type":"auth","action":"login_failed"}\n', encoding="utf-8")
        events = load_jsonl(p)
        assert len(events) == 1
        assert events[0].source_type == "auth"


def test_load_jsonl_ignores_blank_lines_and_sorts_by_timestamp():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "events.jsonl"
        p.write_text(
            '\n'
            '{"timestamp":"2026-08-17T10:05:00Z","source_type":"endpoint","action":"process_start"}\n'
            '   \n'
            '{"timestamp":"2026-08-17T10:00:00Z","source_type":"auth","action":"login_failed"}\n',
            encoding="utf-8",
        )
        events = load_jsonl(p)
        assert [event.source_type for event in events] == ["auth", "endpoint"]
        assert events[0].timestamp <= events[1].timestamp
