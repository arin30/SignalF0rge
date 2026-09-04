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


def test_load_jsonl_normalizes_timezone_offsets_to_utc():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "events.jsonl"
        p.write_text(
            '{"timestamp":"2026-08-17T03:00:00-07:00","source_type":"auth"}\n',
            encoding="utf-8",
        )
        events = load_jsonl(p)
        assert events[0].timestamp.isoformat() == "2026-08-17T10:00:00+00:00"


def test_load_jsonl_reports_malformed_line_number():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "events.jsonl"
        p.write_text(
            '{"timestamp":"2026-08-17T10:00:00Z","source_type":"auth"}\n'
            '{not-json}\n',
            encoding="utf-8",
        )
        try:
            load_jsonl(p)
        except ValueError as exc:
            assert f"{p}:2:" in str(exc)
        else:
            raise AssertionError("malformed JSONL should raise ValueError")
