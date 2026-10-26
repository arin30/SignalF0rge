import tempfile
import json
import pytest
from pathlib import Path
from signalf0rge.parser import load_jsonl


@pytest.mark.parametrize("port", [-1, 65536, True, False, 443.5, [], {}, "https"])
def test_invalid_ports_report_the_source_line(tmp_path, port):
    path = tmp_path / "ports.jsonl"
    path.write_text(json.dumps({"timestamp": "2026-10-26T10:00:00Z", "source_type": "network", "dst_port": port}), encoding="utf-8")
    with pytest.raises(ValueError, match="dst_port must be an integer from 0 to 65535") as error:
        load_jsonl(path)
    assert f"{path}:1:" in str(error.value)


@pytest.mark.parametrize("port, expected", [(0, 0), (65535, 65535), ("443", 443), (None, None)])
def test_valid_port_boundaries(tmp_path, port, expected):
    path = tmp_path / "ports.jsonl"
    path.write_text(json.dumps({"timestamp": "2026-10-26T10:00:00Z", "source_type": "network", "dst_port": port}), encoding="utf-8")
    assert load_jsonl(path)[0].dst_port == expected


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


def test_load_jsonl_accepts_lowercase_utc_suffix():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "events.jsonl"
        p.write_text(
            '{"timestamp":"2026-08-17T10:00:00z","source_type":"auth"}\n',
            encoding="utf-8",
        )
        events = load_jsonl(p)
        assert events[0].timestamp.isoformat() == "2026-08-17T10:00:00+00:00"


def test_load_jsonl_normalizes_source_type_case_and_whitespace():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "events.jsonl"
        p.write_text(
            '{"timestamp":"2026-08-17T10:00:00Z","source_type":"  AUTH  "}\n',
            encoding="utf-8",
        )
        events = load_jsonl(p)
        assert events[0].source_type == "auth"


def test_load_jsonl_rejects_blank_source_type():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "events.jsonl"
        p.write_text(
            '{"timestamp":"2026-08-17T10:00:00Z","source_type":"   "}\n',
            encoding="utf-8",
        )
        try:
            load_jsonl(p)
        except ValueError as exc:
            assert "source_type must be a non-empty string" in str(exc)
        else:
            raise AssertionError("blank source_type should raise ValueError")


def test_load_jsonl_rejects_non_numeric_destination_port():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "events.jsonl"
        p.write_text(
            '{"timestamp":"2026-08-17T10:00:00Z","source_type":"network","dst_port":"https"}\n',
            encoding="utf-8",
        )
        try:
            load_jsonl(p)
        except ValueError as exc:
            assert f"{p}:1:" in str(exc)
        else:
            raise AssertionError("non-numeric dst_port should raise ValueError")


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


def test_load_jsonl_error_line_counts_blank_lines():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "events.jsonl"
        path.write_text(
            '\n'
            '{"timestamp":"2026-08-17T10:00:00Z","source_type":"auth"}\n'
            '  \n'
            '{"timestamp":"not-a-timestamp","source_type":"auth"}\n',
            encoding="utf-8",
        )
        try:
            load_jsonl(path)
        except ValueError as exc:
            assert f"{path}:4:" in str(exc)
        else:
            raise AssertionError("invalid timestamp should identify its physical line")


def test_load_jsonl_rejects_non_string_source_type():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "events.jsonl"
        p.write_text(
            '{"timestamp":"2026-08-17T10:00:00Z","source_type":123}\n',
            encoding="utf-8",
        )
        try:
            load_jsonl(p)
        except ValueError as exc:
            assert "source_type must be a non-empty string" in str(exc)
        else:
            raise AssertionError("non-string source_type should raise ValueError")


def test_load_jsonl_rejects_numeric_timestamp():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "events.jsonl"
        path.write_text(
            '{"timestamp":20260817,"source_type":"auth"}',
            encoding="utf-8",
        )
        try:
            load_jsonl(path)
        except ValueError as exc:
            assert f"{path}:1:" in str(exc)
            assert "timestamp must be an ISO 8601 string" in str(exc)
        else:
            raise AssertionError("numeric timestamps must be rejected")
