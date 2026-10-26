"""Persistent, provider-neutral investigation case history.

Case memory stores compact report metadata rather than raw telemetry so repeated
investigations can compare current findings with earlier runs without giving the
LLM unrestricted long-term memory.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def load_case_history(path: str | Path) -> list[dict[str, Any]]:
    history_path = Path(path)
    if not history_path.exists():
        return []
    data = json.loads(history_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("case history must contain a JSON list")
    return data


def case_snapshot(report: Any) -> dict[str, Any]:
    """Create a compact auditable snapshot without copying raw evidence."""
    return {
        "entity": report.entity,
        "verdict": report.verdict,
        "severity": report.severity,
        "confidence": report.confidence,
        "tool_calls": [step.tool for step in report.steps],
        "evidence_items": sum(step.result_count for step in report.steps),
    }


def append_case_history(path: str | Path, report: Any, max_entries: int = 100) -> None:
    if max_entries < 1 or max_entries > 1000:
        raise ValueError("max_entries must be between 1 and 1000")
    history_path = Path(path)
    history = load_case_history(history_path)
    history.append(case_snapshot(report))
    history = history[-max_entries:]
    history_path.parent.mkdir(parents=True, exist_ok=True)
    # Serialize before opening a file, then replace only after a complete write.
    # A failed save must not truncate previously collected investigation history.
    payload = json.dumps(history, indent=2) + "\n"
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=history_path.parent,
            prefix=f".{history_path.name}.", suffix=".tmp", delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, history_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def prior_cases(history: list[dict[str, Any]], entity: str, limit: int = 5) -> list[dict[str, Any]]:
    if limit < 1 or limit > 20:
        raise ValueError("limit must be between 1 and 20")
    matches = [item for item in history if str(item.get("entity")) == str(entity)]
    return matches[-limit:]
