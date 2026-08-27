import importlib.util
from pathlib import Path

from signalf0rge.engine import analyze
from signalf0rge.evaluate import evaluate_findings
from signalf0rge.parser import load_jsonl
from signalf0rge.rules import load_rules


def load_generator():
    root = Path(__file__).resolve().parents[1]
    path = root / "tools" / "generate_large_dataset.py"
    spec = importlib.util.spec_from_file_location("large_dataset", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_large_mixed_dataset_evaluation(tmp_path):
    generator = load_generator()
    events_data, expected = generator.build_dataset(benign_events=3000, seed=42)
    events_path = tmp_path / "events.jsonl"
    labels_path = tmp_path / "labels.json"
    generator.write_dataset(events_data, expected, events_path, labels_path)

    root = Path(__file__).resolve().parents[1]
    events = load_jsonl(events_path)
    findings = analyze(events, load_rules(root / "rules.yml"))
    metrics = evaluate_findings(findings, {scenario: set(rules) for scenario, rules in expected.items()})

    assert len(events) == 3048
    assert len(expected) == 21
    assert metrics["expected_cases"] >= 30
    assert metrics["recall"] >= 0.95
    assert metrics["precision"] >= 0.95
    assert metrics["f1"] >= 0.95


def test_empty_evaluation_returns_zero_metrics():
    metrics = evaluate_findings([], {})

    assert metrics["expected_cases"] == 0
    assert metrics["predicted_cases"] == 0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0
