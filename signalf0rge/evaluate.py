import json
from pathlib import Path


def load_ground_truth(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return {scenario: set(rule_ids) for scenario, rule_ids in data["expected"].items()}


def evaluate_findings(findings, expected):
    expected_pairs = {
        (scenario, rule_id)
        for scenario, rule_ids in expected.items()
        for rule_id in rule_ids
    }
    predicted_pairs = set()

    for finding in findings:
        scenarios = {
            evidence.get("scenario")
            for evidence in finding.evidence
            if evidence.get("scenario") and evidence.get("scenario") != "benign"
        }
        if not scenarios:
            scenarios = {"benign"}
        for scenario in scenarios:
            predicted_pairs.add((scenario, finding.rule_id))

    true_positives = predicted_pairs & expected_pairs
    false_positives = predicted_pairs - expected_pairs
    false_negatives = expected_pairs - predicted_pairs

    precision = len(true_positives) / len(predicted_pairs) if predicted_pairs else 0.0
    recall = len(true_positives) / len(expected_pairs) if expected_pairs else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "expected_cases": len(expected_pairs),
        "predicted_cases": len(predicted_pairs),
        "true_positives": len(true_positives),
        "false_positives": len(false_positives),
        "false_negatives": len(false_negatives),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_cases": sorted([f"{scenario}:{rule}" for scenario, rule in false_positives]),
        "missed_cases": sorted([f"{scenario}:{rule}" for scenario, rule in false_negatives]),
    }


def write_evaluation(metrics, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    return path
