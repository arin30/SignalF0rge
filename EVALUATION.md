# Detection evaluation

SignalF0rge includes a deterministic large mixed telemetry benchmark so detection changes can be measured instead of judged only from sample reports.

## Generate the benchmark

```bash
python3 tools/generate_large_dataset.py
```

The default seed produces 3,048 normalized events: 3,000 benign background events plus 48 events across 21 labeled attack scenarios. The benign background mixes successful and occasional failed authentication, common endpoint process creation, and routine network traffic. The attack scenarios exercise brute force, password spraying, account targeting, PowerShell execution, credential access, persistence, defense evasion, Windows utilities, network scanning, and a multi-stage compromise chain.

The generator writes:

```text
samples/large_mixed_events.jsonl
samples/large_mixed_labels.json
```

The labels are stored separately from the detector's rule configuration. Each malicious scenario lists the rule IDs expected to detect it, while benign events are marked only with `scenario: benign`.

## Evaluate detections

```bash
signalf0rge evaluate samples/large_mixed_events.jsonl \
  --labels samples/large_mixed_labels.json \
  --rules rules.yml \
  --out output/evaluation.json
```

The evaluation command reports true positives, false positives, false negatives, precision, recall, and F1. A predicted case is a `(scenario, rule)` pair derived from the evidence behind a finding. This makes the benchmark useful for regression testing rule changes without treating multiple findings for one scenario as independent attacks.

The automated test suite generates the full 3,048-event benchmark from seed 42 and requires precision, recall, and F1 of at least 0.95. This threshold is intentionally a regression guard rather than a claim about performance on production telemetry. The benchmark is synthetic, and real-world false-positive rates will depend on environment-specific baselines and log quality.

## Scale the corpus

The generator can create more benign background noise while keeping the same labeled attack set:

```bash
python3 tools/generate_large_dataset.py --benign-events 10000 --seed 42
```

This makes it possible to stress the same detection rules against larger volumes without manually maintaining thousands of JSON lines in the repository.
