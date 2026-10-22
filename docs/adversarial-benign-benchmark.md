# Adversarial benign benchmark

This benchmark extends the mixed evaluation dataset with legitimate activity that deliberately resembles common attack behavior.

## Dataset

- 3,000 ordinary benign background events
- 19 adversarial benign lookalike events
- 48 attack events across 21 labeled attack scenarios
- 3,067 total events
- 31 expected scenario/rule detection cases

The lookalikes include approved PowerShell software retrieval, scheduled-task creation, Windows service creation, vulnerability scanning, and a burst of failed logins caused by an expired password.

## Measured detection result

| Metric | Result |
| --- | ---: |
| True positives | 31 |
| False positives | 8 |
| False negatives | 0 |
| Precision | 79.49% |
| Recall | 100.00% |
| F1 | 88.57% |

The eight false positives are intentionally retained as a regression baseline because the current rules only see telemetry behavior, not business approval context:

- approved PowerShell retrieval -> ENDPOINT-001
- approved scheduled task -> ENDPOINT-005
- approved service creation -> ENDPOINT-006
- approved vulnerability scanner -> NET-001, NET-002, NET-003, NET-004
- expired-password login burst -> AUTH-003

CI asserts this exact set. A new false-positive case fails the regression test rather than being silently absorbed into the benchmark.

## Interpretation

The earlier clean mixed dataset was useful for validating attack coverage, but its >=95% precision/F1 gate overstated how well simple behavioral rules distinguish malicious activity from legitimate dual-use administration. The adversarial benign benchmark keeps attack recall gated at >=95% while reporting precision and F1 honestly against harder background activity.

This result is a baseline, not a target. Future tuning should reduce the known false positives using additional context or explicit suppression/allowlisting without weakening attack coverage.
