# SignalF0rge

SignalF0rge is a lightweight blue-team security automation project for ingesting raw events, normalizing them, detecting suspicious behavior, correlating evidence, mapping findings to MITRE ATT&CK, and generating analyst-friendly reports.

## What it demonstrates

Security event normalization, detection engineering, incident triage, event correlation, severity scoring, MITRE ATT&CK mapping, Python automation, secure input handling, unit testing and CI, and analyst reporting.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
signalf0rge analyze samples/events.jsonl --rules rules.yml --out output
```

## Current detections

Repeated failed authentication, successful login following repeated failures, suspicious and encoded PowerShell, local administrator creation, credential dumping indicators, risky destination ports, and repeated denied firewall traffic.

## Architecture

```text
JSONL events -> parser/normalizer -> rule engine -> correlation/severity -> findings -> JSON + HTML report
```

## Resume ready bullet

Built SignalF0rge, a Python security automation pipeline that normalizes endpoint, authentication, and network events, detects suspicious activity through configurable rules, correlates evidence, maps findings to MITRE ATT&CK, and generates prioritized incident reports.
