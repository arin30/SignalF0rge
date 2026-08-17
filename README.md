# SignalF0rge

SignalF0rge is an open source blue team security automation project for ingesting raw telemetry, normalizing events, detecting suspicious behavior, correlating evidence, mapping findings to MITRE ATT&CK, and generating analyst friendly incident reports.

The project is designed as a small but extensible detection engineering pipeline rather than a collection of disconnected scripts.

## Capabilities

SignalF0rge currently demonstrates security event normalization, configurable detection rules, event correlation, severity scoring, MITRE ATT&CK mapping, incident triage, JSON and HTML reporting, Sigma rule inspection, Python packaging, Docker, automated testing, and GitHub Actions CI.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
signalf0rge analyze samples/events.jsonl --rules rules.yml --out output
```

The analysis command writes structured findings and an analyst friendly HTML report to the output directory.

## Sigma support

SignalF0rge can ingest Sigma YAML metadata so detections from the broader open source ecosystem can be inspected alongside the native rule pipeline.

```bash
signalf0rge sigma samples/sigma_suspicious_powershell.yml
```

The importer validates required Sigma fields and surfaces the detection title, severity, log source, and MITRE ATT&CK tags. Full Sigma condition translation is intentionally listed as future work rather than claiming compatibility that is not yet implemented.

## Current detections

Current native detections cover repeated failed authentication, successful login following repeated failures, suspicious and encoded PowerShell execution, local administrator creation, credential dumping indicators, risky destination ports, and repeated denied firewall traffic.

## Architecture

```text
raw JSONL telemetry
        |
        v
parser and normalizer
        |
        v
configurable rule engine
        |
        v
correlation and severity scoring
        |
        v
MITRE ATT&CK enriched findings
        |
        +--> findings.json
        +--> report.html

Sigma YAML --> metadata importer --> ATT&CK and log source context
```

## Why this project exists

Security teams routinely receive telemetry from different sources and need to turn isolated events into prioritized evidence. SignalF0rge explores that workflow in a transparent codebase that can be extended with additional log sources, detection formats, enrichment providers, and policy engines.

## Development

```bash
pip install -e .
pip install pytest
pytest -q
```

CI runs the test suite automatically on pushes and pull requests.

Contributions are welcome. See `CONTRIBUTING.md` for the development workflow.

## Roadmap

Planned work includes fuller Sigma translation, STIX and TAXII threat intelligence enrichment, a persistent finding store, OpenTelemetry ingestion, Kubernetes audit log support, OPA policy evaluation, and additional CI security checks.

## Resume ready bullet

Built SignalF0rge, an open source Python security automation pipeline that normalizes endpoint, authentication, and network telemetry, detects and correlates suspicious activity, maps findings to MITRE ATT&CK, imports Sigma detection metadata, and generates prioritized incident reports with automated tests and CI.
