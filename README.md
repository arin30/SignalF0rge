# SignalF0rge

SignalF0rge is a lightweight blue-team security automation project for ingesting raw events, normalizing them, detecting suspicious behavior, correlating evidence, mapping findings to MITRE ATT&CK, and generating analyst-friendly reports.

## What it demonstrates

- Security event normalization
- Detection engineering
- Incident triage
- Event correlation
- Severity scoring
- MITRE ATT&CK mapping
- Python automation
- Secure input handling
- Unit testing and CI
- Analyst reporting

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
signalf0rge analyze samples/events.jsonl --rules rules.yml --out output
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
signalf0rge analyze samples/events.jsonl --rules rules.yml --out output
```

The command creates:

```text
output/findings.json
output/report.html
```

## Current detections

- Repeated failed authentication
- Successful login following repeated failures
- Suspicious PowerShell usage
- Encoded PowerShell execution
- Local administrator account creation
- Credential dumping / LSASS indicators
- Connections to risky destination ports
- Repeated denied firewall traffic

## Example event

```json
{"timestamp":"2026-08-17T16:00:00Z","source_type":"auth","user":"alex","src_ip":"198.51.100.23","action":"login_failed"}
```

## Architecture

```text
JSONL events -> parser/normalizer -> rule engine -> correlation/severity -> findings -> JSON + HTML report
```

## Resume-ready bullet

Built SignalF0rge, a Python security automation pipeline that normalizes endpoint, authentication, and network events, detects suspicious activity through configurable rules, correlates evidence, maps findings to MITRE ATT&CK, and generates prioritized incident reports.

## Roadmap

- Sigma rule import
- STIX/TAXII enrichment
- VirusTotal / AbuseIPDB enrichment
- SQLite finding store
- REST API
- Dockerized dashboard
- OpenTelemetry ingest
- Kubernetes audit log parser
- OPA policy evaluation
- CI security scanning
