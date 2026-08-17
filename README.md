# SignalF0rge

SignalF0rge is a security automation project I built to experiment with detection engineering and incident triage workflows. It takes authentication, endpoint, and network events, normalizes them into a common format, runs configurable detections, correlates related activity, and produces findings that are easier to investigate.

I started the project because I wanted something more realistic than isolated security scripts. The goal is to keep the code small enough to understand end to end while still leaving room to add new log sources, detections, and threat intelligence later.

## What it does

Right now SignalF0rge can:

* normalize JSONL security events
* run configurable YAML detection rules
* correlate repeated or sequential activity
* assign severity scores to findings
* attach MITRE ATT&CK technique IDs to detections
* generate JSON findings and an HTML investigation report
* inspect basic metadata from Sigma rules
* compare event observables with exact value STIX 2.x indicators

The repository also includes tests, a Dockerfile, and a GitHub Actions workflow.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
signalf0rge analyze samples/events.jsonl --rules rules.yml --out output
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
signalf0rge analyze samples/events.jsonl --rules rules.yml --out output
```

The analysis command writes `findings.json` and `report.html` to the output directory.

## Detections

The native rule library currently contains 19 detections across authentication, endpoint, and network telemetry.

Authentication coverage includes repeated failed logins by source IP, successful authentication after repeated failures, and repeated failures targeting one account even when the attempts come from different sources.

Endpoint coverage includes suspicious and encoded PowerShell, local administrator creation, credential dumping indicators, scheduled task creation, Windows service creation, Registry Run Key persistence, endpoint security disabling, WMI execution, certutil based remote file retrieval, Office applications spawning command shells, shadow copy deletion, Windows event log clearing, and host firewall disabling.

Network coverage includes higher risk destination ports and repeated denied firewall traffic.

Detection logic is defined in `rules.yml`, so thresholds, matching criteria, severity, and ATT&CK mappings can be changed without editing the engine itself.

A second synthetic sample exercises the expanded Phase 1 rules:

```bash
signalf0rge analyze samples/phase1_events.jsonl --rules rules.yml --out output-phase1
open output-phase1/report.html
```

The original `samples/events.jsonl` remains intentionally small so the basic correlation flow is easy to understand.

## Sigma

I added a small Sigma importer to inspect detection metadata and ATT&CK tags from Sigma YAML files.

```bash
signalf0rge sigma samples/sigma_suspicious_powershell.yml
```

This is not a full Sigma implementation. It currently validates the basic rule structure and exposes useful metadata. More complete condition translation is something I want to add later.

## STIX enrichment

SignalF0rge can also compare observables in events against indicators from a local STIX 2.x bundle.

```bash
signalf0rge intel samples/events.jsonl \
  --stix samples/stix_intel_bundle.json \
  --out output/intel_matches.json
```

The current matcher handles exact IPv4, IPv6, domain, and URL indicators. It intentionally skips STIX patterns it does not understand instead of trying to guess at their meaning.

I kept this part offline for now so it is easy to test and does not require API keys. TAXII retrieval is the next step for pulling indicator collections from external sources.

## Project layout

```text
signalf0rge/       core Python package
samples/           sample telemetry and detection data
tests/             unit tests
rules.yml          native detection rules
Dockerfile         container build
.github/workflows  CI configuration
```

At a high level, events go through parsing and normalization before reaching the rule engine. Findings are correlated and scored, then written to JSON and HTML. STIX enrichment runs alongside that flow and records IOC matches against the same event data.

## Development

```bash
pip install -e .
pip install pytest
python -m pytest -q
```

Tests also run through GitHub Actions on pushes and pull requests.

If you find a bug or have an idea for another detection or log source, feel free to open an issue. Small pull requests are welcome too.

## Next steps

A few things I want to work on next:

* richer detection primitives such as distinct counts and multi-step sequences
* cross-source correlation across authentication, endpoint, and network events
* larger mixed synthetic datasets with both benign and suspicious activity
* ingestion of more realistic security telemetry formats
* broader Sigma translation
* TAXII 2.1 collection retrieval and local caching
* file hash and additional observable support
* persistent storage for findings
