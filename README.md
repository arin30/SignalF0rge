# SignalF0rge

SignalF0rge is a detection engineering project I started to get more hands-on with the part of security work between raw logs and an actual incident finding.

It reads authentication, endpoint, and network events, normalizes them, runs YAML detection rules, and correlates related activity over time. The output is a JSON findings file plus a small HTML report that makes the detections easier to review.

I originally built a few straightforward detections, then kept extending the project as I ran into cases that needed more context than one log line could provide. That led to sequence rules, distinct counts, cross-source correlation, Windows/Sysmon normalization, and some basic threat-intelligence enrichment.

## Current capabilities

- native JSONL event input
- Windows Security and Sysmon-style JSONL normalization
- YAML detection rules
- threshold and distinct-count detections
- ordered sequences and multi-step correlation
- cross-source correlation between authentication, endpoint, and network events
- severity scoring
- MITRE ATT&CK mappings
- JSON findings and an HTML report
- basic Sigma metadata inspection
- exact-match STIX 2.x indicator enrichment
- pytest coverage, Docker support, and GitHub Actions CI

There are currently 24 native detections covering authentication, endpoint, network, behavioral, and cross-source activity.

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

The output directory will contain `findings.json` and `report.html`.

## Detection rules

The rules live in `rules.yml`, which lets me change thresholds, matching fields, severity, time windows, and ATT&CK mappings without changing the engine code.

The current rule types are:

- `contains` - match suspicious text in fields such as commands or messages
- `network_port` - flag selected destination ports
- `threshold` - count repeated events inside a time window
- `distinct_count` - count unique users, hosts, ports, or other values
- `sequence` - detect one event followed by another
- `multi_sequence` - detect an arbitrary ordered chain for the same entity
- `cross_source_sequence` - correlate ordered activity across telemetry sources

Some of the included rules cover password spraying, repeated login failures followed by success, suspicious/encoded PowerShell, credential access, scheduled tasks, service creation, Run Key persistence, WMI, certutil downloads, Office spawning a shell, event-log clearing, firewall disabling, port scanning, and repeated denied traffic.

The correlation rules are the part I have spent the most time on. For example, SignalF0rge can combine a successful authentication, suspicious endpoint activity, credential access, and an outbound network event into one finding when the events share a user and happen close enough together.

## Samples

Small sample:

```bash
signalf0rge analyze samples/events.jsonl --rules rules.yml --out output
```

Larger normalized sample:

```bash
signalf0rge analyze samples/advanced_events.jsonl \
  --rules rules.yml \
  --out output-advanced
open output-advanced/report.html
```

Windows/Sysmon-style sample:

```bash
signalf0rge analyze samples/windows_sysmon_events.jsonl \
  --format windows \
  --rules rules.yml \
  --out output-windows
open output-windows/report.html
```

The Windows adapter currently handles Security event IDs 4624 and 4625 and Sysmon event IDs 1, 3, and 10. Those records are mapped into the same internal event model used by the native samples, so the detection engine does not need separate rules for each input format.

## Sigma

There is a small Sigma importer for looking at rule metadata and ATT&CK tags:

```bash
signalf0rge sigma samples/sigma_suspicious_powershell.yml
```

It is deliberately limited right now. It validates the basic structure and exposes metadata, but it does not pretend to be a full Sigma condition translator.

## STIX indicators

SignalF0rge can compare event observables with indicators from a local STIX 2.x bundle:

```bash
signalf0rge intel samples/events.jsonl \
  --stix samples/stix_intel_bundle.json \
  --out output/intel_matches.json
```

The matcher currently supports exact IPv4, IPv6, domain, and URL values. Unsupported STIX patterns are skipped rather than guessed at. I kept the first version offline so it can be tested without API keys or an external service.

## Tests

```bash
pip install -e .
pip install pytest
python -m pytest -q
```

The same tests run in GitHub Actions on pushes and pull requests.

## Layout

```text
signalf0rge/       detection engine, correlation, reporting, telemetry adapters
samples/           native and Windows/Sysmon-style sample data
tests/             unit and integration tests
rules.yml          native detection rules
Dockerfile         container build
.github/workflows  CI configuration
```

At a high level the flow is:

```text
raw events -> normalize -> detect -> correlate -> score -> JSON / HTML
                                  \
                                   -> STIX indicator matches
```

## What I want to add next

The biggest thing I want to improve is entity linking. Right now user identity is useful for tying several sources together, but real investigations often need to connect users, hosts, IPs, and sessions even when there is no single shared field.

I also want to add more Windows/Sysmon event types, broader Sigma translation, TAXII retrieval, file-hash indicators, and larger datasets with more normal background activity mixed in with the attack scenarios.
