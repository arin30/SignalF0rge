# Contributing to SignalF0rge

Contributions are welcome. SignalF0rge is intentionally structured so new detections, parsers, enrichment modules, and reporting improvements can be added independently.

## Good starter contributions

- Add JSONL, CSV, or syslog parsers
- Add new detection rules
- Improve event correlation logic
- Add MITRE ATT&CK context
- Add Sigma rule import
- Improve reporting
- Add unit tests

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest
pytest -q
```

For Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
pip install pytest
pytest -q
```

Please open an issue before making large architectural changes.
