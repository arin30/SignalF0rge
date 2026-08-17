from html import escape
from pathlib import Path
import json


def write_json(findings, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "findings.json"
    path.write_text(json.dumps([finding.to_dict() for finding in findings], indent=2), encoding="utf-8")
    return path


def write_html(findings, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cards = []
    for finding in findings:
        cards.append(
            f'''<section class="finding severity-{escape(finding.severity)}">
            <div class="top"><h2>{escape(finding.title)}</h2><span>{finding.score}/100</span></div>
            <p>{escape(finding.description)}</p>
            <div class="meta">
              <span><b>Rule:</b> {escape(finding.rule_id)}</span>
              <span><b>Severity:</b> {escape(finding.severity.upper())}</span>
              <span><b>Entity:</b> {escape(finding.entity)}</span>
              <span><b>MITRE:</b> {escape(", ".join(finding.mitre) or "None")}</span>
              <span><b>Evidence:</b> {finding.evidence_count}</span>
              <span><b>Window:</b> {escape(finding.first_seen)} to {escape(finding.last_seen)}</span>
            </div>
            <details><summary>Evidence</summary><pre>{escape(json.dumps(finding.evidence, indent=2))}</pre></details>
            </section>'''
        )

    html = f'''<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SignalF0rge Incident Report</title>
<style>
body {{ font-family: Arial, sans-serif; background: #f4f5f7; margin: 0; padding: 30px; color: #171717; }}
main {{ max-width: 1000px; margin: auto; }}
.finding {{ background: white; border-left: 6px solid #777; padding: 18px; margin: 14px 0; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
.severity-critical {{ border-left-color: #7a0000; }}
.severity-high {{ border-left-color: #b42318; }}
.severity-medium {{ border-left-color: #b26a00; }}
.severity-low {{ border-left-color: #1f6f43; }}
.top {{ display: flex; justify-content: space-between; gap: 20px; align-items: center; }}
.top h2 {{ margin: 0; font-size: 20px; }}
.meta {{ display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 8px 16px; font-size: 14px; }}
pre {{ overflow: auto; background: #111; color: #eee; padding: 14px; }}
summary {{ cursor: pointer; margin-top: 12px; }}
</style>
</head>
<body><main><header><h1>SignalF0rge Security Findings</h1><p>Total findings: {len(findings)}</p></header>{''.join(cards) if cards else '<p>No findings generated.</p>'}</main></body>
</html>'''
    path = out_dir / "report.html"
    path.write_text(html, encoding="utf-8")
    return path
