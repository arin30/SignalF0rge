from collections import Counter
from html import escape
from pathlib import Path
import json


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def write_json(findings, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "findings.json"
    path.write_text(json.dumps([finding.to_dict() for finding in findings], indent=2), encoding="utf-8")
    return path


def _severity_counts(findings):
    counts = Counter(f.severity.lower() for f in findings)
    return {name: counts.get(name, 0) for name in ("critical", "high", "medium", "low", "info")}


def _overall_severity(findings):
    return max(
        (f.severity.lower() for f in findings),
        key=lambda value: SEVERITY_RANK.get(value, -1),
        default="info",
    )


def _recommended_actions(findings):
    if not findings:
        return ["No immediate response action is required. Continue routine monitoring."]
    severity = _overall_severity(findings)
    actions = ["Validate the highest-scoring findings against the affected users and assets."]
    if severity in {"critical", "high"}:
        actions.append("Consider containment of affected accounts or hosts while high-severity activity is investigated.")
    if any(f.mitre for f in findings):
        actions.append("Pivot on the mapped ATT&CK techniques across the same investigation window.")
    actions.append("Search for the same indicators and behavior across additional users, hosts, and network telemetry.")
    return actions


def _evidence_rows(finding):
    rows = []
    for index, item in enumerate(finding.evidence, 1):
        timestamp = item.get("timestamp") or item.get("time") or "—"
        source = item.get("source_type") or item.get("source") or "event"
        detail = item.get("command") or item.get("message") or item.get("action") or json.dumps(item, sort_keys=True)
        rows.append(
            f'<tr><td>{index:02d}</td><td>{escape(str(timestamp))}</td>'
            f'<td>{escape(str(source))}</td><td class="evidence-detail">{escape(str(detail))}</td></tr>'
        )
    return "".join(rows) or '<tr><td colspan="4" class="empty">No evidence rows available.</td></tr>'


def write_html(findings, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = sorted(
        findings,
        key=lambda f: (SEVERITY_RANK.get(f.severity.lower(), -1), f.score, f.evidence_count),
        reverse=True,
    )
    counts = _severity_counts(findings)
    overall = _overall_severity(findings)
    entities = sorted({f.entity for f in findings if f.entity})
    techniques = sorted({tech for f in findings for tech in f.mitre})
    first_seen = min((f.first_seen for f in findings), default="—")
    last_seen = max((f.last_seen for f in findings), default="—")
    evidence_total = sum(f.evidence_count for f in findings)

    severity_cards = "".join(
        f'<div class="metric severity-metric {name}"><span>{name}</span><strong>{counts[name]}</strong></div>'
        for name in ("critical", "high", "medium", "low")
    )
    attack_chips = "".join(f'<span class="chip">{escape(t)}</span>' for t in techniques) or '<span class="muted">No ATT&CK mappings</span>'
    entity_chips = "".join(f'<span class="chip entity">{escape(e)}</span>' for e in entities) or '<span class="muted">No affected entities</span>'
    action_items = "".join(f'<li>{escape(action)}</li>' for action in _recommended_actions(findings))

    cards = []
    for index, finding in enumerate(findings, 1):
        mitre = "".join(f'<span class="chip">{escape(t)}</span>' for t in finding.mitre) or '<span class="muted">None</span>'
        cards.append(f'''<article class="finding severity-{escape(finding.severity.lower())}">
          <div class="finding-index">{index:02d}</div>
          <div class="finding-main">
            <div class="finding-head">
              <div><div class="eyebrow">{escape(finding.rule_id)} · {escape(finding.severity.upper())}</div>
              <h2>{escape(finding.title)}</h2></div>
              <div class="score"><strong>{finding.score}</strong><span>/100</span></div>
            </div>
            <p class="description">{escape(finding.description)}</p>
            <div class="finding-grid">
              <div><span class="label">ENTITY</span><strong>{escape(finding.entity)}</strong></div>
              <div><span class="label">EVIDENCE</span><strong>{finding.evidence_count} event(s)</strong></div>
              <div><span class="label">FIRST SEEN</span><strong>{escape(finding.first_seen)}</strong></div>
              <div><span class="label">LAST SEEN</span><strong>{escape(finding.last_seen)}</strong></div>
            </div>
            <div class="mapping"><span class="label">MITRE ATT&CK</span><div class="chips">{mitre}</div></div>
            <details><summary>Inspect supporting evidence <span>+</span></summary>
              <div class="evidence-wrap"><table><thead><tr><th>#</th><th>Timestamp</th><th>Source</th><th>Observed activity</th></tr></thead>
              <tbody>{_evidence_rows(finding)}</tbody></table>
              <details class="raw"><summary>Raw evidence JSON</summary><pre>{escape(json.dumps(finding.evidence, indent=2))}</pre></details></div>
            </details>
          </div>
        </article>''')

    empty = '''<section class="empty-state"><div class="empty-icon">✓</div><h2>No findings generated.</h2><p>Total findings: 0 · The analyzed telemetry did not produce any SignalF0rge findings.</p></section>'''

    html = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SignalF0rge Incident Report</title>
<style>
:root{{--bg:#080b10;--panel:#10151d;--panel2:#151b24;--line:#252d39;--text:#eef2f6;--muted:#8e9aaa;--accent:#62e6a7;--critical:#ff5d73;--high:#ff7b72;--medium:#f2c15b;--low:#62e6a7;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;line-height:1.55}}
body:before{{content:"";position:fixed;inset:0;background:radial-gradient(circle at 85% 0%,rgba(98,230,167,.08),transparent 28%);pointer-events:none}}
main{{width:min(1180px,calc(100% - 40px));margin:0 auto;padding:52px 0 80px}}
.brand{{font:700 13px var(--mono);letter-spacing:.14em;color:var(--accent);margin-bottom:42px}} .brand span{{color:var(--muted)}}
.hero{{display:grid;grid-template-columns:1.5fr .8fr;gap:40px;border-bottom:1px solid var(--line);padding-bottom:38px}}
.kicker,.eyebrow,.label{{font:600 11px var(--mono);letter-spacing:.12em;color:var(--muted)}} h1{{font-size:clamp(36px,6vw,70px);line-height:.98;letter-spacing:-.055em;margin:12px 0 18px;max-width:780px}}
.hero p{{color:var(--muted);max-width:720px;font-size:16px}} .status{{align-self:end;border:1px solid var(--line);background:var(--panel);padding:22px}}
.status-row{{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding:9px 0;font:12px var(--mono)}} .status-row:last-child{{border:0}} .status-row span{{color:var(--muted)}}
.status .overall{{color:var(--{overall if overall in ("critical","high","medium","low") else "accent"});text-transform:uppercase}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);margin:30px 0}}
.metric{{background:var(--panel);padding:18px 20px;display:flex;justify-content:space-between;align-items:end}} .metric span{{font:11px var(--mono);text-transform:uppercase;color:var(--muted)}} .metric strong{{font:600 28px var(--mono)}}
.metric.critical strong{{color:var(--critical)}} .metric.high strong{{color:var(--high)}} .metric.medium strong{{color:var(--medium)}} .metric.low strong{{color:var(--low)}}
.overview{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:18px 0 54px}} .overview-card{{background:var(--panel);border:1px solid var(--line);padding:24px}}
.overview-card h3{{margin:0 0 15px;font-size:14px}} .chips{{display:flex;flex-wrap:wrap;gap:7px}} .chip{{border:1px solid #34404f;background:#131a22;padding:5px 8px;border-radius:4px;font:11px var(--mono);color:#cbd5df}} .chip.entity{{color:var(--accent)}}
.actions{{grid-column:1/-1}} .actions ol{{margin:12px 0 0;padding-left:20px;color:#c7d0da}} .actions li{{padding:5px 0}}
.section-head{{display:flex;justify-content:space-between;align-items:end;margin-bottom:18px}} .section-head h2{{font-size:26px;margin:0}} .section-head span{{font:11px var(--mono);color:var(--muted)}}
.finding{{position:relative;display:grid;grid-template-columns:58px 1fr;background:var(--panel);border:1px solid var(--line);margin:12px 0;overflow:hidden}} .finding:before{{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:#596575}}
.severity-critical:before{{background:var(--critical)}} .severity-high:before{{background:var(--high)}} .severity-medium:before{{background:var(--medium)}} .severity-low:before{{background:var(--low)}}
.finding-index{{font:12px var(--mono);color:#596575;padding:25px 0;text-align:center;border-right:1px solid var(--line)}} .finding-main{{padding:24px 26px}}
.finding-head{{display:flex;justify-content:space-between;gap:30px;align-items:start}} .finding-head h2{{font-size:20px;margin:5px 0 0}} .score{{font:12px var(--mono);white-space:nowrap;color:var(--muted)}} .score strong{{font-size:28px;color:var(--text)}} .description{{color:#aeb9c5;max-width:850px}}
.finding-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:16px 0;margin:20px 0}} .finding-grid strong{{display:block;font:12px var(--mono);margin-top:5px;overflow-wrap:anywhere}}
.mapping{{display:flex;gap:18px;align-items:center}} details>summary{{cursor:pointer;list-style:none}} details>summary::-webkit-details-marker{{display:none}} .finding-main>details>summary{{display:flex;justify-content:space-between;border-top:1px solid var(--line);margin-top:20px;padding-top:17px;font:12px var(--mono);color:var(--accent)}}
.evidence-wrap{{margin-top:18px;border:1px solid var(--line);overflow:auto}} table{{width:100%;border-collapse:collapse;font:11px var(--mono);min-width:720px}} th{{text-align:left;color:var(--muted);background:#0c1016}} th,td{{padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}} .evidence-detail{{max-width:560px;white-space:pre-wrap;overflow-wrap:anywhere}} .raw{{padding:14px}} .raw summary{{color:var(--muted);font:11px var(--mono)}} pre{{background:#07090d;border:1px solid var(--line);padding:16px;overflow:auto;color:#b9c6d3;font:11px var(--mono)}}
.empty-state{{text-align:center;background:var(--panel);border:1px solid var(--line);padding:70px 20px}} .empty-icon{{font-size:38px;color:var(--accent)}} .empty-state p,.muted{{color:var(--muted)}}
.footer{{margin-top:45px;padding-top:18px;border-top:1px solid var(--line);display:flex;justify-content:space-between;color:#657181;font:10px var(--mono);letter-spacing:.06em}}
@media(max-width:760px){{main{{width:min(100% - 24px,1180px);padding-top:30px}}.hero,.overview{{grid-template-columns:1fr}}.metrics{{grid-template-columns:1fr 1fr}}.finding{{grid-template-columns:1fr}}.finding-index{{display:none}}.finding-grid{{grid-template-columns:1fr 1fr}}.finding-head{{display:block}}.score{{margin-top:10px}}}}
@media print{{body{{background:#fff;color:#111}}body:before{{display:none}}main{{width:100%;padding:0}}.brand,.footer{{color:#555}}.hero,.finding,.overview-card,.status,.metric{{background:#fff;border-color:#ccc}}.finding-main>details{{display:none}}}}
</style></head><body><main>
<div class="brand">SIGNALF0RGE <span>/ INCIDENT ANALYSIS</span></div>
<section class="hero"><div><div class="kicker">SECURITY INCIDENT REPORT</div><h1>Detection summary &amp; investigation evidence.</h1><p>Deterministic findings generated from normalized security telemetry. Severity, evidence, and ATT&amp;CK mappings below are traceable to SignalF0rge detection logic.</p></div>
<div class="status"><div class="status-row"><span>OVERALL SEVERITY</span><strong class="overall">{escape(overall.upper())}</strong></div><div class="status-row"><span>FINDINGS</span><strong>{len(findings)}</strong></div><div class="status-row"><span>AFFECTED ENTITIES</span><strong>{len(entities)}</strong></div><div class="status-row"><span>EVIDENCE EVENTS</span><strong>{evidence_total}</strong></div><div class="status-row"><span>WINDOW</span><strong>{escape(first_seen)} → {escape(last_seen)}</strong></div></div></section>
<section class="metrics">{severity_cards}</section>
<section class="overview"><div class="overview-card"><h3>Affected entities</h3><div class="chips">{entity_chips}</div></div><div class="overview-card"><h3>MITRE ATT&amp;CK coverage</h3><div class="chips">{attack_chips}</div></div><div class="overview-card actions"><h3>Recommended analyst actions</h3><ol>{action_items}</ol></div></section>
<div class="section-head"><h2>Prioritized findings</h2><span>ORDERED BY SEVERITY · SCORE · EVIDENCE</span></div>
{''.join(cards) if cards else empty}
<div class="footer"><span>GENERATED BY SIGNALF0RGE</span><span>DETERMINISTIC DETECTION OUTPUT · REVIEW BEFORE RESPONSE ACTION</span></div>
</main></body></html>'''
    path = out_dir / "report.html"
    path.write_text(html, encoding="utf-8")
    return path
