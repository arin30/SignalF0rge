"""Standalone SOC dashboard combining detections and investigation reports."""
from __future__ import annotations

from html import escape
from pathlib import Path
import json

from .report import write_html


def _safe(value):
    return escape(str(value if value is not None else "—"))


def write_investigation_html(findings, reports, out_path):
    """Write an offline HTML dashboard with escaped, auditable case evidence."""
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Reuse the existing styled, escaped detection report.
    detection_path = write_html(findings, path.parent)
    page = detection_path.read_text(encoding="utf-8")
    cards = []
    for report in reports:
        data = report.to_dict()
        entity = _safe(data.get("entity"))
        severity = _safe(data.get("severity", "info")).lower()
        confidence = _safe(data.get("confidence", "unknown"))
        summary = _safe(data.get("evidence_summary") or data.get("summary") or "No case summary.")
        steps = data.get("steps", [])
        timeline = data.get("timeline", [])
        actions = data.get("recommended_actions") or data.get("next_steps") or []
        gaps = data.get("gaps") or []
        details = []
        for step in steps:
            evidence = step.get("evidence", [])
            details.append(
                '<details><summary>' + _safe(step.get("tool")) + ' · ' +
                _safe(step.get("result_count", len(evidence))) + ' result(s)</summary>' +
                '<p class="description">' + _safe(step.get("reason")) + '</p>' +
                '<pre>' + _safe(json.dumps(evidence, indent=2, default=str)) + '</pre></details>'
            )
        for item in timeline:
            details.append(
                '<div class="timeline-entry"><strong>' + _safe(item.get("timestamp")) +
                '</strong><p>' + _safe(item.get("description")) + '</p><div class="chips">' +
                ''.join('<span class="chip">' + _safe(fid) + '</span>' for fid in item.get("finding_ids", [])) +
                '</div></div>'
            )
        action_html = ''.join('<li>' + _safe(action) + '</li>' for action in actions)
        gap_html = ''.join('<li>' + _safe(gap) + '</li>' for gap in gaps)
        cards.append(
            '<article class="overview-card case-card severity-' + severity + '">' +
            '<div class="case-top"><div><div class="eyebrow">INVESTIGATION CASE</div><h3>' +
            entity + '</h3></div><span class="chip">' + severity.upper() +
            ' · ' + confidence + ' confidence</span></div>' +
            '<p class="description">' + summary + '</p>' +
            ('<div class="case-detail">' + ''.join(details) + '</div>' if details else '') +
            ('<h4>Evidence gaps</h4><ul>' + gap_html + '</ul>' if gaps else '') +
            ('<h4>Recommended next steps</h4><ol>' + action_html + '</ol>' if actions else '') +
            '</article>'
        )
    section = (
        '<section class="case-section"><div class="section-head"><h2>Investigation workspace</h2>' +
        '<span>' + str(len(reports)) + ' CASE(S) · READ ONLY</span></div>' +
        (''.join(cards) if cards else '<div class="overview-card">No investigation cases generated.</div>') +
        '</section>'
    )
    css = """<style>
.case-section{margin:36px 0 55px}.case-card{margin:14px 0;padding:26px 30px;border-left:3px solid #62e6a7}
.case-card.severity-critical{border-left-color:#ff5d73}.case-card.severity-high{border-left-color:#ff7b72}
.case-card.severity-medium{border-left-color:#f2c15b}.case-top{display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}
.case-top h3{font-size:24px;margin:8px 0}.case-detail{margin:22px 0}.case-detail details{border-top:1px solid #252d39;padding:12px 0}
.case-detail summary{font:12px ui-monospace,monospace;color:#62e6a7;cursor:pointer}
.case-detail pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:350px;overflow:auto}
.case-card h4{font-size:13px;margin:20px 0 8px}.case-card li{color:#c7d0da;margin:6px 0}
.timeline-entry{border-left:2px solid #34404f;padding:8px 18px;margin:12px 0}
.timeline-entry strong{font:12px ui-monospace,monospace;color:#62e6a7}
@media print{.case-card{break-inside:avoid}.case-detail details:not([open]){display:none}}
</style>"""
    marker = '<div class="section-head"><h2>Prioritized findings</h2>'
    if marker not in page:
        raise RuntimeError("Detection report template changed; dashboard insertion failed")
    page = page.replace('</head>', css + '</head>', 1)
    page = page.replace(marker, section + '\n' + marker, 1)
    path.write_text(page, encoding="utf-8")
    return path
