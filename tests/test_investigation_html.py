from signalf0rge.agent import Investigation
from signalf0rge.models import Finding
from signalf0rge.investigation_html import write_investigation_html


def test_dashboard_preserves_existing_detection_report(tmp_path):
    detection_report = tmp_path / "report.html"
    detection_report.write_text("Existing analyst report", encoding="utf-8")

    result = write_investigation_html([], [], tmp_path / "dashboard.html")

    assert result.is_file()
    assert "Investigation workspace" in result.read_text(encoding="utf-8")
    assert detection_report.read_text(encoding="utf-8") == "Existing analyst report"


def test_dashboard_does_not_leave_an_extra_detection_report(tmp_path):
    write_investigation_html([], [], tmp_path / "dashboard.html")
    assert sorted(path.name for path in tmp_path.iterdir()) == ["dashboard.html"]


def test_dashboard_renders_cases_and_escapes_untrusted_evidence(tmp_path):
    finding = Finding(
        "ENDPOINT-001", "Suspicious shell", "Detected", "high", "host-1",
        ["T1059"], "2026-10-20T10:00:00", "2026-10-20T10:01:00",
        1, [{"message": "<script>alert(1)</script>"}], 85,
    )
    case = Investigation(
        entity="host-1", severity="high", confidence="medium", finding_count=1,
        finding_ids=["ENDPOINT-001"], mitre_techniques=["T1059"],
        first_seen="2026-10-20T10:00:00", last_seen="2026-10-20T10:01:00",
        evidence_count=1, summary="<script>alert(1)</script>",
        recommended_actions=["Review endpoint telemetry"],
    )
    page = write_investigation_html([finding], [case], tmp_path / "dashboard.html").read_text()
    assert "Investigation workspace" in page
    assert "Prioritized findings" in page
    assert "Review endpoint telemetry" in page
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_dashboard_renders_narrative_timeline(tmp_path):
    report = {
        "entity": "host-1", "severity": "high", "confidence": "medium",
        "summary": "Suspicious activity", "timeline": [
            {"timestamp": "2026-10-20T10:00:00", "description": "Observed",
             "finding_ids": ["ENDPOINT-001"]}
        ], "gaps": ["Missing process tree"], "next_steps": ["Investigate"],
    }
    page = write_investigation_html([], [report], tmp_path / "dashboard.html").read_text()
    assert "Missing process tree" in page
    assert "ENDPOINT-001" in page
    assert "Investigate" in page
