from signalf0rge.models import Finding
from signalf0rge.report import write_html, write_json


def test_write_html_escapes_untrusted_finding_content(tmp_path):
    finding = Finding(
        rule_id="RULE-<1>",
        title="Suspicious <script>alert(1)</script>",
        description="command contained <b>markup</b>",
        severity="high",
        entity="host:<test>",
        mitre=["T1059.001"],
        first_seen="2026-09-01T00:00:00Z",
        last_seen="2026-09-01T00:01:00Z",
        evidence_count=1,
        evidence=[{"command": "<script>alert(1)</script>"}],
        score=90,
    )

    report = write_html([finding], tmp_path).read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "host:&lt;test&gt;" in report


def test_write_html_handles_no_findings(tmp_path):
    report = write_html([], tmp_path).read_text(encoding="utf-8")

    assert "Total findings: 0" in report
    assert "No findings generated." in report


def test_write_json_handles_no_findings(tmp_path):
    path = write_json([], tmp_path / "nested")

    assert path.name == "findings.json"
    assert path.read_text(encoding="utf-8") == "[]"


def test_write_html_includes_incident_summary_and_analyst_sections(tmp_path):
    finding = Finding(
        rule_id="ENDPOINT-002",
        title="Encoded PowerShell",
        description="Encoded PowerShell execution detected",
        severity="high",
        entity="alice",
        mitre=["T1059.001"],
        first_seen="2026-10-22T10:00:00Z",
        last_seen="2026-10-22T10:02:00Z",
        evidence_count=2,
        evidence=[
            {"timestamp": "2026-10-22T10:00:00Z", "source_type": "endpoint", "command": "powershell.exe -enc TEST"},
            {"timestamp": "2026-10-22T10:02:00Z", "source_type": "network", "message": "Outbound connection"},
        ],
        score=90,
    )

    report = write_html([finding], tmp_path).read_text(encoding="utf-8")

    assert "SECURITY INCIDENT REPORT" in report
    assert "OVERALL SEVERITY" in report
    assert "AFFECTED ENTITIES" in report
    assert "MITRE ATT&amp;CK coverage" in report
    assert "Recommended analyst actions" in report
    assert "Prioritized findings" in report
    assert "Inspect supporting evidence" in report
    assert "alice" in report
    assert "T1059.001" in report


def test_write_html_orders_higher_severity_findings_first(tmp_path):
    low = Finding("LOW-1", "Low finding", "low", "low", "host-a", [], "1", "1", 1, [{}], 20)
    high = Finding("HIGH-1", "High finding", "high", "high", "host-b", [], "2", "2", 1, [{}], 80)

    report = write_html([low, high], tmp_path).read_text(encoding="utf-8")

    assert report.index("High finding") < report.index("Low finding")
