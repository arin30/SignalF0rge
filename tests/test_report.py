from signalf0rge.models import Finding
from signalf0rge.report import write_html


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
