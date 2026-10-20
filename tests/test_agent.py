from signalf0rge.agent import investigate
from signalf0rge.models import Finding


def _finding(rule_id, title, severity="medium", entity="alice", mitre=None, evidence_count=1):
    return Finding(
        rule_id=rule_id,
        title=title,
        description="test",
        severity=severity,
        entity=entity,
        mitre=mitre or [],
        first_seen="2026-10-20T10:00:00",
        last_seen="2026-10-20T10:05:00",
        evidence_count=evidence_count,
        evidence=[{"event": "test"}] * evidence_count,
        score=50,
    )


def test_investigate_groups_findings_into_entity_case():
    findings = [
        _finding("AUTH-1", "Successful login", entity="alice", mitre=["T1078"]),
        _finding("PS-1", "Suspicious PowerShell", severity="high", entity="alice", mitre=["T1059.001"], evidence_count=2),
    ]

    cases = investigate(findings)

    assert len(cases) == 1
    assert cases[0].entity == "alice"
    assert cases[0].severity == "high"
    assert cases[0].confidence == "medium"
    assert cases[0].finding_count == 2
    assert cases[0].evidence_count == 3
    assert cases[0].mitre_techniques == ["T1059.001", "T1078"]


def test_investigate_prioritizes_high_severity_case():
    findings = [
        _finding("LOW-1", "Low signal", severity="low", entity="bob"),
        _finding("HIGH-1", "High signal", severity="high", entity="alice"),
    ]

    cases = investigate(findings)

    assert [case.entity for case in cases] == ["alice", "bob"]


def test_three_findings_with_multiple_techniques_raise_confidence():
    findings = [
        _finding("A", "A", entity="alice", mitre=["T1078"]),
        _finding("B", "B", entity="alice", mitre=["T1059.001"]),
        _finding("C", "C", entity="alice"),
    ]

    assert investigate(findings)[0].confidence == "high"
