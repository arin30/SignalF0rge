from signalf0rge.sigma import load_sigma_rule, sigma_summary


def test_sigma_import(tmp_path):
    rule = tmp_path / "rule.yml"
    rule.write_text(
        """title: Test Detection
logsource:
  product: windows
detection:
  selection:
    Image: powershell.exe
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
""",
        encoding="utf-8",
    )
    loaded = load_sigma_rule(rule)
    assert loaded["title"] == "Test Detection"
    assert loaded["level"] == "high"
    assert "attack.t1059.001" in loaded["attack_tags"]
    assert "Sigma: Test Detection" in sigma_summary(loaded)


def test_sigma_requires_detection(tmp_path):
    rule = tmp_path / "bad.yml"
    rule.write_text("title: Incomplete\n", encoding="utf-8")
    try:
        load_sigma_rule(rule)
    except ValueError as exc:
        assert "title and detection" in str(exc)
    else:
        raise AssertionError("Expected invalid Sigma rule to raise ValueError")
