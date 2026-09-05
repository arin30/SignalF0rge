from dataclasses import dataclass
from pathlib import Path
import yaml

@dataclass
class Rule:
    data: dict
    @property
    def source_type(self): return self.data.get("source_type")

def load_rules(path: str | Path) -> list[Rule]:
    with Path(path).open("r", encoding="utf-8") as f: data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("rules.yml must contain a top-level mapping")
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list): raise ValueError("rules.yml must contain a top-level 'rules' list")
    if any(not isinstance(rule, dict) for rule in raw_rules):
        raise ValueError("each rule in rules.yml must be a mapping")
    if any(not isinstance(rule.get("id"), str) or not rule["id"].strip() for rule in raw_rules):
        raise ValueError("each rule in rules.yml must have a non-empty string ID")
    rule_ids = [rule["id"] for rule in raw_rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("rule IDs in rules.yml must be unique")
    return [Rule(r) for r in raw_rules]
