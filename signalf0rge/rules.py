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
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list): raise ValueError("rules.yml must contain a top-level 'rules' list")
    return [Rule(r) for r in raw_rules]
