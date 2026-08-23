from pathlib import Path
import yaml


def load_sigma_rule(path: str | Path) -> dict:
    """Load a Sigma YAML rule and return a normalized metadata view.

    SignalF0rge does not pretend to support the full Sigma condition language yet.
    This importer gives analysts a useful bridge for cataloging Sigma detections,
    ATT&CK tags, log sources, and simple field selections before translation.
    """
    with Path(path).open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("Sigma rule must be a YAML mapping")
    if not data.get("title") or not data.get("detection"):
        raise ValueError("Sigma rule requires title and detection fields")

    tags = data.get("tags", []) or []
    attack = [tag for tag in tags if str(tag).startswith("attack.")]
    return {
        "title": data["title"],
        "id": data.get("id"),
        "status": data.get("status"),
        "description": data.get("description"),
        "logsource": data.get("logsource") or {},
        "detection": data["detection"],
        "level": data.get("level", "medium"),
        "attack_tags": attack,
        "source": str(path),
    }


def sigma_summary(rule: dict) -> str:
    logsource = rule.get("logsource", {})
    product = logsource.get("product", "unknown")
    category = logsource.get("category", "unspecified")
    attacks = ", ".join(rule.get("attack_tags", [])) or "none"
    return (
        f"Sigma: {rule['title']}\n"
        f"Level: {rule['level']}\n"
        f"Log source: {product}/{category}\n"
        f"ATT&CK tags: {attacks}"
    )
