SEVERITY_SCORES = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}

def entity_for(event, preferred=None):
    if preferred:
        value = event.get(preferred)
        if value:
            return f"{preferred}:{value}"
    for field in ("user", "host", "src_ip", "dst_ip"):
        value = event.get(field)
        if value:
            return f"{field}:{value}"
    return "event:unknown"

def severity_score(severity, evidence_count):
    base = SEVERITY_SCORES.get(severity.lower(), 25)
    return min(100, base + max(0, evidence_count - 1) * 2)
