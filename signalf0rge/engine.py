from collections import defaultdict, deque
from datetime import timedelta
from .models import Finding
from .correlate import entity_for, severity_score


def event_matches(event, match):
    return all(event.get(k) == v for k, v in match.items())


def step_matches(event, step):
    source_type = step.get("source_type")
    if source_type and event.source_type != source_type:
        return False

    if not event_matches(event, step.get("match", {})):
        return False

    for field, needles in step.get("contains", {}).items():
        value = event.get(field)
        if value is None:
            return False
        if not isinstance(needles, list):
            needles = [needles]
        haystack = str(value).lower()
        if not any(str(needle).lower() in haystack for needle in needles):
            return False

    ports = step.get("ports")
    if ports is not None and event.dst_port not in set(ports):
        return False

    return True


def serialize_event(event):
    data = dict(event.raw)
    data["timestamp"] = event.timestamp.isoformat().replace("+00:00", "Z")
    return data


def finding_from(rule, events, entity):
    data = rule.data
    return Finding(
        rule_id=data["id"],
        title=data["title"],
        description=data.get("description", ""),
        severity=data.get("severity", "low"),
        entity=entity,
        mitre=data.get("mitre", []),
        first_seen=events[0].timestamp.isoformat().replace("+00:00", "Z"),
        last_seen=events[-1].timestamp.isoformat().replace("+00:00", "Z"),
        evidence_count=len(events),
        evidence=[serialize_event(e) for e in events],
        score=severity_score(data.get("severity", "low"), len(events)),
    )


def evaluate_contains(rule, events):
    data = rule.data
    needles = [str(x).lower() for x in data.get("any", [])]
    findings = []
    for event in events:
        if event.source_type != rule.source_type:
            continue
        value = event.get(data["field"])
        if value and any(needle in str(value).lower() for needle in needles):
            findings.append(finding_from(rule, [event], entity_for(event)))
    return findings


def evaluate_network_port(rule, events):
    ports = set(rule.data.get("ports", []))
    return [
        finding_from(rule, [event], entity_for(event, "dst_ip"))
        for event in events
        if event.source_type == rule.source_type and event.dst_port in ports
    ]


def evaluate_threshold(rule, events):
    data = rule.data
    group_by = data["group_by"]
    threshold = int(data["threshold"])
    window = timedelta(minutes=int(data["window_minutes"]))
    groups = defaultdict(list)

    for event in events:
        if event.source_type == rule.source_type and event_matches(event, data.get("match", {})):
            key = event.get(group_by)
            if key:
                groups[str(key)].append(event)

    findings = []
    for key, group in groups.items():
        queue = deque()
        for event in group:
            while queue and (event.timestamp - queue[0].timestamp) > window:
                queue.popleft()
            queue.append(event)
            if len(queue) == threshold:
                findings.append(finding_from(rule, list(queue), f"{group_by}:{key}"))
    return findings


def evaluate_distinct_count(rule, events):
    data = rule.data
    group_by = data["group_by"]
    distinct_field = data["distinct_field"]
    threshold = int(data["threshold"])
    window = timedelta(minutes=int(data["window_minutes"]))
    groups = defaultdict(list)

    for event in events:
        if event.source_type != rule.source_type:
            continue
        if not event_matches(event, data.get("match", {})):
            continue
        key = event.get(group_by)
        distinct_value = event.get(distinct_field)
        if key and distinct_value is not None:
            groups[str(key)].append(event)

    findings = []
    for key, group in groups.items():
        queue = deque()
        active = False
        for event in group:
            while queue and (event.timestamp - queue[0].timestamp) > window:
                queue.popleft()
            queue.append(event)
            distinct_values = {item.get(distinct_field) for item in queue if item.get(distinct_field) is not None}
            if len(distinct_values) >= threshold and not active:
                findings.append(finding_from(rule, list(queue), f"{group_by}:{key}"))
                active = True
            elif len(distinct_values) < threshold:
                active = False
    return findings


def evaluate_sequence(rule, events):
    data = rule.data
    group_by = data["group_by"]
    threshold = int(data["threshold"])
    window = timedelta(minutes=int(data["window_minutes"]))
    first_match = data["sequence"]["first"]
    second_match = data["sequence"]["second"]
    groups = defaultdict(list)

    for event in events:
        if event.source_type == rule.source_type:
            key = event.get(group_by)
            if key:
                groups[str(key)].append(event)

    findings = []
    for key, group in groups.items():
        first_events = deque()
        for event in group:
            while first_events and (event.timestamp - first_events[0].timestamp) > window:
                first_events.popleft()
            if event_matches(event, first_match):
                first_events.append(event)
            elif event_matches(event, second_match) and len(first_events) >= threshold:
                evidence = list(first_events) + [event]
                findings.append(finding_from(rule, evidence, f"{group_by}:{key}"))
                first_events.clear()
    return findings


def evaluate_multi_sequence(rule, events):
    data = rule.data
    group_by = data["group_by"]
    steps = data.get("steps", [])
    if len(steps) < 2:
        raise ValueError(f"{data.get('id', 'multi_sequence')} requires at least two steps")

    window = timedelta(minutes=int(data["window_minutes"]))
    groups = defaultdict(list)

    for event in events:
        key = event.get(group_by)
        if key:
            groups[str(key)].append(event)

    findings = []
    for key, group in groups.items():
        progress = 0
        evidence = []

        for event in group:
            if evidence and (event.timestamp - evidence[0].timestamp) > window:
                progress = 0
                evidence = []

            if step_matches(event, steps[progress]):
                evidence.append(event)
                progress += 1
                if progress == len(steps):
                    findings.append(finding_from(rule, list(evidence), f"{group_by}:{key}"))
                    progress = 0
                    evidence = []
            elif step_matches(event, steps[0]):
                progress = 1
                evidence = [event]

    return findings


def analyze(events, rules):
    findings = []
    evaluators = {
        "contains": evaluate_contains,
        "network_port": evaluate_network_port,
        "threshold": evaluate_threshold,
        "distinct_count": evaluate_distinct_count,
        "sequence": evaluate_sequence,
        "multi_sequence": evaluate_multi_sequence,
        "cross_source_sequence": evaluate_multi_sequence,
    }
    for rule in rules:
        kind = rule.data.get("kind")
        evaluator = evaluators.get(kind)
        if not evaluator:
            raise ValueError(f"Unsupported rule kind: {kind}")
        findings.extend(evaluator(rule, events))

    findings.sort(key=lambda finding: (-finding.score, finding.first_seen))
    return findings
