from datetime import datetime

from signalf0rge.entity_linking import link_entities, traverse_entities
from signalf0rge.models import Event


def test_link_entities_connects_user_host_and_ip():
    events = [
        Event(datetime(2026, 10, 20, 10), "auth", user="alice", host="laptop-17", src_ip="10.0.0.42"),
        Event(datetime(2026, 10, 20, 11), "network", user="alice", host="laptop-17", src_ip="10.0.0.42", dst_ip="203.0.113.9"),
    ]

    links = link_entities(events, "alice")
    targets = {link.target for link in links}

    assert {"laptop-17", "10.0.0.42", "203.0.113.9"} <= targets
    host_link = next(link for link in links if link.target == "laptop-17")
    assert host_link.observations == 2


def test_traverse_entities_follows_two_hop_relationships():
    events = [
        Event(datetime(2026, 10, 20, 10), "auth", user="alice", host="laptop-17"),
        Event(datetime(2026, 10, 20, 11), "network", host="laptop-17", src_ip="10.0.0.42"),
        Event(datetime(2026, 10, 20, 12), "network", src_ip="10.0.0.42", dst_ip="203.0.113.9"),
    ]

    links = traverse_entities(events, "alice", max_depth=2)
    pairs = {(link.source, link.target) for link in links}

    assert ("alice", "laptop-17") in pairs
    assert ("laptop-17", "10.0.0.42") in pairs
    assert ("10.0.0.42", "203.0.113.9") not in pairs


def test_traverse_entities_respects_depth_limit():
    events = [
        Event(datetime(2026, 10, 20, 10), "auth", user="alice", host="laptop-17"),
        Event(datetime(2026, 10, 20, 11), "network", host="laptop-17", src_ip="10.0.0.42"),
    ]

    links = traverse_entities(events, "alice", max_depth=1)

    assert {link.target for link in links} == {"laptop-17"}


def test_traverse_entities_rejects_unbounded_requests():
    events = []

    try:
        traverse_entities(events, "alice", max_depth=20)
    except ValueError as exc:
        assert "max_depth" in str(exc)
    else:
        raise AssertionError("expected traversal depth validation")
