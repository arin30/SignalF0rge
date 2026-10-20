from datetime import datetime

from signalf0rge.entity_linking import link_entities
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
