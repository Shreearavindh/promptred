"""Tests for the evidence collector."""

from core.evidence.collector import EventType, EvidenceCollector


def test_record_returns_event_with_expected_fields():

    collector = EvidenceCollector()

    event = collector.record(
        event_type=EventType.AUTH_DECISION,
        actor="A001",
        action="can_refund",
        inputs={"amount": 50.0},
        result={"authorized": True},
    )

    assert event.event_type is EventType.AUTH_DECISION
    assert event.actor == "A001"
    assert event.action == "can_refund"
    assert event.inputs == {"amount": 50.0}
    assert event.result == {"authorized": True}
    assert event.timestamp


def test_events_are_recorded_in_order():

    collector = EvidenceCollector()

    collector.record(
        event_type=EventType.POLICY_CHECK,
        actor="system",
        action="first",
    )
    collector.record(
        event_type=EventType.POLICY_CHECK,
        actor="system",
        action="second",
    )

    events = collector.get_events()

    assert [event.action for event in events] == [
        "first",
        "second",
    ]


def test_get_events_by_type_filters_correctly():

    collector = EvidenceCollector()

    collector.record(
        event_type=EventType.REFUND_ACTION,
        actor="A001",
        action="request_refund",
    )
    collector.record(
        event_type=EventType.AUTH_DECISION,
        actor="A001",
        action="can_refund",
    )

    refund_events = collector.get_events_by_type(
        EventType.REFUND_ACTION
    )

    assert len(refund_events) == 1
    assert refund_events[0].action == "request_refund"


def test_to_dict_serializes_all_events():

    collector = EvidenceCollector()

    collector.record(
        event_type=EventType.DATA_ACCESS,
        actor="A001",
        action="get_customer",
        result={"success": True},
    )

    serialized = collector.to_dict()

    assert len(serialized) == 1
    assert serialized[0]["event_type"] == "data_access"
    assert serialized[0]["result"] == {"success": True}


def test_clear_removes_all_events():

    collector = EvidenceCollector()

    collector.record(
        event_type=EventType.TOOL_CALL,
        actor="A001",
        action="anything",
    )

    collector.clear()

    assert collector.get_events() == []
