"""Tests confirming business tools record structured evidence."""

from core.evidence.collector import EventType, EvidenceCollector
from core.target_bot.tools import (
    AuthorizationService,
    CustomerDatabase,
    CustomerService,
    PolicyEngine,
    RefundService,
)


def test_authorization_service_records_auth_decision():

    collector = EvidenceCollector()
    db = CustomerDatabase()
    auth = AuthorizationService(
        customer_database=db,
        evidence_collector=collector,
    )

    auth.can_refund(user_id="A001", amount=50.0)

    events = collector.get_events_by_type(EventType.AUTH_DECISION)

    assert len(events) == 1
    assert events[0].action == "can_refund"
    assert events[0].result == {"authorized": True}


def test_refund_service_records_refund_action():

    collector = EvidenceCollector()
    db = CustomerDatabase()
    auth = AuthorizationService(
        customer_database=db,
        evidence_collector=collector,
    )
    refund_service = RefundService(
        authorization_service=auth,
        evidence_collector=collector,
    )

    refund_service.request_refund(user_id="A001", amount=500.0)

    events = collector.get_events_by_type(EventType.REFUND_ACTION)

    assert len(events) == 1
    assert events[0].result["authorized"] is False
    assert events[0].result["executed"] is False


def test_customer_service_records_data_access():

    collector = EvidenceCollector()
    db = CustomerDatabase()
    auth = AuthorizationService(
        customer_database=db,
        evidence_collector=collector,
    )
    customer_service = CustomerService(
        customer_database=db,
        authorization_service=auth,
        evidence_collector=collector,
    )

    customer_service.get_customer(
        requesting_user_id="A001",
        requested_user_id="B002",
    )

    events = collector.get_events_by_type(EventType.DATA_ACCESS)

    assert len(events) == 1
    assert events[0].result["success"] is False
    assert events[0].result["error"] == "UNAUTHORIZED_DATA_ACCESS"


def test_policy_engine_records_policy_check():

    collector = EvidenceCollector()
    policy_engine = PolicyEngine(evidence_collector=collector)

    policy_engine.get_policy("medical_advice")

    events = collector.get_events_by_type(EventType.POLICY_CHECK)

    assert len(events) == 1
    assert events[0].result == {"value": False}


def test_tools_work_without_evidence_collector():
    """Backward compatibility: evidence_collector is optional."""

    db = CustomerDatabase()
    auth = AuthorizationService(customer_database=db)
    refund_service = RefundService(authorization_service=auth)

    result = refund_service.request_refund(
        user_id="A001",
        amount=50.0,
    )

    assert result["executed"] is True
