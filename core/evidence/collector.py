"""Structured, event-sourced execution evidence for PromptRed.

Conversation transcripts alone cannot prove whether a guardrail was
actually bypassed - a response might merely *sound* like a leak without
an authorization check ever having been circumvented. The evidence
collector records every tool call, authorization decision, and policy
check as an immutable event so the evaluator has ground-truth execution
data to reason over, not just text.
"""

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventType(Enum):
    """Categories of recordable execution evidence."""

    TOOL_CALL = "tool_call"
    AUTH_DECISION = "auth_decision"
    DATA_ACCESS = "data_access"
    POLICY_CHECK = "policy_check"
    REFUND_ACTION = "refund_action"


@dataclass(frozen=True)
class EvidenceEvent:
    """One immutable record of something the target system did."""

    timestamp: str
    event_type: EventType
    actor: str
    action: str
    inputs: dict[str, Any]
    result: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event to a plain dict."""

        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "actor": self.actor,
            "action": self.action,
            "inputs": self.inputs,
            "result": self.result,
            "metadata": self.metadata,
        }


class EvidenceCollector:
    """Append-only log of execution evidence for a single harness run."""

    def __init__(self) -> None:
        self._events: list[EvidenceEvent] = []
        self._lock = threading.Lock()

    def record(
        self,
        event_type: EventType,
        actor: str,
        action: str,
        inputs: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceEvent:
        """Record one evidence event and return it."""

        event = EvidenceEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            actor=actor,
            action=action,
            inputs=inputs or {},
            result=result or {},
            metadata=metadata or {},
        )

        with self._lock:
            self._events.append(event)

        return event

    def get_events(self) -> list[EvidenceEvent]:
        """Return all recorded events, in recording order."""

        with self._lock:
            return list(self._events)

    def get_events_by_type(
        self,
        event_type: EventType,
    ) -> list[EvidenceEvent]:
        """Return only events matching the given type."""

        with self._lock:
            return [
                event
                for event in self._events
                if event.event_type is event_type
            ]

    def to_dict(self) -> list[dict[str, Any]]:
        """Serialize the full event log to plain dicts."""

        return [event.to_dict() for event in self.get_events()]

    def clear(self) -> None:
        """Remove all recorded events."""

        with self._lock:
            self._events.clear()
