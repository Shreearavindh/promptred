"""Tests for the PromptRed multi-turn attack harness."""

from typing import Any

from core.attacks.harness import MultiTurnHarness
from core.evidence.collector import EventType, EvidenceCollector


class FakeAttackSource:
    """Deterministic attack generator for testing."""

    def __init__(self) -> None:
        self.calls = 0

    def generate(
        self,
        system_prompt: str,
        guardrail_category: str,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:

        self.calls += 1

        return {
            "attack": f"Attack turn {self.calls}",
            "technique": "Test Technique",
            "objective": "Test Objective",
        }


class FakeTarget:
    """Deterministic target bot for testing."""

    def __init__(self) -> None:
        self.calls = 0

    def chat(
        self,
        message: str,
    ) -> str:

        self.calls += 1

        return f"Response to: {message}"


def test_one_turn_attack():

    attack_source = FakeAttackSource()
    target = FakeTarget()

    harness = MultiTurnHarness(
        target=target,
        attack_source=attack_source,
    )

    result = harness.run(
        system_prompt="Test system prompt.",
        guardrail_category="unauthorized_refund",
        turns=1,
    )

    assert len(result.turns) == 1
    assert result.turns[0].turn == 1

    assert result.turns[0].attack == (
        "Attack turn 1"
    )

    assert result.turns[0].response == (
        "Response to: Attack turn 1"
    )


def test_three_turn_attack():

    attack_source = FakeAttackSource()
    target = FakeTarget()

    harness = MultiTurnHarness(
        target=target,
        attack_source=attack_source,
    )

    result = harness.run(
        system_prompt="Test system prompt.",
        guardrail_category="policy_circumvention",
        turns=3,
    )

    assert len(result.turns) == 3

    assert result.turns[0].turn == 1
    assert result.turns[1].turn == 2
    assert result.turns[2].turn == 3

    assert result.turns[0].attack == (
        "Attack turn 1"
    )

    assert result.turns[1].attack == (
        "Attack turn 2"
    )

    assert result.turns[2].attack == (
        "Attack turn 3"
    )


def test_transcript_contains_all_turns():

    attack_source = FakeAttackSource()
    target = FakeTarget()

    harness = MultiTurnHarness(
        target=target,
        attack_source=attack_source,
    )

    result = harness.run(
        system_prompt="Test system prompt.",
        guardrail_category="system_prompt_extraction",
        turns=3,
    )

    transcript = result.transcript

    assert len(transcript) == 6

    assert transcript[0]["role"] == "user"
    assert transcript[1]["role"] == "assistant"

    assert transcript[2]["role"] == "user"
    assert transcript[3]["role"] == "assistant"

    assert transcript[4]["role"] == "user"
    assert transcript[5]["role"] == "assistant"


def test_invalid_turn_count_is_rejected():

    attack_source = FakeAttackSource()
    target = FakeTarget()

    harness = MultiTurnHarness(
        target=target,
        attack_source=attack_source,
    )

    try:
        harness.run(
            system_prompt="Test system prompt.",
            guardrail_category="unauthorized_refund",
            turns=2,
        )

        assert False, (
            "Expected ValueError for invalid turn count."
        )

    except ValueError as error:
        assert "1-turn and 3-turn" in str(error)


def test_harness_populates_evidence_from_collector():

    attack_source = FakeAttackSource()
    target = FakeTarget()
    collector = EvidenceCollector()

    collector.record(
        event_type=EventType.AUTH_DECISION,
        actor="A001",
        action="can_refund",
        result={"authorized": True},
    )

    harness = MultiTurnHarness(
        target=target,
        attack_source=attack_source,
        evidence_collector=collector,
    )

    result = harness.run(
        system_prompt="Test system prompt.",
        guardrail_category="unauthorized_refund",
        turns=1,
    )

    assert len(result.evidence) == 1
    assert result.evidence[0]["action"] == "can_refund"


def test_harness_evidence_defaults_to_empty_list():

    attack_source = FakeAttackSource()
    target = FakeTarget()

    harness = MultiTurnHarness(
        target=target,
        attack_source=attack_source,
    )

    result = harness.run(
        system_prompt="Test system prompt.",
        guardrail_category="unauthorized_refund",
        turns=1,
    )

    assert result.evidence == []