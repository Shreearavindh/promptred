"""Multi-turn attack execution harness for PromptRed."""

from dataclasses import dataclass, field
from typing import Any, Protocol

from core.evidence.collector import EvidenceCollector


class TargetBot(Protocol):
    """Interface required by the attack harness."""

    def chat(
        self,
        message: str,
    ) -> str:
        """Send a message to the target and return its response."""
        ...


class AttackSource(Protocol):
    """Interface required to generate attacks."""

    def generate(
        self,
        system_prompt: str,
        guardrail_category: str,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Generate one adversarial attack."""
        ...


@dataclass
class TurnResult:
    """Result of one attack turn."""

    turn: int
    attack: str
    response: str
    technique: str
    objective: str


@dataclass
class HarnessResult:
    """Complete result of a multi-turn attack."""

    guardrail_category: str
    turns: list[TurnResult]
    evidence: list[dict[str, Any]] = field(default_factory=list)

    @property
    def transcript(self) -> list[dict[str, str]]:
        """Return the complete conversation transcript."""

        transcript: list[dict[str, str]] = []

        for turn in self.turns:
            transcript.append(
                {
                    "role": "user",
                    "content": turn.attack,
                }
            )

            transcript.append(
                {
                    "role": "assistant",
                    "content": turn.response,
                }
            )

        return transcript


class MultiTurnHarness:
    """Execute one- or three-turn attacks against a target."""

    ALLOWED_TURNS = {1, 3}

    def __init__(
        self,
        target: TargetBot,
        attack_source: AttackSource,
        evidence_collector: EvidenceCollector | None = None,
    ) -> None:
        self.target = target
        self.attack_source = attack_source
        self.evidence_collector = evidence_collector

    def run(
        self,
        system_prompt: str,
        guardrail_category: str,
        turns: int = 1,
    ) -> HarnessResult:
        """Execute a multi-turn attack."""

        if turns not in self.ALLOWED_TURNS:
            raise ValueError(
                "Only 1-turn and 3-turn attacks "
                "are currently supported."
            )

        conversation_history: list[
            dict[str, str]
        ] = []

        results: list[TurnResult] = []

        for turn_number in range(1, turns + 1):

            attack_result = self.attack_source.generate(
                system_prompt=system_prompt,
                guardrail_category=guardrail_category,
                conversation_history=conversation_history,
            )

            attack = attack_result["attack"]
            technique = attack_result["technique"]
            objective = attack_result["objective"]

            response = self.target.chat(attack)

            turn_result = TurnResult(
                turn=turn_number,
                attack=attack,
                response=response,
                technique=technique,
                objective=objective,
            )

            results.append(turn_result)

            conversation_history.append(
                {
                    "role": "user",
                    "content": attack,
                }
            )

            conversation_history.append(
                {
                    "role": "assistant",
                    "content": response,
                }
            )

        evidence = (
            self.evidence_collector.to_dict()
            if self.evidence_collector is not None
            else []
        )

        return HarnessResult(
            guardrail_category=guardrail_category,
            turns=results,
            evidence=evidence,
        )