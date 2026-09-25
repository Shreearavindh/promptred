"""Attack strategy protocol and registry for PromptRed.

A strategy decides *which* attacks to attempt for a guardrail category
and runs them through the harness - it does not evaluate results.
Evaluation, severity, RCA, and remediation stay centralized in
ScanOrchestrator so that logic isn't duplicated per strategy. This is
what lets PromptRed grow from "one generic attempt per guardrail"
(SingleAttemptStrategy) toward systematic taxonomy coverage
(TaxonomyStrategy) and, later, iterative techniques like PAIR or
Crescendo, without touching the harness or evaluation layer.
"""

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from core.attacks.generator import AttackGenerator
from core.attacks.harness import HarnessResult
from core.evidence.collector import EvidenceCollector

BotFactory = Callable[[str, str, EvidenceCollector], Any]


@dataclass
class AttackAttempt:
    """One attempt a strategy made, successful or not.

    A strategy that makes several independent attempts (e.g. one per
    taxonomy pattern) must not let one attempt's failure prevent the
    others from running - each attempt catches its own transient
    errors (rate limits that exhausted retries, malformed provider
    JSON, etc.) and records them here rather than raising, so a single
    flaky call can't silently truncate the rest of the batch. The one
    exception is SpendCapExceededError, which strategies deliberately
    let propagate uncaught - see core.llm.token_tracker.
    """

    label: str | None
    harness_result: HarnessResult | None
    error: Exception | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None


class AttackStrategy(Protocol):
    """Interface every attack strategy implements."""

    name: str

    def execute(
        self,
        bot_factory: BotFactory,
        generator: AttackGenerator,
        system_prompt: str,
        guardrail_category: str,
        requesting_user_id: str,
        turns: int,
    ) -> list[AttackAttempt]:
        """Run this strategy's attacks and return one AttackAttempt per try.

        `label` on each attempt identifies it (e.g. a taxonomy pattern
        id like "SPE-01") or is None when the strategy makes only one
        undifferentiated attempt.
        """
        ...


class StrategyRegistry:
    """Registers and resolves attack strategies by name."""

    def __init__(self) -> None:
        self._factories: dict[str, Callable[[], AttackStrategy]] = {}

    def register(
        self,
        name: str,
        factory: Callable[[], AttackStrategy],
    ) -> None:
        self._factories[name] = factory

    def get(self, name: str) -> AttackStrategy:
        factory = self._factories.get(name)

        if factory is None:
            raise ValueError(
                f"No attack strategy registered as '{name}'. "
                f"Available: {self.names()}"
            )

        return factory()

    def names(self) -> list[str]:
        return sorted(self._factories)
