"""Single-shot attack strategy: one generic attempt per guardrail category.

This is PromptRed's original Milestone-1 behavior, kept available as a
fast/cheap option: the attack generator picks its own technique per
call rather than being pinned to a specific taxonomy pattern. Use
`--strategies taxonomy` (the default) for full documented-pattern
coverage instead.
"""

from core.attacks.generator import AttackGenerator
from core.attacks.harness import MultiTurnHarness
from core.attacks.strategies.base import AttackAttempt, BotFactory
from core.evidence.collector import EvidenceCollector
from core.llm.token_tracker import SpendCapExceededError


class SingleAttemptStrategy:
    """Runs exactly one undifferentiated attack attempt."""

    name = "single"

    def execute(
        self,
        bot_factory: BotFactory,
        generator: AttackGenerator,
        system_prompt: str,
        guardrail_category: str,
        requesting_user_id: str,
        turns: int,
    ) -> list[AttackAttempt]:
        try:
            collector = EvidenceCollector()
            bot = bot_factory(
                system_prompt, requesting_user_id, collector
            )

            harness = MultiTurnHarness(
                target=bot,
                attack_source=generator,
                evidence_collector=collector,
            )

            harness_result = harness.run(
                system_prompt=system_prompt,
                guardrail_category=guardrail_category,
                turns=turns,
            )

            return [
                AttackAttempt(
                    label=None, harness_result=harness_result
                )
            ]
        except SpendCapExceededError:
            raise
        except Exception as exc:
            return [
                AttackAttempt(
                    label=None, harness_result=None, error=exc
                )
            ]
