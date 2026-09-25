"""Real-world-incident-seeded attack strategy.

Adapts genuine, publicly documented prompt-injection incidents - not
synthetic examples - to the current target's system prompt, so attack
generation can draw on techniques proven to have actually broken
production LLM systems (Bing/Sydney, the Chevrolet $1 Tahoe chatbot,
the DPD swearing bot, the DAN jailbreak family, and the Microsoft 365
Copilot data-exfiltration flaw) rather than only ones invented for
this project. See data/seeds/public_injection_seeds.json for the full
cited seed set and core.attacks.generator.AttackGenerator's
seed_example parameter for how a seed is woven into the generation
prompt.

Opt-in like SingleAttemptStrategy - not every guardrail category has
a documented seed yet, and this is meant to complement full taxonomy
coverage, not replace it.
"""

import json
from pathlib import Path
from typing import Any

from core.attacks.generator import AttackGenerator
from core.attacks.harness import MultiTurnHarness
from core.attacks.strategies.base import AttackAttempt, BotFactory
from core.evidence.collector import EvidenceCollector
from core.llm.token_tracker import SpendCapExceededError

SEEDS_PATH = Path("data/seeds/public_injection_seeds.json")


def load_seeds(path: Path = SEEDS_PATH) -> list[dict[str, Any]]:
    """Load and parse data/seeds/public_injection_seeds.json."""

    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("seeds", [])


def seeds_for_category(
    guardrail_category: str,
    path: Path = SEEDS_PATH,
) -> list[dict[str, Any]]:
    """Return the documented real-world seeds for one guardrail category."""

    return [
        seed
        for seed in load_seeds(path)
        if seed.get("guardrail_category") == guardrail_category
    ]


class SeedAwareAttackSource:
    """Pins an AttackGenerator to one real-world incident seed.

    Mirrors PatternAwareAttackSource (taxonomy.py) so a multi-turn
    attack stays anchored to the same documented incident across every
    turn instead of drifting to a different technique mid-attack.
    """

    def __init__(
        self,
        generator: AttackGenerator,
        seed_prompt: str,
        technique: str,
    ) -> None:
        self.generator = generator
        self.seed_prompt = seed_prompt
        self.technique = technique

    def generate(
        self,
        system_prompt: str,
        guardrail_category: str,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        return self.generator.generate(
            system_prompt=system_prompt,
            guardrail_category=guardrail_category,
            conversation_history=conversation_history,
            technique=self.technique,
            seed_example=self.seed_prompt,
        )


class SeedAugmentedStrategy:
    """Runs one attack per documented real-world incident seed."""

    name = "seed"

    def __init__(self, seeds_path: Path = SEEDS_PATH) -> None:
        self.seeds_path = seeds_path

    def execute(
        self,
        bot_factory: BotFactory,
        generator: AttackGenerator,
        system_prompt: str,
        guardrail_category: str,
        requesting_user_id: str,
        turns: int,
    ) -> list[AttackAttempt]:
        seeds = seeds_for_category(
            guardrail_category, path=self.seeds_path
        )

        attempts: list[AttackAttempt] = []

        for seed in seeds:
            try:
                collector = EvidenceCollector()
                bot = bot_factory(
                    system_prompt, requesting_user_id, collector
                )

                attack_source = SeedAwareAttackSource(
                    generator=generator,
                    seed_prompt=seed["seed_prompt"],
                    technique=seed["technique"],
                )

                harness = MultiTurnHarness(
                    target=bot,
                    attack_source=attack_source,
                    evidence_collector=collector,
                )

                harness_result = harness.run(
                    system_prompt=system_prompt,
                    guardrail_category=guardrail_category,
                    turns=turns,
                )

                attempts.append(
                    AttackAttempt(
                        label=seed["id"],
                        harness_result=harness_result,
                    )
                )
            except SpendCapExceededError:
                # Must stop the whole scan, not be recorded as a
                # skippable per-seed failure - every remaining seed
                # would trip the same cap anyway.
                raise
            except Exception as exc:
                attempts.append(
                    AttackAttempt(
                        label=seed.get("id"),
                        harness_result=None,
                        error=exc,
                    )
                )

        return attempts
