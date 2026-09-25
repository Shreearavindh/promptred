"""Taxonomy-driven attack strategy.

Ensures full coverage of config/taxonomy.yaml's documented attack
patterns for a guardrail category: one attack attempt per pattern,
each pinned to that pattern's specific technique/objective rather
than leaving "which technique to try" up to the generator's own
judgment on every call. Each pattern gets an independently
constructed target bot (fresh conversation, fresh evidence log) so
attempts don't leak state into one another.

This is the baseline strategy for the evaluation-first MVP - PAIR,
Crescendo, and public-seed-augmented strategies (stretch goals) can
layer onto the same AttackStrategy protocol later without touching
the harness or evaluation layer.
"""

from pathlib import Path
from typing import Any

import yaml

from core.attacks.generator import AttackGenerator
from core.attacks.harness import MultiTurnHarness
from core.attacks.strategies.base import AttackAttempt, BotFactory
from core.attacks.strategies.seed_augmented import seeds_for_category
from core.evidence.collector import EvidenceCollector
from core.llm.token_tracker import SpendCapExceededError

TAXONOMY_PATH = Path("config/taxonomy.yaml")


def load_taxonomy(path: Path = TAXONOMY_PATH) -> dict[str, Any]:
    """Load and parse config/taxonomy.yaml."""

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def patterns_for_category(
    guardrail_category: str,
    path: Path = TAXONOMY_PATH,
) -> list[dict[str, str]]:
    """Return the attack_patterns list for one guardrail category."""

    data = load_taxonomy(path)
    guardrails = data.get("guardrails", {})
    entry = guardrails.get(guardrail_category)

    if entry is None:
        raise ValueError(
            "No taxonomy entry for guardrail category "
            f"'{guardrail_category}'."
        )

    return entry.get("attack_patterns", [])


class PatternAwareAttackSource:
    """Pins an AttackGenerator to one taxonomy pattern for every call.

    MultiTurnHarness's AttackSource protocol calls generate(...) once
    per turn; this wrapper supplies the same technique/objective hint
    each time so a multi-turn (turns=3) attack stays focused on one
    taxonomy pattern across all turns instead of drifting to a
    different technique mid-attack.
    """

    def __init__(
        self,
        generator: AttackGenerator,
        technique: str,
        objective: str,
        seed_example: str | None = None,
    ) -> None:
        self.generator = generator
        self.technique = technique
        self.objective = objective
        self.seed_example = seed_example

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
            objective=self.objective,
            seed_example=self.seed_example,
        )


class TaxonomyStrategy:
    """Runs one attack per documented taxonomy pattern for a guardrail.

    If the attacker model fails to produce a usable attack for a
    pattern (invalid JSON, refusal, empty completion), this retries
    that one pattern exactly once, seeding the generator with a real,
    cited public-incident example for the same guardrail category
    (see data/seeds/public_injection_seeds.json) rather than asking it
    to invent again from scratch - answers "what if the rented model
    does not generate attack strings?" with a concrete fallback rather
    than the scan silently reporting fewer attempts than intended.

    For PROACTIVE_SEED_CATEGORIES, that same real-incident seed is
    also woven into the PRIMARY attempt, not just the exception
    fallback. A live 80-case run found system_prompt_extraction and
    unauthorized_refund produced 0 real vulnerabilities out of 20
    attempts each, while cross_user_data_access and
    policy_circumvention found several - the attacker model's primary
    calls never errored, so the fallback seed (the actual Bing/Sydney
    and Chevrolet $1-Tahoe prompts) was never used. taxonomy.yaml's
    one-line technique/objective labels give the attacker no tactical
    detail to work from; the seed examples are the concrete, proven
    phrasing those two categories were missing. The other two
    categories already find real vulnerabilities unseeded, so they're
    left on the exception-only fallback to keep this change surgical.
    """

    name = "taxonomy"

    PROACTIVE_SEED_CATEGORIES = {
        "system_prompt_extraction",
        "unauthorized_refund",
    }

    def __init__(self, taxonomy_path: Path = TAXONOMY_PATH) -> None:
        self.taxonomy_path = taxonomy_path

    def execute(
        self,
        bot_factory: BotFactory,
        generator: AttackGenerator,
        system_prompt: str,
        guardrail_category: str,
        requesting_user_id: str,
        turns: int,
    ) -> list[AttackAttempt]:
        patterns = patterns_for_category(
            guardrail_category, path=self.taxonomy_path
        )

        attempts: list[AttackAttempt] = []

        for pattern in patterns:
            try:
                harness_result = self._run_pattern(
                    bot_factory=bot_factory,
                    generator=generator,
                    system_prompt=system_prompt,
                    guardrail_category=guardrail_category,
                    requesting_user_id=requesting_user_id,
                    turns=turns,
                    pattern=pattern,
                    seed_example=self._proactive_seed_for(
                        guardrail_category
                    ),
                )
                attempts.append(
                    AttackAttempt(
                        label=pattern["id"],
                        harness_result=harness_result,
                    )
                )
                continue
            except SpendCapExceededError:
                # Must stop the whole scan, not be recorded as a
                # skippable per-pattern failure - every remaining
                # pattern would trip the same cap anyway.
                raise
            except Exception as primary_exc:
                pass

            fallback_seed = self._fallback_seed_for(guardrail_category)

            if fallback_seed is None:
                attempts.append(
                    AttackAttempt(
                        label=pattern["id"],
                        harness_result=None,
                        error=primary_exc,
                    )
                )
                continue

            try:
                harness_result = self._run_pattern(
                    bot_factory=bot_factory,
                    generator=generator,
                    system_prompt=system_prompt,
                    guardrail_category=guardrail_category,
                    requesting_user_id=requesting_user_id,
                    turns=turns,
                    pattern=pattern,
                    seed_example=fallback_seed,
                )
                attempts.append(
                    AttackAttempt(
                        label=pattern["id"],
                        harness_result=harness_result,
                    )
                )
            except SpendCapExceededError:
                raise
            except Exception as fallback_exc:
                attempts.append(
                    AttackAttempt(
                        label=pattern["id"],
                        harness_result=None,
                        error=fallback_exc,
                    )
                )

        return attempts

    @staticmethod
    def _fallback_seed_for(guardrail_category: str) -> str | None:
        """The first real-incident seed for this category, if any."""

        seeds = seeds_for_category(guardrail_category)
        return seeds[0]["seed_prompt"] if seeds else None

    def _proactive_seed_for(
        self, guardrail_category: str
    ) -> str | None:
        """The primary-attempt seed for categories that need it.

        Only PROACTIVE_SEED_CATEGORIES get seeded up front - see the
        class docstring for why. Everything else keeps the original
        unseeded primary attempt, with the seed reserved for the
        exception fallback as before.
        """

        if guardrail_category not in self.PROACTIVE_SEED_CATEGORIES:
            return None

        return self._fallback_seed_for(guardrail_category)

    @staticmethod
    def _run_pattern(
        bot_factory: BotFactory,
        generator: AttackGenerator,
        system_prompt: str,
        guardrail_category: str,
        requesting_user_id: str,
        turns: int,
        pattern: dict[str, str],
        seed_example: str | None,
    ):
        collector = EvidenceCollector()
        bot = bot_factory(system_prompt, requesting_user_id, collector)

        attack_source = PatternAwareAttackSource(
            generator=generator,
            technique=pattern["technique"],
            objective=pattern["objective"],
            seed_example=seed_example,
        )

        harness = MultiTurnHarness(
            target=bot,
            attack_source=attack_source,
            evidence_collector=collector,
        )

        return harness.run(
            system_prompt=system_prompt,
            guardrail_category=guardrail_category,
            turns=turns,
        )
