"""Fixed attacks that need no attacker model.

Two uses:

1. Fallback. When the attacker model fails (outage, refusal, unusable
   output), the orchestrator replays one of these instead of dropping
   the attack, so a scan degrades to a weaker attacker rather than
   silently testing less.
2. Offline mode (`--offline`). `StaticAttackStrategy` replays them all,
   so a scan can run with no AI at all.

The attacks are real, not written for this project: the cited incident
prompts in data/seeds/public_injection_seeds.json (replayed verbatim,
not adapted) and, for system-prompt extraction, human attacks from
Lakera's Gandalf dataset (see public_dataset.py).
"""

from typing import Any

from core.attacks.harness import MultiTurnHarness
from core.attacks.strategies.base import AttackAttempt, BotFactory
from core.attacks.strategies.public_dataset import (
    ReplayAttackSource,
    load_gandalf_attacks,
    sample_attacks,
)
from core.attacks.strategies.seed_augmented import seeds_for_category
from core.evidence.collector import EvidenceCollector
from core.llm.token_tracker import SpendCapExceededError

GANDALF_ATTACKS_PER_EXTRACTION_SCAN = 3


def static_attacks_for(guardrail_category: str) -> list[dict[str, Any]]:
    """All fixed attacks for a category, as replayable rows.

    Each row has `text`, `split` and `row_idx` (the shape
    ReplayAttackSource expects) plus an `id` used as the attack label.
    """

    rows = [
        {
            "id": seed["id"],
            "text": seed["seed_prompt"],
            "split": "incident seed",
            "row_idx": seed["id"],
        }
        for seed in seeds_for_category(guardrail_category)
    ]

    if guardrail_category == "system_prompt_extraction":
        for row in sample_attacks(
            load_gandalf_attacks(), GANDALF_ATTACKS_PER_EXTRACTION_SCAN
        ):
            rows.append({
                "id": f"GANDALF-{row['split']}-{row['row_idx']}",
                **row,
            })

    return rows


def run_static_attack(
    bot_factory: BotFactory,
    rows: list[dict[str, Any]],
    system_prompt: str,
    guardrail_category: str,
    requesting_user_id: str,
    turns: int,
    label: str,
) -> AttackAttempt:
    """Replay fixed attack text through the harness (one per turn)."""

    try:
        collector = EvidenceCollector()
        bot = bot_factory(system_prompt, requesting_user_id, collector)
        harness = MultiTurnHarness(
            target=bot,
            attack_source=ReplayAttackSource(rows),
            evidence_collector=collector,
        )
        return AttackAttempt(
            label=label,
            harness_result=harness.run(
                system_prompt=system_prompt,
                guardrail_category=guardrail_category,
                turns=turns,
            ),
        )
    except SpendCapExceededError:
        raise
    except Exception as exc:  # noqa: BLE001 - recorded, not raised
        return AttackAttempt(label=label, harness_result=None, error=exc)


class StaticAttackStrategy:
    """Replays every fixed attack for a category. Makes no model calls
    of its own, so with a rules-based bot the whole scan is offline."""

    name = "static"

    def execute(
        self,
        bot_factory: BotFactory,
        generator,
        system_prompt: str,
        guardrail_category: str,
        requesting_user_id: str,
        turns: int,
    ) -> list[AttackAttempt]:
        return [
            run_static_attack(
                bot_factory,
                [row],
                system_prompt,
                guardrail_category,
                requesting_user_id,
                turns,
                label=row["id"],
            )
            for row in static_attacks_for(guardrail_category)
        ]


class StaticFallback:
    """Hands out fixed attacks one at a time, per category, so repeated
    attacker failures in one scan replay different attacks."""

    def __init__(self) -> None:
        self._next_index: dict[str, int] = {}

    def next_rows(
        self, guardrail_category: str, turns: int
    ) -> tuple[str, list[dict[str, Any]]] | None:
        pool = static_attacks_for(guardrail_category)
        if not pool:
            return None
        start = self._next_index.get(guardrail_category, 0)
        self._next_index[guardrail_category] = start + 1
        rows = [pool[(start + i) % len(pool)] for i in range(turns)]
        return f"FALLBACK-{rows[0]['id']}", rows
