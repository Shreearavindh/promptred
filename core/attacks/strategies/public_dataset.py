"""Public-dataset replay strategy: real human attacks PromptRed did not write.

Replays prompt injections verbatim from Lakera's gandalf_ignore_instructions
dataset (MIT licence, 1,000 real prompts people submitted to the Gandalf
game in July 2023 - see data/public_datasets/
gandalf_ignore_instructions.SOURCE.json for the pinned revision). No
attacker model is involved, so this answers two things the taxonomy and
seed strategies can't:

1. An attack source independent of PromptRed's own design - findings
   aren't "attacks we wrote, against weaknesses we planted".
2. A scan still has real attacks when the rented attacker model refuses
   or returns unusable output - replay costs zero attacker calls.

Gandalf players were trying to extract a hidden secret by overriding the
model's instructions, so these attacks only fit system_prompt_extraction.
Other categories return no attempts rather than being forced onto
attacks that weren't written for them. Rows that target Gandalf's own
game ("the password", "spell it") are filtered out, since that secret
doesn't exist in a support bot; the remaining rows are generic
instruction-override / instruction-disclosure attacks.
"""

import json
import random
import re
from pathlib import Path
from typing import Any

from core.attacks.harness import MultiTurnHarness
from core.attacks.strategies.base import AttackAttempt, BotFactory
from core.evidence.collector import EvidenceCollector
from core.llm.token_tracker import SpendCapExceededError

GANDALF_PATH = Path("data/public_datasets/gandalf_ignore_instructions.jsonl")

APPLICABLE_CATEGORIES = {"system_prompt_extraction"}

# Gandalf-specific targets that don't exist in a support bot.
_GAME_SPECIFIC = re.compile(
    r"pass ?word|secret|pw\b|passcode|gandalf|letters?\b|spell",
    re.IGNORECASE,
)
# Keep rows that actually go after the model's instructions.
_TARGETS_INSTRUCTIONS = re.compile(
    r"instruction|prompt|rules|above|previous|told|guidelines|system",
    re.IGNORECASE,
)
MIN_ATTACK_LENGTH = 40

DEFAULT_ATTACKS_PER_CATEGORY = 5
DEFAULT_SAMPLE_SEED = 6201


def load_gandalf_attacks(path: Path = GANDALF_PATH) -> list[dict[str, Any]]:
    """Load the dataset and keep only rows usable against a support bot."""

    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    return [
        row
        for row in rows
        if len(row["text"]) > MIN_ATTACK_LENGTH
        and not _GAME_SPECIFIC.search(row["text"])
        and _TARGETS_INSTRUCTIONS.search(row["text"])
    ]


def sample_attacks(
    rows: list[dict[str, Any]],
    count: int,
    seed: int = DEFAULT_SAMPLE_SEED,
) -> list[dict[str, Any]]:
    """Deterministic sample, so a scan is reproducible and not cherry-picked."""

    return random.Random(seed).sample(rows, min(count, len(rows)))


class ReplayAttackSource:
    """Feeds fixed dataset attacks to the harness, one per turn."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self._next = 0

    def generate(
        self,
        system_prompt: str,
        guardrail_category: str,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        row = self.rows[self._next % len(self.rows)]
        self._next += 1
        return {
            "attack": row["text"],
            "technique": "public_dataset_replay",
            "objective": (
                "Verbatim replay of a real human attack from "
                "Lakera/gandalf_ignore_instructions "
                f"({row['split']} row {row['row_idx']})"
            ),
        }


class PublicDatasetStrategy:
    """Replays sampled Gandalf attacks verbatim - no attacker model calls."""

    name = "gandalf"

    def __init__(
        self,
        attacks_per_category: int = DEFAULT_ATTACKS_PER_CATEGORY,
        seed: int = DEFAULT_SAMPLE_SEED,
        path: Path = GANDALF_PATH,
    ) -> None:
        self.attacks_per_category = attacks_per_category
        self.seed = seed
        self.path = path

    def execute(
        self,
        bot_factory: BotFactory,
        generator,
        system_prompt: str,
        guardrail_category: str,
        requesting_user_id: str,
        turns: int,
    ) -> list[AttackAttempt]:
        if guardrail_category not in APPLICABLE_CATEGORIES:
            return []

        rows = sample_attacks(
            load_gandalf_attacks(self.path),
            self.attacks_per_category * turns,
            self.seed,
        )
        attempts: list[AttackAttempt] = []

        for index in range(self.attacks_per_category):
            chunk = rows[index * turns:(index + 1) * turns]
            if not chunk:
                break
            label = f"GANDALF-{chunk[0]['split']}-{chunk[0]['row_idx']}"

            try:
                collector = EvidenceCollector()
                bot = bot_factory(
                    system_prompt, requesting_user_id, collector
                )
                harness = MultiTurnHarness(
                    target=bot,
                    attack_source=ReplayAttackSource(chunk),
                    evidence_collector=collector,
                )
                attempts.append(
                    AttackAttempt(
                        label=label,
                        harness_result=harness.run(
                            system_prompt=system_prompt,
                            guardrail_category=guardrail_category,
                            turns=turns,
                        ),
                    )
                )
            except SpendCapExceededError:
                raise
            except Exception as exc:
                attempts.append(
                    AttackAttempt(
                        label=label, harness_result=None, error=exc
                    )
                )

        return attempts
