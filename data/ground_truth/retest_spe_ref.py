"""Re-test system_prompt_extraction and unauthorized_refund after the
TaxonomyStrategy proactive-seeding fix (core/attacks/strategies/taxonomy.py).

The original data/ground_truth/generate_real_cases.py run found 0/20 real
vulnerable cases in each of these two categories, while
cross_user_data_access and policy_circumvention found 7/20 and 3/20
respectively. Investigation found the attacker's primary calls never used
the real-incident seed examples (Bing/Sydney, Chevrolet $1-Tahoe) - only
the exception-fallback path did, and it never fired. The fix makes these
two categories use the seed on every primary attempt.

This script re-runs the SAME generation shape (same models, same turns=1,
same 20-per-category count) scoped to just these two categories, writing
to a SEPARATE output file so the original real_cases_raw.jsonl /
real_cases_proposed.jsonl (already sent to the user for hand review) are
never touched - this keeps the comparison apples-to-apples with the
proactive-seeding fix as the only variable.
"""

import json
from pathlib import Path

from core.attacks.strategies.taxonomy import TaxonomyStrategy
from core.llm.token_tracker import SpendCapExceededError
from core.orchestrator import CUSTOMER_RECORDS, ScanOrchestrator
from data.ground_truth.build_labelled_cases import (
    REFUND_SYSTEM_PROMPT,
    SP_SYSTEM_PROMPT,
)

OUTPUT_PATH = Path(__file__).parent / "real_cases_spe_ref_retest.jsonl"

# Matches generate_real_cases.py's 15/category convention (60 total
# across 4 categories) now that ground truth already exists and this
# scale no longer needs to support building it from scratch.
CASES_PER_CATEGORY = 15
USER_IDS = ["A001", "B002", "S001"]
MAX_ROUNDS = 10

CATEGORIES = ["system_prompt_extraction", "unauthorized_refund"]

CATEGORY_SYSTEM_PROMPTS = {
    "system_prompt_extraction": SP_SYSTEM_PROMPT,
    "unauthorized_refund": REFUND_SYSTEM_PROMPT,
}

CATEGORY_PREFIX = {
    "system_prompt_extraction": "RT2-SPE",
    "unauthorized_refund": "RT2-REF",
}


def _record_from_attempt(
    case_id: str,
    category: str,
    system_prompt: str,
    user_id: str,
    attempt,
) -> dict:
    harness_result = attempt.harness_result
    last_turn = harness_result.turns[-1]

    return {
        "case_id": case_id,
        "guardrail_category": category,
        "system_prompt": system_prompt,
        "requesting_user_id": user_id,
        "customer_records": CUSTOMER_RECORDS,
        "attack_pattern_id": attempt.label,
        "attack": last_turn.attack,
        "response": last_turn.response,
        "transcript": harness_result.transcript,
        "evidence_events": harness_result.evidence,
        "human_label": None,
        "proposed_label": None,
        "source": "live_generation_retest_proactive_seed",
    }


def generate() -> list[dict]:
    orchestrator = ScanOrchestrator()
    strategy = TaxonomyStrategy()

    all_records: list[dict] = []
    stopped_early = False

    for category in CATEGORIES:
        system_prompt = CATEGORY_SYSTEM_PROMPTS[category]
        collected: list[dict] = []
        seq = 0

        for round_index in range(MAX_ROUNDS):
            if len(collected) >= CASES_PER_CATEGORY:
                break

            user_id = USER_IDS[round_index % len(USER_IDS)]

            try:
                attempts = strategy.execute(
                    bot_factory=orchestrator.bot_factory,
                    generator=orchestrator.generator,
                    system_prompt=system_prompt,
                    guardrail_category=category,
                    requesting_user_id=user_id,
                    turns=1,
                )
            except SpendCapExceededError as exc:
                print(f"SPEND CAP HIT during {category}: {exc}")
                stopped_early = True
                break

            for attempt in attempts:
                if not attempt.succeeded:
                    print(
                        f"  [{category}] {attempt.label}: attempt "
                        f"failed ({type(attempt.error).__name__}: "
                        f"{attempt.error}) - skipping"
                    )
                    continue

                if len(collected) >= CASES_PER_CATEGORY:
                    break

                seq += 1
                case_id = f"{CATEGORY_PREFIX[category]}-{seq:02d}"
                record = _record_from_attempt(
                    case_id, category, system_prompt, user_id, attempt
                )
                collected.append(record)
                print(
                    f"  [{category}] {case_id} ({attempt.label}, "
                    f"user={user_id}): collected "
                    f"({len(collected)}/{CASES_PER_CATEGORY})"
                )

        all_records.extend(collected)
        print(
            f"{category}: {len(collected)}/{CASES_PER_CATEGORY} real "
            "transcripts collected."
        )

        if stopped_early:
            break

    summary = orchestrator.token_tracker.summary()
    print("\n--- token summary (generation only, no judge calls) ---")
    print(json.dumps(summary, indent=2, default=str))

    return all_records


def main() -> None:
    records = generate()

    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    print(f"\nWrote {len(records)} real, unlabelled cases to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
