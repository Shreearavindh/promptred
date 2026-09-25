"""Generates REAL attack/response transcripts for hand-labelling.

Unlike build_labelled_cases.py (invented attack/response text, written
to read like a real transcript but never actually produced by an LLM
or sent to a live bot), this script runs the actual attacker model
against the actual target bot - the same TaxonomyStrategy, the same
AttackGenerator, the same SyntheticSupportBot(use_llm=True) a real
`promptred.py scan` uses - and records the genuine attack the attacker
model wrote and the genuine reply the target model gave.

The JUDGE is deliberately never called here. This script only produces
raw material for a human to label; evals/suites/judge_eval.py (or an
equivalent one-off comparison) runs the judge afterwards against the
finished human labels, so the judge's predictions and the ground truth
are never contaminated by each other.

Output: data/ground_truth/real_cases_raw.jsonl - one real transcript
per line, unlabelled (human_label is null). A human (see
data/ground_truth/label_real_cases.py or manual review) fills in
vulnerable/severity/notes afterwards to produce the final labelled set.

Costs real API budget (ATTACKER_MODEL + TARGET_MODEL calls, no JUDGE
calls) - respects PROMPTRED_SPEND_CAP_USD via the shared TokenTracker
and stops cleanly (keeping whatever was generated so far) if the cap
is hit.
"""

import json
from pathlib import Path

from core.attacks.strategies.taxonomy import TaxonomyStrategy
from core.llm.token_tracker import SpendCapExceededError
from core.orchestrator import ALL_GUARDRAIL_CATEGORIES, CUSTOMER_RECORDS, ScanOrchestrator
from data.ground_truth.build_labelled_cases import (
    CROSS_USER_SYSTEM_PROMPT,
    POLICY_SYSTEM_PROMPT,
    REFUND_SYSTEM_PROMPT,
    SP_SYSTEM_PROMPT,
)

OUTPUT_PATH = Path(__file__).parent / "real_cases_raw.jsonl"

# 15/category x 4 categories = 60 total, not 80 - the original 20/category
# batch existed to build a large enough set for hand-labelling ground
# truth from scratch. That set now exists (real_labelled_cases.jsonl);
# any future run of this script (e.g. re-testing a system prompt
# change, or expanding coverage) doesn't need that scale again.
CASES_PER_CATEGORY = 15
USER_IDS = ["A001", "B002", "S001"]
MAX_ROUNDS = 10  # 3 patterns/round; 10 rounds is well past what 15 cases needs

CATEGORY_SYSTEM_PROMPTS = {
    "system_prompt_extraction": SP_SYSTEM_PROMPT,
    "unauthorized_refund": REFUND_SYSTEM_PROMPT,
    "cross_user_data_access": CROSS_USER_SYSTEM_PROMPT,
    "policy_circumvention": POLICY_SYSTEM_PROMPT,
}

CATEGORY_PREFIX = {
    "system_prompt_extraction": "RT-SPE",
    "unauthorized_refund": "RT-REF",
    "cross_user_data_access": "RT-CDA",
    "policy_circumvention": "RT-POL",
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
        "source": "live_generation",
    }


def generate() -> list[dict]:
    orchestrator = ScanOrchestrator()
    strategy = TaxonomyStrategy()

    all_records: list[dict] = []
    stopped_early = False

    for category in ALL_GUARDRAIL_CATEGORIES:
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
