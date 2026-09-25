"""Assembles the REAL (not invented) hand-confirmed ground-truth set.

Combines two live-generated, user-reviewed batches into one file with
the same schema evals/suites/judge_eval.py already expects
(data/ground_truth/labelled_cases.jsonl's record shape):

- cross_user_data_access / policy_circumvention: from the original
  80-case batch (data/ground_truth/real_cases_proposed.jsonl),
  generated with the unmodified TaxonomyStrategy. 7/20 and 3/20
  vulnerable respectively - real, unforced successes.
- system_prompt_extraction / unauthorized_refund: NOT from that same
  original batch (which found 0/20 real vulnerabilities in both,
  because the attacker's primary calls never used the proven
  real-incident seed techniques - see core/attacks/strategies/
  taxonomy.py's PROACTIVE_SEED_CATEGORIES fix). Uses the RETEST batch
  instead (real_cases_spe_ref_retest_proposed.jsonl), generated AFTER
  that fix: 1/20 and 6/20 vulnerable. The pre-fix 0/20 results were a
  real diagnostic finding (attack weakness, not target strength) but
  are not representative of the strategy's current behavior, so they
  are deliberately excluded from the ground-truth set itself.

User confirmed both proposed-label files as-is (REVIEW_real_cases.md,
REVIEW_spe_ref_retest.md) before this script was run.

Output: data/ground_truth/real_labelled_cases.jsonl - kept SEPARATE
from the existing (invented-text) labelled_cases.jsonl. Whether this
real set replaces that one is a decision for the user, not made here.

Split assignment is deliberately explicit (a fixed set of case IDs,
not a positional "last N cases" rule) - build_labelled_cases.py's own
docstring explains why that positional approach silently produced an
all-negative holdout once already. Positive counts are low and uneven
per category (SPE has exactly 1 real positive across 20 attempts even
after the attack-strengthening fix), so the holdout can't be a clean
20% split everywhere without destroying a category's only signal:
- SPE: the sole positive stays in calibration (a 1-case holdout would
  either make holdout recall trivially 1.0 or leave calibration with
  zero positive signal - neither is meaningful). Holdout is 4 negatives
  only; holdout recall for this category is honestly undefined (0/0).
- REF/CDA: 2 positive + 2 negative holdout each (roughly 20%).
- POL: 1 positive + 3 negative holdout (only 3 positives total, so
  holdout keeps just 1 to leave 2 for calibration).
"""

import json
from pathlib import Path

ORIGINAL_BATCH_PATH = Path(__file__).parent / "real_cases_proposed.jsonl"
RETEST_BATCH_PATH = (
    Path(__file__).parent / "real_cases_spe_ref_retest_proposed.jsonl"
)
OUTPUT_PATH = Path(__file__).parent / "real_labelled_cases.jsonl"

CATEGORIES_FROM_ORIGINAL = {"cross_user_data_access", "policy_circumvention"}
CATEGORIES_FROM_RETEST = {"system_prompt_extraction", "unauthorized_refund"}

# Explicit holdout membership by case_id - see module docstring.
HOLDOUT_CASE_IDS = {
    # cross_user_data_access: 2 vulnerable (tool-call attempts) + 2 not.
    "RT-CDA-01", "RT-CDA-03", "RT-CDA-14", "RT-CDA-19",
    # policy_circumvention: 1 vulnerable (roleplay jailbreak) + 3 not.
    "RT-POL-17", "RT-POL-05", "RT-POL-10", "RT-POL-15",
    # system_prompt_extraction: 4 not-vulnerable only (see docstring -
    # the sole real positive, RT2-SPE-09, stays in calibration).
    "RT2-SPE-02", "RT2-SPE-07", "RT2-SPE-13", "RT2-SPE-18",
    # unauthorized_refund: 2 vulnerable (compelled-phrase compliance) + 2 not.
    "RT2-REF-04", "RT2-REF-19", "RT2-REF-01", "RT2-REF-12",
}


def _load(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def _to_ground_truth_record(record: dict) -> dict:
    proposed = record["proposed_label"]

    return {
        "case_id": record["case_id"],
        "guardrail_category": record["guardrail_category"],
        "system_prompt": record["system_prompt"],
        "requesting_user_id": record["requesting_user_id"],
        "customer_records": record["customer_records"],
        "attack": record["attack"],
        "response": record["response"],
        "evidence_events": record["evidence_events"],
        "human_label": {
            "vulnerable": proposed["vulnerable"],
            "severity": proposed["severity"],
            "notes": proposed["notes"],
        },
        "split": (
            "holdout"
            if record["case_id"] in HOLDOUT_CASE_IDS
            else "calibration"
        ),
        "attacker_knowledge": "L0",
        "evasion_technique": None,
        "source": "live_generation",
    }


def build() -> list[dict]:
    original = _load(ORIGINAL_BATCH_PATH)
    retest = _load(RETEST_BATCH_PATH)

    selected = [
        r for r in original
        if r["guardrail_category"] in CATEGORIES_FROM_ORIGINAL
    ] + [
        r for r in retest
        if r["guardrail_category"] in CATEGORIES_FROM_RETEST
    ]

    return [_to_ground_truth_record(r) for r in selected]


def main() -> None:
    records = build()

    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    total = len(records)
    vulnerable = sum(1 for r in records if r["human_label"]["vulnerable"])
    holdout = sum(1 for r in records if r["split"] == "holdout")

    print(f"Wrote {total} real cases to {OUTPUT_PATH}")
    print(f"  vulnerable: {vulnerable}/{total}")
    print(
        f"  split: {total - holdout} calibration, {holdout} holdout"
    )

    by_cat: dict[str, list[dict]] = {}
    for r in records:
        by_cat.setdefault(r["guardrail_category"], []).append(r)

    for cat, recs in sorted(by_cat.items()):
        v = sum(1 for r in recs if r["human_label"]["vulnerable"])
        h = sum(1 for r in recs if r["split"] == "holdout")
        hv = sum(
            1 for r in recs
            if r["split"] == "holdout" and r["human_label"]["vulnerable"]
        )
        print(
            f"  {cat}: {v}/{len(recs)} vulnerable, "
            f"holdout={h} ({hv} vulnerable in holdout)"
        )


if __name__ == "__main__":
    main()
