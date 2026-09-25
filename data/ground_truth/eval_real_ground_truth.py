"""Runs the judge (per current .env JUDGE_MODEL) against the REAL,
hand-confirmed ground truth (data/ground_truth/real_labelled_cases.jsonl) -
not the invented-text set. Reuses the exact same evaluation machinery
as evals/suites/judge_eval.py (EvaluationPipeline with
force_llm_judge=True via JudgeEvalSuite) so the methodology is
identical; only the input data differs.

Writes each case's result to OUTPUT_PATH as it completes (not just at
the end) - a prior version of this script spent real money and
produced nothing recoverable when the process was killed mid-run
(exit code 4, zero output - an external kill, not a caught Python
exception; per-case failures are already handled gracefully inside
JudgeEvalSuite.run_case's caller). This version survives that: rerun
it and it resumes past whatever's already in OUTPUT_PATH instead of
re-paying for cases already judged.

Does not call EvalReport.save() - this deliberately stays out of
evals/results/judge/'s history so it isn't conflated with the existing
invented-text-set run history.
"""

import json
from pathlib import Path

from evals.suites.judge_eval import (
    JudgeEvalSuite,
    _bucket_from_predictions,
    _confusion_rates,
    compute_deterministic_only_baseline,
    compute_majority_class_baseline,
    load_ground_truth_cases,
)

GROUND_TRUTH_PATH = Path("data/ground_truth/real_labelled_cases.jsonl")
OUTPUT_PATH = Path("data/ground_truth/real_judge_eval_results.jsonl")


def _load_done() -> dict[str, dict]:
    if not OUTPUT_PATH.exists():
        return {}

    done: dict[str, dict] = {}

    with OUTPUT_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                rec = json.loads(line)
                done[rec["case_id"]] = rec

    return done


def main() -> None:
    suite = JudgeEvalSuite(ground_truth_path=GROUND_TRUTH_PATH)
    cases = suite.load_cases()

    done = _load_done()
    print(
        f"Resuming: {len(done)}/{len(cases)} cases already have a "
        "result."
    )

    with OUTPUT_PATH.open("a", encoding="utf-8") as out:
        for i, case in enumerate(cases, 1):
            if case.case_id in done:
                continue

            try:
                result = suite.run_case(case)
                details = result.details
            except Exception as exc:  # noqa: BLE001
                details = {
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                }

            rec = {"case_id": case.case_id, "details": details}
            out.write(json.dumps(rec, default=str) + "\n")
            out.flush()
            done[case.case_id] = rec

            if "error" in details:
                status = "ERROR"
            elif details.get("predicted_vulnerable") == details.get(
                "expected_vulnerable"
            ):
                status = "OK"
            else:
                status = "MISS"

            print(f"[{i}/{len(cases)}] {case.case_id}: {status}")

    predictions = {
        cid: rec["details"]
        for cid, rec in done.items()
        if "error" not in rec["details"]
    }
    error_count = len(done) - len(predictions)

    def predict(record: dict) -> bool:
        return predictions[record["case_id"]]["predicted_vulnerable"]

    records = load_ground_truth_cases(GROUND_TRUTH_PATH)
    valid_records = [r for r in records if r["case_id"] in predictions]

    bucket = _bucket_from_predictions(valid_records, predict)
    overall = _confusion_rates(bucket)
    overall["error_rate"] = error_count / len(records)

    print("\n=== judge eval (REAL ground truth) ===")
    print(json.dumps(overall, indent=2, default=str))

    for split in ("calibration", "holdout"):
        split_records = [
            r for r in valid_records if r["split"] == split
        ]
        split_bucket = _bucket_from_predictions(split_records, predict)
        print(f"\n--- {split} (n={len(split_records)}) ---")
        print(json.dumps(_confusion_rates(split_bucket), default=str))

    for cat in sorted({r["guardrail_category"] for r in valid_records}):
        cat_records = [
            r for r in valid_records if r["guardrail_category"] == cat
        ]
        cat_bucket = _bucket_from_predictions(cat_records, predict)
        print(f"\n--- {cat} (n={len(cat_records)}) ---")
        print(json.dumps(_confusion_rates(cat_bucket), default=str))

    majority = compute_majority_class_baseline(records)
    deterministic = compute_deterministic_only_baseline(records)

    print("\n--- baselines ---")
    print("majority_class:", json.dumps(majority, default=str))
    print("deterministic_only:", json.dumps(deterministic, default=str))


if __name__ == "__main__":
    main()
