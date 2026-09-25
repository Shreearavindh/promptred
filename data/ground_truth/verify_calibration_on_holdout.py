"""Checks the calibrated threshold (config/judge_calibration.json,
fit on the calibration split only) against the untouched holdout
split - the same discipline used for the cross_user_data_access
rubric fix: the threshold must never be chosen by looking at holdout,
only checked against it afterward.

No model calls - reuses the same recorded results as calibrate_judge.py.
"""

import json
from pathlib import Path

from core.evaluator.selective_evaluation import load_calibration

RESULTS_PATH = Path("data/ground_truth/real_judge_eval_results.jsonl")
LABELS_PATH = Path("data/ground_truth/real_labelled_cases.jsonl")
CALIBRATION_PATH = Path("config/judge_calibration.json")


def main() -> None:
    calibration = load_calibration(CALIBRATION_PATH)

    if calibration is None:
        print("No calibration file found - run calibrate_judge.py first.")
        return

    print(f"Threshold (from calibration split): {calibration.threshold}")
    print(f"Certified risk: <= {calibration.guaranteed_risk:.3f}")
    print()

    results = {
        json.loads(l)["case_id"]: json.loads(l)
        for l in RESULTS_PATH.open(encoding="utf-8")
    }
    labels = {
        json.loads(l)["case_id"]: json.loads(l)
        for l in LABELS_PATH.open(encoding="utf-8")
    }

    holdout_cases = []

    for case_id, result in results.items():
        details = result["details"]

        if "error" in details:
            continue

        if labels[case_id]["split"] != "holdout":
            continue

        holdout_cases.append(
            {
                "case_id": case_id,
                "confidence": details["predicted_confidence"],
                "correct": (
                    details["predicted_vulnerable"]
                    == details["expected_vulnerable"]
                ),
            }
        )

    trusted = [
        c for c in holdout_cases if c["confidence"] >= calibration.threshold
    ]
    abstained = [c for c in holdout_cases if c not in trusted]
    errors = [c for c in trusted if not c["correct"]]

    print(f"Holdout total: {len(holdout_cases)}")
    print(
        f"Trusted (confidence >= {calibration.threshold}): "
        f"{len(trusted)}/{len(holdout_cases)} "
        f"({len(trusted)/len(holdout_cases):.1%} coverage)"
    )
    print(f"Errors among trusted: {len(errors)}/{len(trusted)}" if trusted else "n/a")
    if trusted:
        empirical_risk = len(errors) / len(trusted)
        print(f"Empirical holdout risk: {empirical_risk:.3f}")
        within = empirical_risk <= calibration.guaranteed_risk
        print(
            f"Within the certified bound ({calibration.guaranteed_risk:.3f})? "
            f"{'YES' if within else 'NO - the guarantee did not hold'}"
        )
    if abstained:
        print(f"Abstained (would escalate): {[c['case_id'] for c in abstained]}")
    if errors:
        print(f"Errors were: {[c['case_id'] for c in errors]}")


if __name__ == "__main__":
    main()
