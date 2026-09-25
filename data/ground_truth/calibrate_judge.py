"""Produces config/judge_calibration.json from data already collected.

Joins data/ground_truth/real_judge_eval_results.jsonl (per-case judge
predictions + confidence, from the post-rubric-fix run) against
data/ground_truth/real_labelled_cases.jsonl (human labels + split),
restricted to the CALIBRATION split only - the holdout split must stay
untouched by this fitting step, exactly as it was kept untouched while
diagnosing the cross_user_data_access rubric bug, so it remains usable
afterward as a genuine check on the result (see
data/ground_truth/verify_calibration_on_holdout.py).

No model calls - this is a deterministic computation over an existing
JSONL file.
"""

import json
from pathlib import Path

from core.evaluator.selective_evaluation import (
    DEFAULT_CONFIDENCE_LEVEL,
    DEFAULT_TARGET_RISK,
    calibrate_selective_threshold,
    save_calibration,
)

RESULTS_PATH = Path("data/ground_truth/real_judge_eval_results.jsonl")
LABELS_PATH = Path("data/ground_truth/real_labelled_cases.jsonl")
OUTPUT_PATH = Path("config/judge_calibration.json")


def build_calibration_records() -> list[dict]:
    results = {
        json.loads(l)["case_id"]: json.loads(l)
        for l in RESULTS_PATH.open(encoding="utf-8")
    }
    labels = {
        json.loads(l)["case_id"]: json.loads(l)
        for l in LABELS_PATH.open(encoding="utf-8")
    }

    records = []

    for case_id, result in results.items():
        details = result["details"]

        if "error" in details:
            continue

        label = labels[case_id]

        if label["split"] != "calibration":
            continue

        records.append(
            {
                "confidence": details["predicted_confidence"],
                "correct": (
                    details["predicted_vulnerable"]
                    == details["expected_vulnerable"]
                ),
            }
        )

    return records


def main() -> None:
    records = build_calibration_records()
    print(f"{len(records)} calibration-split cases with valid results.")

    result = calibrate_selective_threshold(
        records,
        target_risk=DEFAULT_TARGET_RISK,
        confidence_level=DEFAULT_CONFIDENCE_LEVEL,
        source_path=str(RESULTS_PATH),
    )

    if result is None:
        print(
            "No threshold met the target risk - not enough clean "
            "high-confidence calibration data yet."
        )
        return

    save_calibration(result, OUTPUT_PATH)

    print(f"Calibrated threshold: {result.threshold}")
    print(f"Guaranteed risk (95% conf.): {result.guaranteed_risk:.3f}")
    print(
        f"Coverage on calibration set: {result.calibration_coverage:.1%} "
        f"({result.calibration_n}/{len(records)})"
    )
    print(f"Saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
