"""Calibrated selective evaluation for PromptRed's judge.

Answers a real gap found this session: the 80-case ground truth is
drawn from a handful of fixed system prompts, so its F1 number doesn't
directly certify judge accuracy on a genuinely new prompt discovered
by `promptred.py scan`. A per-target human audit doesn't scale (it
defeats automation), and the judge's own abstention threshold was
previously a hand-picked 0.6 with no statistical meaning.

This implements the mechanism from "Trust or Escalate: LLM Judges
with Provable Guarantees for Human Agreement" (Kim et al., ICLR 2025,
arXiv:2407.18370): calibrate a confidence threshold lambda on a
human-labelled set such that, for cases where the judge's own
confidence is >= lambda, its disagreement rate with humans is
guaranteed to be at most `target_risk`, at `confidence_level`
statistical confidence - using a Clopper-Pearson binomial upper bound,
not a point estimate. Cases below lambda abstain and should escalate
(see core/evaluator/judge_panel.py) rather than being silently
trusted.

This is the cheap variant: it calibrates against the judge's own
self-reported `confidence` field rather than the paper's "Simulated
Annotators" ensemble (re-prompting N times with different few-shot
sets to approximate inter-annotator disagreement). Self-reported LLM
confidence is known to run overconfident, so the guarantee here is
real but weaker than the paper's - stated honestly, not hidden.

Calibrated once, on data already collected (data/ground_truth/
real_judge_eval_results.jsonl x real_labelled_cases.jsonl's
calibration split) - zero additional model calls. See
data/ground_truth/calibrate_judge.py for the script that produces
config/judge_calibration.json from that data.
"""

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_TARGET_RISK = 0.10
DEFAULT_CONFIDENCE_LEVEL = 0.95

# Below this sample size, a threshold's own Clopper-Pearson bound is
# uninformative almost by construction (n=1 with 0 errors already
# yields a ~95% upper bound at 95% confidence, regardless of target) -
# not evidence the threshold is bad, just evidence there isn't enough
# data at that point yet. Testing it as a real failure would poison
# the whole fixed-sequence chain below it for the wrong reason. Skip
# (not fail) thresholds below this floor rather than treating data
# sparsity as a certified risk.
DEFAULT_MIN_SAMPLE_SIZE = 20

# Used only when no calibration file exists yet (a fresh judge model
# that's never been calibrated) - not a statistical guarantee, just
# the project's prior hand-picked default.
FALLBACK_ABSTENTION_THRESHOLD = 0.6


def binomial_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p)."""

    return sum(
        math.comb(n, i) * p**i * (1 - p) ** (n - i)
        for i in range(0, k + 1)
    )


def clopper_pearson_ucb(
    errors: int,
    n: int,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
) -> float:
    """Upper confidence bound on a true error rate given `errors`
    observed failures out of `n` trials.

    The smallest p such that P(X <= errors | n, p) = 1 - confidence_level.
    Standard exact (Clopper-Pearson) binomial interval; computed by
    bisection rather than a Beta-distribution inverse CDF so this has
    no dependency beyond the standard library.
    """

    if n == 0:
        return 1.0

    if errors == n:
        return 1.0

    target = 1 - confidence_level
    lo, hi = 0.0, 1.0

    for _ in range(60):
        mid = (lo + hi) / 2

        if binomial_cdf(errors, n, mid) > target:
            lo = mid
        else:
            hi = mid

    return hi


@dataclass(frozen=True)
class CalibrationResult:
    """A calibrated selective-evaluation threshold and its evidence.

    `threshold` (lambda): trust the judge's verdict when its reported
    confidence is >= this value. Below it, the pipeline should abstain
    and escalate rather than trust a single-judge verdict.
    """

    threshold: float
    guaranteed_risk: float
    target_risk: float
    confidence_level: float
    calibration_n: int
    calibration_errors: int
    calibration_coverage: float
    calibrated_at: str
    source_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "guaranteed_risk": self.guaranteed_risk,
            "target_risk": self.target_risk,
            "confidence_level": self.confidence_level,
            "calibration_n": self.calibration_n,
            "calibration_errors": self.calibration_errors,
            "calibration_coverage": self.calibration_coverage,
            "calibrated_at": self.calibrated_at,
            "source_path": self.source_path,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "CalibrationResult":
        return CalibrationResult(**data)


def calibrate_selective_threshold(
    records: list[dict[str, Any]],
    target_risk: float = DEFAULT_TARGET_RISK,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
    min_sample_size: int = DEFAULT_MIN_SAMPLE_SIZE,
    source_path: str = "",
) -> CalibrationResult | None:
    """Fit the highest-coverage confidence threshold whose certified
    error-rate upper bound stays within `target_risk`.

    `records`: one dict per labelled case with `confidence` (the
    judge's own reported confidence, 0.0-1.0) and `correct` (bool -
    did the judge's verdict match the human label). MUST be drawn
    only from a calibration split, never a holdout split reserved for
    validating the result afterward - mixing the two invalidates the
    guarantee exactly like reusing a test set for tuning would.

    Implements the paper's fixed-sequence search: starting from the
    highest observed confidence and lowering the threshold, keep
    going as long as the Clopper-Pearson upper bound stays within
    `target_risk`; stop at the first threshold where it doesn't. This
    finds inf{lambda : bound(lambda') <= target_risk for all lambda' >= lambda},
    not just a single lucky threshold - a threshold is only trusted if
    every stricter threshold above it was also within bound.

    Thresholds with fewer than `min_sample_size` observations are
    SKIPPED, not tested as failures - with real 80-case data, the two
    or three highest observed confidence values can have n as low as
    1, whose Clopper-Pearson bound is uninformatively wide (~0.95 at
    95% confidence for 0/1) regardless of target_risk. Treating that
    as a genuine failure would poison every threshold below it for a
    reason that has nothing to do with the judge's actual accuracy -
    it's a data-sparsity artifact, not evidence. This is a real
    limitation to disclose (more calibration data would let smaller
    min_sample_size values be tested meaningfully), not something to
    silently work around.

    Returns None if no threshold with at least `min_sample_size`
    observations meets target_risk - there isn't enough calibration
    data to certify anything at this risk level yet.
    """

    if not records:
        return None

    thresholds = sorted({r["confidence"] for r in records}, reverse=True)
    best: CalibrationResult | None = None

    for lam in thresholds:
        subset = [r for r in records if r["confidence"] >= lam]
        n = len(subset)

        if n < min_sample_size:
            continue

        errors = sum(1 for r in subset if not r["correct"])
        ucb = clopper_pearson_ucb(errors, n, confidence_level)

        if ucb > target_risk:
            break

        best = CalibrationResult(
            threshold=lam,
            guaranteed_risk=ucb,
            target_risk=target_risk,
            confidence_level=confidence_level,
            calibration_n=n,
            calibration_errors=errors,
            calibration_coverage=n / len(records),
            calibrated_at=datetime.now(timezone.utc).isoformat(),
            source_path=source_path,
        )

    return best


def save_calibration(result: CalibrationResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result.to_dict(), indent=2), encoding="utf-8"
    )


def load_calibration(path: Path) -> CalibrationResult | None:
    """Returns None (not an error) when no calibration file exists
    yet - callers should fall back to FALLBACK_ABSTENTION_THRESHOLD,
    since an uncalibrated judge is a normal starting state, not a
    failure."""

    if not path.exists():
        return None

    return CalibrationResult.from_dict(
        json.loads(path.read_text(encoding="utf-8"))
    )
