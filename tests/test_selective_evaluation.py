"""Tests for calibrated selective evaluation (Trust-or-Escalate style)."""

from pathlib import Path

from core.evaluator.selective_evaluation import (
    CalibrationResult,
    binomial_cdf,
    calibrate_selective_threshold,
    clopper_pearson_ucb,
    load_calibration,
    save_calibration,
)


def test_binomial_cdf_matches_known_value():
    # P(X <= 1) for Binomial(n=2, p=0.5) = 0.25 + 0.5 = 0.75
    assert abs(binomial_cdf(1, 2, 0.5) - 0.75) < 1e-9


def test_clopper_pearson_ucb_is_wide_for_tiny_n_zero_errors():
    # A single perfect observation says almost nothing about the true
    # rate - the bound must stay loose, not collapse toward 0.
    ucb = clopper_pearson_ucb(errors=0, n=1)
    assert ucb > 0.9


def test_clopper_pearson_ucb_tightens_with_more_samples_at_same_ratio():
    small = clopper_pearson_ucb(errors=0, n=10)
    large = clopper_pearson_ucb(errors=0, n=100)
    assert large < small


def test_clopper_pearson_ucb_is_one_when_everything_fails():
    assert clopper_pearson_ucb(errors=5, n=5) == 1.0


def test_clopper_pearson_ucb_matches_the_real_calibration_run():
    """Reproduces the exact number from the real 64-case calibration
    split (data/ground_truth/real_labelled_cases.jsonl x
    real_judge_eval_results.jsonl) at lambda=0.97: n=35, 0 errors,
    UCB=0.082 - this is the number actually cited in the report."""

    ucb = clopper_pearson_ucb(errors=0, n=35)
    assert abs(ucb - 0.082) < 0.001


def test_calibration_selects_lowest_threshold_still_within_target_risk():
    """All cases are correct, so descending the threshold only ever
    grows n and tightens the bound - the fixed-sequence search should
    walk all the way down to maximum coverage. Expected UCB is derived
    from the function under test itself (not hand-computed), so this
    doesn't repeat the mistake of guessing a Clopper-Pearson value by
    hand and getting it wrong."""

    high_block = [
        {"confidence": 0.95, "correct": True} for _ in range(20)
    ]
    low_block = [
        {"confidence": 0.50, "correct": True} for _ in range(5)
    ]
    records = high_block + low_block

    full_ucb = clopper_pearson_ucb(0, len(records), 0.95)

    result = calibrate_selective_threshold(
        records, target_risk=full_ucb + 0.05, confidence_level=0.95
    )

    assert result is not None
    assert result.threshold == 0.50
    assert result.calibration_coverage == 1.0
    assert result.calibration_errors == 0


def test_calibration_stops_before_a_threshold_that_breaks_the_bound():
    """A clean high-confidence block, plus a lower block that
    introduces errors. The target sits strictly between the two
    blocks' own UCBs (both derived from the tested function, not
    guessed), so the search must stop at the high block and never
    descend into the errors."""

    high_block = [
        {"confidence": 0.95, "correct": True} for _ in range(20)
    ]
    low_block = [
        {"confidence": 0.50, "correct": True} for _ in range(5)
    ] + [
        {"confidence": 0.50, "correct": False} for _ in range(5)
    ]
    records = high_block + low_block

    high_only_ucb = clopper_pearson_ucb(0, 20, 0.95)
    full_ucb = clopper_pearson_ucb(5, 30, 0.95)
    assert full_ucb > high_only_ucb  # sanity check on the fixture

    target = (high_only_ucb + full_ucb) / 2

    result = calibrate_selective_threshold(
        records, target_risk=target, confidence_level=0.95
    )

    assert result is not None
    assert result.threshold == 0.95
    assert result.calibration_n == 20
    assert result.calibration_coverage == 20 / 30


def test_calibration_uses_fixed_sequence_not_a_single_lucky_threshold():
    """A threshold is only trusted if every STRICTER threshold above
    it also held - not just the threshold itself. Here lambda=0.80
    alone looks fine (1/1 correct), but lambda=0.90 (which must also
    hold, since 0.90 >= 0.80 cases are a superset check on the way
    down) has a wrong verdict that should already have broken the
    fixed-sequence search before reaching 0.80."""

    records = [
        {"confidence": 0.95, "correct": False},  # breaks it immediately
        {"confidence": 0.80, "correct": True},
    ]

    # min_sample_size=1 so this isolates the fixed-sequence property
    # itself from the separate min-sample-size skip behavior (covered
    # by test_small_top_bin_is_skipped_not_treated_as_failure below).
    result = calibrate_selective_threshold(
        records, target_risk=0.10, confidence_level=0.95, min_sample_size=1
    )

    # The very first (highest) threshold already fails at target 0.10,
    # so nothing should be selected - not even the seemingly-clean 0.80.
    assert result is None


def test_small_top_bin_is_skipped_not_treated_as_failure():
    """The exact real shape hit while calibrating the judge:
    lambda=0.99 has only 1 observation (0 errors, but Clopper-Pearson
    UCB for 0/1 at 95% confidence is ~0.95 - uninformative, not
    evidence of a bad threshold). Without the min_sample_size floor,
    that single sparse point would break the fixed-sequence chain and
    fail calibration entirely, even though real signal exists further
    down. Reproduces the real n/error counts from the first attempt at
    calibrating this project's own judge (lambda=0.99: n=1; lambda=0.98:
    n=16, both below the default floor of 20; lambda=0.97: n=35, 0
    errors, UCB=0.082 - the number actually used in the report)."""

    records = (
        [{"confidence": 0.99, "correct": True}]  # n=1 here alone
        + [{"confidence": 0.98, "correct": True} for _ in range(15)]  # n=16 at >=0.98
        + [{"confidence": 0.97, "correct": True} for _ in range(19)]  # n=35 at >=0.97
    )

    result = calibrate_selective_threshold(
        records, target_risk=0.10, confidence_level=0.95
    )

    assert result is not None
    assert result.threshold == 0.97
    assert result.calibration_n == 35
    assert abs(result.guaranteed_risk - 0.082) < 0.001


def test_calibration_returns_none_when_nothing_meets_target():
    records = [{"confidence": 0.99, "correct": False}]

    result = calibrate_selective_threshold(
        records, target_risk=0.05, confidence_level=0.95
    )

    assert result is None


def test_calibration_returns_none_for_empty_records():
    assert calibrate_selective_threshold([]) is None


def test_save_and_load_round_trip(tmp_path: Path):
    result = CalibrationResult(
        threshold=0.97,
        guaranteed_risk=0.082,
        target_risk=0.10,
        confidence_level=0.95,
        calibration_n=35,
        calibration_errors=0,
        calibration_coverage=35 / 64,
        calibrated_at="2026-09-09T00:00:00+00:00",
        source_path="data/ground_truth/real_labelled_cases.jsonl",
    )

    path = tmp_path / "judge_calibration.json"
    save_calibration(result, path)
    loaded = load_calibration(path)

    assert loaded == result


def test_load_calibration_returns_none_when_file_missing(tmp_path: Path):
    assert load_calibration(tmp_path / "does_not_exist.json") is None
