"""Tests for the cost-to-serve model.

Two tests replicate the course's own worked examples numerically
(Class 5 C2's support-triage case, and the A2 break-even derivation)
to validate the formulas are implemented as taught, not just
internally consistent.
"""

import pytest

from core.economics.cost_model import (
    CostBreakdown,
    break_even_detection_rate,
    compute_cost_breakdown,
    layer1_cost_per_attempt,
    layer2_expected_fallback,
    sensitivity_band,
)


def test_layer1_divides_total_cost_by_attempts():

    token_summary = {"total_cost_usd": 0.02}

    assert layer1_cost_per_attempt(token_summary, 4) == pytest.approx(
        0.005
    )


def test_layer1_zero_attempts_is_zero_not_a_crash():

    assert layer1_cost_per_attempt({"total_cost_usd": 1.0}, 0) == 0.0


def test_layer2_perfect_detection_is_zero():

    assert layer2_expected_fallback(1.0, 340.0) == 0.0


def test_layer2_zero_detection_is_the_full_cost():

    assert layer2_expected_fallback(0.0, 340.0) == 340.0


def test_layer2_rejects_out_of_range_detection_rate():

    with pytest.raises(ValueError):
        layer2_expected_fallback(1.5, 340.0)

    with pytest.raises(ValueError):
        layer2_expected_fallback(-0.1, 340.0)


def test_matches_the_course_support_triage_worked_example():
    """Class 5 C2 "Now add the only column that matters": the cheap
    agent (v3) has token cost $0.00546/task, resolves 55% unaided,
    escalation costs $6.00 -> cost per resolved ticket $2.71.

    "cost per successful task = layer 1 + layer 2" - this is exactly
    that formula, with PromptRed's vocabulary substituted in:
    layer1 = token cost per attempt, detection_rate = resolve rate,
    missed_vulnerability_cost = escalation cost.
    """

    breakdown = compute_cost_breakdown(
        token_summary={"total_cost_usd": 0.00546},
        num_attempts=1,
        detection_rate=0.55,
        missed_vulnerability_cost_usd=6.00,
    )

    assert breakdown.cost_per_confirmed_finding_usd == pytest.approx(
        2.71, abs=0.01
    )


def test_matches_the_course_break_even_worked_example():
    """A2 D6's worked break-even: C=0.005, E=0.657, F=7.60 ->
    break-even p ~= 0.914. Replicated here with the exact figures
    from the course material to validate the formula, not just its
    internal consistency.
    """

    result = break_even_detection_rate(
        cheap_layer1_cost_per_attempt_usd=0.005,
        expensive_cost_per_confirmed_finding_usd=0.657,
        missed_vulnerability_cost_usd=7.60,
    )

    assert result == pytest.approx(0.914, abs=0.001)


def test_break_even_rejects_non_positive_failure_cost():

    with pytest.raises(ValueError):
        break_even_detection_rate(0.01, 0.5, 0.0)


def test_sensitivity_band_has_three_points_and_moves_with_detection():

    band = sensitivity_band(
        token_summary={"total_cost_usd": 0.01},
        num_attempts=1,
        base_detection_rate=0.80,
        missed_vulnerability_cost_usd=340.0,
    )

    assert set(band.keys()) == {"low_detection", "base", "high_detection"}
    # Lower detection rate -> more expected fallback -> higher cost.
    assert band["low_detection"] > band["base"] > band["high_detection"]


def test_sensitivity_band_clamps_at_the_edges():

    band = sensitivity_band(
        token_summary={"total_cost_usd": 0.01},
        num_attempts=1,
        base_detection_rate=0.95,
        missed_vulnerability_cost_usd=340.0,
        delta=0.10,
    )

    # 0.95 + 0.10 would exceed 1.0 - must clamp to 1.0 (perfect
    # detection, zero fallback cost), not raise or go negative.
    assert band["high_detection"] == pytest.approx(0.01)
    assert band["high_detection"] < band["base"]


def test_cost_breakdown_to_dict_round_trips_fields():

    breakdown = CostBreakdown(
        layer1_variable_usd=0.01,
        layer2_expected_fallback_usd=100.0,
        detection_rate=0.7,
        missed_vulnerability_cost_usd=333.33,
    )

    data = breakdown.to_dict()

    assert data["cost_per_confirmed_finding_usd"] == pytest.approx(
        100.01
    )
    assert data["detection_rate"] == 0.7
