"""Tests for the token tracker."""

from core.llm.token_tracker import TokenTracker


def test_record_accumulates_totals():

    tracker = TokenTracker()

    tracker.record(
        model="mistralai/mistral-small-3.1-24b-instruct:free",
        role="judge",
        input_tokens=100,
        output_tokens=50,
        latency_ms=250.0,
    )

    assert tracker.total_tokens() == 150


def test_free_models_are_costed_at_zero():

    tracker = TokenTracker()

    tracker.record(
        model="qwen/qwen-2.5-72b-instruct:free",
        role="attacker",
        input_tokens=10_000,
        output_tokens=10_000,
        latency_ms=500.0,
    )

    assert tracker.total_cost() == 0.0


def test_paid_models_use_price_table():

    tracker = TokenTracker()

    tracker.record(
        model="some/paid-model",
        role="judge",
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        latency_ms=500.0,
    )

    summary = tracker.summary()

    assert summary["total_cost_usd"] > 0.0


def test_judge_model_uses_its_real_verified_price_not_the_generic_default():
    """qwen3.8-27b's real OpenRouter price ($0.42/M in, $3.00/M out,
    checked live 2026-09-08) differs sharply from the generic
    "default" fallback ($0.20/M in, $0.60/M out) - specifically 5x on
    output, since this is a reasoning model whose completion tokens
    are mostly hidden reasoning. A real judge-eval run (1013 input,
    849 output tokens on one case) priced at the old generic default
    would have undercounted actual OpenRouter billing; this asserts
    the tracker now uses the real rate."""

    tracker = TokenTracker()

    tracker.record(
        model="qwen/qwen3.8-27b",
        role="judge",
        input_tokens=1013,
        output_tokens=849,
        latency_ms=1000.0,
    )

    expected = (1013 / 1_000_000) * 0.42 + (849 / 1_000_000) * 3.00

    assert tracker.total_cost() == expected

    generic_default_estimate = (
        (1013 / 1_000_000) * 0.20 + (849 / 1_000_000) * 0.60
    )

    assert tracker.total_cost() > generic_default_estimate


def test_attacker_model_price_reflects_the_2026_09_10_doubling():
    """z-ai/glm-5.3-flash's real OpenRouter price doubled between
    2026-09-08 ($0.075/M in, $0.25/M out, first verified) and
    2026-09-10 (re-checked live after a real 60-case generation run:
    the tracker's self-reported cost at the OLD rate, $0.0164, was
    roughly half the real OpenRouter account-balance delta for that
    same run, $0.0309). This is the second time a hardcoded price in
    this table has gone stale within days, not a one-off - asserts the
    CURRENT real rate is what's actually used."""

    tracker = TokenTracker()

    tracker.record(
        model="z-ai/glm-5.3-flash",
        role="attacker",
        input_tokens=22225,
        output_tokens=58749,
        latency_ms=1000.0,
    )

    expected = (22225 / 1_000_000) * 0.15 + (58749 / 1_000_000) * 0.50

    assert tracker.total_cost() == expected

    stale_2026_09_08_estimate = (
        (22225 / 1_000_000) * 0.075 + (58749 / 1_000_000) * 0.25
    )

    assert tracker.total_cost() > stale_2026_09_08_estimate


def test_summary_breaks_down_by_role():

    tracker = TokenTracker()

    tracker.record(
        model="a:free",
        role="attacker",
        input_tokens=10,
        output_tokens=10,
        latency_ms=1.0,
    )
    tracker.record(
        model="j:free",
        role="judge",
        input_tokens=20,
        output_tokens=20,
        latency_ms=1.0,
    )

    summary = tracker.summary()

    assert summary["total_calls"] == 2
    assert set(summary["by_role"].keys()) == {"attacker", "judge"}
    assert summary["by_role"]["attacker"]["calls"] == 1
    assert summary["by_role"]["judge"]["input_tokens"] == 20


def test_summary_reports_latency_overall_and_per_role():

    tracker = TokenTracker()

    tracker.record(
        model="a:free",
        role="attacker",
        input_tokens=1,
        output_tokens=1,
        latency_ms=100.0,
    )
    tracker.record(
        model="a:free",
        role="attacker",
        input_tokens=1,
        output_tokens=1,
        latency_ms=300.0,
    )
    tracker.record(
        model="j:free",
        role="judge",
        input_tokens=1,
        output_tokens=1,
        latency_ms=1000.0,
    )

    summary = tracker.summary()

    assert summary["median_latency_ms"] == 300.0
    assert summary["max_latency_ms"] == 1000.0
    assert summary["by_role"]["attacker"]["median_latency_ms"] == 200.0
    assert summary["by_role"]["attacker"]["max_latency_ms"] == 300.0
    assert summary["by_role"]["judge"]["median_latency_ms"] == 1000.0


def test_summary_latency_zero_when_no_calls():

    tracker = TokenTracker()

    summary = tracker.summary()

    assert summary["median_latency_ms"] == 0.0
    assert summary["max_latency_ms"] == 0.0


def test_summary_includes_model_per_role():

    tracker = TokenTracker()

    tracker.record(
        model="minimax/minimax-m3:free",
        role="attacker",
        input_tokens=10,
        output_tokens=5,
        latency_ms=1.0,
    )

    summary = tracker.summary()

    assert (
        summary["by_role"]["attacker"]["model"]
        == "minimax/minimax-m3:free"
    )


def test_summary_model_reflects_most_recent_call_for_that_role():

    tracker = TokenTracker()

    tracker.record(
        model="old/model:free",
        role="attacker",
        input_tokens=1,
        output_tokens=1,
        latency_ms=1.0,
    )
    tracker.record(
        model="new/model:free",
        role="attacker",
        input_tokens=1,
        output_tokens=1,
        latency_ms=1.0,
    )

    summary = tracker.summary()

    assert summary["by_role"]["attacker"]["model"] == "new/model:free"
    assert summary["by_role"]["attacker"]["calls"] == 2
