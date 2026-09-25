"""Tests for the hard, always-on spend cap guardrail."""

import os

import pytest

from core.llm.token_tracker import (
    SpendCapExceededError,
    TokenTracker,
    get_global_token_tracker,
    reset_global_token_tracker,
)


# ---------------------------------------------------------
# TokenTracker.check_spend_cap
# ---------------------------------------------------------


def test_check_spend_cap_passes_below_cap():

    tracker = TokenTracker(spend_cap_usd=0.01)
    tracker.record(
        model="some/paid-model",
        role="attacker",
        input_tokens=100,
        output_tokens=100,
        latency_ms=1.0,
    )

    tracker.check_spend_cap()  # should not raise


def test_check_spend_cap_raises_at_or_above_cap():

    tracker = TokenTracker(spend_cap_usd=0.0001)
    tracker.record(
        model="some/paid-model",
        role="attacker",
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        latency_ms=1.0,
    )

    with pytest.raises(SpendCapExceededError, match="Spend cap"):
        tracker.check_spend_cap()


def test_check_spend_cap_disabled_when_none():

    tracker = TokenTracker(spend_cap_usd=None)
    tracker.record(
        model="some/paid-model",
        role="attacker",
        input_tokens=10_000_000,
        output_tokens=10_000_000,
        latency_ms=1.0,
    )

    tracker.check_spend_cap()  # should not raise


def test_free_models_never_trip_the_cap():

    tracker = TokenTracker(spend_cap_usd=0.01)

    for _ in range(50):
        tracker.record(
            model="anything:free",
            role="attacker",
            input_tokens=1_000_000,
            output_tokens=1_000_000,
            latency_ms=1.0,
        )

    tracker.check_spend_cap()  # should not raise


# ---------------------------------------------------------
# Global tracker
# ---------------------------------------------------------


def test_global_tracker_is_a_singleton():

    reset_global_token_tracker()

    first = get_global_token_tracker()
    second = get_global_token_tracker()

    assert first is second


def test_global_tracker_defaults_to_one_cent_cap(monkeypatch):

    # Isolate from whatever PROMPTRED_SPEND_CAP_USD happens to be set
    # to in the real .env (e.g. raised for a deliberate paid-model
    # run) - this test is about the hardcoded fallback constant, not
    # today's ambient configuration.
    monkeypatch.delenv("PROMPTRED_SPEND_CAP_USD", raising=False)
    reset_global_token_tracker()

    tracker = get_global_token_tracker()

    assert tracker.spend_cap_usd == 0.01


def test_global_tracker_respects_env_override(monkeypatch):

    monkeypatch.setenv("PROMPTRED_SPEND_CAP_USD", "0.05")
    reset_global_token_tracker()

    tracker = get_global_token_tracker()

    assert tracker.spend_cap_usd == 0.05


def test_global_tracker_env_none_disables_cap(monkeypatch):

    monkeypatch.setenv("PROMPTRED_SPEND_CAP_USD", "none")
    reset_global_token_tracker()

    tracker = get_global_token_tracker()

    assert tracker.spend_cap_usd is None


def test_reset_global_token_tracker_clears_state():

    reset_global_token_tracker()
    first = get_global_token_tracker()
    first.record(
        model="x:free",
        role="attacker",
        input_tokens=10,
        output_tokens=10,
        latency_ms=1.0,
    )

    reset_global_token_tracker()
    second = get_global_token_tracker()

    assert second is not first
    assert second.total_tokens() == 0
