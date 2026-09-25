"""Tests proving LLMClient enforces the spend cap before calling out."""

from types import SimpleNamespace

import pytest

from core.llm.client import LLMClient
from core.llm.token_tracker import SpendCapExceededError, TokenTracker


def test_client_defaults_to_the_shared_global_tracker():

    from core.llm.token_tracker import get_global_token_tracker

    client = LLMClient(model="test-model:free")

    assert client.token_tracker is get_global_token_tracker()


def test_call_is_never_attempted_once_cap_is_reached():

    tracker = TokenTracker(spend_cap_usd=0.0001)
    tracker.record(
        model="some/paid-model",
        role="attacker",
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        latency_ms=1.0,
    )

    client = LLMClient(
        model="test-model:free", token_tracker=tracker
    )

    def fail_if_called(**kwargs):
        raise AssertionError(
            "The API should never have been called - the spend cap "
            "was already exceeded."
        )

    client.client.chat.completions.create = fail_if_called

    with pytest.raises(SpendCapExceededError):
        client.generate_messages(
            [{"role": "user", "content": "hi"}]
        )


def test_call_succeeds_when_under_the_cap():

    tracker = TokenTracker(spend_cap_usd=0.01)

    client = LLMClient(
        model="test-model:free", token_tracker=tracker
    )

    fake_choice = SimpleNamespace(
        message=SimpleNamespace(content="ok")
    )
    client.client.chat.completions.create = lambda **kwargs: (
        SimpleNamespace(choices=[fake_choice], usage=None)
    )

    result = client.generate_messages(
        [{"role": "user", "content": "hi"}]
    )

    assert result == "ok"
