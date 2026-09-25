"""Tests for LLMClient's handling of malformed provider responses.

Uses a fake `.chat.completions.create` so no real network call is
made; only the response-shape handling is under test.
"""

from types import SimpleNamespace

import pytest

from core.llm.client import LLMClient


def make_client() -> LLMClient:
    client = LLMClient(model="test-model:free")
    return client


def test_raises_clear_error_when_choices_is_none():

    client = make_client()
    client.client.chat.completions.create = lambda **kwargs: (
        SimpleNamespace(choices=None, usage=None)
    )

    with pytest.raises(ValueError, match="no choices"):
        client.generate_messages(
            [{"role": "user", "content": "hi"}]
        )


def test_raises_clear_error_when_choices_is_empty_list():

    client = make_client()
    client.client.chat.completions.create = lambda **kwargs: (
        SimpleNamespace(choices=[], usage=None)
    )

    with pytest.raises(ValueError, match="no choices"):
        client.generate_messages(
            [{"role": "user", "content": "hi"}]
        )


def test_raises_clear_error_when_content_is_none():

    client = make_client()

    fake_choice = SimpleNamespace(
        message=SimpleNamespace(content=None)
    )
    client.client.chat.completions.create = lambda **kwargs: (
        SimpleNamespace(choices=[fake_choice], usage=None)
    )

    with pytest.raises(ValueError, match="no text content"):
        client.generate_messages(
            [{"role": "user", "content": "hi"}]
        )


def test_returns_content_on_well_formed_response():

    client = make_client()

    fake_choice = SimpleNamespace(
        message=SimpleNamespace(content="hello back")
    )
    client.client.chat.completions.create = lambda **kwargs: (
        SimpleNamespace(choices=[fake_choice], usage=None)
    )

    result = client.generate_messages(
        [{"role": "user", "content": "hi"}]
    )

    assert result == "hello back"
