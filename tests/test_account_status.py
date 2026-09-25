"""Tests for OpenRouter account credit status fetching.

No real network calls - urllib.request.urlopen is monkeypatched so
these stay fast, free, and deterministic like the rest of tests/.
"""

import json
import urllib.error
from io import BytesIO

import pytest

from core.llm.account_status import get_account_credit_status


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_returns_none_when_api_key_missing(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    assert get_account_credit_status(api_key=None) is None


def test_parses_a_real_shaped_response(monkeypatch):
    payload = {
        "data": {
            "label": "sk-or-v1-abc...123",
            "limit": 10,
            "limit_remaining": 9.974978495,
            "usage": 0.025021505,
            "is_free_tier": False,
        }
    }

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: FakeResponse(payload),
    )

    status = get_account_credit_status(api_key="fake-key")

    assert status is not None
    assert status.limit == 10
    assert status.limit_remaining == pytest.approx(9.974978495)
    assert status.usage == pytest.approx(0.025021505)
    assert status.is_free_tier is False


def test_returns_none_on_network_error(monkeypatch):
    def raise_error(request, timeout):
        raise urllib.error.URLError("no network")

    monkeypatch.setattr("urllib.request.urlopen", raise_error)

    assert get_account_credit_status(api_key="fake-key") is None


def test_returns_none_on_malformed_response(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: FakeResponse({"data": "not a dict"}),
    )

    assert get_account_credit_status(api_key="fake-key") is None


def test_to_dict_includes_all_fields(monkeypatch):
    payload = {
        "data": {
            "limit": None,
            "limit_remaining": None,
            "usage": 1.5,
            "is_free_tier": True,
        }
    }

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: FakeResponse(payload),
    )

    status = get_account_credit_status(api_key="fake-key")

    assert status.to_dict() == {
        "limit": None,
        "usage": 1.5,
        "limit_remaining": None,
        "is_free_tier": True,
    }
