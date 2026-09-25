"""Tests for LLMClient's retry/backoff logic (no real network calls)."""

from core.llm.client import (
    BACKOFF_SECONDS,
    MAX_RETRY_AFTER_SECONDS,
    LLMClient,
)


class FakeHeaders:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def get(self, key: str):
        return self.values.get(key)


class FakeResponse:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = FakeHeaders(headers)


class FakeRateLimitError(Exception):
    def __init__(self, headers: dict[str, str] | None = None) -> None:
        super().__init__("rate limited")
        self.response = FakeResponse(headers or {})


def test_backoff_uses_retry_after_header_when_present():

    exc = FakeRateLimitError({"Retry-After": "5"})

    delay = LLMClient._backoff_seconds(exc, attempt=0)

    assert delay == 5.0


def test_backoff_caps_retry_after_at_maximum():

    exc = FakeRateLimitError({"Retry-After": "9999"})

    delay = LLMClient._backoff_seconds(exc, attempt=0)

    assert delay == MAX_RETRY_AFTER_SECONDS


def test_backoff_falls_back_to_fixed_schedule_without_header():

    exc = FakeRateLimitError({})

    delay = LLMClient._backoff_seconds(exc, attempt=1)

    assert delay == BACKOFF_SECONDS[1]


def test_backoff_falls_back_when_header_is_not_numeric():

    exc = FakeRateLimitError({"Retry-After": "not-a-number"})

    delay = LLMClient._backoff_seconds(exc, attempt=0)

    assert delay == BACKOFF_SECONDS[0]


def test_backoff_falls_back_when_exception_has_no_response():

    exc = Exception("no response attribute")

    delay = LLMClient._backoff_seconds(exc, attempt=0)

    assert delay == BACKOFF_SECONDS[0]
