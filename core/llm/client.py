"""OpenRouter LLM client for PromptRed."""

import os
import time

from dotenv import load_dotenv
from openai import (
    APIConnectionError,
    APITimeoutError,
    OpenAI,
    RateLimitError,
)
from openai.types.chat import ChatCompletionMessageParam

from core.llm.roles import ModelRole, resolve_model
from core.llm.token_tracker import (
    TokenTracker,
    get_global_token_tracker,
)

load_dotenv()

REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 2
BACKOFF_SECONDS = (1, 4)
MAX_RETRY_AFTER_SECONDS = 15.0

# Applied to every call by default (attacker/target/judge, free or
# paid) unless a caller explicitly passes a different value. This is
# a per-call cost/runaway-output guard distinct from the cumulative
# $ spend cap: the spend cap can only stop the *next* call, so an
# unbounded single call on a reasoning model (which can burn
# thousands of hidden "thinking" tokens before ever producing visible
# output) could still spend more than intended before the cap has a
# chance to react. 2000 turned out too tight for real judge calls on
# a reasoning model - a live judge call against a real transcript
# needed ~3400 completion tokens (~3000 of it hidden reasoning) before
# writing any of the actual verdict JSON, so 2000 produced empty or
# truncated-JSON responses. 6000 leaves real headroom for that (worst
# case ~$0.018/judge-call, ~$0.0015/attacker-call at current pricing -
# trivial against the $0.50 spend cap) while some providers don't
# strictly enforce max_tokens against hidden reasoning tokens anyway,
# so the $ spend cap - not this value - remains the actual hard
# backstop on total cost.
DEFAULT_MAX_TOKENS = 6000

RETRYABLE_ERRORS = (RateLimitError, APITimeoutError, APIConnectionError)


class LLMClient:
    """Small wrapper around the OpenRouter API.

    Resolves its model either from an explicit `model` override, from
    a `role` (attacker/target/judge - see core.llm.roles), or from the
    shared OPENROUTER_MODEL env var for backward compatibility with
    single-model configurations.

    Defaults to the process-wide global TokenTracker (see
    core.llm.token_tracker.get_global_token_tracker) rather than no
    tracker at all, so the $0.01 hard spend cap applies even to code
    that never explicitly wires a tracker through - pass an explicit
    `token_tracker` (e.g. one with `spend_cap_usd=None`) to opt out.
    """

    def __init__(
        self,
        role: ModelRole | None = None,
        model: str | None = None,
        token_tracker: TokenTracker | None = None,
    ):
        self.api_key = os.getenv("OPENROUTER_API_KEY")

        if model:
            self.model = model
        elif role is not None:
            self.model = resolve_model(role)
        else:
            self.model = os.getenv(
                "OPENROUTER_MODEL",
                "openrouter/free",
            )

        self.role = role.value if role is not None else "unspecified"
        self.token_tracker = (
            token_tracker or get_global_token_tracker()
        )

        if not self.api_key:
            raise ValueError(
                "OPENROUTER_API_KEY is not set. "
                "Add it to your .env file."
            )

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=self.api_key,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int | None = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a simple system + user request to OpenRouter."""

        messages: list[ChatCompletionMessageParam] = [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ]

        return self.generate_messages(
            messages,
            max_tokens=max_tokens,
        )

    def generate_messages(
        self,
        messages: list[ChatCompletionMessageParam],
        max_tokens: int | None = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a complete conversation to OpenRouter.

        Retries up to MAX_RETRIES times with exponential backoff on
        rate-limit/timeout/connection errors. If a token tracker was
        provided, usage and latency are recorded for cost economics.
        """

        start = time.monotonic()

        response = self._call_with_retry(
            messages=messages,
            max_tokens=max_tokens,
        )

        latency_ms = (time.monotonic() - start) * 1000

        if not response.choices:
            # Observed in practice on free-tier OpenRouter providers:
            # a 200 response with an empty/None choices list, distinct
            # from the "choice present but content is None" case below.
            # Surface a clear, catchable error instead of crashing on
            # an index into an empty/None list.
            raise ValueError(
                "The LLM response contained no choices "
                f"(model={self.model!r}). This can happen on "
                "free-tier providers under load; retrying the call "
                "may succeed."
            )

        content = response.choices[0].message.content

        if content is None:
            raise ValueError(
                "The LLM returned no text content."
            )

        usage = response.usage

        self.token_tracker.record(
            model=self.model,
            role=self.role,
            input_tokens=(usage.prompt_tokens if usage else 0),
            output_tokens=(
                usage.completion_tokens if usage else 0
            ),
            latency_ms=latency_ms,
        )

        return content

    def _call_with_retry(
        self,
        messages: list[ChatCompletionMessageParam],
        max_tokens: int | None,
    ):
        """Call the chat completion API with bounded retry/backoff.

        Free-tier OpenRouter models share a provider-side rate-limit
        pool, so a 429 there often carries a `Retry-After` header
        telling us exactly how long to wait. Honoring that (capped, so
        a misbehaving provider can't stall a scan indefinitely) makes
        the same MAX_RETRIES budget far more likely to succeed than
        guessing with a fixed schedule - this doesn't raise the retry
        count, it just spends it more effectively.
        """

        self.token_tracker.check_spend_cap()

        kwargs: dict = {
            "model": self.model,
            "messages": messages,
        }

        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens

        for attempt in range(MAX_RETRIES + 1):
            try:
                return self.client.chat.completions.create(**kwargs)
            except RETRYABLE_ERRORS as exc:
                if attempt >= MAX_RETRIES:
                    raise

                time.sleep(
                    self._backoff_seconds(exc, attempt)
                )

    @staticmethod
    def _backoff_seconds(
        exc: Exception,
        attempt: int,
    ) -> float:
        """Prefer the provider's Retry-After header, else fixed backoff."""

        response = getattr(exc, "response", None)
        retry_after = None

        if response is not None:
            retry_after = response.headers.get("Retry-After")

        if retry_after is not None:
            try:
                return min(float(retry_after), MAX_RETRY_AFTER_SECONDS)
            except ValueError:
                pass

        return BACKOFF_SECONDS[attempt]
