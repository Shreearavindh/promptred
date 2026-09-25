"""OpenRouter account credit status for PromptRed.

Local cost tracking (core/llm/token_tracker.py) estimates spend from a
price table PromptRed maintains itself - useful for per-scan economics,
but it can drift from what OpenRouter actually bills (price table
staleness, provider-side rounding). This module asks OpenRouter
directly, via its own /key endpoint, so the CLI can show real
account-level remaining credit alongside the local estimate.
"""

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

OPENROUTER_KEY_ENDPOINT = "https://openrouter.ai/api/v1/key"
REQUEST_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class AccountCreditStatus:
    """Parsed subset of OpenRouter's /key response."""

    limit: float | None
    usage: float
    limit_remaining: float | None
    is_free_tier: bool

    def to_dict(self) -> dict:
        return {
            "limit": self.limit,
            "usage": self.usage,
            "limit_remaining": self.limit_remaining,
            "is_free_tier": self.is_free_tier,
        }


def get_account_credit_status(
    api_key: str | None = None,
) -> AccountCreditStatus | None:
    """Fetch remaining OpenRouter credit for the configured API key.

    Returns None on any failure (missing key, network error, malformed
    response) rather than raising - this is supplementary account
    info, not something that should ever block or crash a scan.
    """

    api_key = api_key or os.getenv("OPENROUTER_API_KEY")

    if not api_key:
        return None

    request = urllib.request.Request(
        OPENROUTER_KEY_ENDPOINT,
        headers={"Authorization": f"Bearer {api_key}"},
    )

    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            payload = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None

    data = payload.get("data")

    if not isinstance(data, dict):
        return None

    usage = data.get("usage")

    if not isinstance(usage, (int, float)):
        return None

    return AccountCreditStatus(
        limit=data.get("limit"),
        usage=float(usage),
        limit_remaining=data.get("limit_remaining"),
        is_free_tier=bool(data.get("is_free_tier", False)),
    )
