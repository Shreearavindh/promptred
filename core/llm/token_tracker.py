"""Token usage and cost tracking for PromptRed LLM calls.

Every attack, evaluation, and discovery pass costs real tokens. This
module accumulates per-call usage so a scan can report total cost,
enforce a budget guard, and let the report show cost-per-finding
economics rather than an unaccounted API bill.

It also enforces a hard, always-on spend cap (default: $0.01) via a
process-wide default TokenTracker shared by every LLMClient that isn't
given a specific one - see get_global_token_tracker(). This is a
safety net independent of any per-scan --budget flag: it applies to
CLI scans, eval runs, and ad hoc scripts alike, and matters even
though the project defaults every model role to a free tier, because
a misconfigured model id (or a provider silently moving a model from
free to paid, which has happened mid-session on OpenRouter's catalog)
could otherwise incur real charges unnoticed.
"""

import os
import statistics
import threading
from dataclasses import dataclass, field
from typing import Any

# USD per 1,000,000 tokens. Free-tier OpenRouter models (any model id
# ending in ":free") are always treated as $0 regardless of this table.
#
# The "default" fallback below is a generic placeholder, not a real
# rate - it silently underpriced the two paid models this project
# actually uses. Checked live against GET https://openrouter.ai/api/v1/models
# on 2026-09-08: qwen/qwen3.8-27b's real output price is $3.00/M, 5x
# the $0.60/M this table previously assumed for every paid model,
# because it's a reasoning model whose completion tokens are mostly
# hidden reasoning, not a short answer. That gap meant every
# total_cost_usd this project ever printed for a qwen3.8-27b judge run
# was wrong - confirmed by comparing the tracker's self-reported cost
# against the real OpenRouter account balance delta for the same run.
# Add a real entry here for any other paid model before trusting its
# cost figures; a model with no entry silently falls back to
# "default", which is real for neither cost-economics claims (point
# 3/5/7) nor the spend cap's own accuracy.
#
# z-ai/glm-5.3-flash's own price DOUBLED between 2026-09-08 (when
# first verified: $0.075/M in, $0.25/M out) and 2026-09-10 (re-checked
# live after a real 60-case generation run's tracker-reported cost
# came in at roughly half the real OpenRouter account-balance delta
# for that same run: $0.0164 vs $0.0309 real). This is the second
# time this exact failure mode has been caught - not a one-off typo,
# but evidence that ANY hardcoded price here has a real, short shelf
# life and must be re-verified live before being trusted for a report
# figure, not assumed stable from a prior session.
DEFAULT_PRICE_TABLE_USD_PER_MILLION: dict[str, dict[str, float]] = {
    "z-ai/glm-5.3-flash": {"input": 0.15, "output": 0.50},
    "qwen/qwen3.8-27b": {"input": 0.42, "output": 3.00},
    # Fallback only - not a real rate for any specific model. Used
    # when a paid model has no entry above; re-verify live and add a
    # specific entry rather than trusting a cost figure computed from
    # this one.
    "default": {"input": 0.20, "output": 0.60},
}

# Hard safety ceiling in USD. Override via PROMPTRED_SPEND_CAP_USD in
# .env (set to "none" to disable - not recommended). This is deliberately
# tiny: normal operation with :free models never approaches it, so it
# should only ever trip if a paid model call sneaks in.
DEFAULT_SPEND_CAP_USD = 0.01


class SpendCapExceededError(RuntimeError):
    """Raised when cumulative spend has already reached the hard cap.

    Unlike a transient provider error, this must never be silently
    retried or treated as a skippable per-attack failure - callers
    (ScanOrchestrator, the CLI) let it propagate and stop the run.
    """


def _spend_cap_from_env() -> float | None:
    raw = os.getenv("PROMPTRED_SPEND_CAP_USD")

    if raw is None:
        return DEFAULT_SPEND_CAP_USD

    raw = raw.strip()

    if not raw or raw.lower() == "none":
        return None

    return float(raw)


@dataclass
class CallRecord:
    """Usage and latency for a single LLM call."""

    model: str
    role: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
    cost_usd: float

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class TokenTracker:
    """Accumulates token usage, latency, and cost across a scan."""

    spend_cap_usd: float | None = DEFAULT_SPEND_CAP_USD
    price_table: dict[str, dict[str, float]] = field(
        default_factory=lambda: dict(
            DEFAULT_PRICE_TABLE_USD_PER_MILLION
        )
    )
    _records: list[CallRecord] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def check_spend_cap(self) -> None:
        """Raise SpendCapExceededError if the cap has already been hit.

        Called before each new LLM request (see LLMClient), not after
        - a call's real cost isn't known until its response returns,
        so this can only stop the *next* call, not un-spend the last
        one. With every model role on a :free tier, total_cost() stays
        at $0.0 and this never trips in normal operation.
        """

        if self.spend_cap_usd is None:
            return

        current = self.total_cost()

        if current >= self.spend_cap_usd:
            raise SpendCapExceededError(
                f"Spend cap of ${self.spend_cap_usd:.4f} reached "
                f"(cumulative spend so far: ${current:.4f}). No "
                "further LLM calls will be made. Raise "
                "PROMPTRED_SPEND_CAP_USD in .env (or pass a "
                "TokenTracker with a higher spend_cap_usd) if this "
                "was intentional spend."
            )

    def record(
        self,
        model: str,
        role: str,
        input_tokens: int,
        output_tokens: int,
        latency_ms: float,
    ) -> CallRecord:
        """Record one LLM call's usage and return the stored record."""

        cost_usd = self._estimate_cost(
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

        call = CallRecord(
            model=model,
            role=role,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )

        with self._lock:
            self._records.append(call)

        return call

    def _estimate_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """Estimate USD cost for one call. Free models always cost $0."""

        if model.endswith(":free"):
            return 0.0

        prices = self.price_table.get(
            model,
            self.price_table["default"],
        )

        input_cost = (input_tokens / 1_000_000) * prices["input"]
        output_cost = (output_tokens / 1_000_000) * prices["output"]

        return input_cost + output_cost

    def total_cost(self) -> float:
        """Total estimated USD cost across all recorded calls."""

        with self._lock:
            return sum(record.cost_usd for record in self._records)

    def total_tokens(self) -> int:
        """Total input + output tokens across all recorded calls."""

        with self._lock:
            return sum(
                record.total_tokens for record in self._records
            )

    def summary(self) -> dict[str, Any]:
        """Aggregate usage summary, broken down by role and model.

        Includes latency (median/max) per role and overall - Class 5
        C2's point that a business cost number ("cost per successful
        task") should sit alongside a technical one, and latency is
        the technical metric PromptRed was already recording
        (CallRecord.latency_ms) but never surfacing.
        """

        with self._lock:
            records = list(self._records)

        by_role: dict[str, dict[str, Any]] = {}
        latencies_by_role: dict[str, list[float]] = {}

        for record in records:
            bucket = by_role.setdefault(
                record.role,
                {
                    "model": record.model,
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost_usd": 0.0,
                },
            )

            # A role's model can change mid-run only if the caller
            # swaps .env/config between calls (rare); keep the most
            # recent one so the label stays accurate either way.
            bucket["model"] = record.model
            bucket["calls"] += 1
            bucket["input_tokens"] += record.input_tokens
            bucket["output_tokens"] += record.output_tokens
            bucket["cost_usd"] += record.cost_usd
            latencies_by_role.setdefault(record.role, []).append(
                record.latency_ms
            )

        for role, latencies in latencies_by_role.items():
            by_role[role]["median_latency_ms"] = statistics.median(
                latencies
            )
            by_role[role]["max_latency_ms"] = max(latencies)

        all_latencies = [r.latency_ms for r in records]

        return {
            "total_calls": len(records),
            "total_input_tokens": sum(
                r.input_tokens for r in records
            ),
            "total_output_tokens": sum(
                r.output_tokens for r in records
            ),
            "total_tokens": sum(r.total_tokens for r in records),
            "total_cost_usd": sum(r.cost_usd for r in records),
            "median_latency_ms": (
                statistics.median(all_latencies)
                if all_latencies
                else 0.0
            ),
            "max_latency_ms": (
                max(all_latencies) if all_latencies else 0.0
            ),
            "by_role": by_role,
        }


_global_tracker_lock = threading.Lock()
_global_tracker: TokenTracker | None = None


def get_global_token_tracker() -> TokenTracker:
    """Process-wide default tracker, shared by every LLMClient that
    isn't given an explicit one.

    This is what makes the spend cap a real guardrail rather than an
    opt-in: a CLI scan, an eval run, and a one-off script all draw
    from the same cumulative total by default, so the cap can't be
    bypassed just by not wiring a tracker through.
    """

    global _global_tracker

    with _global_tracker_lock:
        if _global_tracker is None:
            _global_tracker = TokenTracker(
                spend_cap_usd=_spend_cap_from_env()
            )
        return _global_tracker


def reset_global_token_tracker() -> None:
    """Clear the global tracker's state. Mainly for tests."""

    global _global_tracker

    with _global_tracker_lock:
        _global_tracker = None
