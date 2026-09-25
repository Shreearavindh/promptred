"""Cost-to-serve model for PromptRed scans.

PromptRed's `TokenTracker` reports raw token cost - what a scan spent
on the OpenRouter API. In cost-to-serve terms that is a "raw-material
price": what one call costs, not what a *finding* costs once the
chance of missing something is priced in. This module adds the two
layers that turn a token bill into a business number:

    layer 1 (per-attempt variable) = the measured token cost of one
        attack attempt (attacker + target + judge calls, summed over
        turns) - this is exactly TokenTracker.summary()['total_cost_usd']
        divided by the number of attempts it took to produce it.
    layer 2 (expected fallback)    = (1 - detection_rate) * the cost
        of a vulnerability the judge MISSED - a real bypass that
        shipped because nothing flagged it.
    layer 3 (fixed monthly)        = ground-truth corpus upkeep, eval
        runs, maintenance - amortised, not computed per attempt here.

    cost per confirmed finding = layer 1 + layer 2

This mirrors the "cost per resolved ticket" worked example: the token
cost of *one* attempt, plus the expected cost of handling the cases
that attempt's detection layer would have let through, undiscounted
by how many attempts there were - you pay layer 1 for every attempt
whether or not it succeeds, and layer 2 prices the expected downstream
cost of being wrong on that same attempt.

All prices are declared here, in one place, dated, with their source
stated - "a hardcoded price is already wrong" only when nobody can
tell where it came from.
"""

from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------
# Priced assumptions - dated, sourced, and meant to be argued with.
# ---------------------------------------------------------------

# Loaded hourly rate for the engineer who triages a missed guardrail
# bypass once it reaches production. This is a stated ASSUMPTION, not
# a specific breach-cost citation - public breach-cost reports (e.g.
# IBM's Cost of a Data Breach) report organisation-wide averages, not
# a per-vulnerability-class figure, so using one directly here would
# be a fabricated precision this file explicitly wants to avoid.
# $85/hr is a representative loaded rate for a mid-senior security
# engineer (informed by public salary aggregators as of 2026-09;
# adjust to your own org's real loaded rate before citing this
# number anywhere).
SECURITY_ENGINEER_HOURLY_RATE_USD = 85.0

# Hours to triage, confirm, patch the responsible layer (prompt /
# tool / loop / code), and verify a single missed guardrail bypass
# once it surfaces - a stated assumption, not a benchmark figure.
# State and defend your own estimate; this is a starting point.
TRIAGE_HOURS_PER_MISSED_VULNERABILITY = 4.0

DEFAULT_MISSED_VULNERABILITY_COST_USD = (
    SECURITY_ENGINEER_HOURLY_RATE_USD
    * TRIAGE_HOURS_PER_MISSED_VULNERABILITY
)  # = $340.00 at the defaults above

# Sensitivity band width, in percentage points of detection rate.
# "Report the break-even and the sensitivity, not a point estimate."
DEFAULT_SENSITIVITY_DELTA = 0.10


@dataclass(frozen=True)
class CostBreakdown:
    """Layer 1 / layer 2 breakdown for one attack attempt."""

    layer1_variable_usd: float
    layer2_expected_fallback_usd: float
    detection_rate: float
    missed_vulnerability_cost_usd: float

    @property
    def cost_per_confirmed_finding_usd(self) -> float:
        return self.layer1_variable_usd + self.layer2_expected_fallback_usd

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer1_variable_usd": self.layer1_variable_usd,
            "layer2_expected_fallback_usd": (
                self.layer2_expected_fallback_usd
            ),
            "detection_rate": self.detection_rate,
            "missed_vulnerability_cost_usd": (
                self.missed_vulnerability_cost_usd
            ),
            "cost_per_confirmed_finding_usd": (
                self.cost_per_confirmed_finding_usd
            ),
        }


def layer1_cost_per_attempt(
    token_summary: dict[str, Any],
    num_attempts: int,
) -> float:
    """Average measured token cost of one attack attempt.

    `num_attempts` should be the number of attempts that produced
    `token_summary`'s total (e.g. taxonomy patterns run, including
    ones that later errored) - not the number of confirmed findings.
    """

    if num_attempts <= 0:
        return 0.0

    total_cost = token_summary.get("total_cost_usd", 0.0)
    return total_cost / num_attempts


def layer2_expected_fallback(
    detection_rate: float,
    missed_vulnerability_cost_usd: float = (
        DEFAULT_MISSED_VULNERABILITY_COST_USD
    ),
) -> float:
    """Expected cost of a miss, given how often detection succeeds.

    `detection_rate` should be the judge's measured recall against
    hand-labelled ground truth (evals/suites/judge_eval.py), not an
    assumed number - "if a model judges your outputs, that judge is
    a component of your system... measure its precision and recall."
    """

    if not (0.0 <= detection_rate <= 1.0):
        raise ValueError(
            "detection_rate must be between 0.0 and 1.0, got "
            f"{detection_rate!r}."
        )

    return (1.0 - detection_rate) * missed_vulnerability_cost_usd


def compute_cost_breakdown(
    token_summary: dict[str, Any],
    num_attempts: int,
    detection_rate: float,
    missed_vulnerability_cost_usd: float = (
        DEFAULT_MISSED_VULNERABILITY_COST_USD
    ),
) -> CostBreakdown:
    """Layer 1 + layer 2 for one attempt, given a scan's token summary."""

    layer1 = layer1_cost_per_attempt(token_summary, num_attempts)
    layer2 = layer2_expected_fallback(
        detection_rate, missed_vulnerability_cost_usd
    )

    return CostBreakdown(
        layer1_variable_usd=layer1,
        layer2_expected_fallback_usd=layer2,
        detection_rate=detection_rate,
        missed_vulnerability_cost_usd=missed_vulnerability_cost_usd,
    )


def sensitivity_band(
    token_summary: dict[str, Any],
    num_attempts: int,
    base_detection_rate: float,
    missed_vulnerability_cost_usd: float = (
        DEFAULT_MISSED_VULNERABILITY_COST_USD
    ),
    delta: float = DEFAULT_SENSITIVITY_DELTA,
) -> dict[str, float]:
    """Cost per confirmed finding at detection_rate +/- `delta`.

    "A cost model without a sensitivity table is a guess with decimal
    places." Never report the base case alone - report whether the
    conclusion survives the whole range.
    """

    layer1 = layer1_cost_per_attempt(token_summary, num_attempts)

    rates = {
        "low_detection": max(0.0, base_detection_rate - delta),
        "base": base_detection_rate,
        "high_detection": min(1.0, base_detection_rate + delta),
    }

    return {
        label: layer1
        + layer2_expected_fallback(
            rate, missed_vulnerability_cost_usd
        )
        for label, rate in rates.items()
    }


def break_even_detection_rate(
    cheap_layer1_cost_per_attempt_usd: float,
    expensive_cost_per_confirmed_finding_usd: float,
    missed_vulnerability_cost_usd: float = (
        DEFAULT_MISSED_VULNERABILITY_COST_USD
    ),
) -> float:
    """The detection rate at which a cheap judge stops paying for itself.

    Direct application of the course's break-even formula:
    `break-even = 1 - (E - C) / F`, where:
      C = the cheap option's cost per attempt - tokens only, since its
          own detection rate is the unknown being solved for.
      E = the expensive option's cost PER CONFIRMED FINDING - its own
          tokens plus its own layer 2, at its own measured detection
          rate. (Compute this with `compute_cost_breakdown` using the
          expensive judge's real measured recall, then pass its
          `.cost_per_confirmed_finding_usd` in here as E.)
      F = the cost of one missed vulnerability.

    "When failures are expensive, the price of the model barely
    matters. Accuracy does." For a security scanner F is generally
    large, so the expected answer is a high break-even bar - i.e. the
    cheap judge would need to be nearly as accurate as the expensive
    one before it is worth using, which is itself the headline finding
    this function exists to produce.
    """

    if missed_vulnerability_cost_usd <= 0:
        raise ValueError(
            "missed_vulnerability_cost_usd must be positive."
        )

    gap = (
        expensive_cost_per_confirmed_finding_usd
        - cheap_layer1_cost_per_attempt_usd
    )
    return 1.0 - (gap / missed_vulnerability_cost_usd)
