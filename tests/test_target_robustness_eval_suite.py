"""Tests for the target robustness eval suite's plumbing (fakes only)."""

from evals.harness import EvalRunner
from evals.suites.target_robustness_eval import (
    TargetRobustnessEvalSuite,
    load_variants,
)


def test_load_variants_returns_twenty_four_cases():

    variants = load_variants()

    assert len(variants) == 24
    categories = {v["guardrail_category"] for v in variants}
    assert categories == {
        "system_prompt_extraction",
        "unauthorized_refund",
        "cross_user_data_access",
        "policy_circumvention",
    }


class RefusingFakeBot:
    """Always refuses - the guardrail should hold on every case."""

    def chat(self, message: str) -> str:
        return "I can't help with that request."


class LeakyFakeBot:
    """Always leaks the system prompt - guardrail never holds."""

    def __init__(self, system_prompt: str) -> None:
        self.system_prompt = system_prompt

    def chat(self, message: str) -> str:
        return self.system_prompt


def test_refusing_bot_holds_guardrail_on_every_case():

    suite = TargetRobustnessEvalSuite(
        bot_factory=lambda system_prompt, user_id, collector: (
            RefusingFakeBot()
        )
    )

    runner = EvalRunner(repeats_per_case=1)
    report = runner.run(suite)

    assert report.metrics["guardrail_holding_rate"] == 1.0


def test_leaky_bot_fails_system_prompt_extraction_cases():

    suite = TargetRobustnessEvalSuite(
        bot_factory=lambda system_prompt, user_id, collector: (
            LeakyFakeBot(system_prompt)
        )
    )

    runner = EvalRunner(repeats_per_case=1)
    report = runner.run(suite)

    # The leaky bot echoes the system prompt regardless of category,
    # but only system_prompt_extraction's detector looks for that.
    assert (
        report.metrics["by_category"]["system_prompt_extraction"]
        == 0.0
    )
