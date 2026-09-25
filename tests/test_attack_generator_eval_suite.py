"""Tests for the attack generator eval suite's plumbing (fakes only)."""

from evals.harness import EvalRunner
from evals.suites.attack_generator_eval import (
    AttackGeneratorEvalSuite,
    GradeResult,
    load_taxonomy_patterns,
    _jaccard_dissimilarity,
)


def test_load_taxonomy_patterns_returns_twelve_patterns():

    patterns = load_taxonomy_patterns()

    assert len(patterns) == 12
    assert all(p["pattern_id"] for p in patterns)
    assert all(p["guardrail_category"] for p in patterns)


class FakeGenerator:
    def __init__(self) -> None:
        self.calls = 0

    def generate(self, system_prompt, guardrail_category, conversation_history=None):
        self.calls += 1
        return {
            "attack": f"Attack variant {self.calls} for {guardrail_category}",
            "technique": "Test Technique",
            "objective": "Test Objective",
        }


class FakeGrader:
    def grade(self, attack, technique, objective, guardrail_category):
        return GradeResult(
            on_target=True,
            specificity=4,
            reasoning="looks fine",
        )


def test_suite_runs_and_scores_cases():

    suite = AttackGeneratorEvalSuite(
        generator=FakeGenerator(),
        grader=FakeGrader(),
    )

    runner = EvalRunner(repeats_per_case=2)
    report = runner.run(suite)

    assert len(report.case_summaries) == 12
    assert report.metrics["on_target_rate"] == 1.0
    assert report.metrics["mean_specificity"] == 4.0


def test_diversity_is_zero_for_identical_attacks():

    class RepeatingGenerator:
        def generate(self, system_prompt, guardrail_category, conversation_history=None):
            return {
                "attack": "Always the exact same attack text.",
                "technique": "x",
                "objective": "x",
            }

    suite = AttackGeneratorEvalSuite(
        generator=RepeatingGenerator(),
        grader=FakeGrader(),
    )

    runner = EvalRunner(repeats_per_case=3)
    report = runner.run(suite)

    assert report.metrics["mean_diversity"] == 0.0


def test_jaccard_dissimilarity_identical_text_is_zero():

    assert _jaccard_dissimilarity("same text here", "same text here") == 0.0


def test_jaccard_dissimilarity_disjoint_text_is_one():

    assert _jaccard_dissimilarity("apple banana", "car truck") == 1.0
