"""Tests for the system eval suite's plumbing (fakes only)."""

from core.evaluator.pipeline import EvaluationResult
from evals.suites.system_eval import (
    ALL_GUARDRAIL_CATEGORIES,
    SystemEvalSuite,
    load_benchmark_prompts,
)


def test_load_benchmark_prompts_returns_five_prompts():

    prompts = load_benchmark_prompts()

    assert len(prompts) == 5
    assert all(p["planted_vulnerabilities"] for p in prompts)


class FakeGenerator:
    def generate(
        self, system_prompt, guardrail_category, conversation_history=None
    ):
        return {
            "attack": f"attack for {guardrail_category}",
            "technique": "x",
            "objective": "x",
        }


class FakeBot:
    def chat(self, message: str) -> str:
        return "response"


def _stub_result(category: str, vulnerable: bool) -> EvaluationResult:
    return EvaluationResult(
        guardrail_category=category,
        vulnerable=vulnerable,
        severity="high" if vulnerable else "none",
        confidence=0.9,
        reasoning="stub",
        evidence_cited=[],
        root_cause="stub",
        abstained=False,
        used_llm_judge=True,
        deterministic_confidence=0.0,
        deterministic_evidence="",
    )


def make_suite(pipeline) -> SystemEvalSuite:
    return SystemEvalSuite(
        generator=FakeGenerator(),
        pipeline=pipeline,
        bot_factory=lambda sp, uid, ec: FakeBot(),
    )


def test_perfect_pipeline_achieves_full_recall_no_false_positives():

    planted = None  # set per-case below

    class PerfectPipeline:
        def evaluate(
            self, attack, response, transcript, evidence_events, context
        ):
            return _stub_result(
                context.guardrail_category,
                context.guardrail_category in planted,
            )

    suite = make_suite(PerfectPipeline())
    case = suite.load_cases()[0]
    planted = set(case.expected["planted_vulnerabilities"])

    result = suite.run_case(case)

    assert result.score == 1.0
    assert result.details["false_positives"] == []
    assert result.passed is True


def test_pipeline_flagging_nothing_scores_zero_recall():

    class NeverVulnerablePipeline:
        def evaluate(
            self, attack, response, transcript, evidence_events, context
        ):
            return _stub_result(context.guardrail_category, False)

    suite = make_suite(NeverVulnerablePipeline())
    case = suite.load_cases()[0]

    result = suite.run_case(case)

    assert result.score == 0.0
    assert result.passed is False


def test_pipeline_flagging_everything_has_false_positives():

    class AlwaysVulnerablePipeline:
        def evaluate(
            self, attack, response, transcript, evidence_events, context
        ):
            return _stub_result(context.guardrail_category, True)

    suite = make_suite(AlwaysVulnerablePipeline())
    case = suite.load_cases()[0]
    planted = set(case.expected["planted_vulnerabilities"])

    result = suite.run_case(case)

    assert result.score == 1.0  # all planted ones were caught too
    non_planted = set(ALL_GUARDRAIL_CATEGORIES) - planted
    assert set(result.details["false_positives"]) == non_planted
    assert result.passed is False  # false positives fail the case
