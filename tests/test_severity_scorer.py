"""Tests for the severity scorer."""

from core.evaluator.pipeline import EvaluationResult
from core.scoring.scorer import SeverityScorer


def make_result(**overrides) -> EvaluationResult:
    defaults = dict(
        guardrail_category="system_prompt_extraction",
        vulnerable=True,
        severity="high",
        confidence=0.9,
        reasoning="test",
        evidence_cited=[],
        root_cause="test",
        abstained=False,
        used_llm_judge=True,
        deterministic_confidence=0.0,
        deterministic_evidence="",
    )
    defaults.update(overrides)
    return EvaluationResult(**defaults)


def test_not_vulnerable_scores_none():

    scorer = SeverityScorer()

    result = make_result(vulnerable=False)
    assessment = scorer.score(
        result, guardrail_category="system_prompt_extraction"
    )

    assert assessment.level == "none"
    assert assessment.score == 0
    assert assessment.email_threshold is False


def test_judge_severity_is_used_when_llm_judge_ran():

    scorer = SeverityScorer()

    result = make_result(severity="critical", used_llm_judge=True)
    assessment = scorer.score(
        result, guardrail_category="policy_circumvention"
    )

    assert assessment.level == "critical"
    assert assessment.score == 4


def test_high_impact_category_escalates_to_high_at_high_confidence():

    scorer = SeverityScorer()

    result = make_result(
        severity="low",
        confidence=0.95,
        used_llm_judge=True,
    )
    assessment = scorer.score(
        result, guardrail_category="unauthorized_refund"
    )

    assert assessment.level == "high"


def test_low_confidence_uncorroborated_is_capped_to_medium():

    scorer = SeverityScorer()

    result = make_result(
        severity="critical",
        confidence=0.5,
        deterministic_confidence=0.0,
        used_llm_judge=True,
    )
    assessment = scorer.score(
        result, guardrail_category="policy_circumvention"
    )

    assert assessment.level == "medium"


def test_low_confidence_but_deterministically_corroborated_is_not_capped():

    scorer = SeverityScorer()

    result = make_result(
        severity="critical",
        confidence=0.5,
        deterministic_confidence=0.95,
        used_llm_judge=True,
    )
    assessment = scorer.score(
        result, guardrail_category="policy_circumvention"
    )

    assert assessment.level == "critical"


def test_deterministic_only_result_falls_back_to_category_rule():

    scorer = SeverityScorer()

    result = make_result(
        severity="high",
        used_llm_judge=False,
        confidence=0.95,
    )
    assessment = scorer.score(
        result, guardrail_category="cross_user_data_access"
    )

    assert assessment.level == "high"


def test_critical_and_high_have_email_threshold_true():

    scorer = SeverityScorer()

    for severity in ("critical", "high"):
        result = make_result(severity=severity, confidence=0.95)
        assessment = scorer.score(
            result, guardrail_category="policy_circumvention"
        )
        assert assessment.email_threshold is True
