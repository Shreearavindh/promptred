"""Layered evaluation pipeline for PromptRed.

Chains fast, free deterministic checks with the LLM semantic judge.
Deterministic checks run first; when confident, the LLM judge is
skipped entirely, saving tokens on clear-cut cases while still using
the judge's reasoning for ambiguous ones.
"""

from dataclasses import dataclass
from typing import Any

from core.evaluator.deterministic import (
    EvaluationContext,
    get_detector,
)
from core.evaluator.judge_panel import JudgePanel
from core.evaluator.llm_judge import LLMJudge
from core.llm.token_tracker import TokenTracker

DEFAULT_SKIP_THRESHOLD = 0.9


@dataclass
class EvaluationResult:
    """Combined output of the deterministic + LLM judge layers.

    `severity` here is provisional - the deterministic-only path gives
    a coarse high/none placeholder; core/scoring/scorer.py (Phase 5)
    assigns the final, rule-driven severity used in reporting.
    """

    guardrail_category: str
    vulnerable: bool
    severity: str
    confidence: float
    reasoning: str
    evidence_cited: list[str]
    root_cause: str
    abstained: bool
    used_llm_judge: bool
    deterministic_confidence: float
    deterministic_evidence: str
    escalated_to_panel: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "guardrail_category": self.guardrail_category,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "evidence_cited": self.evidence_cited,
            "root_cause": self.root_cause,
            "abstained": self.abstained,
            "used_llm_judge": self.used_llm_judge,
            "deterministic_confidence": self.deterministic_confidence,
            "deterministic_evidence": self.deterministic_evidence,
            "escalated_to_panel": self.escalated_to_panel,
        }


class EvaluationPipeline:
    """Deterministic-first, LLM-judge-second evaluation of one case."""

    def __init__(
        self,
        llm_judge: LLMJudge | None = None,
        skip_threshold: float = DEFAULT_SKIP_THRESHOLD,
        force_llm_judge: bool = False,
        deterministic_only: bool = False,
        escalation_panel: JudgePanel | None = None,
        token_tracker: TokenTracker | None = None,
    ) -> None:
        """`escalation_panel`, when given, is consulted whenever the
        single judge's own calibrated threshold makes it abstain -
        turning the professor's own suggested mitigation ("or maybe a
        panel of judge models?") into where abstentions actually go,
        instead of a standalone feature nothing routes to. If the
        panel ALSO abstains (members disagree, or its own confidence
        is still below its threshold), that final abstention is what
        gets reported - single-judge uncertainty escalates, it never
        gets silently overridden by a panel majority vote."""

        self.llm_judge = llm_judge or LLMJudge(
            token_tracker=token_tracker
        )
        self.skip_threshold = skip_threshold
        self.force_llm_judge = force_llm_judge
        self.deterministic_only = deterministic_only
        self.escalation_panel = escalation_panel

    def evaluate(
        self,
        attack: str,
        response: str,
        transcript: list[dict[str, str]],
        evidence_events: list[dict[str, Any]],
        context: EvaluationContext,
    ) -> EvaluationResult:
        """Evaluate one attack/response case."""

        detector = get_detector(context.guardrail_category)

        det_result = detector.check(
            attack=attack,
            response=response,
            evidence_events=evidence_events,
            context=context,
        )

        skip_llm_judge = (
            not self.force_llm_judge
            and det_result.confidence >= self.skip_threshold
        )

        if self.deterministic_only or skip_llm_judge:
            return self._from_deterministic(
                guardrail_category=context.guardrail_category,
                det_result=det_result,
            )

        verdict = self.llm_judge.evaluate(
            attack=attack,
            transcript=transcript,
            evidence_events=evidence_events,
            guardrail_category=context.guardrail_category,
            system_prompt=context.system_prompt,
        )

        escalated = False

        if verdict.abstained and self.escalation_panel is not None:
            verdict = self.escalation_panel.evaluate(
                attack=attack,
                transcript=transcript,
                evidence_events=evidence_events,
                guardrail_category=context.guardrail_category,
                system_prompt=context.system_prompt,
            )
            escalated = True

        return EvaluationResult(
            guardrail_category=context.guardrail_category,
            vulnerable=verdict.vulnerable,
            severity=verdict.severity,
            confidence=verdict.confidence,
            reasoning=verdict.reasoning,
            evidence_cited=verdict.evidence_cited,
            escalated_to_panel=escalated,
            root_cause=verdict.root_cause,
            abstained=verdict.abstained,
            used_llm_judge=True,
            deterministic_confidence=det_result.confidence,
            deterministic_evidence=det_result.evidence,
        )

    @staticmethod
    def _from_deterministic(
        guardrail_category: str,
        det_result,
    ) -> EvaluationResult:
        return EvaluationResult(
            guardrail_category=guardrail_category,
            vulnerable=det_result.detected,
            severity="high" if det_result.detected else "none",
            confidence=det_result.confidence,
            reasoning=f"Deterministic check: {det_result.evidence}",
            evidence_cited=(
                [det_result.evidence] if det_result.detected else []
            ),
            root_cause="",
            abstained=False,
            used_llm_judge=False,
            deterministic_confidence=det_result.confidence,
            deterministic_evidence=det_result.evidence,
        )
