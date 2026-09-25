"""Target bot guardrail robustness eval suite.

The deterministic bot mode is exact by construction (keyword/regex
routing), so testing it here would be circular. What matters is the
LLM-mode target - a real system prompt driving a real model - and
whether phrasing variety (paraphrase, obfuscation, framing) changes
whether the guardrail holds. Run this suite before and after any
system-prompt or model change and diff the guardrail-holding rate:
that diff is the regression signal, the behavioral equivalent of a
code regression test.
"""

import json
from pathlib import Path
from typing import Any, Callable, Protocol

from core.evaluator.deterministic import (
    EvaluationContext,
    get_detector,
)
from core.evidence.collector import EvidenceCollector
from core.target_bot.bot import SyntheticSupportBot
from evals.harness import CaseSummary, EvalCase, EvalResult

VARIANTS_PATH = Path("data/ground_truth/robustness_variants.json")


class ChatBot(Protocol):
    def chat(self, message: str) -> str:
        ...


BotFactory = Callable[[str, str, EvidenceCollector], ChatBot]


def _default_bot_factory(
    system_prompt: str,
    user_id: str,
    evidence_collector: EvidenceCollector,
) -> ChatBot:
    return SyntheticSupportBot(
        system_prompt=system_prompt,
        user_id=user_id,
        use_llm=True,
        evidence_collector=evidence_collector,
    )

CUSTOMER_RECORDS: dict[str, dict[str, Any]] = {
    "A001": {
        "name": "Alice",
        "email": "alice@example.com",
        "role": "customer",
        "refund_limit": 100.0,
    },
    "B002": {
        "name": "Bob",
        "email": "bob@example.com",
        "role": "customer",
        "refund_limit": 100.0,
    },
}


def load_variants(
    path: Path = VARIANTS_PATH,
) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


class TargetRobustnessEvalSuite:
    """Measures guardrail-holding rate across paraphrased attack variants."""

    name = "target_robustness"

    def __init__(
        self,
        variants_path: Path = VARIANTS_PATH,
        requesting_user_id: str = "A001",
        bot_factory: BotFactory | None = None,
    ) -> None:
        self.variants_path = variants_path
        self.requesting_user_id = requesting_user_id
        self.bot_factory = bot_factory or _default_bot_factory

    def load_cases(self) -> list[EvalCase]:
        variants = load_variants(self.variants_path)

        return [
            EvalCase(
                case_id=entry["case_id"],
                inputs=entry,
                expected={"should_hold": True},
            )
            for entry in variants
        ]

    def run_case(self, case: EvalCase) -> EvalResult:
        entry = case.inputs
        collector = EvidenceCollector()

        bot = self.bot_factory(
            entry["system_prompt"],
            self.requesting_user_id,
            collector,
        )

        response = bot.chat(entry["variant_text"])

        context = EvaluationContext(
            system_prompt=entry["system_prompt"],
            guardrail_category=entry["guardrail_category"],
            requesting_user_id=self.requesting_user_id,
            customer_records=CUSTOMER_RECORDS,
        )

        detector = get_detector(entry["guardrail_category"])

        det_result = detector.check(
            attack=entry["variant_text"],
            response=response,
            evidence_events=collector.to_dict(),
            context=context,
        )

        held = not det_result.detected

        return EvalResult(
            case_id=case.case_id,
            passed=held,
            score=1.0 if held else 0.0,
            details={
                "held": held,
                "guardrail_category": entry[
                    "guardrail_category"
                ],
                "response": response,
                "detector_evidence": det_result.evidence,
            },
        )

    def compute_metrics(
        self,
        case_summaries: list[CaseSummary],
    ) -> dict[str, Any]:
        by_category: dict[str, list[float]] = {}
        overall_rates: list[float] = []
        error_count = 0
        total_samples = 0

        for summary in case_summaries:
            total_samples += len(summary.results)

            valid_results = [
                r for r in summary.results if "error" not in r.details
            ]
            error_count += len(summary.results) - len(valid_results)

            if not valid_results:
                continue

            hold_rate = sum(
                1 for r in valid_results if r.passed
            ) / len(valid_results)
            overall_rates.append(hold_rate)

            category = valid_results[0].details[
                "guardrail_category"
            ]
            by_category.setdefault(category, []).append(hold_rate)

        return {
            "guardrail_holding_rate": (
                sum(overall_rates) / len(overall_rates)
                if overall_rates
                else 0.0
            ),
            "by_category": {
                category: sum(rates) / len(rates)
                for category, rates in by_category.items()
            },
            "error_rate": (
                error_count / total_samples if total_samples else 0.0
            ),
            "cases_evaluated": len(case_summaries),
        }
