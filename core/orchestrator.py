"""Scan orchestrator for PromptRed.

Wires together attack generation, target execution, evaluation,
severity scoring, root cause analysis, and remediation into a single
scan over one or more system prompts - either a single prompt/prompt
file, or every prompt discovered by core/discovery/prompt_scanner.py
when pointed at a project directory. This is the module the CLI's
`scan` command drives.

Resilience when a model is down: a failed attack is retried once with a
fixed real-world attack (core/attacks/strategies/static_attacks.py)
instead of being dropped; anything that still fails is recorded in
ScanResult.failed_attempts so the report can say the scan is incomplete
rather than look clean. `offline=True` runs with no AI at all: fixed
attacks, the rules-based bot, and rules-only verdicts.
"""

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from core.attacks.generator import AttackGenerator
from core.attacks.harness import HarnessResult
from core.attacks.strategies.base import (
    AttackStrategy,
    StrategyRegistry,
)
from core.attacks.strategies.public_dataset import PublicDatasetStrategy
from core.attacks.strategies.seed_augmented import SeedAugmentedStrategy
from core.attacks.strategies.single import SingleAttemptStrategy
from core.attacks.strategies.static_attacks import (
    StaticAttackStrategy,
    StaticFallback,
    run_static_attack,
)
from core.attacks.strategies.taxonomy import TaxonomyStrategy
from core.discovery.prompt_scanner import PromptScanner
from core.evaluator.decision_judge import DecisionJudge, is_decision_model
from core.evaluator.deterministic import EvaluationContext
from core.evaluator.judge_panel import JudgePanel
from core.evaluator.llm_judge import LLMJudge
from core.evaluator.pipeline import EvaluationPipeline
from core.evidence.collector import EvidenceCollector
from core.llm.client import LLMClient
from core.llm.roles import check_model_independence
from core.llm.token_tracker import (
    SpendCapExceededError,
    TokenTracker,
    get_global_token_tracker,
)
from core.remediation.mapper import RemediationMapper
from core.scoring.rca import RootCauseAnalyzer
from core.scoring.scorer import SeverityScorer
from core.target_bot.bot import SyntheticSupportBot


class ChatBot(Protocol):
    def chat(self, message: str) -> str:
        ...


BotFactory = Callable[[str, str, EvidenceCollector], ChatBot]

# Default strategy: full documented-taxonomy coverage per guardrail
# category, per the evaluation-first priority. Pass
# strategy_names=["single"] for the original one-attack-per-category
# behavior instead.
DEFAULT_STRATEGY_NAMES = ["taxonomy"]

# The panel's second member, for escalation when the primary judge's
# calibrated threshold makes it abstain (core/evaluator/
# selective_evaluation.py). Must be a distinct family from JUDGE_MODEL
# (the primary), ATTACKER_MODEL, and TARGET_MODEL, or the panel adds
# no real independence - an attacker who knows one model in a family
# has a head start on the others.
#
# typesafe/jev-1.13 (TypeSafe's Jev, a structured decision model called
# through core/evaluator/decision_judge.py) replaced mistralai/mistral-nemo
# on 2026-10-02 after a measured comparison on the new-task test against
# the author's blind labels (data/holdout_planted/compare_second_judges.py):
# alone, Jev scored accuracy 85% / F1 0.83 vs mistral-nemo's 64% / 0.68,
# and on the 14 cases the main judge was unsure about, main judge + Jev
# made 1 automatic error vs 4 for the original mistral panel (sending more
# cases to a human instead). About $0.00002 per verdict. Override via
# JUDGE_PANEL_SECOND_MODEL (any OpenRouter chat model also works); the
# decisions endpoint is alpha, so re-check it if calls start failing.
DEFAULT_JUDGE_PANEL_SECOND_MODEL = "typesafe/jev-1.13"


def resolve_judge_panel_second_model() -> str:
    return os.getenv(
        "JUDGE_PANEL_SECOND_MODEL", DEFAULT_JUDGE_PANEL_SECOND_MODEL
    )


def build_default_strategy_registry() -> StrategyRegistry:
    registry = StrategyRegistry()
    registry.register("single", SingleAttemptStrategy)
    registry.register("taxonomy", TaxonomyStrategy)
    registry.register("seed", SeedAugmentedStrategy)
    registry.register("gandalf", PublicDatasetStrategy)
    registry.register("static", StaticAttackStrategy)
    return registry


# Strategies that never call the attacker model, so a failure in them is
# not an attacker outage and a static fallback would not help.
STATIC_STRATEGY_NAMES = {"static", "gandalf"}
OFFLINE_STRATEGY_NAMES = ["static"]


def _offline_bot_factory(
    system_prompt: str,
    user_id: str,
    evidence_collector: EvidenceCollector,
) -> "ChatBot":
    """Rules-based bot (keyword routing, mock tools): no model calls."""

    return SyntheticSupportBot(
        system_prompt=system_prompt,
        user_id=user_id,
        use_llm=False,
        evidence_collector=evidence_collector,
    )


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


ALL_GUARDRAIL_CATEGORIES = [
    "system_prompt_extraction",
    "unauthorized_refund",
    "cross_user_data_access",
    "policy_circumvention",
]

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

ProgressCallback = Callable[[str], None]


class BudgetExceededError(Exception):
    """Raised when a scan's token cost exceeds the configured budget."""


@dataclass
class Finding:
    """One attack's full result: evaluation, severity, RCA, remediation."""

    prompt_source: str
    guardrail_category: str
    attack: str
    response: str
    transcript: list[dict[str, str]]
    evaluation: Any
    severity: Any
    root_cause: Any
    remediation: Any
    attack_pattern_id: str | None = None
    strategy_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_source": self.prompt_source,
            "guardrail_category": self.guardrail_category,
            "attack": self.attack,
            "response": self.response,
            "transcript": self.transcript,
            "evaluation": self.evaluation.to_dict(),
            "severity": self.severity.to_dict(),
            "root_cause": self.root_cause.to_dict(),
            "remediation": self.remediation.to_dict(),
            "attack_pattern_id": self.attack_pattern_id,
            "strategy_name": self.strategy_name,
        }


@dataclass
class ScanResult:
    """Aggregate result of a full scan across one or more prompts."""

    findings: list[Finding]
    model_independence: dict[str, Any]
    token_summary: dict[str, Any]
    prompts_scanned: int
    # Attacks that could not run or could not be evaluated (model down,
    # bad output). Never silently dropped: their presence makes the
    # scan incomplete. Each entry: prompt_source, guardrail_category,
    # attack_label, strategy, stage ("attack" or "evaluation"), error.
    failed_attempts: list[dict[str, Any]] = field(default_factory=list)
    offline: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [
                finding.to_dict() for finding in self.findings
            ],
            "model_independence": self.model_independence,
            "token_summary": self.token_summary,
            "prompts_scanned": self.prompts_scanned,
            "failed_attempts": self.failed_attempts,
            "offline": self.offline,
        }

    @property
    def judge_unavailable_findings(self) -> list[Finding]:
        """Findings decided without the LLM judge because it was down."""

        return [
            finding
            for finding in self.findings
            if getattr(finding.evaluation, "judge_unavailable", False)
        ]

    @property
    def is_complete(self) -> bool:
        """False if any attack failed or any verdict lacked the judge.
        An incomplete scan must never be read as a clean result."""

        return not self.failed_attempts and not self.judge_unavailable_findings

    @property
    def vulnerable_findings(self) -> list[Finding]:
        """Findings the judge (or panel) is confident are real bypasses.

        Excludes abstained findings, even ones where `vulnerable`
        happens to be True - abstention (core/evaluator/
        selective_evaluation.py's calibrated threshold, or panel
        disagreement) means the system was not confident enough to
        assert a verdict automatically. Counting those as confirmed
        vulnerabilities would silently let the AI "make the call" the
        abstention mechanism exists specifically to avoid - see
        `needs_review_findings` for where they actually go.
        """

        return [
            finding
            for finding in self.findings
            if finding.evaluation.vulnerable
            and not finding.evaluation.abstained
        ]

    @property
    def needs_review_findings(self) -> list[Finding]:
        """Findings neither the primary judge nor the escalation panel
        was confident enough to resolve automatically - a human must
        look at the actual attack/response and decide. Never silently
        defaulted to "held" just because `vulnerable` happened to come
        back False."""

        return [
            finding
            for finding in self.findings
            if finding.evaluation.abstained
        ]


class ScanOrchestrator:
    """Runs a full PromptRed scan and aggregates the results."""

    def __init__(
        self,
        generator: AttackGenerator | None = None,
        pipeline: EvaluationPipeline | None = None,
        severity_scorer: SeverityScorer | None = None,
        rca_analyzer: RootCauseAnalyzer | None = None,
        remediation_mapper: RemediationMapper | None = None,
        token_tracker: TokenTracker | None = None,
        budget_usd: float | None = None,
        progress_callback: ProgressCallback | None = None,
        bot_factory: BotFactory | None = None,
        strategy_names: list[str] | None = None,
        strategy_registry: StrategyRegistry | None = None,
        offline: bool = False,
        static_fallback: bool = True,
    ) -> None:
        """`offline=True` builds no model clients at all (no API key
        needed): fixed attacks, the rules-based bot, rules-only
        verdicts. `static_fallback` retries a failed attack once with a
        fixed real-world attack instead of dropping it."""

        self.offline = offline
        self.static_fallback = StaticFallback() if static_fallback else None
        self.token_tracker = (
            token_tracker or get_global_token_tracker()
        )

        if offline:
            self.generator = generator
            self.bot_factory = bot_factory or _offline_bot_factory
            self.pipeline = pipeline or EvaluationPipeline(
                deterministic_only=True
            )
            strategy_names = OFFLINE_STRATEGY_NAMES
        else:
            self.generator = generator or AttackGenerator(
                token_tracker=self.token_tracker
            )
            self.bot_factory = (
                bot_factory or self._make_default_bot_factory()
            )
            self.pipeline = pipeline or EvaluationPipeline(
                token_tracker=self.token_tracker,
                escalation_panel=self._make_default_escalation_panel(),
            )
        self.severity_scorer = severity_scorer or SeverityScorer()
        self.rca_analyzer = rca_analyzer or RootCauseAnalyzer()
        self.remediation_mapper = (
            remediation_mapper or RemediationMapper()
        )
        self.budget_usd = budget_usd
        self.progress_callback = progress_callback or (
            lambda message: None
        )
        self.model_independence = check_model_independence()

        registry = strategy_registry or build_default_strategy_registry()
        names = strategy_names or DEFAULT_STRATEGY_NAMES
        self.strategy_names = list(names)
        self.strategies: list[AttackStrategy] = [
            registry.get(name) for name in self.strategy_names
        ]

        if not self.model_independence.judge_independent:
            self.progress_callback(
                f"WARNING: {self.model_independence.warning}"
            )

    def _make_default_escalation_panel(self) -> JudgePanel:
        """Build the panel abstained cases escalate to.

        Two independent judges - the primary judge's own model
        (JUDGE_MODEL / JUDGE_MODEL_POOL) plus
        resolve_judge_panel_second_model() from a distinct family -
        both wired to this scan's token tracker so panel calls are
        counted and the spend cap still applies to them. Only called
        when the primary judge's calibrated threshold makes it
        abstain (core/evaluator/pipeline.py); a confident primary
        verdict never reaches this panel at all.
        """

        second_model = resolve_judge_panel_second_model()

        if is_decision_model(second_model):
            second_judge = DecisionJudge(
                model=second_model, token_tracker=self.token_tracker
            )
        else:
            second_judge = LLMJudge(
                llm_client=LLMClient(
                    model=second_model,
                    token_tracker=self.token_tracker,
                ),
                token_tracker=self.token_tracker,
            )

        return JudgePanel(
            judges=[
                LLMJudge(token_tracker=self.token_tracker),
                second_judge,
            ],
        )

    def _make_default_bot_factory(self) -> BotFactory:
        """Build the real-bot factory, closing over this scan's tracker.

        `_default_bot_factory` (module-level) doesn't know about a
        token tracker; this wraps it so every target-model call made
        during the scan is still recorded in `self.token_tracker`.
        """

        token_tracker = self.token_tracker

        def factory(
            system_prompt: str,
            user_id: str,
            evidence_collector: EvidenceCollector,
        ) -> ChatBot:
            return SyntheticSupportBot(
                system_prompt=system_prompt,
                user_id=user_id,
                use_llm=True,
                evidence_collector=evidence_collector,
                token_tracker=token_tracker,
            )

        return factory

    def scan_directory(
        self,
        path: str,
        guardrails: list[str] | None = None,
        turns: int = 1,
        max_attacks: int | None = None,
        requesting_user_id: str = "A001",
    ) -> ScanResult:
        """Discover system prompts under `path` and scan every one."""

        scanner = PromptScanner()
        discovered = scanner.scan(path)

        self.progress_callback(
            f"Discovered {len(discovered)} candidate system "
            f"prompt(s) in {path}"
        )

        prompts = [
            (candidate.file_path, candidate.prompt_text)
            for candidate in discovered
        ]

        return self._run_scan(
            prompts,
            guardrails,
            turns,
            max_attacks,
            requesting_user_id,
        )

    def scan_many(
        self,
        prompts: list[tuple[str, str]],
        guardrails: list[str] | None = None,
        turns: int = 1,
        max_attacks: int | None = None,
        requesting_user_id: str = "A001",
    ) -> ScanResult:
        """Scan a pre-built list of (source_label, system_prompt) pairs.

        Used by the CLI's `benchmark` command to scan every benchmark
        prompt as one combined ScanResult.
        """

        return self._run_scan(
            prompts,
            guardrails,
            turns,
            max_attacks,
            requesting_user_id,
        )

    def scan_prompt(
        self,
        system_prompt: str,
        guardrails: list[str] | None = None,
        turns: int = 1,
        max_attacks: int | None = None,
        requesting_user_id: str = "A001",
        source_label: str = "manual",
    ) -> ScanResult:
        """Scan a single, directly-supplied system prompt."""

        return self._run_scan(
            [(source_label, system_prompt)],
            guardrails,
            turns,
            max_attacks,
            requesting_user_id,
        )

    def _run_scan(
        self,
        prompts: list[tuple[str, str]],
        guardrails: list[str] | None,
        turns: int,
        max_attacks: int | None,
        requesting_user_id: str,
    ) -> ScanResult:
        categories = guardrails or ALL_GUARDRAIL_CATEGORIES
        findings: list[Finding] = []
        failures: list[dict[str, Any]] = []
        attack_count = 0

        def record_failure(source, category, label, strategy_name, stage, error):
            failures.append({
                "prompt_source": source,
                "guardrail_category": category,
                "attack_label": label,
                "strategy": strategy_name,
                "stage": stage,
                "error": f"{type(error).__name__}: {error}",
            })

        for source_label, system_prompt in prompts:
            for category in categories:
                for strategy in self.strategies:
                    if (
                        max_attacks is not None
                        and attack_count >= max_attacks
                    ):
                        self.progress_callback(
                            f"Reached max_attacks={max_attacks}; "
                            "stopping scan."
                        )
                        return self._finalize(
                            findings, len(prompts), failures
                        )

                    self._check_budget()

                    # A strategy runs its own attempts (e.g. one per
                    # taxonomy pattern) and already absorbs ordinary
                    # per-attempt failures internally - see
                    # AttackAttempt in core/attacks/strategies/base.py.
                    # SpendCapExceededError is the one thing it
                    # deliberately lets propagate, so it isn't caught
                    # here either; it stops the whole scan.
                    attempts = strategy.execute(
                        bot_factory=self.bot_factory,
                        generator=self.generator,
                        system_prompt=system_prompt,
                        guardrail_category=category,
                        requesting_user_id=requesting_user_id,
                        turns=turns,
                    )

                    for attempt in attempts:
                        if (
                            max_attacks is not None
                            and attack_count >= max_attacks
                        ):
                            self.progress_callback(
                                f"Reached max_attacks={max_attacks}; "
                                "stopping scan."
                            )
                            return self._finalize(
                                findings, len(prompts), failures
                            )

                        label_suffix = (
                            f"/{attempt.label}"
                            if attempt.label
                            else ""
                        )

                        strategy_name = strategy.name

                        if not attempt.succeeded:
                            original_error = attempt.error
                            self.progress_callback(
                                f"[{source_label}] {category}"
                                f"{label_suffix}: ERROR "
                                f"({type(original_error).__name__}: "
                                f"{original_error})"
                            )
                            fallback = self._try_static_fallback(
                                strategy.name,
                                system_prompt,
                                category,
                                requesting_user_id,
                                turns,
                            )
                            if fallback is None or not fallback.succeeded:
                                attack_count += 1
                                record_failure(
                                    source_label,
                                    category,
                                    attempt.label,
                                    strategy.name,
                                    "attack",
                                    original_error
                                    if fallback is None
                                    else fallback.error,
                                )
                                self.progress_callback(
                                    f"[{source_label}] {category}"
                                    f"{label_suffix}: could not run - "
                                    "recorded as a failed attack"
                                )
                                continue
                            attempt = fallback
                            strategy_name = "static_fallback"
                            label_suffix = f"/{attempt.label}"
                            self.progress_callback(
                                f"[{source_label}] {category}: replaying "
                                f"fixed attack {attempt.label} instead"
                            )

                        try:
                            finding = self._evaluate_harness_result(
                                source_label,
                                system_prompt,
                                category,
                                requesting_user_id,
                                attempt.harness_result,
                                attack_pattern_id=attempt.label,
                                strategy_name=strategy_name,
                            )
                        except SpendCapExceededError:
                            raise
                        except Exception as exc:
                            attack_count += 1
                            record_failure(
                                source_label,
                                category,
                                attempt.label,
                                strategy_name,
                                "evaluation",
                                exc,
                            )
                            self.progress_callback(
                                f"[{source_label}] {category}"
                                f"{label_suffix}: ERROR "
                                f"(evaluation failed: "
                                f"{type(exc).__name__}: {exc}) - "
                                "recorded as a failed attack"
                            )
                            continue

                        findings.append(finding)
                        attack_count += 1

                        status = (
                            "VULNERABLE"
                            if finding.evaluation.vulnerable
                            else "held"
                        )
                        self.progress_callback(
                            f"[{source_label}] {category}"
                            f"{label_suffix}: {status} "
                            f"(severity={finding.severity.level})"
                        )

        return self._finalize(findings, len(prompts), failures)

    def _try_static_fallback(
        self,
        strategy_name: str,
        system_prompt: str,
        category: str,
        requesting_user_id: str,
        turns: int,
    ):
        """Replay a fixed real-world attack after a failed attempt.

        Returns None when no fallback applies (disabled, offline, the
        failed strategy was already static, or the category has no fixed
        attacks). If the target itself is down, the fallback fails too
        and the caller records the attack as failed.
        """

        if (
            self.static_fallback is None
            or self.offline
            or strategy_name in STATIC_STRATEGY_NAMES
        ):
            return None

        picked = self.static_fallback.next_rows(category, turns)
        if picked is None:
            return None
        label, rows = picked
        return run_static_attack(
            self.bot_factory,
            rows,
            system_prompt,
            category,
            requesting_user_id,
            turns,
            label=label,
        )

    def _evaluate_harness_result(
        self,
        source_label: str,
        system_prompt: str,
        category: str,
        requesting_user_id: str,
        harness_result: HarnessResult,
        attack_pattern_id: str | None = None,
        strategy_name: str | None = None,
    ) -> Finding:
        last_turn = harness_result.turns[-1]

        context = EvaluationContext(
            system_prompt=system_prompt,
            guardrail_category=category,
            requesting_user_id=requesting_user_id,
            customer_records=CUSTOMER_RECORDS,
        )

        evaluation = self.pipeline.evaluate(
            attack=last_turn.attack,
            response=last_turn.response,
            transcript=harness_result.transcript,
            evidence_events=harness_result.evidence,
            context=context,
        )

        severity = self.severity_scorer.score(evaluation, category)
        root_cause = self.rca_analyzer.analyze(
            evaluation,
            category,
            last_turn.attack,
            harness_result.evidence,
        )
        remediation = self.remediation_mapper.map(
            category, root_cause
        )

        return Finding(
            prompt_source=source_label,
            guardrail_category=category,
            attack=last_turn.attack,
            response=last_turn.response,
            transcript=harness_result.transcript,
            evaluation=evaluation,
            severity=severity,
            root_cause=root_cause,
            remediation=remediation,
            attack_pattern_id=attack_pattern_id,
            strategy_name=strategy_name,
        )

    def _check_budget(self) -> None:
        if (
            self.budget_usd is not None
            and self.token_tracker.total_cost() > self.budget_usd
        ):
            raise BudgetExceededError(
                "Scan halted: token cost "
                f"${self.token_tracker.total_cost():.4f} exceeded "
                f"budget ${self.budget_usd:.4f}."
            )

    def _finalize(
        self,
        findings: list[Finding],
        prompts_scanned: int,
        failures: list[dict[str, Any]] | None = None,
    ) -> ScanResult:
        return ScanResult(
            findings=findings,
            model_independence=self.model_independence.to_dict(),
            token_summary=self.token_tracker.summary(),
            prompts_scanned=prompts_scanned,
            failed_attempts=list(failures or []),
            offline=self.offline,
        )
