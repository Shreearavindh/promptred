"""Shared eval harness for PromptRed's evals framework.

Distinct from `tests/`: evals call real models and measure the
statistical, behavioral quality of LLM-driven components (precision,
recall, F1, pass rate, agreement) over a dataset, rather than
asserting exact deterministic output. Because LLM output is
non-deterministic, each case is sampled `repeats_per_case` times and
aggregated so a single unlucky (or lucky) generation doesn't decide
the result. Every run is written to evals/results/<suite>/<timestamp>.json
rather than overwritten, so metric drift across model, prompt, or
strategy changes is visible over time.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

DEFAULT_RESULTS_DIR = Path("evals/results")
DEFAULT_REPEATS_PER_CASE = 3


@dataclass
class EvalCase:
    """One case in an eval dataset."""

    case_id: str
    inputs: dict[str, Any]
    expected: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvalResult:
    """Outcome of running one case through a suite once."""

    case_id: str
    passed: bool
    score: float
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class CaseSummary:
    """A case's results aggregated across repeated samples."""

    case_id: str
    results: list[EvalResult]

    @property
    def pass_rate(self) -> float:
        if not self.results:
            return 0.0
        return sum(
            1 for r in self.results if r.passed
        ) / len(self.results)

    @property
    def mean_score(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.score for r in self.results) / len(
            self.results
        )

    @property
    def score_variance(self) -> float:
        if len(self.results) < 2:
            return 0.0
        mean = self.mean_score
        return sum(
            (r.score - mean) ** 2 for r in self.results
        ) / len(self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "pass_rate": self.pass_rate,
            "mean_score": self.mean_score,
            "score_variance": self.score_variance,
            "results": [
                {
                    "passed": r.passed,
                    "score": r.score,
                    "details": r.details,
                }
                for r in self.results
            ],
        }


class EvalSuite(Protocol):
    """Interface every eval suite implements.

    A suite owns the system under test (e.g. an EvaluationPipeline for
    the judge eval, an AttackGenerator for the generator eval) and
    knows how to score its own cases - the harness only handles
    sampling, aggregation, and persistence.
    """

    name: str

    def load_cases(self) -> list[EvalCase]:
        ...

    def run_case(self, case: EvalCase) -> EvalResult:
        ...

    def compute_metrics(
        self,
        case_summaries: list[CaseSummary],
    ) -> dict[str, Any]:
        ...


@dataclass
class EvalReport:
    """Full result of one eval run, ready to persist and compare."""

    suite_name: str
    timestamp: str
    repeats_per_case: int
    case_summaries: list[CaseSummary]
    metrics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_name": self.suite_name,
            "timestamp": self.timestamp,
            "repeats_per_case": self.repeats_per_case,
            "metrics": self.metrics,
            "cases": [
                summary.to_dict()
                for summary in self.case_summaries
            ],
        }

    def save(
        self,
        results_dir: Path = DEFAULT_RESULTS_DIR,
    ) -> Path:
        """Persist this report under evals/results/<suite>/<ts>.json."""

        suite_dir = results_dir / self.suite_name
        suite_dir.mkdir(parents=True, exist_ok=True)

        safe_timestamp = self.timestamp.replace(":", "-")
        path = suite_dir / f"{safe_timestamp}.json"

        path.write_text(
            json.dumps(self.to_dict(), indent=2),
            encoding="utf-8",
        )

        return path

    @staticmethod
    def latest_previous(
        suite_name: str,
        results_dir: Path = DEFAULT_RESULTS_DIR,
    ) -> dict[str, Any] | None:
        """Load the most recent prior report for a suite, if any."""

        suite_dir = results_dir / suite_name

        if not suite_dir.exists():
            return None

        reports = sorted(suite_dir.glob("*.json"))

        if not reports:
            return None

        return json.loads(reports[-1].read_text(encoding="utf-8"))


class EvalRunner:
    """Executes an EvalSuite with repeated sampling and aggregation."""

    def __init__(
        self,
        repeats_per_case: int = DEFAULT_REPEATS_PER_CASE,
    ) -> None:
        self.repeats_per_case = repeats_per_case

    @staticmethod
    def _run_case_safely(
        suite: EvalSuite,
        case: EvalCase,
    ) -> EvalResult:
        """Run one sample, converting any exception into a failed result.

        Suites should treat `details.get("error")` as a signal to
        exclude the sample from their metric math (while still
        counting it toward an error/failure rate) rather than
        indexing into `details` unconditionally.
        """

        try:
            return suite.run_case(case)
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            return EvalResult(
                case_id=case.case_id,
                passed=False,
                score=0.0,
                details={
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )

    def run(self, suite: EvalSuite) -> EvalReport:
        """Run every case in a suite, sampled `repeats_per_case` times.

        Eval suites call real, often free-tier-shared models, which
        occasionally return transient errors (rate limits, empty
        completions, malformed JSON) that have nothing to do with the
        suite's own logic. A single such failure must not abort an
        entire multi-case report: each sample that raises is recorded
        as a failed EvalResult carrying the error, so the report still
        completes and the failure rate itself becomes visible data
        rather than a crash.
        """

        cases = suite.load_cases()
        summaries: list[CaseSummary] = []

        for case in cases:
            results = [
                self._run_case_safely(suite, case)
                for _ in range(self.repeats_per_case)
            ]

            summaries.append(
                CaseSummary(case_id=case.case_id, results=results)
            )

        metrics = suite.compute_metrics(summaries)

        return EvalReport(
            suite_name=suite.name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            repeats_per_case=self.repeats_per_case,
            case_summaries=summaries,
            metrics=metrics,
        )
