"""Tests for the shared eval harness (evals/harness.py).

These are ordinary deterministic unit tests of the harness plumbing
itself (sampling, aggregation, persistence) using a fake suite - they
do not call any real model. The eval *suites* built on top of this
harness are what call real models; see evals/suites/.
"""

import json
from pathlib import Path

from evals.harness import (
    CaseSummary,
    EvalCase,
    EvalReport,
    EvalResult,
    EvalRunner,
)


class FakeSuite:
    """Deterministic suite: alternates pass/fail per call."""

    name = "fake_suite"

    def __init__(self) -> None:
        self.call_count = 0

    def load_cases(self) -> list[EvalCase]:
        return [
            EvalCase(case_id="c1", inputs={}, expected={}),
            EvalCase(case_id="c2", inputs={}, expected={}),
        ]

    def run_case(self, case: EvalCase) -> EvalResult:
        self.call_count += 1
        passed = self.call_count % 2 == 0
        return EvalResult(
            case_id=case.case_id,
            passed=passed,
            score=1.0 if passed else 0.0,
        )

    def compute_metrics(
        self,
        case_summaries: list[CaseSummary],
    ) -> dict:
        overall_pass_rate = sum(
            s.pass_rate for s in case_summaries
        ) / len(case_summaries)
        return {"overall_pass_rate": overall_pass_rate}


def test_runner_samples_each_case_repeats_per_case_times():

    runner = EvalRunner(repeats_per_case=4)
    suite = FakeSuite()

    report = runner.run(suite)

    assert len(report.case_summaries) == 2
    assert all(
        len(summary.results) == 4
        for summary in report.case_summaries
    )
    assert suite.call_count == 8


def test_case_summary_pass_rate_and_mean_score():

    summary = CaseSummary(
        case_id="c1",
        results=[
            EvalResult(case_id="c1", passed=True, score=1.0),
            EvalResult(case_id="c1", passed=False, score=0.0),
        ],
    )

    assert summary.pass_rate == 0.5
    assert summary.mean_score == 0.5


def test_report_metrics_come_from_suite():

    runner = EvalRunner(repeats_per_case=2)
    suite = FakeSuite()

    report = runner.run(suite)

    assert "overall_pass_rate" in report.metrics


def test_report_save_writes_json_file(tmp_path: Path):

    runner = EvalRunner(repeats_per_case=1)
    suite = FakeSuite()

    report = runner.run(suite)
    saved_path = report.save(results_dir=tmp_path)

    assert saved_path.exists()

    loaded = json.loads(saved_path.read_text(encoding="utf-8"))

    assert loaded["suite_name"] == "fake_suite"
    assert len(loaded["cases"]) == 2


def test_latest_previous_returns_none_when_no_history(
    tmp_path: Path,
):

    result = EvalReport.latest_previous(
        "nonexistent_suite",
        results_dir=tmp_path,
    )

    assert result is None


def test_latest_previous_returns_most_recent_report(
    tmp_path: Path,
):

    runner = EvalRunner(repeats_per_case=1)
    suite = FakeSuite()

    report1 = runner.run(suite)
    report1.save(results_dir=tmp_path)

    report2 = runner.run(suite)
    report2.save(results_dir=tmp_path)

    previous = EvalReport.latest_previous(
        "fake_suite",
        results_dir=tmp_path,
    )

    assert previous is not None
    assert previous["suite_name"] == "fake_suite"


class FlakySuite:
    """A case that raises on its first call, succeeds after."""

    name = "flaky_suite"

    def __init__(self) -> None:
        self.call_count = 0

    def load_cases(self) -> list[EvalCase]:
        return [EvalCase(case_id="flaky", inputs={}, expected={})]

    def run_case(self, case: EvalCase) -> EvalResult:
        self.call_count += 1
        if self.call_count == 1:
            raise RuntimeError("simulated transient 429")
        return EvalResult(case_id=case.case_id, passed=True, score=1.0)

    def compute_metrics(
        self,
        case_summaries: list[CaseSummary],
    ) -> dict:
        return {}


def test_a_raising_case_does_not_abort_the_whole_run():

    runner = EvalRunner(repeats_per_case=3)
    suite = FlakySuite()

    report = runner.run(suite)

    assert len(report.case_summaries) == 1
    results = report.case_summaries[0].results
    assert len(results) == 3
    assert results[0].details.get("error")
    assert results[1].passed is True
    assert results[2].passed is True
