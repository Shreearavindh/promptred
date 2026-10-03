"""Tests for the PromptRed CLI argument parsing (no suites executed)."""

from pathlib import Path

import pytest

from core.orchestrator import ScanResult
from promptred import _print_cost_summary, build_parser, run_scan_command


def test_eval_command_defaults_to_all_suites():

    parser = build_parser()
    args = parser.parse_args(["eval"])

    assert args.command == "eval"
    assert args.suite is None
    assert args.repeats == 3


def test_eval_command_accepts_single_suite():

    parser = build_parser()
    args = parser.parse_args(["eval", "--suite", "judge"])

    assert args.suite == "judge"


def test_eval_command_rejects_unknown_suite():

    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["eval", "--suite", "not_a_suite"])


def test_eval_command_accepts_custom_repeats():

    parser = build_parser()
    args = parser.parse_args(["eval", "--repeats", "5"])

    assert args.repeats == 5


def test_validate_command_parses():

    parser = build_parser()
    args = parser.parse_args(["validate"])

    assert args.command == "validate"
    assert args.repeats == 3


def test_no_command_exits_nonzero():

    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_discover_command_requires_path():

    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["discover"])


def test_discover_command_parses_path():

    parser = build_parser()
    args = parser.parse_args(["discover", "--path", "some/dir"])

    assert args.command == "discover"
    assert args.path == "some/dir"


def test_scan_command_defaults():

    parser = build_parser()
    args = parser.parse_args(["scan", "--prompt", "You are..."])

    assert args.command == "scan"
    assert args.prompt == "You are..."
    assert args.prompt_file is None
    assert args.path is None
    assert args.turns == 1
    assert args.output == "reports"
    assert args.email is False
    assert args.email_to is None
    assert args.strategies is None
    assert args.max_attacks == 60


def test_scan_command_accepts_strategies():

    parser = build_parser()
    args = parser.parse_args(
        [
            "scan",
            "--prompt",
            "x",
            "--strategies",
            "single,taxonomy",
        ]
    )

    assert args.strategies == "single,taxonomy"


def test_benchmark_command_accepts_strategies():

    parser = build_parser()
    args = parser.parse_args(
        ["benchmark", "--strategies", "single"]
    )

    assert args.strategies == "single"


def test_scan_command_rejects_invalid_turns():

    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            ["scan", "--prompt", "x", "--turns", "2"]
        )


def test_scan_command_accepts_email_to():

    parser = build_parser()
    args = parser.parse_args(
        [
            "scan",
            "--path",
            "some/dir",
            "--email-to",
            "a@example.com",
        ]
    )

    assert args.email_to == "a@example.com"


def test_benchmark_command_parses():

    parser = build_parser()
    args = parser.parse_args(["benchmark"])

    assert args.command == "benchmark"
    assert args.output == "reports"
    assert args.turns == 1


# ---------------------------------------------------------
# Functional tests (fake orchestrator, no real network calls)
# ---------------------------------------------------------


def _empty_scan_result(prompts_scanned: int = 1) -> ScanResult:
    return ScanResult(
        findings=[],
        model_independence={"judge_independent": True},
        token_summary={},
        prompts_scanned=prompts_scanned,
    )


class FakeOrchestrator:
    def __init__(
        self,
        budget_usd=None,
        progress_callback=None,
        strategy_names=None,
        offline=False,
    ):
        self.progress_callback = progress_callback or (
            lambda message: None
        )

    def scan_prompt(
        self,
        system_prompt,
        guardrails=None,
        turns=1,
        max_attacks=None,
        source_label="manual",
    ):
        self.progress_callback("scanned prompt")
        return _empty_scan_result()

    def scan_directory(
        self, path, guardrails=None, turns=1, max_attacks=None
    ):
        return _empty_scan_result()


def test_scan_command_rejects_conflicting_sources(capsys):

    parser = build_parser()
    args = parser.parse_args(
        ["scan", "--prompt", "x", "--path", "y"]
    )

    exit_code = run_scan_command(args)

    assert exit_code == 1
    assert "Specify exactly one" in capsys.readouterr().out


def test_scan_command_rejects_no_source(capsys):

    parser = build_parser()
    args = parser.parse_args(["scan"])

    exit_code = run_scan_command(args)

    assert exit_code == 1
    assert "Specify exactly one" in capsys.readouterr().out


def test_scan_command_saves_reports_and_skips_email_when_no_findings(
    tmp_path: Path,
    monkeypatch,
    capsys,
):

    import core.orchestrator as orchestrator_module

    monkeypatch.setattr(
        orchestrator_module, "ScanOrchestrator", FakeOrchestrator
    )

    parser = build_parser()
    args = parser.parse_args(
        [
            "scan",
            "--prompt",
            "You are a support assistant.",
            "--output",
            str(tmp_path),
            "--email",
        ]
    )

    exit_code = run_scan_command(args)

    assert exit_code == 0
    assert len(list(tmp_path.glob("*.json"))) == 1
    assert len(list(tmp_path.glob("*.html"))) == 1

    output = capsys.readouterr().out
    assert "skipping email" in output


def test_scan_command_reports_spend_cap_cleanly(
    tmp_path: Path,
    monkeypatch,
    capsys,
):

    import core.orchestrator as orchestrator_module
    from core.llm.token_tracker import SpendCapExceededError

    class SpendCappedOrchestrator:
        def __init__(
            self,
            budget_usd=None,
            progress_callback=None,
            strategy_names=None,
            offline=False,
        ):
            pass

        def scan_prompt(self, *args, **kwargs):
            raise SpendCapExceededError(
                "Spend cap of $0.0100 reached."
            )

    monkeypatch.setattr(
        orchestrator_module,
        "ScanOrchestrator",
        SpendCappedOrchestrator,
    )

    parser = build_parser()
    args = parser.parse_args(
        [
            "scan",
            "--prompt",
            "You are a support assistant.",
            "--output",
            str(tmp_path),
        ]
    )

    exit_code = run_scan_command(args)

    assert exit_code == 1
    assert "Spend cap" in capsys.readouterr().out
    # No report should be written for a run that never completed.
    assert list(tmp_path.glob("*.json")) == []


def test_resolve_strategies_splits_comma_separated_values():

    from promptred import _resolve_strategies

    assert _resolve_strategies("single,taxonomy") == [
        "single",
        "taxonomy",
    ]
    assert _resolve_strategies(None) is None
    assert _resolve_strategies("") is None


def test_resolve_max_attacks_passes_through_a_positive_cap():

    from promptred import _resolve_max_attacks

    assert _resolve_max_attacks(60) == 60


def test_resolve_max_attacks_treats_zero_as_the_ceiling():
    """0 used to mean unbounded; a guardrail now caps every run so
    PromptRed cannot be used to mass-produce attacks."""

    from promptred import MAX_ATTACKS_PER_RUN, _resolve_max_attacks

    assert _resolve_max_attacks(0) == MAX_ATTACKS_PER_RUN


def test_resolve_max_attacks_treats_negative_and_none_as_the_ceiling():

    from promptred import MAX_ATTACKS_PER_RUN, _resolve_max_attacks

    assert _resolve_max_attacks(-1) == MAX_ATTACKS_PER_RUN
    assert _resolve_max_attacks(None) == MAX_ATTACKS_PER_RUN


def test_resolve_max_attacks_clamps_requests_above_the_ceiling(capsys):

    from promptred import MAX_ATTACKS_PER_RUN, _resolve_max_attacks

    assert _resolve_max_attacks(MAX_ATTACKS_PER_RUN + 500) == MAX_ATTACKS_PER_RUN
    assert "capped" in capsys.readouterr().out


def test_benchmark_command_defaults_max_attacks_to_60():

    parser = build_parser()
    args = parser.parse_args(["benchmark"])

    assert args.max_attacks == 60


class FakeScanResultForCost:
    def __init__(self, token_summary):
        self.token_summary = token_summary


def test_print_cost_summary_shows_tokens_in_and_out(capsys):

    scan_result = FakeScanResultForCost(
        {
            "total_calls": 3,
            "total_input_tokens": 100,
            "total_output_tokens": 200,
            "total_tokens": 300,
            "total_cost_usd": 0.0,
            "by_role": {
                "attacker": {
                    "model": "minimax/minimax-m3:free",
                    "calls": 1,
                    "input_tokens": 30,
                    "output_tokens": 50,
                    "cost_usd": 0.0,
                },
                "judge": {
                    "model": "cohere/north-mini-code:free",
                    "calls": 2,
                    "input_tokens": 70,
                    "output_tokens": 150,
                    "cost_usd": 0.0,
                },
            },
        }
    )

    _print_cost_summary(scan_result)

    output = capsys.readouterr().out
    assert "minimax/minimax-m3:free" in output
    assert "cohere/north-mini-code:free" in output
    # tokens in/out are visible per role, not just an aggregate.
    assert "30" in output
    assert "50" in output
    assert "70" in output
    assert "150" in output
    assert "TOTAL" in output
    assert "300" in output
    assert "3 API call(s)" in output


def test_print_cost_summary_handles_no_calls(capsys):

    scan_result = FakeScanResultForCost({})

    _print_cost_summary(scan_result)

    output = capsys.readouterr().out
    assert "no LLM calls were recorded" in output
