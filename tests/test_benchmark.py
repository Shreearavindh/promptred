"""Tests for the PromptRed benchmark dataset."""

from core.attacks.benchmark import BenchmarkLoader


def test_benchmark_contains_five_prompts():
    """The MVP benchmark must contain five prompts."""

    loader = BenchmarkLoader()

    prompts = loader.load()

    assert len(prompts) == 5


def test_benchmark_contains_ten_planted_vulnerabilities():
    """The benchmark must contain ten planted vulnerabilities."""

    loader = BenchmarkLoader()

    prompts = loader.load()

    total = sum(
        len(prompt["planted_vulnerabilities"])
        for prompt in prompts
    )

    assert total == 10


def test_each_prompt_has_two_planted_vulnerabilities():
    """Each benchmark prompt must contain two vulnerabilities."""

    loader = BenchmarkLoader()

    prompts = loader.load()

    for prompt in prompts:
        assert len(
            prompt["planted_vulnerabilities"]
        ) == 2


def test_benchmark_prompt_lookup():
    """A benchmark prompt should be retrievable by ID."""

    loader = BenchmarkLoader()

    prompt = loader.get_prompt("VP-001")

    assert prompt["id"] == "VP-001"