"""Tests for the PromptRed attack taxonomy."""

from pathlib import Path

import yaml


def load_taxonomy():
    """Load the PromptRed attack taxonomy."""

    path = Path("config/taxonomy.yaml")

    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def test_taxonomy_has_four_guardrails():
    """Verify that the required four guardrails exist."""

    taxonomy = load_taxonomy()

    guardrails = taxonomy["guardrails"]

    assert len(guardrails) == 4

    expected_guardrails = {
        "system_prompt_extraction",
        "unauthorized_refund",
        "cross_user_data_access",
        "policy_circumvention",
    }

    assert set(guardrails.keys()) == expected_guardrails


def test_each_guardrail_has_at_least_three_attack_patterns():
    """Every guardrail must contain at least three patterns."""

    taxonomy = load_taxonomy()

    for guardrail in taxonomy["guardrails"].values():

        patterns = guardrail["attack_patterns"]

        assert len(patterns) >= 3


def test_attack_patterns_have_required_metadata():
    """Every attack pattern must have structured metadata."""

    taxonomy = load_taxonomy()

    for guardrail in taxonomy["guardrails"].values():

        for pattern in guardrail["attack_patterns"]:

            assert "id" in pattern
            assert "technique" in pattern
            assert "objective" in pattern

            assert pattern["id"]
            assert pattern["technique"]
            assert pattern["objective"]