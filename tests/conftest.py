"""Shared pytest fixtures for PromptRed's test suite."""

import pytest

from core.llm.roles import reset_judge_rotation
from core.llm.token_tracker import reset_global_token_tracker


@pytest.fixture(autouse=True)
def _isolated_global_token_tracker():
    """Reset the process-wide TokenTracker before/after every test.

    core.llm.client.LLMClient now defaults to a global TokenTracker
    (see core.llm.token_tracker.get_global_token_tracker) so the
    $0.01 spend cap applies even to code that never wires a tracker
    through explicitly. Without this fixture, tests that construct a
    real LLMClient without an explicit tracker would share cumulative
    state across the whole test session.
    """

    reset_global_token_tracker()
    yield
    reset_global_token_tracker()


@pytest.fixture(autouse=True)
def _isolated_judge_rotation():
    """Reset the cached rotated judge choice before/after every test.

    core.llm.roles caches one rotated judge model per process (see
    reset_judge_rotation's docstring) - without this, a test that sets
    JUDGE_MODEL_POOL would leak its cached choice into later tests.
    """

    reset_judge_rotation()
    yield
    reset_judge_rotation()
