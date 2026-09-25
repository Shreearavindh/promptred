"""Tests for model role resolution and independence checking."""

import pytest

from core.llm.roles import (
    ModelRole,
    check_model_independence,
    reset_judge_rotation,
    resolve_model,
)


def test_resolve_model_prefers_role_specific_env_var(monkeypatch):

    monkeypatch.setenv("JUDGE_MODEL", "role-specific-model:free")
    monkeypatch.setenv("OPENROUTER_MODEL", "shared-fallback:free")

    assert (
        resolve_model(ModelRole.JUDGE) == "role-specific-model:free"
    )


def test_resolve_model_falls_back_to_shared_model(monkeypatch):

    monkeypatch.delenv("ATTACKER_MODEL", raising=False)
    monkeypatch.setenv("OPENROUTER_MODEL", "shared-fallback:free")

    assert (
        resolve_model(ModelRole.ATTACKER) == "shared-fallback:free"
    )


def test_resolve_model_raises_when_nothing_configured(monkeypatch):

    monkeypatch.delenv("TARGET_MODEL", raising=False)
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)

    with pytest.raises(ValueError):
        resolve_model(ModelRole.TARGET)


def test_judge_pool_overrides_judge_model_when_configured(monkeypatch):

    monkeypatch.setenv("JUDGE_MODEL", "role-specific-model:free")
    monkeypatch.setenv("JUDGE_MODEL_POOL", "pool-model-a:free")
    reset_judge_rotation()

    assert resolve_model(ModelRole.JUDGE) == "pool-model-a:free"


def test_judge_pool_choice_is_stable_within_a_process(monkeypatch):

    monkeypatch.setenv(
        "JUDGE_MODEL_POOL",
        "pool-a:free,pool-b:free,pool-c:free,pool-d:free",
    )
    reset_judge_rotation()

    first = resolve_model(ModelRole.JUDGE)
    second = resolve_model(ModelRole.JUDGE)
    third = resolve_model(ModelRole.JUDGE)

    assert first == second == third
    assert first in {"pool-a:free", "pool-b:free", "pool-c:free", "pool-d:free"}


def test_judge_pool_can_reroll_after_reset(monkeypatch):

    monkeypatch.setenv(
        "JUDGE_MODEL_POOL",
        ",".join(f"pool-{i}:free" for i in range(20)),
    )
    reset_judge_rotation()
    first = resolve_model(ModelRole.JUDGE)

    # Rerolling 20 times against a 20-option pool should hit a
    # different choice at least once - this isn't testing randomness
    # itself, just that reset_judge_rotation() actually clears the
    # cache rather than being a no-op.
    saw_a_different_choice = False
    for _ in range(20):
        reset_judge_rotation()
        if resolve_model(ModelRole.JUDGE) != first:
            saw_a_different_choice = True
            break

    assert saw_a_different_choice


def test_no_pool_configured_falls_back_to_normal_resolution(
    monkeypatch,
):

    monkeypatch.delenv("JUDGE_MODEL_POOL", raising=False)
    monkeypatch.setenv("JUDGE_MODEL", "role-specific-model:free")
    reset_judge_rotation()

    assert (
        resolve_model(ModelRole.JUDGE) == "role-specific-model:free"
    )


def test_independence_check_passes_for_distinct_models():

    result = check_model_independence(
        attacker_model="attacker:free",
        target_model="target:free",
        judge_model="judge:free",
    )

    assert result.judge_independent is True
    assert result.warning is None


def test_independence_check_flags_judge_matching_attacker():

    result = check_model_independence(
        attacker_model="same-model:free",
        target_model="target:free",
        judge_model="same-model:free",
    )

    assert result.judge_independent is False
    assert result.warning is not None
    assert "attacker" in result.warning


def test_independence_check_flags_judge_matching_target():

    result = check_model_independence(
        attacker_model="attacker:free",
        target_model="same-model:free",
        judge_model="same-model:free",
    )

    assert result.judge_independent is False
    assert "target" in result.warning
