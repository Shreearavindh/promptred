"""Model role configuration and anti-collusion safeguards for PromptRed.

If the same LLM plays attacker, target, and judge, three problems
appear: (1) attack effectiveness is measured against a model attacking
a copy of itself, which does not generalize to other targets; (2) a
judge grading its own (or a same-family) model's output is not an
independent evaluator - a conflict of interest that weakens judge
validation; (3) shared training artifacts between attacker and target
can make attacks look more or less successful than they would against
a genuinely different system.

This module resolves a distinct model per role from `.env` and exposes
a check that flags when independence does not hold, so results are
never silently reported as validated when they aren't.
"""

import os
import random
import threading
from dataclasses import dataclass
from enum import Enum

from dotenv import load_dotenv

load_dotenv()


class ModelRole(Enum):
    """The three independent LLM roles in a PromptRed scan."""

    ATTACKER = "attacker"
    TARGET = "target"
    JUDGE = "judge"


_ROLE_ENV_VARS: dict[ModelRole, str] = {
    ModelRole.ATTACKER: "ATTACKER_MODEL",
    ModelRole.TARGET: "TARGET_MODEL",
    ModelRole.JUDGE: "JUDGE_MODEL",
}

# Judge rotation: an attacker who learns "the" judge model from one
# scan's report (model_independence.judge_model is reported openly,
# by design - hiding it would just be security through obscurity)
# should not be able to rely on that same model still being the judge
# on the next scan. If JUDGE_MODEL_POOL (comma-separated model ids)
# is set, one is chosen at random per PROCESS - not per call - so a
# single scan's judge stays internally consistent while the choice
# varies across separate invocations. Purely additive: with no pool
# configured, resolution is unchanged from before.
_JUDGE_POOL_ENV_VAR = "JUDGE_MODEL_POOL"

_judge_rotation_lock = threading.Lock()
_rotated_judge_model: str | None = None


def _resolve_judge_pool() -> list[str]:
    raw = os.getenv(_JUDGE_POOL_ENV_VAR, "")
    return [model.strip() for model in raw.split(",") if model.strip()]


def _resolve_rotated_judge_model() -> str | None:
    """Return this process's rotated judge choice, or None if no pool
    is configured (in which case normal resolution applies)."""

    global _rotated_judge_model

    pool = _resolve_judge_pool()

    if not pool:
        return None

    with _judge_rotation_lock:
        if (
            _rotated_judge_model is None
            or _rotated_judge_model not in pool
        ):
            _rotated_judge_model = random.choice(pool)

        return _rotated_judge_model


def reset_judge_rotation() -> None:
    """Clear the cached rotated judge choice. Mainly for tests."""

    global _rotated_judge_model

    with _judge_rotation_lock:
        _rotated_judge_model = None


def resolve_model(role: ModelRole) -> str:
    """Resolve the configured model id for a role.

    For the judge role, JUDGE_MODEL_POOL takes priority over
    JUDGE_MODEL when set (see _resolve_rotated_judge_model). Falls
    back to the shared OPENROUTER_MODEL env var if nothing
    role-specific is set, so single-model .env files from earlier
    phases of this project keep working.
    """

    if role is ModelRole.JUDGE:
        rotated = _resolve_rotated_judge_model()

        if rotated is not None:
            return rotated

    env_var = _ROLE_ENV_VARS[role]
    model = os.getenv(env_var)

    if model:
        return model

    shared = os.getenv("OPENROUTER_MODEL")

    if shared:
        return shared

    raise ValueError(
        f"No model configured for role '{role.value}'. "
        f"Set {env_var} or OPENROUTER_MODEL in your .env file."
    )


@dataclass(frozen=True)
class IndependenceCheck:
    """Result of comparing the attacker/target/judge model triple."""

    attacker_model: str
    target_model: str
    judge_model: str
    judge_independent: bool
    warning: str | None

    def to_dict(self) -> dict:
        return {
            "attacker_model": self.attacker_model,
            "target_model": self.target_model,
            "judge_model": self.judge_model,
            "judge_independent": self.judge_independent,
            "warning": self.warning,
        }


def check_model_independence(
    attacker_model: str | None = None,
    target_model: str | None = None,
    judge_model: str | None = None,
) -> IndependenceCheck:
    """Compare the resolved attacker/target/judge models for collusion.

    Same-model runs are still allowed (useful for quick local
    iteration) but must never be silently reported as validated.
    """

    attacker_model = attacker_model or resolve_model(
        ModelRole.ATTACKER
    )
    target_model = target_model or resolve_model(ModelRole.TARGET)
    judge_model = judge_model or resolve_model(ModelRole.JUDGE)

    colluding_with: str | None = None

    if judge_model == attacker_model:
        colluding_with = "attacker"
    elif judge_model == target_model:
        colluding_with = "target"

    warning: str | None = None

    if colluding_with is not None:
        warning = (
            "Judge independence warning: judge shares a model with "
            f"the {colluding_with} ({judge_model}) - treat findings "
            "as directional, not validated."
        )

    return IndependenceCheck(
        attacker_model=attacker_model,
        target_model=target_model,
        judge_model=judge_model,
        judge_independent=colluding_with is None,
        warning=warning,
    )
