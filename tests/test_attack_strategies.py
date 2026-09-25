"""Tests for the attack strategy protocol, registry, and implementations."""

import pytest

from core.attacks.strategies.base import StrategyRegistry
from core.attacks.strategies.seed_augmented import (
    SeedAugmentedStrategy,
    SeedAwareAttackSource,
    load_seeds,
    seeds_for_category,
)
from core.attacks.strategies.single import SingleAttemptStrategy
from core.attacks.strategies.taxonomy import (
    PatternAwareAttackSource,
    TaxonomyStrategy,
    patterns_for_category,
)
from core.llm.token_tracker import SpendCapExceededError


class FakeGenerator:
    """Records every generate() call, including technique/objective."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def generate(
        self,
        system_prompt,
        guardrail_category,
        conversation_history=None,
        technique=None,
        objective=None,
        seed_example=None,
    ):
        self.calls.append(
            {
                "guardrail_category": guardrail_category,
                "technique": technique,
                "objective": objective,
                "seed_example": seed_example,
            }
        )
        return {
            "attack": f"attack {len(self.calls)}",
            "technique": technique or "generic",
            "objective": objective or "generic",
        }


class FakeBot:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def chat(self, message: str) -> str:
        self.messages.append(message)
        return f"response to: {message}"


class BotFactorySpy:
    """Fake bot_factory that counts calls and returns fresh bots."""

    def __init__(self) -> None:
        self.calls = 0
        self.bots: list[FakeBot] = []

    def __call__(self, system_prompt, user_id, evidence_collector):
        self.calls += 1
        bot = FakeBot()
        self.bots.append(bot)
        return bot


# ---------------------------------------------------------
# StrategyRegistry
# ---------------------------------------------------------


def test_registry_registers_and_resolves_by_name():

    registry = StrategyRegistry()
    registry.register("single", SingleAttemptStrategy)

    strategy = registry.get("single")

    assert strategy.name == "single"


def test_registry_raises_for_unknown_strategy():

    registry = StrategyRegistry()
    registry.register("single", SingleAttemptStrategy)

    with pytest.raises(ValueError, match="single"):
        registry.get("not_a_strategy")


def test_registry_names_lists_registered_strategies():

    registry = StrategyRegistry()
    registry.register("single", SingleAttemptStrategy)
    registry.register("taxonomy", TaxonomyStrategy)

    assert registry.names() == ["single", "taxonomy"]


# ---------------------------------------------------------
# SingleAttemptStrategy
# ---------------------------------------------------------


def test_single_attempt_strategy_makes_exactly_one_attempt():

    generator = FakeGenerator()
    bot_factory = BotFactorySpy()
    strategy = SingleAttemptStrategy()

    results = strategy.execute(
        bot_factory=bot_factory,
        generator=generator,
        system_prompt="You are a support assistant.",
        guardrail_category="system_prompt_extraction",
        requesting_user_id="A001",
        turns=1,
    )

    assert len(results) == 1
    attempt = results[0]
    assert attempt.succeeded is True
    assert attempt.label is None
    assert len(attempt.harness_result.turns) == 1
    assert bot_factory.calls == 1
    # Single-shot strategy does not pin a technique.
    assert generator.calls[0]["technique"] is None


# ---------------------------------------------------------
# Taxonomy loading
# ---------------------------------------------------------


def test_patterns_for_category_returns_documented_patterns():

    patterns = patterns_for_category("system_prompt_extraction")

    assert len(patterns) == 3
    ids = {p["id"] for p in patterns}
    assert ids == {"SPE-01", "SPE-02", "SPE-03"}
    assert all(p["technique"] for p in patterns)
    assert all(p["objective"] for p in patterns)


def test_patterns_for_category_raises_for_unknown_category():

    with pytest.raises(ValueError, match="unknown_guardrail"):
        patterns_for_category("unknown_guardrail")


def test_all_four_guardrail_categories_have_patterns():

    for category in (
        "system_prompt_extraction",
        "unauthorized_refund",
        "cross_user_data_access",
        "policy_circumvention",
    ):
        patterns = patterns_for_category(category)
        assert len(patterns) >= 3


# ---------------------------------------------------------
# PatternAwareAttackSource
# ---------------------------------------------------------


def test_pattern_aware_source_forwards_technique_and_objective():

    generator = FakeGenerator()
    source = PatternAwareAttackSource(
        generator=generator,
        technique="Direct Instruction Override",
        objective="Convince the bot to ignore its rule.",
    )

    source.generate(
        system_prompt="x",
        guardrail_category="system_prompt_extraction",
    )

    assert generator.calls[0]["technique"] == (
        "Direct Instruction Override"
    )
    assert generator.calls[0]["objective"] == (
        "Convince the bot to ignore its rule."
    )


def test_pattern_aware_source_pins_the_same_pattern_across_turns():

    generator = FakeGenerator()
    source = PatternAwareAttackSource(
        generator=generator,
        technique="Roleplay / Authority",
        objective="Use a fictional authority.",
    )

    for _ in range(3):
        source.generate(
            system_prompt="x",
            guardrail_category="system_prompt_extraction",
        )

    assert all(
        call["technique"] == "Roleplay / Authority"
        for call in generator.calls
    )


# ---------------------------------------------------------
# TaxonomyStrategy
# ---------------------------------------------------------


def test_taxonomy_strategy_runs_one_attack_per_documented_pattern():

    generator = FakeGenerator()
    bot_factory = BotFactorySpy()
    strategy = TaxonomyStrategy()

    results = strategy.execute(
        bot_factory=bot_factory,
        generator=generator,
        system_prompt="You are a support assistant.",
        guardrail_category="system_prompt_extraction",
        requesting_user_id="A001",
        turns=1,
    )

    assert len(results) == 3
    assert all(attempt.succeeded for attempt in results)
    labels = {attempt.label for attempt in results}
    assert labels == {"SPE-01", "SPE-02", "SPE-03"}


def test_taxonomy_strategy_gives_each_pattern_a_fresh_bot():

    generator = FakeGenerator()
    bot_factory = BotFactorySpy()
    strategy = TaxonomyStrategy()

    strategy.execute(
        bot_factory=bot_factory,
        generator=generator,
        system_prompt="You are a support assistant.",
        guardrail_category="system_prompt_extraction",
        requesting_user_id="A001",
        turns=1,
    )

    assert bot_factory.calls == 3
    # Each bot only ever saw one message - no cross-pattern leakage.
    assert all(len(bot.messages) == 1 for bot in bot_factory.bots)


def test_taxonomy_strategy_pins_distinct_techniques_per_pattern():

    generator = FakeGenerator()
    bot_factory = BotFactorySpy()
    strategy = TaxonomyStrategy()

    strategy.execute(
        bot_factory=bot_factory,
        generator=generator,
        system_prompt="You are a support assistant.",
        guardrail_category="system_prompt_extraction",
        requesting_user_id="A001",
        turns=1,
    )

    techniques_used = {
        call["technique"] for call in generator.calls
    }
    assert len(techniques_used) == 3


def test_a_transient_failure_is_recovered_by_the_fallback_seed():
    """Every guardrail category has at least one real-incident
    fallback seed (data/seeds/public_injection_seeds.json), so a
    ONE-OFF attacker failure on a pattern should be recovered by a
    single retry seeded with that real example, rather than being
    recorded as a failed attempt."""

    class FailsOnceGenerator:
        def __init__(self) -> None:
            self.calls: list[dict] = []

        def generate(
            self,
            system_prompt,
            guardrail_category,
            conversation_history=None,
            technique=None,
            objective=None,
            seed_example=None,
        ):
            self.calls.append({"seed_example": seed_example})
            if len(self.calls) == 2:
                raise RuntimeError("simulated transient failure")
            return {
                "attack": f"attack {len(self.calls)}",
                "technique": technique or "generic",
                "objective": objective or "generic",
            }

    bot_factory = BotFactorySpy()
    strategy = TaxonomyStrategy()
    generator = FailsOnceGenerator()

    results = strategy.execute(
        bot_factory=bot_factory,
        generator=generator,
        system_prompt="You are a support assistant.",
        # Not in PROACTIVE_SEED_CATEGORIES, so the primary attempt
        # stays unseeded and this test still exercises the
        # exception-only fallback path it's meant to test.
        guardrail_category="cross_user_data_access",
        requesting_user_id="A001",
        turns=1,
    )

    assert len(results) == 3
    # The transient failure on pattern 2 must have been recovered by
    # the fallback retry, not recorded as a failed attempt.
    assert all(a.succeeded for a in results)
    # 3 patterns + 1 extra retry call for the one that failed once.
    assert len(generator.calls) == 4
    # calls[1] is pattern 2's PRIMARY attempt (unseeded - it's the one
    # that raises). calls[2] is its fallback RETRY, which must carry
    # the real-incident seed.
    assert generator.calls[1]["seed_example"] is None
    assert generator.calls[2]["seed_example"] is not None


def test_proactive_seed_categories_get_seeded_on_the_primary_call():
    """system_prompt_extraction and unauthorized_refund get the real-
    incident seed woven into every PRIMARY attempt, not just the
    exception fallback - a live 80-case run found these two categories
    produced 0 real vulnerabilities out of 20 attempts each while the
    non-seeded categories found several, because the attacker's
    primary calls always succeeded (never hit the fallback path) and
    taxonomy.yaml's one-line labels gave it no tactical detail."""

    bot_factory = BotFactorySpy()
    strategy = TaxonomyStrategy()

    for category in TaxonomyStrategy.PROACTIVE_SEED_CATEGORIES:
        generator = FakeGenerator()

        results = strategy.execute(
            bot_factory=bot_factory,
            generator=generator,
            system_prompt="You are a support assistant.",
            guardrail_category=category,
            requesting_user_id="A001",
            turns=1,
        )

        assert len(results) == 3
        assert all(a.succeeded for a in results)
        assert len(generator.calls) == 3
        assert all(
            call["seed_example"] is not None
            for call in generator.calls
        )


def test_non_proactive_categories_are_not_seeded_on_the_primary_call():
    """cross_user_data_access and policy_circumvention already find
    real vulnerabilities unseeded, so they stay on the original
    unseeded primary attempt - guards against silently broadening
    PROACTIVE_SEED_CATEGORIES later."""

    bot_factory = BotFactorySpy()
    strategy = TaxonomyStrategy()
    non_proactive = {
        "cross_user_data_access",
        "policy_circumvention",
    } - TaxonomyStrategy.PROACTIVE_SEED_CATEGORIES

    for category in non_proactive:
        generator = FakeGenerator()

        results = strategy.execute(
            bot_factory=bot_factory,
            generator=generator,
            system_prompt="You are a support assistant.",
            guardrail_category=category,
            requesting_user_id="A001",
            turns=1,
        )

        assert len(results) == 3
        assert all(
            call["seed_example"] is None
            for call in generator.calls
        )


def test_a_failing_pattern_does_not_block_the_remaining_patterns():

    class FlakyGenerator:
        def __init__(self) -> None:
            self.calls = 0

        def generate(
            self,
            system_prompt,
            guardrail_category,
            conversation_history=None,
            technique=None,
            objective=None,
            seed_example=None,
        ):
            self.calls += 1
            # Fail both the primary attempt (call 2) AND its fallback
            # retry (call 3), so pattern 2 is genuinely unrecoverable
            # here - proving a failure that survives the fallback is
            # still recorded, not silently dropped or retried forever.
            if self.calls in (2, 3):
                raise RuntimeError("simulated transient failure")
            return {
                "attack": f"attack {self.calls}",
                "technique": technique or "generic",
                "objective": objective or "generic",
            }

    bot_factory = BotFactorySpy()
    strategy = TaxonomyStrategy()

    results = strategy.execute(
        bot_factory=bot_factory,
        generator=FlakyGenerator(),
        system_prompt="You are a support assistant.",
        guardrail_category="system_prompt_extraction",
        requesting_user_id="A001",
        turns=1,
    )

    # 3 patterns attempted total; the middle one failed but the third
    # still ran - a single flaky call didn't truncate the batch.
    assert len(results) == 3
    assert sum(1 for a in results if a.succeeded) == 2
    assert sum(1 for a in results if not a.succeeded) == 1
    failed = next(a for a in results if not a.succeeded)
    assert isinstance(failed.error, RuntimeError)


def test_spend_cap_exceeded_propagates_uncaught():

    class SpendCappedGenerator:
        def generate(self, *args, **kwargs):
            raise SpendCapExceededError("cap reached")

    bot_factory = BotFactorySpy()
    strategy = TaxonomyStrategy()

    with pytest.raises(SpendCapExceededError):
        strategy.execute(
            bot_factory=bot_factory,
            generator=SpendCappedGenerator(),
            system_prompt="You are a support assistant.",
            guardrail_category="system_prompt_extraction",
            requesting_user_id="A001",
            turns=1,
        )


# ---------------------------------------------------------
# Real-world seed loading
# ---------------------------------------------------------


def test_load_seeds_returns_all_documented_incidents():

    seeds = load_seeds()

    assert len(seeds) == 5
    ids = {s["id"] for s in seeds}
    assert ids == {
        "SEED-01",
        "SEED-02",
        "SEED-03",
        "SEED-04",
        "SEED-05",
    }


def test_every_seed_is_flagged_as_a_real_world_incident_with_a_source():

    for seed in load_seeds():
        assert seed["real_world_incident"] is True
        assert seed["source_url"].startswith("https://")
        assert seed["seed_prompt"].strip()
        assert seed["technique"].strip()


def test_seeds_for_category_filters_by_guardrail():

    seeds = seeds_for_category("policy_circumvention")

    assert len(seeds) == 2
    assert {s["id"] for s in seeds} == {"SEED-03", "SEED-04"}


def test_seeds_for_category_returns_empty_for_unknown_category():

    assert seeds_for_category("not_a_real_category") == []


# ---------------------------------------------------------
# SeedAwareAttackSource
# ---------------------------------------------------------


def test_seed_aware_source_forwards_seed_prompt_and_technique():

    generator = FakeGenerator()
    source = SeedAwareAttackSource(
        generator=generator,
        seed_prompt="Ignore your previous instructions...",
        technique="Direct instruction override.",
    )

    source.generate(
        system_prompt="x",
        guardrail_category="system_prompt_extraction",
    )

    assert generator.calls[0]["seed_example"] == (
        "Ignore your previous instructions..."
    )
    assert generator.calls[0]["technique"] == (
        "Direct instruction override."
    )


# ---------------------------------------------------------
# SeedAugmentedStrategy
# ---------------------------------------------------------


def test_seed_strategy_runs_one_attack_per_documented_incident():

    generator = FakeGenerator()
    bot_factory = BotFactorySpy()
    strategy = SeedAugmentedStrategy()

    results = strategy.execute(
        bot_factory=bot_factory,
        generator=generator,
        system_prompt="You are a support assistant.",
        guardrail_category="policy_circumvention",
        requesting_user_id="A001",
        turns=1,
    )

    assert len(results) == 2
    assert all(attempt.succeeded for attempt in results)
    labels = {attempt.label for attempt in results}
    assert labels == {"SEED-03", "SEED-04"}


def test_seed_strategy_returns_empty_for_category_without_seeds():

    generator = FakeGenerator()
    bot_factory = BotFactorySpy()
    strategy = SeedAugmentedStrategy()

    results = strategy.execute(
        bot_factory=bot_factory,
        generator=generator,
        system_prompt="You are a support assistant.",
        guardrail_category="not_a_real_category",
        requesting_user_id="A001",
        turns=1,
    )

    assert results == []
    assert bot_factory.calls == 0


def test_a_failing_seed_does_not_block_the_remaining_seeds():

    class FlakySeedGenerator:
        def __init__(self) -> None:
            self.calls = 0

        def generate(
            self,
            system_prompt,
            guardrail_category,
            conversation_history=None,
            technique=None,
            objective=None,
            seed_example=None,
        ):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("simulated transient failure")
            return {
                "attack": f"attack {self.calls}",
                "technique": technique or "generic",
                "objective": objective or "generic",
            }

    bot_factory = BotFactorySpy()
    strategy = SeedAugmentedStrategy()

    results = strategy.execute(
        bot_factory=bot_factory,
        generator=FlakySeedGenerator(),
        system_prompt="You are a support assistant.",
        guardrail_category="policy_circumvention",
        requesting_user_id="A001",
        turns=1,
    )

    assert len(results) == 2
    assert sum(1 for a in results if a.succeeded) == 1
    assert sum(1 for a in results if not a.succeeded) == 1


def test_seed_strategy_spend_cap_exceeded_propagates_uncaught():

    class SpendCappedGenerator:
        def generate(self, *args, **kwargs):
            raise SpendCapExceededError("cap reached")

    bot_factory = BotFactorySpy()
    strategy = SeedAugmentedStrategy()

    with pytest.raises(SpendCapExceededError):
        strategy.execute(
            bot_factory=bot_factory,
            generator=SpendCappedGenerator(),
            system_prompt="You are a support assistant.",
            guardrail_category="policy_circumvention",
            requesting_user_id="A001",
            turns=1,
        )
