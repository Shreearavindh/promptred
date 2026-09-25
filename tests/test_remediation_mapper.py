"""Tests for the OWASP-grounded remediation mapper."""

from core.remediation.mapper import RemediationMapper
from core.scoring.rca import (
    CONTEXT_WINDOW_MANIPULATION,
    MISSING_AUTHORIZATION_CHECK,
    RootCauseAssessment,
)


def test_no_primary_root_cause_returns_empty_assessment():

    mapper = RemediationMapper()
    root_cause = RootCauseAssessment(primary="", contributing=[])

    result = mapper.map(
        guardrail_category="system_prompt_extraction",
        root_cause=root_cause,
    )

    assert result.owasp_references == []
    assert result.remediation_steps == []


def test_missing_authorization_check_maps_to_llm03():

    mapper = RemediationMapper()
    root_cause = RootCauseAssessment(
        primary=MISSING_AUTHORIZATION_CHECK,
        contributing=[],
    )

    result = mapper.map(
        guardrail_category="unauthorized_refund",
        root_cause=root_cause,
    )

    owasp_ids = {ref.id for ref in result.owasp_references}
    assert "LLM03" in owasp_ids
    assert len(result.remediation_steps) > 0
    assert all(
        isinstance(step, str) and step for step in result.remediation_steps
    )


def test_contributing_cause_adds_its_own_owasp_reference():

    mapper = RemediationMapper()
    root_cause = RootCauseAssessment(
        primary=MISSING_AUTHORIZATION_CHECK,
        contributing=[CONTEXT_WINDOW_MANIPULATION],
    )

    result = mapper.map(
        guardrail_category="unauthorized_refund",
        root_cause=root_cause,
    )

    owasp_ids = {ref.id for ref in result.owasp_references}
    assert "LLM01" in owasp_ids  # from CONTEXT_WINDOW_MANIPULATION
    assert "LLM03" in owasp_ids  # from MISSING_AUTHORIZATION_CHECK


def test_guardrail_category_reference_always_included():

    mapper = RemediationMapper()
    # A root cause with no configured owasp mapping (simulated by an
    # unregistered string) should still surface the category-level ref.
    root_cause = RootCauseAssessment(
        primary="SOME_UNMAPPED_CAUSE",
        contributing=[],
    )

    result = mapper.map(
        guardrail_category="cross_user_data_access",
        root_cause=root_cause,
    )

    owasp_ids = {ref.id for ref in result.owasp_references}
    assert "LLM02" in owasp_ids


def test_no_duplicate_owasp_references():

    mapper = RemediationMapper()
    root_cause = RootCauseAssessment(
        primary=MISSING_AUTHORIZATION_CHECK,
        contributing=[],
    )

    result = mapper.map(
        guardrail_category="unauthorized_refund",
        root_cause=root_cause,
    )

    ids = [ref.id for ref in result.owasp_references]
    assert len(ids) == len(set(ids))
