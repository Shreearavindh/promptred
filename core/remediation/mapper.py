"""OWASP-grounded remediation mapping for PromptRed findings.

Given a finding's guardrail category and root cause (from
core/scoring/rca.py), returns the relevant OWASP Top 10 for LLM
Applications references, concrete remediation steps, and
defense-in-depth recommendations - grounding remediation in
recognized industry guidance rather than generic advice.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from core.scoring.rca import RootCauseAssessment

OWASP_MAPPING_PATH = Path("config/owasp_mapping.yaml")


def load_owasp_mapping(
    path: Path = OWASP_MAPPING_PATH,
) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@dataclass
class OwaspReference:
    id: str
    name: str
    url: str

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "url": self.url}


@dataclass
class RemediationAssessment:
    """OWASP references and remediation guidance for one finding."""

    owasp_references: list[OwaspReference]
    remediation_steps: list[str]
    defense_in_depth: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "owasp_references": [
                ref.to_dict() for ref in self.owasp_references
            ],
            "remediation_steps": self.remediation_steps,
            "defense_in_depth": self.defense_in_depth,
        }


class RemediationMapper:
    """Maps a finding's root cause to OWASP-grounded remediation."""

    def __init__(
        self,
        config_path: Path = OWASP_MAPPING_PATH,
    ) -> None:
        self.config = load_owasp_mapping(config_path)
        self.owasp_categories: dict[str, Any] = self.config[
            "owasp_categories"
        ]
        self.guardrail_mapping: dict[str, Any] = self.config[
            "guardrail_mapping"
        ]
        self.root_cause_remediation: dict[str, Any] = self.config[
            "root_cause_remediation"
        ]

    def map(
        self,
        guardrail_category: str,
        root_cause: RootCauseAssessment,
    ) -> RemediationAssessment:
        """Build remediation guidance for a finding's root cause(s)."""

        if not root_cause.primary:
            return RemediationAssessment(
                owasp_references=[],
                remediation_steps=[],
                defense_in_depth=[],
            )

        owasp_ids: list[str] = []
        remediation_steps: list[str] = []
        defense_in_depth: list[str] = []

        all_causes = [root_cause.primary, *root_cause.contributing]

        for cause in all_causes:
            entry = self.root_cause_remediation.get(cause)

            if entry is None:
                continue

            for owasp_id in entry.get("owasp", []):
                if owasp_id not in owasp_ids:
                    owasp_ids.append(owasp_id)

            for step in entry.get("steps", []):
                if step not in remediation_steps:
                    remediation_steps.append(step)

            for item in entry.get("defense_in_depth", []):
                if item not in defense_in_depth:
                    defense_in_depth.append(item)

        # Ensure the guardrail-category-level OWASP reference is
        # present even if the root cause mapping didn't surface it.
        category_mapping = self.guardrail_mapping.get(
            guardrail_category
        )

        if category_mapping:
            primary_id = category_mapping.get("primary")

            if primary_id and primary_id not in owasp_ids:
                owasp_ids.insert(0, primary_id)

        owasp_references = [
            self._resolve_owasp_ref(owasp_id)
            for owasp_id in owasp_ids
        ]

        return RemediationAssessment(
            owasp_references=owasp_references,
            remediation_steps=remediation_steps,
            defense_in_depth=defense_in_depth,
        )

    def _resolve_owasp_ref(self, owasp_id: str) -> OwaspReference:
        entry = self.owasp_categories[owasp_id]
        return OwaspReference(
            id=owasp_id,
            name=entry["name"],
            url=entry["url"],
        )
