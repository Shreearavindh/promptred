"""JSON report generator for PromptRed scans.

Structured, machine-readable output: scan metadata, per-finding
detail (attack, transcript, evidence, verdict, severity, RCA, OWASP
reference, remediation), aggregate metrics, and token economics -
everything the HTML report renders, in a form other tools can consume.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.orchestrator import ScanResult

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
}


class JSONReportGenerator:
    """Builds and saves a structured JSON report from a ScanResult."""

    def generate(self, scan_result: ScanResult) -> dict[str, Any]:
        vulnerable = scan_result.vulnerable_findings
        needs_review = scan_result.needs_review_findings
        severity_counts = self._severity_distribution(
            scan_result.findings
        )
        risk_score = sum(
            finding.severity.score for finding in scan_result.findings
        )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "prompts_scanned": scan_result.prompts_scanned,
                "total_attacks": len(scan_result.findings),
                "vulnerable_findings": len(vulnerable),
                "needs_human_review": len(needs_review),
                "failed_attacks": len(scan_result.failed_attempts),
                "judge_unavailable_verdicts": len(
                    scan_result.judge_unavailable_findings
                ),
                "complete": scan_result.is_complete,
                "offline": scan_result.offline,
                "aggregate_risk_score": risk_score,
                "severity_distribution": severity_counts,
            },
            "model_independence": scan_result.model_independence,
            "token_economics": scan_result.token_summary,
            "failed_attempts": scan_result.failed_attempts,
            "findings": [
                finding.to_dict() for finding in scan_result.findings
            ],
        }

    def save(
        self,
        scan_result: ScanResult,
        output_path: str | Path,
    ) -> Path:
        report = self.generate(scan_result)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )
        return output_path

    @staticmethod
    def _severity_distribution(findings) -> dict[str, int]:
        counts: dict[str, int] = {}

        for finding in findings:
            level = finding.severity.level
            counts[level] = counts.get(level, 0) + 1

        return dict(
            sorted(
                counts.items(),
                key=lambda item: -SEVERITY_ORDER.get(item[0], 0),
            )
        )
