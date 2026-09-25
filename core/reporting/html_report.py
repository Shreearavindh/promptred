"""HTML report generator for PromptRed scans.

Self-contained single-file report (inline CSS, no external
dependencies, no Jinja2) with a two-level structure: an executive
summary (risk score, severity distribution, cost summary, judge
independence status) and technical detail (per-finding transcript,
evidence-grounded reasoning, OWASP reference, remediation guidance).
All scan-derived text is HTML-escaped before insertion, since attacks
and model responses are untrusted, LLM-generated content.
"""

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.orchestrator import ScanResult
from core.reporting.json_report import SEVERITY_ORDER

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#4d7c0f",
    "none": "#6b7280",
}

NEEDS_REVIEW_COLOR = "#7c3aed"


def _esc(value: Any) -> str:
    return html.escape(str(value))


class HTMLReportGenerator:
    """Builds and saves a self-contained HTML report from a ScanResult."""

    def generate(self, scan_result: ScanResult) -> str:
        vulnerable = scan_result.vulnerable_findings
        needs_review = scan_result.needs_review_findings
        severity_counts = self._severity_distribution(
            scan_result.findings
        )
        risk_score = sum(
            finding.severity.score for finding in scan_result.findings
        )

        other_findings = [
            finding
            for finding in scan_result.findings
            if finding not in needs_review
        ]

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PromptRed Scan Report</title>
<style>{self._css()}</style>
</head>
<body>
<header>
  <h1>PromptRed Scan Report</h1>
  <p class="meta">Generated {_esc(datetime.now(timezone.utc).isoformat())}</p>
</header>
{self._render_independence(scan_result.model_independence)}
{self._render_executive_summary(scan_result, vulnerable, needs_review, severity_counts, risk_score)}
{self._render_cost_summary(scan_result.token_summary)}
{self._render_needs_review_section(needs_review)}
<section class="findings">
  <h2>Findings</h2>
  {"".join(self._render_finding(finding) for finding in other_findings)}
</section>
</body>
</html>"""

    def save(
        self,
        scan_result: ScanResult,
        output_path: str | Path,
    ) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self.generate(scan_result),
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

    @staticmethod
    def _render_independence(independence: dict[str, Any]) -> str:
        if independence.get("judge_independent"):
            return (
                '<div class="independence ok">Judge model is '
                "independent from attacker/target models.</div>"
            )

        warning = _esc(independence.get("warning", ""))
        return f'<div class="independence warn">{warning}</div>'

    def _render_executive_summary(
        self,
        scan_result: ScanResult,
        vulnerable: list,
        needs_review: list,
        severity_counts: dict[str, int],
        risk_score: int,
    ) -> str:
        rows = "".join(
            f"<tr><td>{_esc(level)}</td><td>{count}</td></tr>"
            for level, count in severity_counts.items()
        )

        review_stat_class = (
            "stat needs-review-stat" if needs_review else "stat"
        )

        return f"""
<section class="summary">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat"><span class="stat-value">{scan_result.prompts_scanned}</span><span class="stat-label">Prompts Scanned</span></div>
    <div class="stat"><span class="stat-value">{len(scan_result.findings)}</span><span class="stat-label">Attacks Run</span></div>
    <div class="stat"><span class="stat-value">{len(vulnerable)}</span><span class="stat-label">Confirmed Vulnerable</span></div>
    <div class="{review_stat_class}"><span class="stat-value">{len(needs_review)}</span><span class="stat-label">Needs Human Review</span></div>
    <div class="stat"><span class="stat-value">{risk_score}</span><span class="stat-label">Aggregate Risk Score</span></div>
  </div>
  <table class="severity-table">
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>
"""

    @staticmethod
    def _render_cost_summary(token_summary: dict[str, Any]) -> str:
        total_calls = token_summary.get("total_calls", 0)
        total_tokens = token_summary.get("total_tokens", 0)
        total_cost = token_summary.get("total_cost_usd", 0.0)

        return f"""
<section class="cost">
  <h2>Token Economics</h2>
  <table>
    <tr><td>Total calls</td><td>{total_calls}</td></tr>
    <tr><td>Total tokens</td><td>{total_tokens}</td></tr>
    <tr><td>Total cost (USD)</td><td>${total_cost:.4f}</td></tr>
  </table>
</section>
"""

    def _render_needs_review_section(self, needs_review: list) -> str:
        """Cases where neither the primary judge nor the escalation
        panel was confident enough to resolve automatically. Rendered
        BEFORE the regular findings list, with the transcript already
        expanded (not behind a click) - the AI did not make the call
        here, so a human reading this report is the actual decision-
        maker, and needs the real attack/response in front of them
        without extra steps."""

        if not needs_review:
            return ""

        cases_html = "".join(
            self._render_needs_review_finding(finding)
            for finding in needs_review
        )

        return f"""
<section class="needs-review">
  <h2>Needs Human Review ({len(needs_review)})</h2>
  <p class="needs-review-intro">
    The judge, and a second independent judge escalated to on abstention,
    were not confident enough to call these automatically. No automated
    vulnerable/held verdict is reported for them - review the attack and
    the target's actual response below and decide.
  </p>
  {cases_html}
</section>
"""

    def _render_needs_review_finding(self, finding) -> str:
        transcript_html = "".join(
            f'<div class="turn {_esc(message["role"])}">'
            f'<strong>{_esc(message["role"])}:</strong> '
            f'{_esc(message["content"])}</div>'
            for message in finding.transcript
        )

        escalation_note = (
            "Escalated to the judge panel (a second, independent "
            "model also reviewed this)."
            if finding.evaluation.escalated_to_panel
            else "The primary judge abstained before any escalation "
            "was configured."
        )

        return f"""
<div class="finding needs-review-finding" style="border-left-color: {NEEDS_REVIEW_COLOR}">
  <div class="finding-header">
    <span class="badge" style="background:{NEEDS_REVIEW_COLOR}">NEEDS HUMAN REVIEW</span>
    <span class="category">{_esc(finding.guardrail_category)}</span>
    <span class="source">{_esc(finding.prompt_source)}</span>
  </div>
  <p class="escalation-note">{_esc(escalation_note)} Judge confidence: {finding.evaluation.confidence:.2f}.</p>
  <div class="attack-response">
    <div><strong>Attack:</strong> {_esc(finding.attack)}</div>
    <div><strong>Response:</strong> {_esc(finding.response)}</div>
  </div>
  <details open>
    <summary>Full transcript</summary>
    {transcript_html}
  </details>
  <div class="reasoning">
    <strong>What the judge(s) said:</strong>
    <p>{_esc(finding.evaluation.reasoning)}</p>
  </div>
</div>
"""

    def _render_finding(self, finding) -> str:
        color = SEVERITY_COLORS.get(finding.severity.level, "#6b7280")
        vulnerable_badge = (
            "VULNERABLE" if finding.evaluation.vulnerable else "held"
        )

        transcript_html = "".join(
            f'<div class="turn {_esc(message["role"])}">'
            f'<strong>{_esc(message["role"])}:</strong> '
            f'{_esc(message["content"])}</div>'
            for message in finding.transcript
        )

        remediation_dict = finding.remediation.to_dict()

        owasp_html = "".join(
            f'<li><a href="{_esc(ref["url"])}" target="_blank" '
            f'rel="noopener">{_esc(ref["id"])}: '
            f'{_esc(ref["name"])}</a></li>'
            for ref in remediation_dict["owasp_references"]
        )

        remediation_html = "".join(
            f"<li>{_esc(step)}</li>"
            for step in remediation_dict["remediation_steps"]
        )

        pattern_html = (
            f'<span class="pattern">{_esc(finding.attack_pattern_id)}</span>'
            if finding.attack_pattern_id
            else ""
        )

        return f"""
<div class="finding" style="border-left-color: {color}">
  <div class="finding-header">
    <span class="badge" style="background:{color}">{_esc(vulnerable_badge)}</span>
    <span class="category">{_esc(finding.guardrail_category)}</span>
    {pattern_html}
    <span class="severity">{_esc(finding.severity.level)}</span>
    <span class="source">{_esc(finding.prompt_source)}</span>
  </div>
  <details>
    <summary>Transcript</summary>
    {transcript_html}
  </details>
  <div class="rca">
    <strong>Root cause:</strong> {_esc(finding.root_cause.primary or "n/a")}
    <p>{_esc(finding.root_cause.rationale)}</p>
  </div>
  <div class="remediation">
    <strong>OWASP references:</strong>
    <ul>{owasp_html or "<li>n/a</li>"}</ul>
    <strong>Remediation:</strong>
    <ul>{remediation_html or "<li>n/a</li>"}</ul>
  </div>
  <div class="reasoning">
    <strong>Evaluation reasoning:</strong>
    <p>{_esc(finding.evaluation.reasoning)}</p>
  </div>
</div>
"""

    @staticmethod
    def _css() -> str:
        return """
body { font-family: -apple-system, Segoe UI, sans-serif; margin: 0; padding: 2rem; background: #f8fafc; color: #1e293b; }
header h1 { margin-bottom: 0.25rem; }
.meta { color: #64748b; font-size: 0.9rem; }
section { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.stat-grid { display: flex; gap: 1.5rem; margin-bottom: 1rem; }
.stat { text-align: center; }
.stat-value { display: block; font-size: 2rem; font-weight: 700; }
.stat-label { font-size: 0.85rem; color: #64748b; }
table { width: 100%; border-collapse: collapse; }
td, th { padding: 0.5rem; border-bottom: 1px solid #e2e8f0; text-align: left; }
.independence { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-weight: 600; }
.independence.ok { background: #dcfce7; color: #166534; }
.independence.warn { background: #fef3c7; color: #92400e; }
.finding { border-left: 4px solid #6b7280; padding: 1rem; margin-bottom: 1rem; background: #f8fafc; border-radius: 4px; }
.finding-header { display: flex; gap: 0.75rem; align-items: center; margin-bottom: 0.5rem; }
.badge { color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }
.category { font-weight: 600; }
.pattern { font-size: 0.75rem; color: #64748b; font-family: monospace; background: #e2e8f0; padding: 0.1rem 0.4rem; border-radius: 3px; }
.severity { text-transform: uppercase; font-size: 0.75rem; color: #64748b; }
.source { font-size: 0.75rem; color: #94a3b8; margin-left: auto; }
.turn { padding: 0.4rem 0; border-bottom: 1px dashed #e2e8f0; }
.turn.user { color: #b91c1c; }
.turn.assistant { color: #1e40af; }
.rca, .remediation, .reasoning { margin-top: 0.75rem; font-size: 0.9rem; }
ul { margin: 0.25rem 0; padding-left: 1.25rem; }
.needs-review-stat .stat-value { color: #7c3aed; }
.needs-review { border: 2px solid #7c3aed; }
.needs-review h2 { color: #7c3aed; }
.needs-review-intro { font-size: 0.9rem; color: #475569; margin-top: -0.5rem; }
.needs-review-finding { background: #f5f3ff; }
.escalation-note { font-size: 0.85rem; color: #6d28d9; font-style: italic; }
.attack-response { margin: 0.5rem 0; font-size: 0.9rem; }
.attack-response div { margin-bottom: 0.4rem; }
"""
