"""Redaction for shared reports, so a report is not a ready-made attack kit.

A full report shows the exact attack text that broke the bot, which the
engineer fixing it needs. When the report is shared more widely,
`--redact-attacks` replaces that text for every confirmed-successful
attack (and the attacker's turns in its transcript) with a placeholder
naming only the technique. Verdicts, severity, root cause, the bot's
response and the fix all stay. Held and needs-human-review findings are
left intact: they are not working attacks, and a reviewer needs the text.
"""

from dataclasses import replace

USAGE_NOTICE = (
    "Authorized security testing of your own system prompts only. "
    "Do not use these attacks against systems you do not own."
)


def redacted_placeholder(finding) -> str:
    technique = finding.attack_pattern_id or finding.strategy_name or "attack"
    return f"[redacted - technique: {technique}]"


def redact_scan_result(scan_result):
    """Return a copy of the scan result with successful attack text removed."""

    findings = []
    for finding in scan_result.findings:
        evaluation = finding.evaluation
        if evaluation.vulnerable and not evaluation.abstained:
            placeholder = redacted_placeholder(finding)
            finding = replace(
                finding,
                attack=placeholder,
                transcript=[
                    {**turn, "content": placeholder}
                    if turn.get("role") == "user"
                    else turn
                    for turn in finding.transcript
                ],
            )
        findings.append(finding)
    return replace(scan_result, findings=findings)
