"""Email reporting for PromptRed scans.

For this MVP, "the report" means something that lands in an inbox,
not a dashboard someone has to remember to open. The sender is a
company address configured once via .env; recipients are configured
separately (config/recipients.yaml) or supplied per-run via the CLI,
which interactively asks for one if none is on file when a scan
produces a flagged finding. Uses only stdlib smtplib/email - no new
dependency.
"""

import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Callable

import yaml

from core.orchestrator import ScanResult

RECIPIENTS_PATH = Path("config/recipients.yaml")

SMTPClientFactory = Callable[[], smtplib.SMTP]


def load_recipients(path: Path = RECIPIENTS_PATH) -> list[str]:
    """Return the configured recipient list, or [] if none is on file."""

    if not path.exists():
        return []

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("recipients", []) or []


def save_recipient(
    email: str,
    path: Path = RECIPIENTS_PATH,
) -> None:
    """Persist a recipient address for future runs (dedup, append-only)."""

    recipients = load_recipients(path)

    if email not in recipients:
        recipients.append(email)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"recipients": recipients}),
        encoding="utf-8",
    )


class EmailReportFilter:
    """Decides whether a scan's findings warrant emailing a report.

    Only sends when at least one finding meets/exceeds the severity
    threshold in config/severity.yaml (email_threshold: true) -
    informational/low-severity-only scans don't spam the inbox.
    """

    @staticmethod
    def should_send(scan_result: ScanResult) -> bool:
        return any(
            finding.severity.email_threshold
            for finding in scan_result.findings
        )


class EmailSender:
    """Sends flagged-finding reports via SMTP.

    Sending only happens when the user's own CLI invocation triggers
    it (`promptred scan --email`) using their own SMTP credentials -
    this module never sends automatically in the background.
    """

    def __init__(
        self,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_username: str | None = None,
        smtp_password: str | None = None,
        sender_email: str | None = None,
        smtp_client_factory: SMTPClientFactory | None = None,
    ) -> None:
        self.smtp_host = smtp_host or os.getenv("SMTP_HOST")
        self.smtp_port = int(
            smtp_port or os.getenv("SMTP_PORT", "587")
        )
        self.smtp_username = smtp_username or os.getenv(
            "SMTP_USERNAME"
        )
        self.smtp_password = smtp_password or os.getenv(
            "SMTP_PASSWORD"
        )
        self.sender_email = sender_email or os.getenv("SENDER_EMAIL")
        self.smtp_client_factory = (
            smtp_client_factory
            or (lambda: smtplib.SMTP(self.smtp_host, self.smtp_port))
        )

    def is_configured(self) -> bool:
        return bool(self.smtp_host and self.sender_email)

    def send_report(
        self,
        scan_result: ScanResult,
        recipients: list[str],
        json_report_path: str | Path,
        html_report_path: str | Path,
    ) -> None:
        """Send the scan summary with both reports attached."""

        if not self.is_configured():
            raise RuntimeError(
                "Email sending is not configured. Set SMTP_HOST and "
                "SENDER_EMAIL (and SMTP_USERNAME/SMTP_PASSWORD if "
                "required) in your .env file."
            )

        if not recipients:
            raise RuntimeError(
                "No recipients configured to send the report to."
            )

        message = self._build_message(
            scan_result,
            recipients,
            Path(json_report_path),
            Path(html_report_path),
        )

        server = self.smtp_client_factory()

        with server:
            server.starttls()

            if self.smtp_username and self.smtp_password:
                server.login(
                    self.smtp_username, self.smtp_password
                )

            server.send_message(message)

    def _build_message(
        self,
        scan_result: ScanResult,
        recipients: list[str],
        json_report_path: Path,
        html_report_path: Path,
    ) -> EmailMessage:
        vulnerable = scan_result.vulnerable_findings

        message = EmailMessage()
        message["Subject"] = (
            f"PromptRed: {len(vulnerable)} flagged finding(s) across "
            f"{scan_result.prompts_scanned} prompt(s)"
        )
        message["From"] = self.sender_email
        message["To"] = ", ".join(recipients)

        message.set_content(
            self._build_body(scan_result, vulnerable)
        )

        for path in (json_report_path, html_report_path):
            if not path.exists():
                continue

            subtype = path.suffix.lstrip(".") or "octet-stream"
            maintype = "application" if subtype == "json" else "text"

            message.add_attachment(
                path.read_bytes(),
                maintype=maintype,
                subtype=subtype,
                filename=path.name,
            )

        return message

    @staticmethod
    def _build_body(
        scan_result: ScanResult,
        vulnerable: list,
    ) -> str:
        lines = [
            "PromptRed scan complete.",
            f"Prompts scanned: {scan_result.prompts_scanned}",
            f"Total attacks: {len(scan_result.findings)}",
            f"Flagged findings: {len(vulnerable)}",
            "",
            "Top findings:",
        ]

        top_findings = sorted(
            vulnerable, key=lambda f: -f.severity.score
        )[:5]

        for finding in top_findings:
            lines.append(
                f"  - [{finding.severity.level}] "
                f"{finding.guardrail_category}: "
                f"{finding.root_cause.primary}"
            )

        lines.append("")
        lines.append("Full JSON and HTML reports are attached.")

        return "\n".join(lines)
