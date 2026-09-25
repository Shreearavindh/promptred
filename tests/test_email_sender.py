"""Tests for email reporting (fake SMTP client only - no real network)."""

from pathlib import Path

from core.orchestrator import Finding, ScanResult
from core.reporting.email_sender import (
    EmailReportFilter,
    EmailSender,
    load_recipients,
    save_recipient,
)
from tests.test_reporting import make_finding


def make_scan_result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        findings=findings,
        model_independence={"judge_independent": True},
        token_summary={},
        prompts_scanned=1,
    )


# ---------------------------------------------------------
# Recipients config
# ---------------------------------------------------------


def test_load_recipients_returns_empty_when_no_file(tmp_path: Path):

    assert load_recipients(tmp_path / "missing.yaml") == []


def test_save_recipient_persists_and_dedupes(tmp_path: Path):

    path = tmp_path / "recipients.yaml"

    save_recipient("a@example.com", path)
    save_recipient("b@example.com", path)
    save_recipient("a@example.com", path)  # duplicate

    assert load_recipients(path) == [
        "a@example.com",
        "b@example.com",
    ]


# ---------------------------------------------------------
# EmailReportFilter
# ---------------------------------------------------------


def test_filter_sends_when_a_finding_meets_email_threshold():

    scan_result = make_scan_result(
        [make_finding(True, "critical", 4)]
    )

    assert EmailReportFilter.should_send(scan_result) is True


def test_filter_does_not_send_for_low_severity_only():

    finding = make_finding(True, "low", 1)
    finding.severity.email_threshold = False
    scan_result = make_scan_result([finding])

    assert EmailReportFilter.should_send(scan_result) is False


# ---------------------------------------------------------
# EmailSender
# ---------------------------------------------------------


def test_is_configured_requires_host_and_sender():

    unconfigured = EmailSender(smtp_host=None, sender_email=None)
    assert unconfigured.is_configured() is False

    configured = EmailSender(
        smtp_host="smtp.example.com",
        sender_email="reports@example.com",
    )
    assert configured.is_configured() is True


def test_send_report_raises_when_not_configured(tmp_path: Path):

    sender = EmailSender(smtp_host=None, sender_email=None)
    scan_result = make_scan_result([make_finding(True, "high", 3)])

    try:
        sender.send_report(
            scan_result,
            ["a@example.com"],
            tmp_path / "r.json",
            tmp_path / "r.html",
        )
        assert False, "Expected RuntimeError."
    except RuntimeError as error:
        assert "not configured" in str(error)


def test_send_report_raises_without_recipients():

    sender = EmailSender(
        smtp_host="smtp.example.com",
        sender_email="reports@example.com",
    )
    scan_result = make_scan_result([make_finding(True, "high", 3)])

    try:
        sender.send_report(
            scan_result, [], "r.json", "r.html"
        )
        assert False, "Expected RuntimeError."
    except RuntimeError as error:
        assert "recipients" in str(error)


class FakeSMTP:
    """Fake SMTP client - records calls, never touches a real socket."""

    def __init__(self) -> None:
        self.starttls_called = False
        self.login_calls: list[tuple[str, str]] = []
        self.sent_messages: list[object] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def starttls(self):
        self.starttls_called = True

    def login(self, username, password):
        self.login_calls.append((username, password))

    def send_message(self, message):
        self.sent_messages.append(message)


def test_send_report_sends_via_fake_smtp_with_attachments(
    tmp_path: Path,
):

    json_path = tmp_path / "r.json"
    html_path = tmp_path / "r.html"
    json_path.write_text("{}", encoding="utf-8")
    html_path.write_text("<html></html>", encoding="utf-8")

    fake_smtp = FakeSMTP()

    sender = EmailSender(
        smtp_host="smtp.example.com",
        sender_email="reports@example.com",
        smtp_username="user",
        smtp_password="pass",
        smtp_client_factory=lambda: fake_smtp,
    )

    scan_result = make_scan_result(
        [make_finding(True, "critical", 4)]
    )

    sender.send_report(
        scan_result,
        ["recipient@example.com"],
        json_path,
        html_path,
    )

    assert fake_smtp.starttls_called is True
    assert fake_smtp.login_calls == [("user", "pass")]
    assert len(fake_smtp.sent_messages) == 1

    sent = fake_smtp.sent_messages[0]
    assert sent["To"] == "recipient@example.com"
    assert sent["From"] == "reports@example.com"

    attachment_filenames = [
        part.get_filename()
        for part in sent.iter_attachments()
    ]
    assert "r.json" in attachment_filenames
    assert "r.html" in attachment_filenames


def test_send_report_skips_login_without_credentials(
    tmp_path: Path,
):

    fake_smtp = FakeSMTP()

    sender = EmailSender(
        smtp_host="smtp.example.com",
        sender_email="reports@example.com",
        smtp_client_factory=lambda: fake_smtp,
    )

    scan_result = make_scan_result(
        [make_finding(True, "critical", 4)]
    )

    sender.send_report(
        scan_result,
        ["recipient@example.com"],
        tmp_path / "missing.json",
        tmp_path / "missing.html",
    )

    assert fake_smtp.login_calls == []
    assert len(fake_smtp.sent_messages) == 1
