"""
LocalSMTPNotifier — stdlib-only notification backend for local Postfix + Dovecot.

No third-party packages. All network I/O uses smtplib and imaplib from the
Python standard library. Credentials come from the config block in
config/notifier.json. Designed for an on-prem or air-gapped network — no
cloud endpoints are contacted.

Authorization flow
------------------
1. send_alert() / request_authorization() compose a MIME email and hand it
   to the local SMTP relay (Postfix).
2. request_authorization() then opens an IMAP connection (Dovecot) and polls
   INBOX every poll_interval_sec seconds for an UNSEEN reply whose body
   contains YES or IGNORE.  Messages that arrived before the request was sent
   are skipped via INTERNALDATE comparison.
3. The matched reply is marked \\Seen so it is never processed twice.
4. Returns "YES", "IGNORE", or "TIMEOUT" — identical to TelegramNotifier.

Config keys (config/notifier.json → "local_smtp" block)
--------------------------------------------------------
    smtp_host          str  — SMTP relay hostname      (default: localhost)
    smtp_port          int  — 25 / 587 (STARTTLS) or 465 (SSL)  (default: 25)
    smtp_from          str  — envelope sender           (default: sentinel@localhost)
    smtp_to            str  — alert recipient           (default: admin@localhost)
    smtp_user          str  — SMTP auth username        (optional — omit for unauthenticated relay)
    smtp_password_env  str  — env var holding SMTP password      (optional)
    imap_host          str  — IMAP server hostname      (default: localhost)
    imap_port          int  — 993 (SSL) or 143 (STARTTLS)        (default: 993)
    imap_user          str  — IMAP login username
    imap_password_env  str  — env var holding IMAP password
    imap_mailbox       str  — mailbox to poll           (default: INBOX)
    poll_interval_sec  int  — seconds between IMAP checks        (default: 5)
"""

import email as _email_stdlib
import imaplib
import logging
import os
import re
import smtplib
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from .base import Notifier

logger = logging.getLogger(__name__)


class LocalSMTPNotifier(Notifier):
    """
    Sends alerts via a local SMTP relay and waits for authorization replies
    by polling a local IMAP mailbox.  All transports use stdlib only.
    """

    def __init__(self, cfg: dict) -> None:
        # SMTP settings
        self._smtp_host = cfg.get("smtp_host", "localhost")
        self._smtp_port = int(cfg.get("smtp_port", 25))
        self._smtp_from = cfg.get("smtp_from", "sentinel@localhost")
        self._smtp_to   = cfg.get("smtp_to",   "admin@localhost")
        self._smtp_user = cfg.get("smtp_user", "")
        self._smtp_password = os.environ.get(
            cfg.get("smtp_password_env", "SMTP_PASSWORD"), ""
        )

        # IMAP settings
        self._imap_host     = cfg.get("imap_host", "localhost")
        self._imap_port     = int(cfg.get("imap_port", 993))
        self._imap_user     = cfg.get("imap_user", "")
        self._imap_password = os.environ.get(
            cfg.get("imap_password_env", "IMAP_PASSWORD"), ""
        )
        self._imap_mailbox   = cfg.get("imap_mailbox", "INBOX")
        self._poll_interval  = int(cfg.get("poll_interval_sec", 5))

    # ------------------------------------------------------------------
    # Notifier interface (required)
    # ------------------------------------------------------------------

    def send_alert(self, message: str, photo_path: str = None) -> bool:
        """
        Send an alert email via local SMTP.

        photo_path is not transmitted as a binary attachment — its local
        filesystem path is appended to the email body so the admin knows
        where to find the SHAP chart on the sentinel machine.
        """
        body = message
        if photo_path:
            body += f"\n\nSHAP chart saved locally at:\n  {photo_path}"

        try:
            msg = self._build_mime("SentiHealth THREAT ALERT", body)
            self._smtp_send(msg)
            logger.info(f"[LocalSMTP] Alert dispatched to {self._smtp_to}")
            return True
        except Exception as exc:
            logger.error(f"[LocalSMTP] send_alert failed: {exc}")
            return False

    def request_authorization(
        self,
        prompt: str | None,
        timeout_sec: int = 90,
        accept_ignore: bool = False,
    ) -> str:
        """
        Send an authorization request email, then poll the IMAP inbox for a
        reply whose plain-text body contains YES, IGNORE, or TIMEOUT.

        Returns "YES", "IGNORE", or "TIMEOUT".
        """
        # Record the dispatch timestamp *before* sending so we can filter
        # IMAP results to only messages that arrive after this moment.
        sent_at = time.time()

        if prompt:
            body = (
                f"{prompt}\n\n"
                f"Reply to this email with exactly one of:\n"
                f"  YES    — approve the pending action\n"
                f"  IGNORE — skip this alert (only honoured where applicable)\n\n"
                f"This request expires in {timeout_sec} seconds.\n"
                f"Sent: {datetime.now(timezone.utc).isoformat()}"
            )
            try:
                msg = self._build_mime("SentiHealth AUTHORIZATION REQUIRED", body)
                self._smtp_send(msg)
                logger.info("[LocalSMTP] Authorization request dispatched")
            except Exception as exc:
                logger.error(f"[LocalSMTP] Could not send auth request: {exc}")
                return "TIMEOUT"

        deadline = sent_at + timeout_sec
        while time.time() < deadline:
            time.sleep(self._poll_interval)
            try:
                decision = self._poll_imap(
                    since_ts=sent_at,
                    accept_ignore=accept_ignore,
                )
                if decision:
                    logger.info(f"[LocalSMTP] Authorization reply: {decision}")
                    return decision
            except Exception as exc:
                # Log and keep polling — a transient IMAP error should not
                # abort the authorization wait.
                logger.warning(f"[LocalSMTP] IMAP poll error (will retry): {exc}")

        logger.info("[LocalSMTP] Authorization timed out — no reply received")
        return "TIMEOUT"

    # ------------------------------------------------------------------
    # SMTP helpers
    # ------------------------------------------------------------------

    def _build_mime(self, subject: str, body: str) -> MIMEMultipart:
        """Construct a plain-text MIME email message."""
        msg = MIMEMultipart()
        msg["From"]    = self._smtp_from
        msg["To"]      = self._smtp_to
        msg["Subject"] = subject
        msg["Date"]    = datetime.now(timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S +0000"
        )
        msg.attach(MIMEText(body, "plain", "utf-8"))
        return msg

    def _smtp_send(self, msg: MIMEMultipart) -> None:
        """
        Transmit a MIME message.

        Port 465  → SMTP_SSL  (implicit TLS, no STARTTLS negotiation).
        Port 25/587 → plain SMTP, STARTTLS attempted and required where
                      the server advertises it; silently skipped when the
                      local relay (e.g. Postfix on loopback) does not.
        Authentication is performed only when smtp_user is non-empty.
        """
        raw = msg.as_string()

        if self._smtp_port == 465:
            with smtplib.SMTP_SSL(
                self._smtp_host, self._smtp_port, timeout=15
            ) as conn:
                if self._smtp_user:
                    conn.login(self._smtp_user, self._smtp_password)
                conn.sendmail(self._smtp_from, [self._smtp_to], raw)
        else:
            with smtplib.SMTP(
                self._smtp_host, self._smtp_port, timeout=15
            ) as conn:
                conn.ehlo()
                try:
                    conn.starttls()
                    conn.ehlo()
                except smtplib.SMTPException:
                    # Local Postfix on 127.0.0.1 typically does not require
                    # TLS.  Log at debug level and continue.
                    logger.debug(
                        "[LocalSMTP] STARTTLS not offered by server — "
                        "continuing without encryption"
                    )
                if self._smtp_user:
                    conn.login(self._smtp_user, self._smtp_password)
                conn.sendmail(self._smtp_from, [self._smtp_to], raw)

    # ------------------------------------------------------------------
    # IMAP helpers
    # ------------------------------------------------------------------

    def _poll_imap(self, since_ts: float, accept_ignore: bool) -> str | None:
        """
        Open an IMAP connection, search INBOX for UNSEEN messages that arrived
        after since_ts, and scan their plain-text body for a decision keyword.

        Returns "YES", "IGNORE", or None (keep polling).
        Marks matched messages as \\Seen to prevent re-processing.
        """
        # IMAP SINCE only accepts a date (no time), so we also compare the
        # INTERNALDATE of each message against the exact sent_at timestamp.
        since_date = datetime.fromtimestamp(since_ts).strftime("%d-%b-%Y")

        conn = self._imap_connect()
        try:
            conn.login(self._imap_user, self._imap_password)
            conn.select(self._imap_mailbox)

            status, data = conn.search(None, f'(UNSEEN SINCE "{since_date}")')
            if status != "OK" or not data or not data[0]:
                return None

            for uid in data[0].split():
                # Fetch RFC822 body + INTERNALDATE in one round-trip.
                status, parts = conn.fetch(uid, "(RFC822 INTERNALDATE)")
                if status != "OK" or not parts:
                    continue

                raw_bytes  = None
                date_line  = ""

                for part in parts:
                    if isinstance(part, tuple):
                        raw_bytes = part[1]
                    elif isinstance(part, bytes):
                        date_line = part.decode(errors="replace")

                # Skip messages that arrived before we sent our request.
                arrival = self._parse_internaldate(date_line)
                if arrival is not None and arrival < since_ts:
                    continue

                if raw_bytes is None:
                    continue

                body_text = self._extract_plain_text(
                    _email_stdlib.message_from_bytes(raw_bytes)
                ).upper()

                if "YES" in body_text:
                    conn.store(uid, "+FLAGS", "\\Seen")
                    return "YES"

                if accept_ignore and "IGNORE" in body_text:
                    conn.store(uid, "+FLAGS", "\\Seen")
                    return "IGNORE"

        finally:
            try:
                conn.logout()
            except Exception:
                pass

        return None

    def _imap_connect(self) -> imaplib.IMAP4:
        """
        Return an authenticated IMAP connection.
        Port 993 → IMAP4_SSL (implicit TLS).
        Port 143 → IMAP4   + STARTTLS.
        """
        if self._imap_port == 143:
            conn = imaplib.IMAP4(self._imap_host, self._imap_port)
            conn.starttls()
        else:
            conn = imaplib.IMAP4_SSL(self._imap_host, self._imap_port)
        return conn

    # ------------------------------------------------------------------
    # Static utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_plain_text(msg) -> str:
        """
        Walk a parsed MIME message and return the first text/plain part's
        decoded content.  Returns an empty string if none is found.
        """
        if msg.is_multipart():
            for part in msg.walk():
                if (
                    part.get_content_type() == "text/plain"
                    and "attachment" not in str(part.get("Content-Disposition", ""))
                ):
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode(errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                return payload.decode(errors="replace")
        return ""

    @staticmethod
    def _parse_internaldate(header_line: str) -> float | None:
        """
        Extract a Unix timestamp from an IMAP INTERNALDATE response fragment.

        Example fragment: b'1 (INTERNALDATE "04-Jun-2026 13:00:00 +0000" RFC822 ...)'
        Returns None on any parse failure — callers treat None as "do not skip".
        """
        match = re.search(r'INTERNALDATE "([^"]+)"', header_line)
        if not match:
            return None
        try:
            return _email_stdlib.utils.parsedate_to_datetime(
                match.group(1)
            ).timestamp()
        except Exception:
            return None
