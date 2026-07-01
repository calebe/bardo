"""notify.py — out-of-band security alert delivery.

When a kind="security" notice fires and the agent has registered a contact
endpoint, this module dispatches a notification. The agent owns the endpoint
— atrium doesn't know or care whether it reaches a human, another system, or
the agent itself.

Endpoint detection:
  - starts with http:// or https://  → webhook (POST)
  - contains @                        → email (SMTP)

Delivery is best-effort and non-blocking. Failures are logged, never raised
— a notification failure must never break the main auth flow.

SMTP config (env vars, all optional — email delivery silently skipped if unset):
  BARDO_SMTP_HOST    default: localhost
  BARDO_SMTP_PORT    default: 587
  BARDO_SMTP_USER
  BARDO_SMTP_PASS
  BARDO_SMTP_FROM    default: bardo@localhost
"""

from __future__ import annotations

import logging
import os
import threading

logger = logging.getLogger("bardo.notify")


def _is_webhook(endpoint: str) -> bool:
    return endpoint.startswith("http://") or endpoint.startswith("https://")


def _is_email(endpoint: str) -> bool:
    return "@" in endpoint and not _is_webhook(endpoint)


def _send_webhook(endpoint: str, subject: str, body: str) -> None:
    try:
        import httpx
        httpx.post(endpoint, json={"subject": subject, "body": body}, timeout=10)
        logger.info("security alert delivered → webhook %s", endpoint)
    except Exception as exc:
        logger.warning("webhook delivery failed (%s): %s", endpoint, exc)


def _send_email(endpoint: str, subject: str, body: str) -> None:
    host = os.environ.get("BARDO_SMTP_HOST", "localhost")
    port = int(os.environ.get("BARDO_SMTP_PORT", "587"))
    user = os.environ.get("BARDO_SMTP_USER")
    password = os.environ.get("BARDO_SMTP_PASS")
    from_addr = os.environ.get("BARDO_SMTP_FROM", "bardo@localhost")

    if not host:
        logger.info("SMTP not configured — skipping email to %s", endpoint)
        return

    try:
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = endpoint
        msg.set_content(body)
        with smtplib.SMTP(host, port) as s:
            if user and password:
                s.starttls()
                s.login(user, password)
            s.send_message(msg)
        logger.info("security alert delivered → email %s", endpoint)
    except Exception as exc:
        logger.warning("email delivery failed (%s): %s", endpoint, exc)


def dispatch(endpoint: str, subject: str, body: str) -> None:
    """Fire-and-forget: dispatch a security alert to the agent's contact endpoint."""
    def _run():
        if _is_webhook(endpoint):
            _send_webhook(endpoint, subject, body)
        elif _is_email(endpoint):
            _send_email(endpoint, subject, body)
        else:
            logger.warning("unrecognised contact endpoint format: %s", endpoint)

    threading.Thread(target=_run, daemon=True).start()
