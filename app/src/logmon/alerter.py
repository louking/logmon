"""
alerter.py — Send alert emails via Flask-Mail.
"""
from __future__ import annotations

import logging
from flask_mail import Message

log = logging.getLogger(__name__)


def send_alert(flask_app, event) -> None:
    """Send an alert email for a LogEvent. Must be called inside app context."""
    from .app import mail

    recipients = flask_app.config.get("ALERT_RECIPIENTS", [])
    recipients = [r for r in recipients if r.strip()]
    if not recipients:
        log.warning("No ALERT_RECIPIENTS configured — skipping alert")
        return

    exc_type = event.exception_type or "Unknown exception"
    subject = f"[logmonitor] {event.app_name}: {exc_type[:80]}"

    lines = [
        f"App:       {event.app_name}",
        f"Time:      {event.occurred_at}",
        f"User:      {event.user or '–'}",
        f"URL:       {event.method or ''} {event.url or '–'}",
        f"Exception: {exc_type}",
        "",
    ]
    if event.traceback:
        lines += ["--- Traceback ---", event.traceback]

    try:
        mail.send(Message(subject=subject, recipients=recipients, body="\n".join(lines)))
        log.info("Alert sent: %s / %s", event.app_name, exc_type)
    except Exception:
        log.exception("Failed to send alert email")
