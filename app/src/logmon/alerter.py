"""
alerter.py — Send alert emails via loutilities mailer.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def send_alert(flask_app, event) -> None:
    """Send an alert email for a LogEvent. Must be called inside app context."""
    from loutilities.flask_helpers.mailer import sendmail

    recipients = flask_app.config.get("ALERT_RECIPIENTS", [])
    recipients = [r for r in recipients if r.strip()]
    if not recipients:
        log.warning("No ALERT_RECIPIENTS configured — skipping alert")
        return

    exc_type = event.exception_type or "Unknown exception"
    subject = f"[logmon] {event.app_name}: {exc_type[:80]}"

    fromaddr = flask_app.config.get(
        "ALERT_FROM",
        flask_app.config.get("MAIL_DEFAULT_SENDER", None),
    )

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
        # no html version for now, just text
        sendmail(subject, fromaddr, recipients, None, text="\n".join(lines))
        log.info("Alert sent: %s / %s", event.app_name, exc_type)
    except Exception:
        log.exception("Failed to send alert email")


def send_disk_alert(flask_app, fs: dict, threshold: int) -> None:
    """
    Send an alert email when a filesystem exceeds the configured threshold.

    ``fs`` is one entry from the ``filesystems`` list in a diskmon snapshot::

        {
            "device":   "/dev/sda1",
            "mount":    "/",
            "total_kb": 102400,
            "used_kb":  87040,
            "avail_kb": 15360,
            "use_pct":  85,
        }

    Must be called inside an app context (same pattern as send_alert).
    """
    from loutilities.flask_helpers.mailer import sendmail

    recipients = flask_app.config.get("ALERT_RECIPIENTS", [])
    recipients = [r for r in recipients if r.strip()]
    if not recipients:
        log.warning("No ALERT_RECIPIENTS configured — skipping disk alert")
        return

    mount   = fs["mount"]
    use_pct = fs["use_pct"]
    subject = f"[logmon] disk alert: {mount} is {use_pct}% full (threshold {threshold}%)"

    fromaddr = flask_app.config.get(
        "ALERT_FROM",
        flask_app.config.get("MAIL_DEFAULT_SENDER", None),
    )

    def _fmt_kb(kb: int) -> str:
        if kb >= 1_048_576:
            return f"{kb / 1_048_576:.1f} GB"
        if kb >= 1_024:
            return f"{kb / 1_024:.1f} MB"
        return f"{kb} KB"

    lines = [
        f"Mount:     {mount}",
        f"Device:    {fs.get('device', '–')}",
        f"Used:      {use_pct}%  (threshold: {threshold}%)",
        f"Total:     {_fmt_kb(fs.get('total_kb', 0))}",
        f"Used:      {_fmt_kb(fs.get('used_kb',  0))}",
        f"Available: {_fmt_kb(fs.get('avail_kb', 0))}",
    ]

    try:
        sendmail(subject, fromaddr, recipients, None, text="\n".join(lines))
        log.info("Disk alert sent: %s at %d%%", mount, use_pct)
    except Exception:
        log.exception("Failed to send disk alert email")
