from __future__ import annotations

import json
import logging
import urllib.request

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_security import login_required

from ..model import db
from ..model import SnsNotification
from .auth import require_super_admin

bp = Blueprint("sns", __name__, url_prefix="/sns")

log = logging.getLogger(__name__)


@bp.route("/webhook", methods=["POST"])
def webhook():
    """Public endpoint — no login or role required; SNS posts here.

    Protected by a shared secret key passed as ?key=<value> in the URL.
    Configure the key in config/snswebhook-key.txt and include it in the
    SNS HTTP subscription URL:  https://yourhost/sns/webhook?key=<value>
    """
    # Key check — if SNS_WEBHOOK_KEY is set, the request must supply it
    expected_key = current_app.config.get("SNS_WEBHOOK_KEY")
    if expected_key:
        provided_key = request.args.get("key", "")
        if not provided_key or provided_key != expected_key:
            log.warning("SNS webhook: rejected request with invalid or missing key")
            return jsonify({"error": "forbidden"}), 403

    msg_type = request.headers.get("x-amz-sns-message-type", "")
    payload = request.get_json(force=True, silent=True) or {}
    topic_arn = payload.get("TopicArn", "")

    allowed = current_app.config.get("SNS_TOPIC_ARNS_ALLOWED", [])
    if allowed:
        if topic_arn not in allowed:
            log.warning("SNS webhook: rejected unknown TopicArn %s", topic_arn)
            return jsonify({"error": "unknown topic"}), 403

    if msg_type == "SubscriptionConfirmation":
        subscribe_url = payload.get("SubscribeURL")
        if subscribe_url:
            try:
                urllib.request.urlopen(subscribe_url, timeout=10)
                log.info("SNS subscription confirmed: %s", topic_arn)
            except Exception:
                log.exception("Failed to confirm SNS subscription")
        _store(payload, msg_type)
        return jsonify({"status": "confirmed"}), 200

    if msg_type == "Notification":
        _store(payload, msg_type)
        return jsonify({"status": "ok"}), 200

    return jsonify({"status": "ignored"}), 200


def _store(payload: dict, msg_type: str) -> None:
    msg_id = payload.get("MessageId")
    if msg_id and SnsNotification.query.filter_by(message_id=msg_id).first():
        return

    message_text = payload.get("Message", "")
    try:
        inner = json.loads(message_text)
        subject = inner.get("notificationType") or payload.get("Subject", "")
        message_display = json.dumps(inner, indent=2)
    except Exception:
        subject = payload.get("Subject", msg_type)
        message_display = message_text

    db.session.add(SnsNotification(
        notification_type=msg_type,
        topic_arn=payload.get("TopicArn"),
        subject=subject,
        message=message_display,
        message_id=msg_id,
        raw_payload=json.dumps(payload),
    ))
    db.session.commit()


@bp.route("/")
@login_required
def index():
    require_super_admin()   # role check — webhook above is intentionally exempt
    page = request.args.get("page", 1, type=int)
    pagination = (
        SnsNotification.query
        .order_by(SnsNotification.received_at.desc())
        .paginate(page=page, per_page=30, error_out=False)
    )
    return render_template("sns.jinja2", pagination=pagination)
