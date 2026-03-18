from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_security import login_required
from sqlalchemy import func

from ..follower import get_all_tails, get_tail
from ..model import db, LogEvent, SnsNotification
from .auth import require_super_admin

bp = Blueprint("api", __name__, url_prefix="/api")
bp.before_request(require_super_admin)


@bp.route("/tail/<app_name>")
@login_required
def tail(app_name: str):
    return jsonify(get_tail(app_name, request.args.get("n", 100, type=int)))


@bp.route("/tail")
@login_required
def tail_all():
    return jsonify(get_all_tails(request.args.get("n", 50, type=int)))


@bp.route("/stats")
@login_required
def stats():
    hours = request.args.get("hours", 24, type=int)
    since = datetime.now() - timedelta(hours=hours)
    rows = (
        db.session.query(LogEvent.app_name, func.count(LogEvent.id))
        .filter(LogEvent.level == "ERROR", LogEvent.occurred_at >= since)
        .group_by(LogEvent.app_name)
        .all()
    )
    return jsonify({app: count for app, count in rows})


@bp.route("/recent_errors")
@login_required
def recent_errors():
    events = (
        LogEvent.query
        .filter(LogEvent.level == "ERROR")
        .order_by(LogEvent.occurred_at.desc())
        .limit(request.args.get("n", 20, type=int))
        .all()
    )
    return jsonify([e.to_dict() for e in events])


@bp.route("/sns/recent")
@login_required
def sns_recent():
    items = (
        SnsNotification.query
        .order_by(SnsNotification.received_at.desc())
        .limit(request.args.get("n", 10, type=int))
        .all()
    )
    return jsonify([i.to_dict() for i in items])
