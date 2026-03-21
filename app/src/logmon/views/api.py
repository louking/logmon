from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request
from flask_security import login_required
from sqlalchemy import func

from ..model import db
from ..model import LogEvent, SnsNotification
from ..follower import get_all_tails, get_tail
from .auth import require_super_admin

bp = Blueprint("api", __name__, url_prefix="/api")
bp.before_request(require_super_admin)


@bp.route("/tail/<app_name>")
@login_required
def tail(app_name: str):
    n    = request.args.get("n", 100, type=int)
    kind = request.args.get("kind", "app")   # "app" or "access"
    if kind not in ("app", "access"):
        kind = "app"
    return jsonify(get_tail(
        app_name, n, kind=kind,
        flask_app=current_app._get_current_object(),
    ))


@bp.route("/tail")
@login_required
def tail_all():
    n    = request.args.get("n", 50, type=int)
    kind = request.args.get("kind", "app")
    if kind not in ("app", "access"):
        kind = "app"
    return jsonify(get_all_tails(
        n, kind=kind,
        flask_app=current_app._get_current_object(),
    ))


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
