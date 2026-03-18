from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, render_template
from flask_security import login_required
from sqlalchemy import func

from ..model import db, LogEvent, SnsNotification
from .auth import require_super_admin

bp = Blueprint("dashboard", __name__)
bp.before_request(require_super_admin)

@bp.route("/dashboard")
@login_required
def index():
    recent_errors = (
        LogEvent.query
        .filter(LogEvent.level == "ERROR")
        .order_by(LogEvent.occurred_at.desc())
        .limit(20)
        .all()
    )

    since = datetime.now() - timedelta(hours=24)
    app_counts = (
        db.session.query(LogEvent.app_name, func.count(LogEvent.id))
        .filter(LogEvent.level == "ERROR", LogEvent.occurred_at >= since)
        .group_by(LogEvent.app_name)
        .all()
    )

    recent_sns = (
        SnsNotification.query
        .order_by(SnsNotification.received_at.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "dashboard.jinja2",
        recent_errors=recent_errors,
        app_counts=app_counts,
        recent_sns=recent_sns,
    )
