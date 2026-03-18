from __future__ import annotations

from flask import Blueprint, current_app, render_template, request
from flask_security import login_required

from ..model import db, LogEvent
from .auth import require_super_admin

bp = Blueprint("logs", __name__, url_prefix="/logs")
bp.before_request(require_super_admin)

@bp.route("/")
@login_required
def index():
    # Apps that have events
    db_apps = [r[0] for r in db.session.query(LogEvent.app_name).distinct().all()]
    # Apps configured but not yet seen
    cfg_apps = [e.name for e in current_app.config.get("LOG_APPS", [])]
    app_names = sorted(set(db_apps) | set(cfg_apps))
    return render_template("logs_index.jinja2", app_names=app_names)


@bp.route("/<app_name>")
@login_required
def app_log(app_name: str):
    page = request.args.get("page", 1, type=int)
    level = request.args.get("level", "")
    search = request.args.get("q", "")

    q = LogEvent.query.filter_by(app_name=app_name)
    if level:
        q = q.filter(LogEvent.level == level.upper())
    if search:
        q = q.filter(db.or_(
            LogEvent.message.ilike(f"%{search}%"),
            LogEvent.exception_type.ilike(f"%{search}%"),
            LogEvent.url.ilike(f"%{search}%"),
        ))
    pagination = q.order_by(LogEvent.occurred_at.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template(
        "app_log.jinja2",
        app_name=app_name,
        pagination=pagination,
        level=level,
        search=search,
    )


@bp.route("/<app_name>/event/<int:event_id>")
@login_required
def event_detail(app_name: str, event_id: int):
    event = LogEvent.query.filter_by(id=event_id, app_name=app_name).first_or_404()
    return render_template("event_detail.jinja2", event=event)


@bp.route("/live")
@login_required
def live():
    app_names = [e.name for e in current_app.config.get("LOG_APPS", [])]
    selected = request.args.get("app", app_names[0] if app_names else "")
    return render_template("live_tail.jinja2", app_names=app_names, selected=selected)
