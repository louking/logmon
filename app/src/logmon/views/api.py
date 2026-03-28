from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request
from flask_security import login_required
from sqlalchemy import func

from datetime import datetime, timedelta, timezone

from ..access_analysis import get_bad_actors, get_bad_actors_summary, get_cpu_metrics
from ..model import db
from ..model import LogEvent, SnsNotification
from ..follower import get_all_tails, get_tail
from .auth import require_super_admin

bp = Blueprint("api", __name__, url_prefix="/api")
bp.before_request(require_super_admin)


# ---------------------------------------------------------------------------
# JSON API helpers
# ---------------------------------------------------------------------------

def _parse_window() -> tuple[datetime, datetime]:
    """Parse ?start= and ?end= ISO query params; default to last 24 h."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    raw_start = request.args.get("start")
    raw_end   = request.args.get("end")

    try:
        end = datetime.fromisoformat(raw_end) if raw_end else now
    except ValueError:
        end = now

    try:
        start = datetime.fromisoformat(raw_start) if raw_start else end - timedelta(hours=24)
    except ValueError:
        start = end - timedelta(hours=24)

    return start, end



# ---------------------------------------------------------------------------
# JSON API — Logs / dashboard
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# JSON API — SNS notifications
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# JSON API — bad actors
# ---------------------------------------------------------------------------

@bp.route("/access/bad_actors")
@login_required
def api_bad_actors():
    start, end = _parse_window()
    threshold = int(request.args.get("threshold", 0))
    limit     = int(request.args.get("limit", 100))

    actors = get_bad_actors(start=start, end=end, threshold=threshold, limit=limit)

    return jsonify(
        {
            "start": start.isoformat(),
            "end":   end.isoformat(),
            "threshold": threshold,
            "actors": actors,
        }
    )


@bp.route("/access/bad_actors/summary")
@login_required
def api_bad_actors_summary():
    """Lightweight endpoint for the dashboard tile.

    Uses the configured BAD_ACTOR_THRESHOLD (default 200) and looks back
    BAD_ACTOR_WINDOW_HOURS hours (default 24).
    """
    threshold = int(
        request.args.get(
            "threshold",
            current_app.config.get("BAD_ACTOR_THRESHOLD", 200),
        )
    )
    hours = int(
        request.args.get(
            "hours",
            current_app.config.get("BAD_ACTOR_WINDOW_HOURS", 24),
        )
    )
    actors = get_bad_actors_summary(threshold=threshold, hours=hours)
    return jsonify(
        {
            "threshold": threshold,
            "hours": hours,
            "actors": actors,
        }
    )


# ---------------------------------------------------------------------------
# JSON API — CPU
# ---------------------------------------------------------------------------

@bp.route("/access/cpu")
@login_required
def api_cpu():
    start, end = _parse_window()
    points = get_cpu_metrics(current_app._get_current_object(), start=start, end=end)
    return jsonify(
        {
            "start": start.isoformat(),
            "end":   end.isoformat(),
            "points": points,
        }
    )
