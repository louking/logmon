from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request
from flask_security import login_required
from sqlalchemy import func

from datetime import datetime, timedelta, timezone

from ..access_analysis import get_bad_actors, get_bad_actors_summary, get_cpu_metrics, get_access_rate
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

    actors = get_bad_actors(start=start, end=end, flask_app=current_app._get_current_object(), threshold=threshold, limit=limit)

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
    actors = get_bad_actors_summary(threshold=threshold, hours=hours, flask_app=current_app._get_current_object())
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

# ---------------------------------------------------------------------------
# JSON API — Disk usage
# ---------------------------------------------------------------------------

@bp.route("/disk/summary")
@login_required
def api_disk_summary():
    """
    Return the most-recent disk snapshot for the dashboard tile.

    Response shape::

        {
            "collected_at": "2025-01-01T00:00:00",
            "filesystems": [
                {
                    "device":   "/dev/sda1",
                    "mount":    "/",
                    "total_kb": 102400,
                    "used_kb":  51200,
                    "avail_kb": 51200,
                    "use_pct":  50
                },
                ...
            ],
            "docker": {
                "images_size_bytes":             1234567,
                "images_reclaimable_bytes":      123456,
                "images_active":                 3,
                "containers_size_bytes":         0,
                "containers_active":             2,
                "volumes_count":                 4,
                "volumes_size_bytes":            9876,
                "volumes_reclaimable_bytes":     0,
                "build_cache_size_bytes":        0,
                "build_cache_reclaimable_bytes": 0
            },
            "threshold_pct": 85
        }

    ``docker`` is ``null`` when the Docker socket is unavailable.
    ``threshold_pct`` reflects the configured ``DISK_ALERT_THRESHOLD_PCT``.
    """
    from ..diskmon import get_disk_snapshot

    snapshot = get_disk_snapshot(current_app._get_current_object())
    if snapshot is None:
        return jsonify({"error": "No disk snapshot available yet"}), 503

    # Strip verbose image/volume lists — those belong in the detail endpoint.
    docker = snapshot.get("docker")
    if docker is not None:
        docker = {k: v for k, v in docker.items() if k not in ("images", "volumes")}

    return jsonify({
        "collected_at":  snapshot.get("collected_at"),
        "filesystems":   snapshot.get("filesystems", []),
        "docker":        docker,
        "threshold_pct": current_app.config.get("DISK_ALERT_THRESHOLD_PCT", 85),
    })


@bp.route("/disk/detail")
@login_required
def api_disk_detail():
    """
    Return the most-recent full snapshot including per-image and per-volume
    detail lists, for the disk detail view.

    Response shape::

        {
            "collected_at": "2025-01-01T00:00:00",
            "filesystems": [ ... ],          # same as /disk/summary
            "docker": {
                ...summary fields...,
                "images": [
                    {
                        "repository": "nginx",
                        "tag":        "latest",
                        "image_id":   "abc123",
                        "size":       "142MB",
                        "shared_size":"100MB",
                        "unique_size":"42MB"
                    },
                    ...
                ],
                "volumes": [
                    {"name": "myapp_data", "links": "1", "size": "9.6kB"},
                    ...
                ]
            },
            "threshold_pct": 85
        }
    """
    from ..diskmon import get_disk_snapshot

    snapshot = get_disk_snapshot(current_app._get_current_object())
    if snapshot is None:
        return jsonify({"error": "No disk snapshot available yet"}), 503

    return jsonify({
        "collected_at":  snapshot.get("collected_at"),
        "filesystems":   snapshot.get("filesystems", []),
        "docker":        snapshot.get("docker"),
        "threshold_pct": current_app.config.get("DISK_ALERT_THRESHOLD_PCT", 85),
    })

@bp.route("/disk/history")
@login_required
def api_disk_history():
    """
    Return time-series disk usage from the database for charting.

    Query params
    ------------
    mount   str   specific mount point, e.g. ``/`` or ``/var/lib/docker``
                  use ``__docker__`` to get Docker sentinel rows
    hours   int   look-back window (default 24, max 8760 = 1 year)
    docker  "1"   shorthand for mount=__docker__

    Response (filesystem mounts)::

        {
            "mount": "/",
            "hours": 24,
            "points": [
                {"collected_at": "2025-01-01T00:00:00", "use_pct": 52,
                 "used_kb": 53248, "total_kb": 102400},
                ...
            ]
        }

    Response (docker sentinel, mount=__docker__ or docker=1)::

        {
            "mount": "__docker__",
            "hours": 24,
            "points": [
                {
                    "collected_at": "2025-01-01T00:00:00",
                    "images_size_bytes": 1234567,
                    "volumes_size_bytes": 9876,
                    "build_cache_size_bytes": 0,
                    "total_bytes": 1244443
                },
                ...
            ]
        }
    """
    from ..model import db, DiskSnapshot
    from datetime import datetime, timedelta

    hours = min(int(request.args.get("hours", 24)), 8760)
    since = datetime.now() - timedelta(hours=hours)

    use_docker = request.args.get("docker") == "1"
    mount = request.args.get("mount", "__docker__" if use_docker else None)

    query = (
        DiskSnapshot.query
        .filter(DiskSnapshot.collected_at >= since)
        .order_by(DiskSnapshot.collected_at.asc())
    )

    if mount:
        query = query.filter(DiskSnapshot.mount == mount)
    else:
        # All real filesystems (exclude Docker sentinel)
        query = query.filter(DiskSnapshot.mount != "__docker__")

    rows = query.all()

    if mount == "__docker__" or use_docker:
        points = [
            {
                "collected_at":          r.collected_at.isoformat(),
                "images_size_bytes":     r.docker_images_size_bytes,
                "volumes_size_bytes":    r.docker_volumes_size_bytes,
                "build_cache_size_bytes":r.docker_build_cache_size_bytes,
                "total_bytes": (
                    (r.docker_images_size_bytes or 0)
                    + (r.docker_volumes_size_bytes or 0)
                    + (r.docker_build_cache_size_bytes or 0)
                ),
            }
            for r in rows
        ]
    else:
        # Group by mount so the caller gets one series per mount
        from collections import defaultdict
        by_mount: dict = defaultdict(list)
        for r in rows:
            by_mount[r.mount].append({
                "collected_at": r.collected_at.isoformat(),
                "use_pct":      r.use_pct,
                "used_kb":      r.used_kb,
                "total_kb":     r.total_kb,
            })

        if mount:
            # Single mount requested — return flat points list
            return jsonify({
                "mount":  mount,
                "hours":  hours,
                "points": by_mount.get(mount, []),
            })

        # No mount filter — return all mounts as a dict of series
        return jsonify({
            "mount":  None,
            "hours":  hours,
            "series": {m: pts for m, pts in by_mount.items()},
        })

    return jsonify({
        "mount":  mount or "__docker__",
        "hours":  hours,
        "points": points,
    })


# ---------------------------------------------------------------------------
# JSON API — Access rate (for CPU chart overlay)
# ---------------------------------------------------------------------------

@bp.route("/access/rate")
@login_required
def api_access_rate():
    """
    Return per-interval request counts aligned to the CPU sample timestamps.

    Query params: start=, end=  (ISO, same as /access/cpu)

    The caller should first fetch /access/cpu to get the timestamps, then
    pass those same start/end values here so the intervals line up.

    Response::
        {
            "start": "...",
            "end":   "...",
            "points": [
                {"timestamp": "2025-01-01T00:00:00", "req_count": 42},
                ...
            ]
        }
    """
    start, end = _parse_window()

    # Fetch CPU points first to get the canonical timestamps
    cpu_points = get_cpu_metrics(current_app._get_current_object(), start=start, end=end)
    timestamps = [datetime.fromisoformat(p["timestamp"]) for p in cpu_points]

    points = get_access_rate(
        current_app._get_current_object(),
        start=start,
        end=end,
        timestamps=timestamps,
    )
    return jsonify({"start": start.isoformat(), "end": end.isoformat(), "points": points})