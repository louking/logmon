from __future__ import annotations

from flask import Blueprint, render_template, current_app
from flask_security import login_required

from .auth import require_super_admin

bp = Blueprint("disk", __name__, url_prefix="/disk")
bp.before_request(require_super_admin)

@bp.route("/detail")
@login_required
def disk_detail():
    from flask import current_app, render_template
    return render_template(
        "disk_detail.jinja2",
        threshold_pct=current_app.config.get("DISK_ALERT_THRESHOLD_PCT", 85),
    )
