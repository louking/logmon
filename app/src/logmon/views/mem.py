from __future__ import annotations

from flask import Blueprint, render_template, current_app
from flask_security import login_required

from .auth import require_super_admin

bp = Blueprint("mem", __name__, url_prefix="/mem")
bp.before_request(require_super_admin)


@bp.route("/history")
@login_required
def mem_history():
    return render_template(
        "mem_history.jinja2",
        swap_threshold_pct=current_app.config.get("SWAP_ALERT_THRESHOLD_PCT", 90),
    )
