from __future__ import annotations

from flask import Blueprint, render_template
from flask_security import login_required

from .auth import require_super_admin

bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")
bp.before_request(require_super_admin)


@bp.route("/")
@login_required
def index():
    # All data is loaded client-side via /api/stats, /api/recent_errors,
    # and /api/sns/recent — no server-side DB queries needed here.
    return render_template("dashboard.jinja2")
