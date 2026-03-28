"""
views/access.py — Access-analysis views: bad-actor report and CPU utilization.

Routes
------
GET /access/                      bad-actor report page
GET /access/cpu                   CPU utilization chart page
GET /api/access/bad_actors        JSON data for bad-actor table
GET /api/access/cpu               JSON data for CPU chart
GET /api/access/bad_actors/summary  JSON – used by dashboard tile
"""

from __future__ import annotations

from flask import Blueprint, render_template
from flask_security import login_required

from .auth import require_super_admin

bp = Blueprint("access", __name__, url_prefix="/access")
bp.before_request(require_super_admin)


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@bp.route("/")
@login_required
def index():
    """Bad-actor report page."""
    return render_template("bad_actors.jinja2")


@bp.route("/cpu")
@login_required
def cpu():
    """CPU utilization chart page."""
    return render_template("cpu.jinja2")


