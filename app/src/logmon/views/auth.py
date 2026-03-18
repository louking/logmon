"""
views/auth.py — Shared auth helpers for logmon blueprints.

All protected blueprints call require_super_admin() in a before_request hook
so there is exactly one place to change the required role name.
"""
from __future__ import annotations

from functools import wraps
from flask import abort
from flask_security import current_user

REQUIRED_ROLE = "super-admin"


def require_super_admin():
    """
    Call this from a blueprint's before_request hook.
    Aborts with 403 if the current user is not authenticated or does not
    hold the REQUIRED_ROLE role.  Flask-Security's @login_required on each
    view still handles the redirect-to-login for unauthenticated requests;
    this check is the additional role gate on top of that.
    """
    if not current_user.is_authenticated:
        # Let @login_required on the view handle the redirect
        return
    if not current_user.has_role(REQUIRED_ROLE):
        abort(403)
