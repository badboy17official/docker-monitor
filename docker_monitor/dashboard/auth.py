"""Dashboard authentication helpers."""

from __future__ import annotations

import os
import secrets
from functools import wraps
from hmac import compare_digest

from flask import Flask, redirect, request, session, url_for


def configure_auth(app: Flask):
    """Configure Flask app authentication."""
    secret = os.getenv("SECRET_KEY")
    if not secret:
        secret = secrets.token_hex(32)
    app.secret_key = secret

    user = os.getenv("DASHBOARD_AUTH_USER", "")
    password = os.getenv("DASHBOARD_AUTH_PASSWORD", "")
    allow_insecure = os.getenv("DASHBOARD_ALLOW_INSECURE", "").lower() == "true"

    app.config["AUTH_USER"] = user
    app.config["AUTH_PASSWORD"] = password
    app.config["AUTH_ENABLED"] = bool(user and password)
    app.config["ALLOW_INSECURE"] = allow_insecure

    if not allow_insecure and not (user and password):
        import logging
        logging.warning(
            "Dashboard auth not configured. Set DASHBOARD_AUTH_USER and DASHBOARD_AUTH_PASSWORD, "
            "or DASHBOARD_ALLOW_INSECURE=true for local dev."
        )


def is_authorized(app) -> bool:
    """Check if the current request is authorized."""
    if not app.config.get("AUTH_ENABLED"):
        return True

    if session.get("authenticated"):
        return True

    auth = request.authorization
    if auth and (auth.type or "").lower() == "basic":
        return (
            compare_digest(auth.username or "", app.config.get("AUTH_USER", ""))
            and compare_digest(auth.password or "", app.config.get("AUTH_PASSWORD", ""))
        )

    return False


def require_auth(view_func):
    """Decorator to require authentication on a route."""
    from flask import current_app, jsonify

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if is_authorized(current_app):
            return view_func(*args, **kwargs)
        if request.path == "/" or request.path.startswith("/reports/"):
            return redirect(url_for("login"))
        return jsonify({"success": False, "error": "Authentication required"}), 401

    return wrapper
