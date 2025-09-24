# app/rtb_api_key.py
from flask import request, abort, current_app
import os

def rtb_api_key_protect(app):
    """
    Simple Flask before_request hook to require an API key for any /api/* endpoint.
    Usage: call rtb_api_key_protect(app) after app is created (before serving).
    """

    @app.before_request
    def _enforce_rtb_api_key():
        # Only protect API endpoints
        path = request.path or ""
        if not path.startswith("/api/"):
            return None  # allow other routes (admin, static, etc.)

        # Allow health checks (optional)
        if path.startswith("/api/health") or path.startswith("/api/ping"):
            return None

        # Fetch expected key from env
        expected = os.environ.get("RTB_API_KEY")
        if not expected:
            # If RTB_API_KEY isn't set, default to blocking access to be safe
            current_app.logger.warning("RTB_API_KEY not set; rejecting /api/ requests")
            abort(401, description="API key not configured")

        auth = request.headers.get("Authorization", "")
        # Accept "Bearer <token>" form
        if not auth or not auth.startswith("Bearer "):
            abort(401, description="Missing Authorization header")

        token = auth.split(" ", 1)[1].strip()
        if token != expected:
            abort(401, description="Invalid API key")

        # allowed
        return None
