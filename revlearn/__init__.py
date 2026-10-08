"""Flask application factory."""

from __future__ import annotations

import logging
from pathlib import Path

from flask import Flask

from .auth import init_app as init_auth
from .classroom import init_app as init_classroom
from .config import Config
from .database import init_app as init_database
from .examples import init_app as init_examples
from .routes import bp


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(
        __name__,
        instance_relative_config=True,
        static_folder="static",
        template_folder="templates",
    )
    app.config.from_object(Config())
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)

    init_database(app)
    init_auth(app)
    init_classroom(app)
    init_examples(app)
    app.register_blueprint(bp)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'",
        )
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        if request_is_sensitive(response):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    if not app.config.get("SECRET_KEY_WAS_CONFIGURED"):
        app.logger.warning(
            "REVLEARN_SECRET_KEY is not set; a random development key is in use."
        )

    logging.getLogger("revlearn").setLevel(logging.INFO)
    return app


def request_is_sensitive(response) -> bool:
    """All HTML and error reports may contain upload-derived information."""
    return response.mimetype == "text/html" or response.status_code >= 400
