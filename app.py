"""Application entry point for the ELF Security Learning System."""

from __future__ import annotations

import os

from revlearn import create_app as _create_app


def create_app():
    """WSGI application factory used by Flask and Waitress."""
    return _create_app()


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.getenv("REVLEARN_HOST", "127.0.0.1"),
        port=int(os.getenv("REVLEARN_PORT", "5000")),
        debug=os.getenv("REVLEARN_DEBUG", "0") == "1",
    )

