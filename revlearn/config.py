"""Environment-based application configuration."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


class Config:
    """Safe defaults for a local, single-process classroom deployment."""

    _root = Path(__file__).resolve().parent.parent
    _instance = _root / "instance"
    _configured_secret = os.getenv("REVLEARN_SECRET_KEY")

    SECRET_KEY = _configured_secret or secrets.token_hex(32)
    SECRET_KEY_WAS_CONFIGURED = bool(_configured_secret)
    MAX_CONTENT_LENGTH = (
        _bounded_int("REVLEARN_MAX_UPLOAD_MB", 10, 1, 100) * 1024 * 1024
    )
    ANALYSIS_TIMEOUT = _bounded_int(
        "REVLEARN_ANALYSIS_TIMEOUT", 5, 1, 30
    )
    MAX_STRINGS = _bounded_int("REVLEARN_MAX_STRINGS", 500, 25, 5000)
    MAX_INSTRUCTIONS = _bounded_int(
        "REVLEARN_MAX_INSTRUCTIONS", 400, 25, 2000
    )
    RATE_LIMIT = _bounded_int("REVLEARN_RATE_LIMIT", 20, 1, 1000)
    RATE_WINDOW = _bounded_int("REVLEARN_RATE_WINDOW", 60, 10, 3600)
    UPLOAD_DIR = str(_instance / "uploads")
    DATABASE = str(_instance / "learning.db")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("REVLEARN_HTTPS", "0") == "1"
    MAX_FORM_MEMORY_SIZE = 256 * 1024
