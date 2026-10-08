"""Shared session, CSRF, and authorization helpers."""

from __future__ import annotations

import hmac
import secrets
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, g, redirect, request, session, url_for


ROLES = ("student", "instructor", "admin")


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_is_valid() -> bool:
    expected = session.get("csrf_token", "")
    received = request.form.get("csrf_token", "")
    return bool(
        expected
        and received
        and hmac.compare_digest(expected, received)
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            return redirect(
                url_for("auth.login", next=request.full_path.rstrip("?"))
            )
        return view(*args, **kwargs)

    return wrapped


def roles_required(*roles: str):
    allowed = frozenset(roles)
    unknown = allowed.difference(ROLES)
    if unknown:
        raise ValueError(f"Unknown roles: {sorted(unknown)}")

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = g.get("user")
            if user is None:
                return redirect(
                    url_for("auth.login", next=request.full_path.rstrip("?"))
                )
            if user["role"] not in allowed:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def safe_next_url(value: str | None, fallback_endpoint: str) -> str:
    """Allow only local absolute paths as post-login destinations."""
    if value:
        parsed = urlsplit(value)
        if (
            not parsed.scheme
            and not parsed.netloc
            and parsed.path.startswith("/")
            and not parsed.path.startswith("//")
        ):
            return value
    return url_for(fallback_endpoint)
