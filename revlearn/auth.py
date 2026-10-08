"""Account authentication, role-aware pages, and administrative access."""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from collections import defaultdict, deque

import click
from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .database import (
    create_user,
    get_user_by_email,
    get_user_by_id,
    mark_user_login,
    record_audit_event,
)
from .security import (
    ROLES,
    csrf_is_valid,
    csrf_token,
    login_required,
    safe_next_url,
)


bp = Blueprint("auth", __name__)
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_AUTH_FAILURES: dict[str, deque[float]] = defaultdict(deque)
_AUTH_FAILURES_LOCK = threading.Lock()
_AUTH_FAILURE_LIMIT = 8
_AUTH_FAILURE_WINDOW = 5 * 60
_DUMMY_PASSWORD_HASH = generate_password_hash(
    "not-a-real-account-password", method="scrypt"
)


@bp.before_app_request
def load_logged_in_user() -> None:
    user_id = session.get("user_id")
    user = None
    if isinstance(user_id, int):
        user = get_user_by_id(user_id)
        if user is not None and not user["active"]:
            session.clear()
            user = None
        elif user is not None:
            user.pop("password_hash", None)
    g.user = user


@bp.app_context_processor
def inject_account_context() -> dict:
    return {
        "current_user": g.get("user"),
        "csrf_token": csrf_token(),
    }


@bp.route("/register", methods=("GET", "POST"))
def register():
    if g.get("user") is not None:
        return redirect(url_for("auth.account"))

    errors: list[str] = []
    values = {
        "display_name": request.form.get("display_name", "").strip(),
        "email": request.form.get("email", "").strip().lower(),
    }
    if request.method == "POST":
        if not csrf_is_valid():
            errors.append("The form expired or failed its security check. Refresh and try again.")
        errors.extend(
            registration_errors(
                values["display_name"],
                values["email"],
                request.form.get("password", ""),
                request.form.get("confirm_password", ""),
            )
        )
        if not errors:
            try:
                user = create_user(
                    email=values["email"],
                    display_name=values["display_name"],
                    password_hash=generate_password_hash(
                        request.form["password"], method="scrypt"
                    ),
                )
            except sqlite3.IntegrityError:
                errors.append("An account with that email address already exists.")
            else:
                session.clear()
                session["user_id"] = user["user_id"]
                record_audit_event(
                    "auth.register",
                    actor_user_id=user["user_id"],
                    target_type="user",
                    target_id=str(user["user_id"]),
                )
                flash("Your student account is ready.", "success")
                return redirect(url_for("auth.account"))

    return render_template("auth/register.html", errors=errors, values=values), (400 if errors else 200)


@bp.route("/login", methods=("GET", "POST"))
def login():
    if g.get("user") is not None:
        return redirect(url_for("auth.account"))

    errors: list[str] = []
    email = request.form.get("email", "").strip().lower()
    next_url = request.values.get("next", "")
    if request.method == "POST":
        key = request.remote_addr or "local"
        if not csrf_is_valid():
            errors.append("The form expired or failed its security check. Refresh and try again.")
        elif not _auth_attempt_allowed(key):
            errors.append("Too many unsuccessful sign-in attempts. Wait five minutes and try again.")
        else:
            user = get_user_by_email(email)
            password = request.form.get("password", "")
            password_valid = check_password_hash(
                user["password_hash"] if user else _DUMMY_PASSWORD_HASH,
                password,
            )
            if (
                user is None
                or not user["active"]
                or not password_valid
            ):
                _record_auth_failure(key)
                errors.append("The email address or password is incorrect.")
            else:
                _clear_auth_failures(key)
                session.clear()
                session["user_id"] = user["user_id"]
                mark_user_login(user["user_id"])
                record_audit_event(
                    "auth.login",
                    actor_user_id=user["user_id"],
                    target_type="user",
                    target_id=str(user["user_id"]),
                )
                return redirect(safe_next_url(next_url, "auth.account"))

    return render_template("auth/login.html", errors=errors, email=email, next_url=next_url), (400 if errors else 200)


@bp.post("/logout")
@login_required
def logout():
    if not csrf_is_valid():
        return render_template(
            "error.html",
            title="Invalid request",
            message="The sign-out form expired or failed its security check.",
            guidance="Refresh the page and try signing out again.",
        ), 400
    user_id = g.user["user_id"]
    record_audit_event(
        "auth.logout",
        actor_user_id=user_id,
        target_type="user",
        target_id=str(user_id),
    )
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("main.index"))


@bp.get("/account")
@login_required
def account():
    return render_template("auth/account.html")


def registration_errors(
    display_name: str,
    email: str,
    password: str,
    confirmation: str,
) -> list[str]:
    errors = []
    if not 2 <= len(display_name) <= 80:
        errors.append("Display name must contain between 2 and 80 characters.")
    if len(email) > 254 or not _EMAIL_PATTERN.fullmatch(email):
        errors.append("Enter a valid email address.")
    if len(password) < 12:
        errors.append("Password must contain at least 12 characters.")
    elif not any(character.isalpha() for character in password) or not any(
        character.isdigit() for character in password
    ):
        errors.append("Password must include at least one letter and one number.")
    if password != confirmation:
        errors.append("Password confirmation does not match.")
    return errors


def _auth_attempt_allowed(key: str) -> bool:
    now = time.monotonic()
    with _AUTH_FAILURES_LOCK:
        failures = _AUTH_FAILURES[key]
        while failures and now - failures[0] > _AUTH_FAILURE_WINDOW:
            failures.popleft()
        return len(failures) < _AUTH_FAILURE_LIMIT


def _record_auth_failure(key: str) -> None:
    with _AUTH_FAILURES_LOCK:
        _AUTH_FAILURES[key].append(time.monotonic())


def _clear_auth_failures(key: str) -> None:
    with _AUTH_FAILURES_LOCK:
        _AUTH_FAILURES.pop(key, None)


def init_app(app) -> None:
    app.register_blueprint(bp)

    @app.cli.command("create-user")
    @click.option("--email", prompt=True)
    @click.option("--name", "display_name", prompt="Display name")
    @click.option(
        "--role",
        type=click.Choice(ROLES, case_sensitive=False),
        default="admin",
        show_default=True,
    )
    @click.password_option(confirmation_prompt=True)
    def create_user_command(email, display_name, role, password):
        """Create an approved student, instructor, or administrator account."""
        errors = registration_errors(display_name, email, password, password)
        if errors:
            raise click.ClickException(" ".join(errors))
        try:
            user = create_user(
                email=email,
                display_name=display_name,
                password_hash=generate_password_hash(password, method="scrypt"),
                role=role.lower(),
            )
        except sqlite3.IntegrityError as exc:
            raise click.ClickException(
                "An account with that email address already exists."
            ) from exc
        record_audit_event(
            "admin.bootstrap_user",
            actor_user_id=user["user_id"],
            target_type="user",
            target_id=str(user["user_id"]),
            details=f"Created with role {user['role']} from the local CLI.",
        )
        click.echo(f"Created {user['role']} account for {user['email']}.")
