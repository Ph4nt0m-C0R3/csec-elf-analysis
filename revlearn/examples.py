"""Browsable binary-learning examples and staff authoring workflows."""

from __future__ import annotations

import re
import sqlite3

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from .database import (
    create_binary_example,
    get_binary_example_by_slug,
    list_binary_examples,
    record_audit_event,
    update_binary_example,
)
from .security import csrf_is_valid, roles_required


bp = Blueprint("examples", __name__)
_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_DIFFICULTIES = ("beginner", "intermediate", "advanced")


@bp.get("/examples")
def index():
    return render_template(
        "examples/index.html",
        examples=list_binary_examples(),
    )


@bp.get("/examples/<slug>")
def detail(slug: str):
    can_preview = bool(
        g.get("user") and g.user["role"] in {"instructor", "admin"}
    )
    example = get_binary_example_by_slug(
        slug, include_unpublished=can_preview
    )
    if example is None:
        abort(404)
    return render_template(
        "examples/detail.html",
        example=example,
        can_manage=can_preview,
    )


@bp.get("/instructor/examples")
@roles_required("instructor", "admin")
def manage():
    return render_template(
        "examples/manage.html",
        examples=list_binary_examples(include_unpublished=True),
    )


@bp.route("/instructor/examples/new", methods=("GET", "POST"))
@roles_required("instructor", "admin")
def create():
    values = _form_values()
    errors: list[str] = []
    if request.method == "POST":
        if not csrf_is_valid():
            errors.append(
                "The example form expired or failed its security check."
            )
        errors.extend(_example_errors(values))
        if not errors:
            try:
                example = create_binary_example(
                    author_user_id=g.user["user_id"], **values
                )
            except sqlite3.IntegrityError:
                errors.append("That URL slug is already used by another example.")
            else:
                record_audit_event(
                    "instructor.example_create",
                    actor_user_id=g.user["user_id"],
                    target_type="binary_example",
                    target_id=str(example["example_id"]),
                    details=f"slug={example['slug']}; published={bool(example['published'])}",
                )
                flash("Binary learning example created.", "success")
                return redirect(url_for("examples.manage"))
    return render_template(
        "examples/form.html",
        heading="Add binary learning example",
        introduction="Create a safe, reproducible lesson without uploading or distributing an executable file.",
        values=values,
        errors=errors,
        difficulties=_DIFFICULTIES,
    ), (400 if errors else 200)


@bp.route("/instructor/examples/<slug>/edit", methods=("GET", "POST"))
@roles_required("instructor", "admin")
def edit(slug: str):
    example = get_binary_example_by_slug(slug, include_unpublished=True)
    if example is None:
        abort(404)
    values = _form_values(example)
    errors: list[str] = []
    if request.method == "POST":
        if not csrf_is_valid():
            errors.append(
                "The example form expired or failed its security check."
            )
        errors.extend(_example_errors(values))
        if not errors:
            try:
                updated = update_binary_example(example["example_id"], **values)
            except sqlite3.IntegrityError:
                errors.append("That URL slug is already used by another example.")
            else:
                record_audit_event(
                    "instructor.example_update",
                    actor_user_id=g.user["user_id"],
                    target_type="binary_example",
                    target_id=str(updated["example_id"]),
                    details=f"slug={updated['slug']}; published={bool(updated['published'])}",
                )
                flash("Binary learning example updated.", "success")
                return redirect(url_for("examples.manage"))
    return render_template(
        "examples/form.html",
        heading="Edit binary learning example",
        introduction="Keep the lesson reproducible, defensive, and suitable for authorized classroom use.",
        values=values,
        errors=errors,
        difficulties=_DIFFICULTIES,
    ), (400 if errors else 200)


def _form_values(existing: dict | None = None) -> dict:
    existing = existing or {}
    title = request.form.get("title", existing.get("title", "")).strip()
    supplied_slug = request.form.get("slug", existing.get("slug", "")).strip()
    return {
        "title": title,
        "slug": supplied_slug or _slugify(title),
        "summary": request.form.get(
            "summary", existing.get("summary", "")
        ).strip(),
        "difficulty": request.form.get(
            "difficulty", existing.get("difficulty", "beginner")
        ).strip().lower(),
        "architecture": request.form.get(
            "architecture", existing.get("architecture", "x86-64 ELF")
        ).strip(),
        "source_code": request.form.get(
            "source_code", existing.get("source_code", "")
        ).strip(),
        "build_command": request.form.get(
            "build_command", existing.get("build_command", "")
        ).strip(),
        "expected_findings": request.form.get(
            "expected_findings", existing.get("expected_findings", "")
        ).strip(),
        "walkthrough": request.form.get(
            "walkthrough", existing.get("walkthrough", "")
        ).strip(),
        "published": (
            request.form.get("published") == "1"
            if request.method == "POST"
            else bool(existing.get("published"))
        ),
    }


def _slugify(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")


def _example_errors(values: dict) -> list[str]:
    errors = []
    limits = {
        "title": (4, 120, "Title"),
        "summary": (20, 500, "Summary"),
        "architecture": (2, 80, "Architecture"),
        "source_code": (20, 12000, "Source code"),
        "build_command": (5, 4000, "Build command"),
        "expected_findings": (20, 4000, "Expected findings"),
        "walkthrough": (30, 8000, "Walkthrough"),
    }
    for field, (minimum, maximum, label) in limits.items():
        if not minimum <= len(values[field]) <= maximum:
            errors.append(
                f"{label} must contain between {minimum} and {maximum} characters."
            )
    if len(values["slug"]) > 100 or not _SLUG_PATTERN.fullmatch(values["slug"]):
        errors.append(
            "URL slug must use lowercase letters, numbers, and single hyphens only."
        )
    if values["difficulty"] not in _DIFFICULTIES:
        errors.append("Select a valid difficulty level.")
    return errors


def init_app(app) -> None:
    app.register_blueprint(bp)
