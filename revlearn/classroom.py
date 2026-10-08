"""Distinct Student, Instructor, and Administrator capabilities."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from .auth import registration_errors
from .database import (
    create_user,
    delete_analysis_record,
    get_analysis_record,
    get_completed_topics,
    get_learning_content,
    get_learning_map,
    get_recent_audit_events,
    list_users,
    list_analysis_records,
    record_audit_event,
    set_learning_progress,
    set_user_access,
    update_learning_topic,
)
from .security import csrf_is_valid, roles_required
from .routes import forget_report


bp = Blueprint("classroom", __name__)


@bp.get("/student")
@roles_required("student")
def student_dashboard():
    topics = get_learning_content()
    completed = get_completed_topics(g.user["user_id"])
    reports = list_analysis_records(g.user["user_id"])
    return render_template(
        "classroom/student.html",
        topics=topics,
        completed_topics=completed,
        completed_total=len(completed),
        topic_total=len(topics),
        report_total=len(reports),
    )


@bp.get("/student/reports")
@roles_required("student")
def report_history():
    return render_template(
        "classroom/report_history.html",
        records=list_analysis_records(g.user["user_id"]),
    )


@bp.get("/student/reports/<analysis_id>")
@roles_required("student")
def saved_report(analysis_id: str):
    record = get_analysis_record(g.user["user_id"], analysis_id)
    if record is None:
        abort(404)
    return render_template(
        "result.html",
        result=record["result"],
        saved_record=record,
        saved_to_history=True,
    )


@bp.route("/student/reports/<analysis_id>/delete", methods=("GET", "POST"))
@roles_required("student")
def delete_report(analysis_id: str):
    record = get_analysis_record(g.user["user_id"], analysis_id)
    if record is None:
        abort(404)
    if request.method == "GET":
        return render_template("classroom/report_delete.html", record=record)
    if not csrf_is_valid():
        return _invalid_request(
            "The report-deletion form expired or failed its security check."
        )
    delete_analysis_record(g.user["user_id"], analysis_id)
    forget_report(analysis_id)
    record_audit_event(
        "student.analysis_delete",
        actor_user_id=g.user["user_id"],
        target_type="analysis_record",
        target_id=analysis_id,
    )
    flash(f"Deleted the saved report for {record['filename']}.", "success")
    return redirect(url_for("classroom.report_history"))


@bp.post("/student/progress/<topic>")
@roles_required("student")
def update_progress(topic: str):
    if not csrf_is_valid():
        return _invalid_request(
            "The learning-progress form expired or failed its security check."
        )
    completed = request.form.get("completed") == "1"
    try:
        set_learning_progress(g.user["user_id"], topic, completed)
    except ValueError as error:
        return _invalid_request(str(error))
    record_audit_event(
        "student.progress_update",
        actor_user_id=g.user["user_id"],
        target_type="learning_topic",
        target_id=topic,
        details="completed" if completed else "not completed",
    )
    flash("Learning progress updated.", "success")
    if request.form.get("return_to") == "detail":
        return redirect(url_for("main.learning_detail", topic=topic))
    return redirect(url_for("classroom.student_dashboard", _anchor=topic))


@bp.get("/instructor")
@roles_required("instructor", "admin")
def instructor_dashboard():
    return render_template(
        "classroom/instructor.html",
        topics=get_learning_content(),
    )


@bp.post("/instructor/learning/<topic>")
@roles_required("instructor", "admin")
def update_learning(topic: str):
    if not csrf_is_valid():
        return _invalid_request(
            "The learning-content form expired or failed its security check."
        )
    current = get_learning_map().get(topic)
    if current is None:
        return _invalid_request("The selected learning topic does not exist.")
    values = {
        "title": request.form.get("title", "").strip(),
        "category": request.form.get("category", "").strip(),
        "explanation": request.form.get("explanation", "").strip(),
        "risk": request.form.get("risk", "").strip(),
        "recommendation": request.form.get("recommendation", "").strip(),
        "vulnerable_example": request.form.get(
            "vulnerable_example", current["vulnerable_example"]
        ).strip(),
        "secure_example": request.form.get(
            "secure_example", current["secure_example"]
        ).strip(),
        "review_steps": request.form.get(
            "review_steps", current["review_steps"]
        ).strip(),
        "technical_details": request.form.get(
            "technical_details", current["technical_details"]
        ).strip(),
        "lab_exercise": request.form.get(
            "lab_exercise", current["lab_exercise"]
        ).strip(),
        "expected_observations": request.form.get(
            "expected_observations", current["expected_observations"]
        ).strip(),
    }
    errors = _learning_content_errors(values)
    if errors:
        for error in errors:
            flash(error, "error")
        return redirect(url_for("classroom.instructor_dashboard", _anchor=topic))
    try:
        update_learning_topic(topic, **values)
    except ValueError as error:
        return _invalid_request(str(error))
    record_audit_event(
        "instructor.learning_update",
        actor_user_id=g.user["user_id"],
        target_type="learning_topic",
        target_id=topic,
    )
    flash(f"Updated learning topic: {values['title']}.", "success")
    return redirect(url_for("classroom.instructor_dashboard", _anchor=topic))


@bp.get("/admin")
@roles_required("admin")
def admin_dashboard():
    return render_template(
        "classroom/admin.html",
        users=list_users(),
        audit_events=get_recent_audit_events(),
    )


@bp.route("/admin/instructors/new", methods=("GET", "POST"))
@roles_required("admin")
def create_instructor():
    values = {
        "display_name": request.form.get("display_name", "").strip(),
        "email": request.form.get("email", "").strip().lower(),
    }
    errors: list[str] = []
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if not csrf_is_valid():
            errors.append(
                "The instructor form expired or failed its security check."
            )
        errors.extend(
            registration_errors(
                values["display_name"],
                values["email"],
                password,
                confirmation,
            )
        )
        if not errors:
            try:
                instructor = create_user(
                    email=values["email"],
                    display_name=values["display_name"],
                    password_hash=generate_password_hash(
                        password, method="scrypt"
                    ),
                    role="instructor",
                )
            except sqlite3.IntegrityError:
                errors.append(
                    "An account with that email address already exists."
                )
            else:
                record_audit_event(
                    "admin.instructor_create",
                    actor_user_id=g.user["user_id"],
                    target_type="user",
                    target_id=str(instructor["user_id"]),
                    details="Created as an active Instructor from the Admin UI.",
                )
                flash(
                    f"Instructor account created for {instructor['email']}.",
                    "success",
                )
                return redirect(url_for("classroom.admin_dashboard"))
    return render_template(
        "classroom/admin_instructor_form.html",
        values=values,
        errors=errors,
    ), (400 if errors else 200)


@bp.post("/admin/users/<int:user_id>")
@roles_required("admin")
def update_user(user_id: int):
    if not csrf_is_valid():
        return _invalid_request(
            "The account-management form expired or failed its security check."
        )
    role = request.form.get("role", "")
    active = request.form.get("active") == "1"
    try:
        updated = set_user_access(
            target_user_id=user_id,
            role=role,
            active=active,
            acting_user_id=g.user["user_id"],
        )
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("classroom.admin_dashboard"))
    record_audit_event(
        "admin.user_access_update",
        actor_user_id=g.user["user_id"],
        target_type="user",
        target_id=str(user_id),
        details=f"role={updated['role']}; active={bool(updated['active'])}",
    )
    flash(f"Updated access for {updated['email']}.", "success")
    return redirect(url_for("classroom.admin_dashboard"))


def _learning_content_errors(values: dict[str, str]) -> list[str]:
    limits = {
        "title": (2, 120),
        "category": (2, 80),
        "explanation": (10, 2000),
        "risk": (10, 2000),
        "recommendation": (10, 2000),
        "vulnerable_example": (10, 12000),
        "secure_example": (10, 12000),
        "review_steps": (20, 4000),
        "technical_details": (40, 5000),
        "lab_exercise": (30, 5000),
        "expected_observations": (30, 5000),
    }
    labels = {
        "title": "Title",
        "category": "Category",
        "explanation": "Explanation",
        "risk": "Risk guidance",
        "recommendation": "Recommendation",
        "vulnerable_example": "Vulnerable example",
        "secure_example": "Secure example",
        "review_steps": "Review guidance",
        "technical_details": "Technical details",
        "lab_exercise": "Lab exercise",
        "expected_observations": "Expected observations",
    }
    errors = []
    for field, (minimum, maximum) in limits.items():
        if not minimum <= len(values[field]) <= maximum:
            errors.append(
                f"{labels[field]} must contain between {minimum} and {maximum} characters."
            )
    return errors


def _invalid_request(message: str):
    return render_template(
        "error.html",
        title="Invalid request",
        message=message,
        guidance="Refresh the page and try again.",
    ), 400


def init_app(app) -> None:
    app.register_blueprint(bp)
