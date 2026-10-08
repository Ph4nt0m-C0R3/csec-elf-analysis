from __future__ import annotations

import io
import re

from werkzeug.security import generate_password_hash

from conftest import minimal_elf64
from revlearn.database import (
    create_user,
    get_analysis_record,
    list_analysis_records,
)


def csrf_from(response) -> str:
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


def create_student(app, email: str):
    with app.app_context():
        return create_user(
            email=email,
            display_name="History Student",
            password_hash=generate_password_hash(
                "classroom-pass-123", method="scrypt"
            ),
            role="student",
        )


def login(client, email: str):
    page = client.get("/login")
    return client.post(
        "/login",
        data={
            "csrf_token": csrf_from(page),
            "email": email,
            "password": "classroom-pass-123",
        },
        follow_redirects=True,
    )


def logout(client):
    account = client.get("/account")
    return client.post(
        "/logout",
        data={"csrf_token": csrf_from(account)},
        follow_redirects=True,
    )


def analyze_file(client, filename="student-history.elf"):
    page = client.get("/")
    return client.post(
        "/analyze",
        data={
            "csrf_token": csrf_from(page),
            "binary": (io.BytesIO(minimal_elf64()), filename),
        },
        content_type="multipart/form-data",
    )


def analysis_id_from(response) -> str:
    match = re.search(rb"/reports/([a-f0-9]+)\.pdf", response.data)
    assert match
    return match.group(1).decode()


def test_student_report_persists_until_owner_deletes_it(client, app):
    first = create_student(app, "first@example.test")
    create_student(app, "second@example.test")
    login(client, "first@example.test")

    report = analyze_file(client)
    assert report.status_code == 200
    assert b"Saved to your private report history" in report.data
    assert list(__import__("pathlib").Path(app.config["UPLOAD_DIR"]).glob("*")) == []
    analysis_id = analysis_id_from(report)

    history = client.get("/student/reports")
    assert b"student-history.elf" in history.data
    assert client.get(f"/student/reports/{analysis_id}").status_code == 200
    assert client.get(f"/reports/{analysis_id}.pdf").status_code == 200

    logout(client)
    login(client, "second@example.test")
    assert client.get(f"/student/reports/{analysis_id}").status_code == 404
    assert client.get(f"/reports/{analysis_id}.pdf").status_code == 400

    logout(client)
    login(client, "first@example.test")
    history = client.get("/student/reports")
    confirmation = client.get(f"/student/reports/{analysis_id}/delete")
    assert confirmation.status_code == 200
    assert b"permanently deletes your saved analysis result" in confirmation.data
    deleted = client.post(
        f"/student/reports/{analysis_id}/delete",
        data={"csrf_token": csrf_from(history)},
        follow_redirects=True,
    )
    assert b"Deleted the saved report" in deleted.data
    assert b"Review report" not in deleted.data
    assert client.get(f"/reports/{analysis_id}.pdf").status_code == 400
    with app.app_context():
        assert get_analysis_record(first["user_id"], analysis_id) is None


def test_guest_reports_are_temporary_and_student_comparison_saves_both(client, app):
    guest_report = analyze_file(client, "guest.elf")
    assert b"Saved to your private report history" not in guest_report.data

    student = create_student(app, "student@example.test")
    login(client, "student@example.test")
    form = client.get("/compare")
    response = client.post(
        "/compare",
        data={
            "csrf_token": csrf_from(form),
            "binary_left": (io.BytesIO(minimal_elf64()), "weak.elf"),
            "binary_right": (
                io.BytesIO(minimal_elf64(pie=True)),
                "hardened.elf",
            ),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    with app.app_context():
        records = list_analysis_records(student["user_id"])
    assert {record["filename"] for record in records} == {
        "weak.elf",
        "hardened.elf",
    }
