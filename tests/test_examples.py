from __future__ import annotations

import re

from werkzeug.security import generate_password_hash

from revlearn.database import (
    create_user,
    get_binary_example_by_slug,
    get_recent_audit_events,
)


def csrf_from(response) -> str:
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


def create_role_user(app, email: str, role: str):
    with app.app_context():
        return create_user(
            email=email,
            display_name=f"Example {role.title()}",
            password_hash=generate_password_hash(
                "classroom-pass-123", method="scrypt"
            ),
            role=role,
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


def example_form(**overrides):
    values = {
        "title": "Reviewing an Unsafe Copy",
        "slug": "reviewing-unsafe-copy",
        "summary": "Learn how an imported copy function becomes meaningful when connected to source-level length handling.",
        "difficulty": "beginner",
        "architecture": "x86-64 ELF",
        "source_code": "#include <string.h>\nint main(void) { char out[8]; strcpy(out, \"example\"); return out[0]; }",
        "build_command": "gcc -O0 copy_demo.c -o copy_demo",
        "expected_findings": "The imported-functions section should identify strcpy as requiring careful source review.",
        "walkthrough": "Find the import, inspect the fixed destination size, and explain why input length control determines the actual risk.",
    }
    values.update(overrides)
    return values


def test_published_examples_are_browsable_without_an_account(client):
    library = client.get("/examples")
    assert library.status_code == 200
    assert b"Unsafe Format String" in library.data
    assert b"Weak vs Hardened ELF Build" in library.data

    detail = client.get("/examples/unsafe-format-string")
    assert detail.status_code == 200
    assert b"Source code" in detail.data
    assert b"Expected findings" in detail.data
    assert b"printf(argv[1]);" in detail.data
    assert client.get("/instructor/examples").status_code == 302


def test_instructor_can_create_draft_and_publish_it(client, app):
    create_role_user(app, "instructor@example.test", "instructor")
    login(client, "instructor@example.test")

    form = client.get("/instructor/examples/new")
    response = client.post(
        "/instructor/examples/new",
        data={"csrf_token": csrf_from(form), **example_form()},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Binary learning example created" in response.data
    assert b"Draft" in response.data
    with app.app_context():
        example = get_binary_example_by_slug(
            "reviewing-unsafe-copy", include_unpublished=True
        )
        assert example["published"] == 0
        assert get_recent_audit_events()[0]["action"] == "instructor.example_create"

    logout(client)
    assert client.get("/examples/reviewing-unsafe-copy").status_code == 404
    assert b"Reviewing an Unsafe Copy" not in client.get("/examples").data

    login(client, "instructor@example.test")
    edit_page = client.get("/instructor/examples/reviewing-unsafe-copy/edit")
    response = client.post(
        "/instructor/examples/reviewing-unsafe-copy/edit",
        data={
            "csrf_token": csrf_from(edit_page),
            **example_form(published="1"),
        },
        follow_redirects=True,
    )
    assert b"Binary learning example updated" in response.data
    logout(client)
    assert client.get("/examples/reviewing-unsafe-copy").status_code == 200


def test_students_cannot_author_examples_and_invalid_forms_are_rejected(client, app):
    create_role_user(app, "student@example.test", "student")
    create_role_user(app, "admin@example.test", "admin")

    login(client, "student@example.test")
    assert client.get("/instructor/examples").status_code == 403
    assert client.post("/instructor/examples/new").status_code == 403
    logout(client)

    login(client, "admin@example.test")
    form = client.get("/instructor/examples/new")
    response = client.post(
        "/instructor/examples/new",
        data={
            "csrf_token": csrf_from(form),
            **example_form(slug="Invalid slug", summary="too short"),
        },
    )
    assert response.status_code == 400
    assert b"URL slug must use lowercase" in response.data
    assert b"Summary must contain" in response.data


def test_duplicate_example_slug_is_reported_without_overwriting(client, app):
    create_role_user(app, "instructor@example.test", "instructor")
    login(client, "instructor@example.test")
    form = client.get("/instructor/examples/new")
    response = client.post(
        "/instructor/examples/new",
        data={
            "csrf_token": csrf_from(form),
            **example_form(slug="unsafe-format-string"),
        },
    )
    assert response.status_code == 400
    assert b"already used by another example" in response.data
