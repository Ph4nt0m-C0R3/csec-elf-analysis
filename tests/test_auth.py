from __future__ import annotations

import re

from werkzeug.security import generate_password_hash

from revlearn.database import (
    create_user,
    get_completed_topics,
    get_learning_map,
    get_recent_audit_events,
    get_user_by_email,
)


def csrf_from(response) -> str:
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


def register_student(client, *, email="student@example.test"):
    page = client.get("/register")
    return client.post(
        "/register",
        data={
            "csrf_token": csrf_from(page),
            "display_name": "Test Student",
            "email": email,
            "password": "classroom-pass-123",
            "confirm_password": "classroom-pass-123",
        },
        follow_redirects=True,
    )


def login(client, email, password="classroom-pass-123", next_url=""):
    page = client.get("/login", query_string={"next": next_url})
    return client.post(
        "/login",
        data={
            "csrf_token": csrf_from(page),
            "email": email,
            "password": password,
            "next": next_url,
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


def create_role_user(app, email: str, role: str):
    with app.app_context():
        return create_user(
            email=email,
            display_name=f"Test {role.title()}",
            password_hash=generate_password_hash(
                "classroom-pass-123", method="scrypt"
            ),
            role=role,
        )


def test_guest_navigation_and_existing_analyzer_remain_public(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Guest" in response.data
    assert b"Sign in" in response.data
    assert b"Create account" in response.data
    assert b"Understand an ELF file without running it" in response.data


def test_password_fields_have_accessible_visibility_controls(client):
    login_page = client.get("/login")
    assert b'type="password"' in login_page.data
    assert b'data-password-toggle="login-password"' in login_page.data
    assert b'aria-label="Show password"' in login_page.data
    assert b"js/password-toggle.js" in login_page.data

    register_page = client.get("/register")
    assert register_page.data.count(b'data-password-toggle=') == 2
    assert b'data-password-toggle="register-password"' in register_page.data
    assert b'data-password-toggle="confirm-password"' in register_page.data


def test_success_notices_can_be_dismissed_and_expire_automatically(client):
    register_student(client)
    response = logout(client)
    assert b"You have signed out." in response.data
    assert b'data-auto-dismiss="6000"' in response.data
    assert b'aria-label="Dismiss notification"' in response.data
    assert b"js/flash-messages.js" in response.data


def test_student_registration_creates_account_and_audit_event(client, app):
    response = register_student(client)
    assert response.status_code == 200
    assert b"Welcome, Test Student" in response.data
    assert b"student workspace" in response.data

    with app.app_context():
        user = get_user_by_email("student@example.test")
        audit = get_recent_audit_events()

    assert user is not None
    assert user["role"] == "student"
    assert user["active"] == 1
    assert audit[0]["action"] == "auth.register"


def test_registration_validates_csrf_password_and_duplicate_email(client):
    missing_csrf = client.post(
        "/register",
        data={
            "display_name": "Student",
            "email": "student@example.test",
            "password": "short",
            "confirm_password": "different",
        },
    )
    assert missing_csrf.status_code == 400
    assert b"security check" in missing_csrf.data
    assert b"at least 12 characters" in missing_csrf.data

    assert register_student(client).status_code == 200
    logout(client)
    duplicate = register_student(client)
    assert duplicate.status_code == 400
    assert b"already exists" in duplicate.data


def test_login_logout_and_external_next_url_protection(client):
    register_student(client)
    signed_out = logout(client)
    assert b"You have signed out" in signed_out.data
    assert client.get("/account").status_code == 302
    assert client.get("/logout").status_code == 405

    response = login(
        client,
        "student@example.test",
        next_url="https://attacker.invalid/redirect",
    )
    assert response.status_code == 200
    assert b"Welcome, Test Student" in response.data


def test_login_rejects_wrong_password_without_account_disclosure(client):
    register_student(client)
    logout(client)
    response = login(client, "student@example.test", password="wrong-password")
    assert response.status_code == 400
    assert b"email address or password is incorrect" in response.data


def test_role_permissions_are_enforced_server_side(client, app):
    create_role_user(app, "student@example.test", "student")
    create_role_user(app, "instructor@example.test", "instructor")
    create_role_user(app, "admin@example.test", "admin")

    login(client, "student@example.test")
    assert client.get("/instructor").status_code == 403
    assert client.get("/admin").status_code == 403
    logout(client)

    instructor = login(client, "instructor@example.test")
    assert b"Instructor workspace" in instructor.data or instructor.status_code == 200
    assert client.get("/instructor").status_code == 200
    assert client.get("/admin").status_code == 403
    logout(client)

    login(client, "admin@example.test")
    assert client.get("/instructor").status_code == 200
    admin = client.get("/admin")
    assert admin.status_code == 200
    assert b"User access" in admin.data
    assert b"Recent audit activity" in admin.data
    assert b"instructor@example.test" in admin.data


def test_student_can_track_progress_but_staff_cannot(client, app):
    student_id = create_role_user(app, "student@example.test", "student")["user_id"]
    create_role_user(app, "instructor@example.test", "instructor")

    login(client, "student@example.test")
    dashboard = client.get("/student")
    assert dashboard.status_code == 200
    assert b"Learning progress" in dashboard.data
    assert b"Open detailed lesson" in dashboard.data
    assert b"<details" not in dashboard.data
    detail = client.get("/learning/canary")
    response = client.post(
        "/student/progress/canary",
        data={
            "csrf_token": csrf_from(detail),
            "completed": "1",
            "return_to": "detail",
        },
        follow_redirects=True,
    )
    assert b"Mark for review" in response.data
    with app.app_context():
        assert "canary" in get_completed_topics(student_id)
        assert get_recent_audit_events()[0]["action"] == "student.progress_update"

    logout(client)
    login(client, "instructor@example.test")
    assert client.get("/student").status_code == 403


def test_instructor_can_edit_learning_content_but_student_cannot(client, app):
    create_role_user(app, "student@example.test", "student")
    create_role_user(app, "instructor@example.test", "instructor")

    login(client, "instructor@example.test")
    workspace = client.get("/instructor")
    assert workspace.status_code == 200
    response = client.post(
        "/instructor/learning/canary",
        data={
            "csrf_token": csrf_from(workspace),
            "title": "Stack Canary Review",
            "category": "Protection",
            "explanation": "A revised instructor explanation for learners.",
            "risk": "Missing canaries can make stack corruption harder to detect.",
            "recommendation": "Enable strong stack protection in supported builds.",
        },
        follow_redirects=True,
    )
    assert b"Updated learning topic" in response.data
    with app.app_context():
        assert get_learning_map()["canary"]["title"] == "Stack Canary Review"
        assert get_recent_audit_events()[0]["action"] == "instructor.learning_update"

    logout(client)
    login(client, "student@example.test")
    assert client.post("/instructor/learning/canary").status_code == 403


def test_admin_can_manage_another_users_access(client, app):
    student_id = create_role_user(app, "student@example.test", "student")["user_id"]
    admin_id = create_role_user(app, "admin@example.test", "admin")["user_id"]

    login(client, "admin@example.test")
    dashboard = client.get("/admin")
    response = client.post(
        f"/admin/users/{student_id}",
        data={
            "csrf_token": csrf_from(dashboard),
            "role": "instructor",
            "active": "1",
        },
        follow_redirects=True,
    )
    assert b"Updated access for student@example.test" in response.data
    with app.app_context():
        updated = get_user_by_email("student@example.test")
        assert updated["role"] == "instructor"
        assert updated["active"] == 1
        assert get_recent_audit_events()[0]["action"] == "admin.user_access_update"

    response = client.post(
        f"/admin/users/{admin_id}",
        data={
            "csrf_token": csrf_from(response),
            "role": "student",
        },
        follow_redirects=True,
    )
    assert b"cannot change their own role or status" in response.data
    with app.app_context():
        assert get_user_by_email("admin@example.test")["role"] == "admin"


def test_admin_can_create_instructor_from_protected_ui(client, app):
    create_role_user(app, "admin@example.test", "admin")
    create_role_user(app, "student@example.test", "student")

    login(client, "admin@example.test")
    form = client.get("/admin/instructors/new")
    assert form.status_code == 200
    assert b"Add an Instructor" in form.data
    assert form.data.count(b'data-password-toggle=') == 2
    response = client.post(
        "/admin/instructors/new",
        data={
            "csrf_token": csrf_from(form),
            "display_name": "New Instructor",
            "email": "new-instructor@example.test",
            "password": "instructor-pass-123",
            "confirm_password": "instructor-pass-123",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Instructor account created" in response.data
    assert b"new-instructor@example.test" in response.data
    with app.app_context():
        instructor = get_user_by_email("new-instructor@example.test")
        assert instructor["role"] == "instructor"
        assert instructor["active"] == 1
        assert get_recent_audit_events()[0]["action"] == "admin.instructor_create"

    logout(client)
    login(client, "student@example.test")
    assert client.get("/admin/instructors/new").status_code == 403


def test_admin_instructor_creation_rejects_duplicate_email(client, app):
    create_role_user(app, "admin@example.test", "admin")
    create_role_user(app, "existing@example.test", "instructor")
    login(client, "admin@example.test")
    form = client.get("/admin/instructors/new")
    response = client.post(
        "/admin/instructors/new",
        data={
            "csrf_token": csrf_from(form),
            "display_name": "Existing Instructor",
            "email": "existing@example.test",
            "password": "instructor-pass-123",
            "confirm_password": "instructor-pass-123",
        },
    )
    assert response.status_code == 400
    assert b"already exists" in response.data


def test_privileged_account_can_be_created_only_through_local_cli(app):
    runner = app.test_cli_runner()
    result = runner.invoke(
        args=[
            "create-user",
            "--email",
            "owner@example.test",
            "--name",
            "Lab Owner",
            "--role",
            "admin",
        ],
        input="classroom-pass-123\nclassroom-pass-123\n",
    )

    assert result.exit_code == 0
    assert "Created admin account" in result.output
    with app.app_context():
        user = get_user_by_email("owner@example.test")
    assert user is not None
    assert user["role"] == "admin"
