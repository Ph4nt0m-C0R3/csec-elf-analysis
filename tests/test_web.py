from __future__ import annotations

import io
import re

from conftest import elf64_with_text, minimal_elf64


def csrf_from(response) -> str:
    match = re.search(
        rb'name="csrf_token" value="([^"]+)"',
        response.data,
    )
    assert match
    return match.group(1).decode()


def test_home_and_learning_pages(client):
    home = client.get("/")
    assert home.status_code == 200
    assert b"Understand an ELF file without running it" in home.data
    assert home.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in home.headers["Content-Security-Policy"]

    learning = client.get("/learning")
    assert learning.status_code == 200
    assert b"Stack Canary" in learning.data
    assert b"ELF Structure" in learning.data
    assert b"ELF Security Score" in learning.data
    assert b"Secure ELF Build Baseline" in learning.data
    assert b"Secure Coding Practices" in learning.data
    assert b"Limits of Static Analysis" in learning.data
    assert b"Study this topic" in learning.data
    assert b'href="/learning/canary"' in learning.data

    detail = client.get("/learning/canary")
    assert detail.status_code == 200
    assert b"Weak program and secure alternative" in detail.data
    assert b"Weak or vulnerable version" in detail.data
    assert b"Secure version" in detail.data
    assert b"What to examine" in detail.data
    assert b"Technical deep dive" in detail.data
    assert b"Reproduce and compare" in detail.data
    assert b"Expected observations" in detail.data
    assert b"Complete small programs" in detail.data
    assert b"int main" in detail.data
    assert b"Learning topic navigation" in detail.data
    assert client.get("/learning/not-a-topic").status_code == 404


def test_csrf_is_required(client):
    response = client.post(
        "/analyze",
        data={"binary": (io.BytesIO(minimal_elf64()), "sample.elf")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"security check" in response.data


def test_non_elf_is_rejected(client):
    token = csrf_from(client.get("/"))
    response = client.post(
        "/analyze",
        data={
            "csrf_token": token,
            "binary": (io.BytesIO(b"ordinary text"), "fake.elf"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"ELF signature missing" in response.data


def test_valid_report_escapes_binary_strings_and_cleans_upload(client, app):
    token = csrf_from(client.get("/"))
    sample = minimal_elf64(
        trailer=(
            b"\x00https://example.invalid/demo\x00"
            b"<script>alert(1)</script>\x00/bin/sh\x00"
        )
    )
    response = client.post(
        "/analyze",
        data={
            "csrf_token": token,
            "binary": (
                io.BytesIO(sample),
                r"C:\fakepath\student-sample.elf",
            ),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert b"Protection snapshot" in response.data
    assert b"Download PDF" in response.data
    assert b"ELF security score" in response.data
    assert b"How the score is calculated" in response.data
    assert b"Secure ELF build and coding practices" in response.data
    assert b"Example GCC command :" in response.data
    assert b"&#39;student-sample.c&#39; -o &#39;student-sample&#39;" in response.data
    assert b"Readelf-like details" in response.data
    assert b"Highest review priority" in response.data
    assert b"Finding counts by attention level" in response.data
    assert b"Potential vulnerabilities and attacker impact" in response.data
    assert b"How to prevent or reduce it" in response.data
    assert b"Capstone raw disassembly" in response.data
    high_group = response.data.index(b'id="vulnerability-group-high"')
    medium_group = response.data.index(b'id="vulnerability-group-medium"')
    low_group = response.data.index(b'id="vulnerability-group-low"')
    assert high_group < medium_group < low_group
    assert b"student-sample.elf" in response.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data
    assert b"<script>alert(1)</script>" not in response.data
    assert list((__import__("pathlib").Path(app.config["UPLOAD_DIR"])).glob("*")) == []
    assert response.headers["Cache-Control"] == "no-store"


def test_pdf_export_for_recent_report(client):
    token = csrf_from(client.get("/"))
    report = client.post(
        "/analyze",
        data={
            "csrf_token": token,
            "binary": (io.BytesIO(minimal_elf64()), "pdf-sample.elf"),
        },
        content_type="multipart/form-data",
    )
    match = re.search(rb"/reports/([a-f0-9]+)\.pdf", report.data)
    assert match

    response = client.get(f"/reports/{match.group(1).decode()}.pdf")
    assert response.status_code == 200
    assert response.content_type == "application/pdf"
    assert response.data.startswith(b"%PDF-")
    assert b"pdf-sample.elf" in response.data


def test_compare_mode_renders_side_by_side_report(client, app):
    form = client.get("/compare")
    assert form.status_code == 200
    assert b"Compare two ELF files side by side" in form.data

    token = csrf_from(form)
    response = client.post(
        "/compare",
        data={
            "csrf_token": token,
            "binary_left": (io.BytesIO(minimal_elf64()), "demo_weak"),
            "binary_right": (
                io.BytesIO(minimal_elf64(pie=True, executable_stack=True)),
                "demo_changed",
            ),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert b"Comparison report" in response.data
    assert b"Hardening comparison" in response.data
    assert b"Per-file analysis" in response.data
    assert b"Clear summary for each uploaded file" in response.data
    assert b"Baseline" in response.data
    assert b"Comparison" in response.data
    assert b"demo_weak" in response.data
    assert b"demo_changed" in response.data
    assert list((__import__("pathlib").Path(app.config["UPLOAD_DIR"])).glob("*")) == []


def test_report_renders_raw_disassembly_and_review_annotation(client):
    token = csrf_from(client.get("/"))
    response = client.post(
        "/analyze",
        data={
            "csrf_token": token,
            "binary": (
                io.BytesIO(elf64_with_text(b"\x0f\x05\xc3")),
                "assembly-sample.elf",
            ),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert b"Raw assembly disassembly" in response.data
    assert b"syscall" in response.data
    assert b"Direct operating-system call boundary" in response.data


def test_request_size_limit_returns_friendly_error(client):
    token = csrf_from(client.get("/"))
    response = client.post(
        "/analyze",
        data={
            "csrf_token": token,
            "binary": (io.BytesIO(b"A" * (1024 * 1024 + 1000)), "huge.elf"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 413
    assert b"File is too large" in response.data


def test_health_endpoint(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
