from __future__ import annotations

import time

from elftools.elf.elffile import ELFFile

from revlearn.services.controller import analyze
from revlearn.services.disassembly import analyze_disassembly
from revlearn.services.protections import analyze_protections
from revlearn.services.strings import analyze_strings

from conftest import elf64_with_text, minimal_elf64


def test_protection_detection_for_minimal_exec(tmp_path):
    sample = tmp_path / "sample.elf"
    sample.write_bytes(minimal_elf64())
    with sample.open("rb") as stream:
        result = analyze_protections(ELFFile(stream), time.monotonic() + 2)

    assert result["nx"]["status"] == "Enabled"
    assert result["pie"]["status"] == "Disabled"
    assert result["relro"]["status"] == "None"
    assert result["rpath"]["status"] == "Not Found"


def test_executable_stack_and_pie_are_reported(tmp_path):
    sample = tmp_path / "pie.elf"
    sample.write_bytes(minimal_elf64(pie=True, executable_stack=True))
    with sample.open("rb") as stream:
        result = analyze_protections(ELFFile(stream), time.monotonic() + 2)

    assert result["nx"]["status"] == "Disabled"
    assert result["pie"]["status"] == "Enabled"


def test_strings_are_categorized_and_bounded(tmp_path):
    trailer = (
        b"\x00https://example.invalid/path\x00"
        b"/tmp/student-secret\x00"
        b"bash -c demo\x00password=training-only\x00"
    )
    sample = tmp_path / "strings.elf"
    sample.write_bytes(minimal_elf64(trailer=trailer))
    result = analyze_strings(sample, time.monotonic() + 2, maximum=3)

    assert result["total_found"] >= 4
    assert result["retained"] == 3
    assert result["truncated"] is True
    assert result["urls"]
    assert result["paths"]


def test_raw_disassembly_of_text_section(tmp_path):
    sample = tmp_path / "code.elf"
    sample.write_bytes(elf64_with_text())
    with sample.open("rb") as stream:
        result = analyze_disassembly(
            ELFFile(stream),
            time.monotonic() + 2,
            maximum=50,
        )

    assert result["available"] is True
    assert result["engine"] == "Capstone"
    assert result["architecture"] == "x86-64"
    assert result["instruction_count"] >= 4
    assert any(row["mnemonic"] == "ret" for row in result["instructions"])


def test_system_call_is_highlighted_for_review(tmp_path):
    sample = tmp_path / "syscall.elf"
    sample.write_bytes(elf64_with_text(b"\x0f\x05\xc3"))
    with sample.open("rb") as stream:
        result = analyze_disassembly(
            ELFFile(stream),
            time.monotonic() + 2,
            maximum=50,
        )

    assert result["risk_count"] == 1
    assert result["risks"][0]["title"] == "Direct operating-system call boundary"


def test_controller_returns_educational_report(tmp_path):
    sample = tmp_path / "sample.elf"
    sample.write_bytes(
        minimal_elf64(trailer=b"\x00https://example.invalid\x00/bin/sh\x00")
    )
    learning = {
        key: {
            "title": key,
            "explanation": "Explanation",
            "risk": "Risk",
            "recommendation": "Recommendation",
        }
        for key in (
            "canary",
            "nx",
            "pie",
            "relro",
            "rpath",
            "fortify",
            "unsafe_functions",
        )
    }
    result = analyze(sample, "sample.elf", sample.stat().st_size, 5, 100, learning)

    assert result["metadata"]["architecture"] == "x64"
    assert result["metadata"]["bits"] == 64
    assert result["education"]["observations"]
    assert result["education"]["recommendations"]
    assert result["education"]["vulnerabilities"]
    assert {
        "title",
        "severity",
        "attack",
        "prevention",
        "qualification",
    }.issubset(result["education"]["vulnerabilities"][0])
    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    vulnerability_ranks = [
        severity_rank[item["severity"]]
        for item in result["education"]["vulnerabilities"]
    ]
    assert vulnerability_ranks == sorted(vulnerability_ranks)
    assert result["risk_summary"]["highest"] in {
        "critical", "high", "medium", "low", "info"
    }
    assert result["risk_summary"]["attention_total"] >= 1
    assert 0 <= result["risk_summary"]["score"] <= 100
    assert result["risk_summary"]["rating"] in {"Poor", "Weak", "Moderate", "Strong"}
    assert result["risk_summary"]["security_level"] in {"good", "low", "medium", "high"}
    assert result["risk_summary"]["score_details"]["factors"]
    assert result["risk_summary"]["score_details"]["protection_weights"]
    assert result["developer_guidance"]["secure_build"]
    assert result["developer_guidance"]["coding_practices"]
    assert "Tailored to this ELF security score" in result["developer_guidance"]["summary"]
    assert any(
        "PIE is disabled" in item
        for item in result["developer_guidance"]["secure_build"]
    )
    assert any(
        "Full RELRO was not detected" in item
        for item in result["developer_guidance"]["secure_build"]
    )
    assert any(
        "Embedded URLs or filesystem paths" in item
        for item in result["developer_guidance"]["coding_practices"]
    )
    assert "'sample.c' -o 'sample'" in result["developer_guidance"]["build_example"]

    canary_result = analyze(sample, "canary", sample.stat().st_size, 5, 100, learning)
    assert "'canary.c' -o 'canary'" in canary_result["developer_guidance"]["build_example"]
    assert "disassembly" in result
    assert result["evidence"]["header"]
    assert result["evidence"]["program_headers"]
    assert result["elapsed_ms"] >= 0
