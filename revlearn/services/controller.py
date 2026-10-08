"""Coordinates the complete bounded static-analysis workflow."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from revlearn.errors import AnalysisError, AnalysisTimeout

from .disassembly import analyze_disassembly
from .explanations import build_education
from .evidence import analyze_evidence
from .functions import analyze_functions
from .metadata import analyze_metadata
from .protections import analyze_protections
from .strings import analyze_strings

PROTECTION_DEDUCTION_WEIGHTS = {
    "canary": {"warn": 8, "danger": 12, "unknown": 4},
    "nx": {"warn": 10, "danger": 22, "unknown": 5},
    "pie": {"warn": 10, "danger": 14, "unknown": 5},
    "relro": {"warn": 10, "danger": 18, "unknown": 5},
    "rpath": {"warn": 12, "danger": 16, "unknown": 4},
    "fortify": {"warn": 6, "danger": 8, "unknown": 3},
}

FUNCTION_DEDUCTION_WEIGHTS = {
    "critical": 18,
    "high": 12,
    "medium": 7,
    "low": 3,
    "info": 1,
}

SECURITY_RATING_BANDS = [
    {"rating": "Poor", "range": "0-24"},
    {"rating": "Weak", "range": "25-49"},
    {"rating": "Moderate", "range": "50-74"},
    {"rating": "Strong", "range": "75-100"},
]


def analyze(
    path: Path,
    display_name: str,
    size: int,
    timeout_seconds: int,
    max_strings: int,
    learning: dict[str, dict],
    max_instructions: int = 400,
) -> dict:
    started = time.monotonic()
    deadline = started + timeout_seconds
    module_errors: list[dict] = []

    try:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            metadata = analyze_metadata(elf, deadline)
            protections = _module(
                "protections",
                lambda: analyze_protections(elf, deadline),
                module_errors,
                {},
            )
            functions = _module(
                "functions",
                lambda: analyze_functions(elf, deadline),
                module_errors,
                {"imports": [], "warnings": [], "imports_truncated": False},
            )
            disassembly = _module(
                "disassembly",
                lambda: analyze_disassembly(elf, deadline, max_instructions),
                module_errors,
                {
                    "available": False,
                    "engine": "Capstone",
                    "architecture": "Unavailable",
                    "instructions": [],
                    "instruction_count": 0,
                    "risks": [],
                    "risk_count": 0,
                    "truncated": False,
                    "note": "The disassembly module could not process this file.",
                },
            )
            evidence = _module(
                "evidence",
                lambda: analyze_evidence(elf, deadline),
                module_errors,
                {
                    "header": [],
                    "program_headers": [],
                    "dynamic_entries": [],
                },
            )
        strings = _module(
            "strings",
            lambda: analyze_strings(path, deadline, max_strings),
            module_errors,
            {
                "items": [],
                "total_found": 0,
                "retained": 0,
                "truncated": False,
                "urls": [],
                "paths": [],
                "commands": [],
                "suspicious": [],
            },
        )
    except AnalysisTimeout:
        raise
    except (ELFError, OSError, ValueError, TypeError, OverflowError) as exc:
        raise AnalysisError(
            "The ELF structure could not be analyzed safely."
        ) from exc

    if not protections:
        protections = _unknown_protections()

    education = build_education(
        protections, functions, strings, learning
    )
    risk_summary = _risk_summary(protections, functions, education)
    elapsed_ms = round((time.monotonic() - started) * 1000, 2)
    return {
        "analysis_id": uuid.uuid4().hex,
        "filename": display_name,
        "file_size": size,
        "file_size_display": _human_size(size),
        "elapsed_ms": elapsed_ms,
        "metadata": metadata,
        "protections": protections,
        "functions": functions,
        "strings": strings,
        "disassembly": disassembly,
        "evidence": evidence,
        "education": education,
        "risk_summary": risk_summary,
        "developer_guidance": _developer_guidance(
            protections, functions, strings, risk_summary, display_name
        ),
        "errors": module_errors,
    }


def _module(name, operation, errors, fallback):
    try:
        return operation()
    except AnalysisTimeout:
        raise
    except (ELFError, OSError, ValueError, TypeError, OverflowError) as exc:
        errors.append(
            {
                "module": name,
                "message": (
                    f"The {name} module could not interpret part of this file."
                ),
                "detail": type(exc).__name__,
            }
        )
        return fallback


def _unknown_protections() -> dict:
    return {
        key: {
            "status": "Unknown",
            "level": "unknown",
            "evidence": "The protection module could not determine this value.",
        }
        for key in ("canary", "nx", "pie", "relro", "rpath", "fortify")
    }


def _human_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.2f} MiB"


def _risk_summary(protections: dict, functions: dict, education: dict) -> dict:
    """Count attention levels without claiming exploitability."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for warning in functions["warnings"]:
        severity = warning.get("severity", "info")
        counts[severity if severity in counts else "info"] += 1
    for observation in education["observations"]:
        severity = observation.get("severity", "info")
        counts[severity if severity in counts else "info"] += 1

    score_details = _security_score_details(protections, functions, education)
    score = score_details["score"]
    attention_order = ("critical", "high", "medium", "low")
    highest = next(
        (level for level in attention_order if counts[level]),
        "info",
    )
    return {
        "counts": counts,
        "highest": highest,
        "highest_label": (
            "Informational" if highest == "info" else highest.title()
        ),
        "attention_total": sum(counts[level] for level in attention_order),
        "score": score,
        "rating": _security_rating(score),
        "security_level": _security_level(score),
        "score_details": score_details,
    }


def _security_score_details(protections: dict, functions: dict, education: dict) -> dict:
    deductions = 0
    factors = []
    for key, weights in PROTECTION_DEDUCTION_WEIGHTS.items():
        level = protections.get(key, {}).get("level", "unknown")
        points = weights.get(level, 0)
        if points:
            factors.append(
                {
                    "source": key.upper() if key != "rpath" else "RPATH / RUNPATH",
                    "reason": f"{protections.get(key, {}).get('status', 'Unknown')} ({level})",
                    "points": points,
                }
            )
        deductions += points

    retained_warnings = functions.get("warnings", [])[:12]
    for warning in retained_warnings:
        severity = warning.get("severity", "info")
        points = FUNCTION_DEDUCTION_WEIGHTS.get(severity, 1)
        factors.append(
            {
                "source": f"{warning.get('name', 'function')}()",
                "reason": f"{severity} imported-function warning",
                "points": points,
            }
        )
        deductions += points

    if any(
        item.get("source") == "Printable-string analysis"
        for item in education.get("vulnerabilities", [])
    ):
        factors.append(
            {
                "source": "Strings",
                "reason": "Command or suspicious string indicator",
                "points": 4,
            }
        )
        deductions += 4

    capped_deductions = min(deductions, 100)
    security_score = max(0, 100 - capped_deductions)

    return {
        "score": security_score,
        "raw_deductions": deductions,
        "deductions": capped_deductions,
        "capped": deductions > 100,
        "factors": factors,
        "protection_weights": _weight_rows(PROTECTION_DEDUCTION_WEIGHTS),
        "function_weights": [
            {"severity": key, "points": value}
            for key, value in FUNCTION_DEDUCTION_WEIGHTS.items()
        ],
        "rating_bands": SECURITY_RATING_BANDS,
        "notes": [
            "The score starts at 100 and deductions are subtracted for missing hardening or risky indicators.",
            "Good protection checks subtract 0 points.",
            "Function warning deductions are counted for the first 12 retained warnings.",
            "Command or suspicious string indicators subtract 4 points once.",
            "Total deductions are capped at 100, so the final security score cannot go below 0.",
        ],
    }


def _security_rating(score: int) -> str:
    if score >= 75:
        return "Strong"
    if score >= 50:
        return "Moderate"
    if score >= 25:
        return "Weak"
    return "Poor"


def _security_level(score: int) -> str:
    if score >= 75:
        return "good"
    if score >= 50:
        return "low"
    if score >= 25:
        return "medium"
    return "high"


def _weight_rows(weights: dict) -> list[dict]:
    rows = []
    for check, levels in weights.items():
        rows.append(
            {
                "check": check.upper() if check != "rpath" else "RPATH / RUNPATH",
                "warn": levels.get("warn", 0),
                "danger": levels.get("danger", 0),
                "unknown": levels.get("unknown", 0),
            }
        )
    return rows


def _developer_guidance(
    protections: dict,
    functions: dict,
    strings: dict,
    risk_summary: dict,
    display_name: str,
) -> dict:
    secure_build = _secure_build_guidance(protections)
    coding_practices = _coding_practice_guidance(functions, strings)
    return {
        "summary": (
            f"Tailored to this ELF security score: "
            f"{risk_summary['score']}/100 ({risk_summary['rating']})."
        ),
        "secure_build": secure_build,
        "build_example": _build_example(protections, display_name),
        "coding_practices": coding_practices,
    }


def _secure_build_guidance(protections: dict) -> list[str]:
    rows = [
        "Keep compiler diagnostics enabled in developer builds: -Wall -Wextra -Wformat -Wformat-security -Werror=format-security.",
    ]
    if protections["canary"]["status"] != "Enabled":
        rows.append(
            "Stack canary was not detected; rebuild supported C/C++ code with -fstack-protector-strong."
        )
    if protections["nx"]["status"] != "Enabled":
        rows.append(
            "NX is not clearly enabled; remove executable-stack options such as -z execstack and prefer -Wl,-z,noexecstack."
        )
    if protections["pie"]["status"] != "Enabled":
        rows.append(
            "PIE is disabled; compile and link executables with -fPIE -pie so ASLR can randomize the main program."
        )
    if protections["relro"]["status"] != "Full":
        rows.append(
            "Full RELRO was not detected; link with -Wl,-z,relro,-z,now to harden relocation data."
        )
    if protections["fortify"]["status"] != "Detected":
        rows.append(
            "Fortify imports were not detected; use optimization with -D_FORTIFY_SOURCE=2, or _FORTIFY_SOURCE=3 when supported."
        )
    if protections["rpath"]["status"] == "Present":
        rows.append(
            "RPATH/RUNPATH is present; remove unnecessary embedded library paths and never use writable or relative library directories."
        )
    if len(rows) == 1:
        rows.append(
            "Supported hardening checks look strong; keep these flags in the release build and verify them in CI with readelf or checksec."
        )
    rows.append(
        "Keep separate debug symbols for authorized debugging before stripping release binaries."
    )
    return rows


def _build_example(protections: dict, display_name: str) -> str:
    flags = [
        "-O2",
        "-Wall",
        "-Wextra",
        "-Wformat",
        "-Wformat-security",
        "-Werror=format-security",
    ]
    if protections["fortify"]["status"] != "Detected":
        flags.append("-D_FORTIFY_SOURCE=2")
    if protections["canary"]["status"] != "Enabled":
        flags.append("-fstack-protector-strong")
    if protections["pie"]["status"] != "Enabled":
        flags.extend(["-fPIE", "-pie"])
    if protections["relro"]["status"] != "Full":
        flags.append("-Wl,-z,relro,-z,now")
    if protections["nx"]["status"] != "Enabled":
        flags.append("-Wl,-z,noexecstack")
    stem = _source_output_stem(display_name)
    return (
        "gcc "
        + " ".join(flags)
        + " "
        + _posix_shell_quote(stem + ".c")
        + " -o "
        + _posix_shell_quote(stem)
    )


def _coding_practice_guidance(functions: dict, strings: dict) -> list[str]:
    rows = [
        "Validate length, type, range, and encoding for all external input before parsing or copying it.",
    ]
    warning_names = {warning["name"] for warning in functions.get("warnings", [])}
    if "gets" in warning_names:
        rows.append(
            "Remove gets completely; use fgets or getline with explicit size limits and newline handling."
        )
    if warning_names.intersection({"strcpy", "strcat"}):
        rows.append(
            "Replace unbounded string copy/append patterns with size-aware logic and validate destination capacity before writing."
        )
    if warning_names.intersection({"sprintf", "vsprintf"}):
        rows.append(
            "Replace sprintf or vsprintf with snprintf or vsnprintf and check for truncation."
        )
    if warning_names.intersection({"scanf", "__isoc99_scanf"}):
        rows.append(
            "Use width limits in scanf formats, or prefer fgets followed by explicit parsing and range checks."
        )
    if warning_names.intersection({"system", "popen"}):
        rows.append(
            "Avoid shell execution for untrusted input; use fixed argument arrays with exec-family APIs or posix_spawn."
        )
    if "printf" in warning_names:
        rows.append(
            "Keep format strings constant, for example printf(\"%s\", value), and never let user input become the format string."
        )
    if warning_names.intersection({"memcpy", "strncpy"}):
        rows.append(
            "Review every copy length against both source and destination sizes; treat truncation as an explicit error path."
        )
    if strings.get("suspicious"):
        rows.append(
            "Suspicious strings were found; remove embedded secrets, rotate exposed credentials, and move configuration outside the binary."
        )
    if strings.get("urls") or strings.get("paths"):
        rows.append(
            "Embedded URLs or filesystem paths were found; verify they do not expose internal services, secrets, or environment-specific assumptions."
        )
    if strings.get("commands"):
        rows.append(
            "Command-like strings were found; keep command choices allow-listed and separate user data from executable command text."
        )
    rows.append(
        "Run automated tests with AddressSanitizer and UndefinedBehaviorSanitizer during development."
    )
    rows.append(
        "Check return values from allocation, parsing, conversion, file, and process APIs."
    )
    return _unique(rows)


def _unique(rows: list[str]) -> list[str]:
    return list(dict.fromkeys(rows))


def _posix_shell_quote(value: str) -> str:
    cleaned = value.strip() or "output.elf"
    return "'" + cleaned.replace("'", "'\"'\"'") + "'"


def _source_output_stem(display_name: str) -> str:
    name = Path(display_name.replace("\\", "/")).name.strip()
    stem = Path(name).stem if name else "output"
    return stem or "output"
