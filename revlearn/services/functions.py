"""Imported-function inventory and educational warnings."""

from __future__ import annotations

from .elf_parser import imported_symbols


RISKY_FUNCTIONS = {
    "gets": (
        "critical",
        "Reads input without a length limit and should not be used.",
    ),
    "strcpy": (
        "high",
        "Copies until a null byte; the destination size must be sufficient.",
    ),
    "strcat": (
        "high",
        "Appends without knowing the remaining destination capacity.",
    ),
    "sprintf": (
        "high",
        "Formats without an explicit destination-size argument.",
    ),
    "vsprintf": (
        "high",
        "Formats variable arguments without an explicit destination size.",
    ),
    "scanf": (
        "medium",
        "Some format patterns can read more data than a destination can hold.",
    ),
    "__isoc99_scanf": (
        "medium",
        "Some format patterns can read more data than a destination can hold.",
    ),
    "system": (
        "high",
        "Invokes a command shell; untrusted command content can be dangerous.",
    ),
    "popen": (
        "high",
        "Starts a shell command and requires strict control of all input.",
    ),
    "memcpy": (
        "medium",
        "Safe use depends on a correct length and sufficiently large destination.",
    ),
    "strncpy": (
        "medium",
        "Can truncate without null termination and is often misunderstood.",
    ),
    "printf": (
        "low",
        "A user-controlled format string can create a format-string vulnerability.",
    ),
}


def analyze_functions(elf, deadline: float) -> dict:
    imports = imported_symbols(elf, deadline)
    warnings = []
    for name in imports:
        if name in RISKY_FUNCTIONS:
            severity, explanation = RISKY_FUNCTIONS[name]
            warnings.append(
                {
                    "name": name,
                    "severity": severity,
                    "explanation": explanation,
                }
            )
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    warnings.sort(key=lambda row: (severity_order[row["severity"]], row["name"]))
    return {
        "imports": imports[:1000],
        "imports_truncated": len(imports) > 1000,
        "warnings": warnings,
    }

