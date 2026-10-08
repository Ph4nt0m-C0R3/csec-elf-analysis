"""Bounded printable-string extraction and categorization."""

from __future__ import annotations

import re
from pathlib import Path

from .elf_parser import ensure_before

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]{4,}")
UNIX_PATH_RE = re.compile(r"(?<!\w)/(?:[\w.@+~-]+/)*[\w.@+~-]+")
WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
COMMAND_RE = re.compile(
    r"(?i)(?:^|[\s;&|])(?:sh|bash|cmd(?:\.exe)?|powershell|wget|curl|nc|netcat)\b"
)
SUSPICIOUS_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|shell|"
    r"/bin/sh|admin|credential|exploit|malware)\b"
)


def analyze_strings(path: Path, deadline: float, maximum: int) -> dict:
    ensure_before(deadline)
    data = path.read_bytes()
    ensure_before(deadline)

    values: list[str] = []
    seen: set[str] = set()
    total = 0
    for match in PRINTABLE_RE.finditer(data):
        if total % 100 == 0:
            ensure_before(deadline)
        total += 1
        text = match.group().decode("ascii", errors="replace").strip()
        if text and text not in seen:
            seen.add(text)
            if len(values) < maximum:
                values.append(text[:1000])

    urls = _matching(values, URL_RE)
    unix_paths = _matching(values, UNIX_PATH_RE)
    windows_paths = _matching(values, WINDOWS_PATH_RE)
    commands = [value for value in values if COMMAND_RE.search(value)]
    suspicious = [value for value in values if SUSPICIOUS_RE.search(value)]

    return {
        "items": values,
        "total_found": total,
        "retained": len(values),
        "truncated": total > len(values),
        "urls": urls[:100],
        "paths": list(dict.fromkeys(unix_paths + windows_paths))[:100],
        "commands": commands[:100],
        "suspicious": suspicious[:100],
    }


def _matching(values: list[str], pattern: re.Pattern) -> list[str]:
    matches = []
    for value in values:
        matches.extend(match.group(0) for match in pattern.finditer(value))
    return list(dict.fromkeys(matches))

