"""Detection of common ELF hardening mechanisms."""

from __future__ import annotations

from .elf_parser import dynamic_symbols, dynamic_tags, ensure_before

PF_X = 0x1
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1


def _finding(status: str, level: str, evidence: str) -> dict:
    return {"status": status, "level": level, "evidence": evidence}


def analyze_protections(elf, deadline: float) -> dict[str, dict]:
    ensure_before(deadline)
    symbols = set(dynamic_symbols(elf, deadline))
    tags = dynamic_tags(elf, deadline)
    segments = list(elf.iter_segments())

    canary_names = {"__stack_chk_fail", "__stack_chk_guard"}
    canary_hits = sorted(canary_names.intersection(symbols))
    canary = (
        _finding("Enabled", "good", f"Found symbol: {', '.join(canary_hits)}")
        if canary_hits
        else _finding(
            "Not Found",
            "warn",
            "No common stack-canary support symbol was found.",
        )
    )

    stack_segments = [
        segment
        for segment in segments
        if segment.header["p_type"] == "PT_GNU_STACK"
    ]
    if not stack_segments:
        nx = _finding(
            "Unknown",
            "unknown",
            "The ELF file has no PT_GNU_STACK program header.",
        )
    elif any(int(seg.header["p_flags"]) & PF_X for seg in stack_segments):
        nx = _finding(
            "Disabled",
            "danger",
            "PT_GNU_STACK requests execute permission.",
        )
    else:
        nx = _finding(
            "Enabled",
            "good",
            "PT_GNU_STACK does not request execute permission.",
        )

    is_pie = elf.header["e_type"] == "ET_DYN"
    pie = (
        _finding(
            "Enabled",
            "good",
            "The ELF type is ET_DYN, consistent with PIE.",
        )
        if is_pie
        else _finding(
            "Disabled",
            "warn",
            "The ELF type is ET_EXEC, which normally uses a fixed base address.",
        )
    )

    has_relro = any(
        segment.header["p_type"] == "PT_GNU_RELRO" for segment in segments
    )
    bind_now = _has_bind_now(tags)
    if has_relro and bind_now:
        relro = _finding(
            "Full",
            "good",
            "PT_GNU_RELRO and immediate binding were found.",
        )
    elif has_relro:
        relro = _finding(
            "Partial",
            "warn",
            "PT_GNU_RELRO was found without evidence of immediate binding.",
        )
    else:
        relro = _finding(
            "None",
            "danger",
            "No PT_GNU_RELRO program header was found.",
        )

    rpath_values, runpath_values = _paths_from_tags(tags)
    path_values = rpath_values + runpath_values
    loader_path = (
        _finding(
            "Present",
            "warn",
            "Embedded paths: " + ", ".join(path_values[:8]),
        )
        if path_values
        else _finding(
            "Not Found",
            "good",
            "No DT_RPATH or DT_RUNPATH entry was found.",
        )
    )
    loader_path["rpath"] = rpath_values
    loader_path["runpath"] = runpath_values

    fortify_hits = sorted(
        name for name in symbols if name.endswith("_chk") or "_chk_" in name
    )
    fortify = (
        _finding(
            "Detected",
            "good",
            "Fortified imports: " + ", ".join(fortify_hits[:12]),
        )
        if fortify_hits
        else _finding(
            "Not Found",
            "warn",
            "No common fortified C-library import was found.",
        )
    )
    fortify["symbols"] = fortify_hits

    return {
        "canary": canary,
        "nx": nx,
        "pie": pie,
        "relro": relro,
        "rpath": loader_path,
        "fortify": fortify,
    }


def _has_bind_now(tags: list) -> bool:
    for tag in tags:
        kind = str(tag.entry["d_tag"])
        if kind == "DT_BIND_NOW":
            return True
        value = int(tag.entry.get("d_val", 0))
        if kind == "DT_FLAGS" and value & DF_BIND_NOW:
            return True
        if kind == "DT_FLAGS_1" and value & DF_1_NOW:
            return True
    return False


def _paths_from_tags(tags: list) -> tuple[list[str], list[str]]:
    rpath: list[str] = []
    runpath: list[str] = []
    for tag in tags:
        kind = str(tag.entry["d_tag"])
        if kind == "DT_RPATH":
            rpath.append(str(getattr(tag, "rpath", "(unreadable)")))
        elif kind == "DT_RUNPATH":
            runpath.append(str(getattr(tag, "runpath", "(unreadable)")))
    return list(dict.fromkeys(rpath)), list(dict.fromkeys(runpath))

