"""Readelf-like evidence extraction for report transparency."""

from __future__ import annotations

from .elf_parser import dynamic_tags, ensure_before


HEADER_FIELDS = (
    ("Class", "elfclass"),
    ("Data", "endianness"),
    ("Type", "e_type"),
    ("Machine", "e_machine"),
    ("Entry point", "e_entry"),
    ("Program header offset", "e_phoff"),
    ("Section header offset", "e_shoff"),
    ("Flags", "e_flags"),
    ("Header size", "e_ehsize"),
    ("Program header entry size", "e_phentsize"),
    ("Program header count", "e_phnum"),
    ("Section header entry size", "e_shentsize"),
    ("Section header count", "e_shnum"),
)


def analyze_evidence(elf, deadline: float) -> dict:
    ensure_before(deadline)
    return {
        "header": _header_rows(elf),
        "program_headers": _program_header_rows(elf, deadline),
        "dynamic_entries": _dynamic_rows(elf, deadline),
    }


def _header_rows(elf) -> list[dict]:
    header = elf.header
    values = {
        "elfclass": f"ELF{elf.elfclass}",
        "endianness": "little endian" if elf.little_endian else "big endian",
    }
    rows = []
    for label, key in HEADER_FIELDS:
        value = values.get(key, header.get(key, ""))
        rows.append({"field": label, "value": _format_value(value)})
    return rows


def _program_header_rows(elf, deadline: float) -> list[dict]:
    rows = []
    for index, segment in enumerate(elf.iter_segments()):
        ensure_before(deadline)
        header = segment.header
        rows.append(
            {
                "index": index,
                "type": str(header["p_type"]),
                "offset": _hex(header["p_offset"]),
                "virtual_address": _hex(header["p_vaddr"]),
                "file_size": int(header["p_filesz"]),
                "memory_size": int(header["p_memsz"]),
                "flags": _segment_flags(int(header["p_flags"])),
                "align": _hex(header["p_align"]),
            }
        )
    return rows[:80]


def _dynamic_rows(elf, deadline: float) -> list[dict]:
    rows = []
    for tag in dynamic_tags(elf, deadline):
        ensure_before(deadline)
        kind = str(tag.entry["d_tag"])
        value = _dynamic_value(tag)
        rows.append({"tag": kind, "value": value})
    return rows[:120]


def _dynamic_value(tag) -> str:
    for attr in ("needed", "rpath", "runpath", "soname"):
        if hasattr(tag, attr):
            return str(getattr(tag, attr))
    if "d_val" in tag.entry:
        return _format_value(tag.entry["d_val"])
    if "d_ptr" in tag.entry:
        return _format_value(tag.entry["d_ptr"])
    return ""


def _segment_flags(value: int) -> str:
    flags = []
    if value & 4:
        flags.append("R")
    if value & 2:
        flags.append("W")
    if value & 1:
        flags.append("E")
    return "".join(flags) or "-"


def _format_value(value) -> str:
    if isinstance(value, int):
        return _hex(value)
    return str(value)


def _hex(value) -> str:
    return f"0x{int(value):x}"
