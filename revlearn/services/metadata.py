"""ELF header and section metadata extraction."""

from __future__ import annotations

import re

from .elf_parser import ensure_before


TYPE_LABELS = {
    "ET_EXEC": "Executable",
    "ET_DYN": "Position-independent executable / shared object",
}


def analyze_metadata(elf, deadline: float) -> dict:
    ensure_before(deadline)
    header = elf.header
    elf_class = elf.elfclass
    endian = "Little endian" if elf.little_endian else "Big endian"
    sections = []
    compiler_clues: list[str] = []

    for section in elf.iter_sections():
        ensure_before(deadline)
        sections.append(
            {
                "name": section.name or "(unnamed)",
                "type": str(section.header["sh_type"]),
                "size": int(section.header["sh_size"]),
            }
        )
        if section.name == ".comment":
            try:
                raw = section.data()[:8192]
                compiler_clues.extend(_read_comment_strings(raw))
            except (OSError, ValueError):
                pass

    return {
        "architecture": elf.get_machine_arch() or str(header["e_machine"]),
        "bits": elf_class,
        "endianness": endian,
        "file_type": TYPE_LABELS.get(
            str(header["e_type"]), str(header["e_type"])
        ),
        "elf_type": str(header["e_type"]),
        "entry_point": f"0x{int(header['e_entry']):x}",
        "program_headers": elf.num_segments(),
        "section_count": elf.num_sections(),
        "sections": sections[:80],
        "sections_truncated": len(sections) > 80,
        "compiler_clues": compiler_clues[:10],
    }


def _read_comment_strings(raw: bytes) -> list[str]:
    values = []
    for item in raw.split(b"\x00"):
        text = item.decode("utf-8", errors="replace").strip()
        if len(text) >= 3 and re.search(r"[A-Za-z]", text):
            values.append(text[:300])
    return list(dict.fromkeys(values))

