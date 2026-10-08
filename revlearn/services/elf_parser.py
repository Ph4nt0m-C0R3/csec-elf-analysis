"""Shared ELF parsing helpers."""

from __future__ import annotations

import time

from elftools.elf.sections import SymbolTableSection

from revlearn.errors import AnalysisTimeout


def ensure_before(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise AnalysisTimeout(
            "The analysis exceeded its time limit. Try a smaller ELF file."
        )


def dynamic_symbols(elf, deadline: float) -> list[str]:
    names: set[str] = set()
    for section in elf.iter_sections():
        ensure_before(deadline)
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            ensure_before(deadline)
            name = symbol.name
            if name:
                names.add(name.split("@", 1)[0])
    return sorted(names, key=str.lower)


def imported_symbols(elf, deadline: float) -> list[str]:
    names: set[str] = set()
    for section in elf.iter_sections():
        ensure_before(deadline)
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            ensure_before(deadline)
            section_index = symbol.entry["st_shndx"]
            if section_index in ("SHN_UNDEF", 0):
                name = symbol.name.split("@", 1)[0]
                if name:
                    names.add(name)
    return sorted(names, key=str.lower)


def dynamic_tags(elf, deadline: float) -> list:
    tags = []
    for section in elf.iter_sections():
        ensure_before(deadline)
        if section.header["sh_type"] != "SHT_DYNAMIC":
            continue
        tags.extend(section.iter_tags())
    return tags

