from __future__ import annotations

import struct

import pytest

from revlearn import create_app


def minimal_elf64(
    *,
    pie: bool = False,
    executable_stack: bool = False,
    trailer: bytes = b"",
) -> bytes:
    """Build a small structurally valid ELF64 file for parser tests."""
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2  # ELFCLASS64
    ident[5] = 1  # ELFDATA2LSB
    ident[6] = 1  # EV_CURRENT
    ident[7] = 0  # ELFOSABI_NONE

    elf_type = 3 if pie else 2  # ET_DYN / ET_EXEC
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(ident),
        elf_type,
        62,  # EM_X86_64
        1,
        0x401000,
        64,
        0,
        0,
        64,
        56,
        1,
        64,
        0,
        0,
    )
    flags = 7 if executable_stack else 6  # RWX or RW
    program_header = struct.pack(
        "<IIQQQQQQ",
        0x6474E551,  # PT_GNU_STACK
        flags,
        0,
        0,
        0,
        0,
        0,
        16,
    )
    return header + program_header + b"\x00" + trailer


def elf64_with_text(
    text: bytes = b"\x55\x48\x89\xe5\x90\x5d\xc3",
) -> bytes:
    """Build a small ELF64 with a real executable .text section."""
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1

    names = b"\x00.text\x00.shstrtab\x00"
    text_offset = 128
    names_offset = text_offset + len(text)
    section_offset = (names_offset + len(names) + 7) & ~7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(ident),
        2,
        62,
        1,
        0x401000,
        64,
        section_offset,
        0,
        64,
        56,
        1,
        64,
        3,
        2,
    )
    program_header = struct.pack(
        "<IIQQQQQQ",
        0x6474E551,
        6,
        0,
        0,
        0,
        0,
        0,
        16,
    )
    null_section = bytes(64)
    text_section = struct.pack(
        "<IIQQQQIIQQ",
        1,
        1,
        6,
        0x401000,
        text_offset,
        len(text),
        0,
        0,
        16,
        0,
    )
    names_section = struct.pack(
        "<IIQQQQIIQQ",
        7,
        3,
        0,
        0,
        names_offset,
        len(names),
        0,
        0,
        1,
        0,
    )
    prefix = header + program_header
    prefix += bytes(text_offset - len(prefix)) + text + names
    prefix += bytes(section_offset - len(prefix))
    return prefix + null_section + text_section + names_section


@pytest.fixture()
def app(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key",
            "SECRET_KEY_WAS_CONFIGURED": True,
            "DATABASE": str(tmp_path / "learning.db"),
            "UPLOAD_DIR": str(tmp_path / "uploads"),
            "MAX_CONTENT_LENGTH": 1024 * 1024,
            "ANALYSIS_TIMEOUT": 5,
            "MAX_STRINGS": 100,
            "RATE_LIMIT": 1000,
            "RATE_WINDOW": 60,
        }
    )
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()
