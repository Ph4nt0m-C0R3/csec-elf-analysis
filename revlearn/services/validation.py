"""Secure upload storage and ELF validation."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from revlearn.errors import ValidationError

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
EXECUTABLE_TYPES = {"ET_EXEC", "ET_DYN"}


@dataclass(frozen=True)
class StoredUpload:
    path: Path
    display_name: str
    size: int


def _display_name(raw_name: str | None) -> str:
    cleaned = (raw_name or "uploaded.elf").replace("\\", "/").split("/")[-1]
    cleaned = "".join(ch for ch in cleaned if ch >= " " and ch != "\x7f")
    return (cleaned.strip() or "uploaded.elf")[:160]


def store_and_validate(file_storage, upload_dir: str, maximum_bytes: int) -> StoredUpload:
    if file_storage is None or not file_storage.filename:
        raise ValidationError("Choose an ELF file before starting the analysis.")

    target_dir = Path(upload_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{uuid.uuid4().hex}.upload"
    size = 0
    first_bytes = b""

    try:
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            while True:
                chunk = file_storage.stream.read(64 * 1024)
                if not chunk:
                    break
                if len(first_bytes) < 4:
                    first_bytes += chunk[: 4 - len(first_bytes)]
                size += len(chunk)
                if size > maximum_bytes:
                    raise ValidationError(
                        "The file exceeds the configured upload-size limit."
                    )
                output.write(chunk)

        if size == 0:
            raise ValidationError("The selected file is empty.")
        if first_bytes.startswith(PE_MAGIC):
            raise ValidationError(
                "This is a Windows PE executable. This version detects PE files but analyzes ELF files only."
            )
        if first_bytes != ELF_MAGIC:
            raise ValidationError(
                "The selected file is not an ELF executable (ELF signature missing)."
            )
        _validate_elf_structure(target)
        return StoredUpload(target, _display_name(file_storage.filename), size)
    except Exception:
        target.unlink(missing_ok=True)
        raise


def _validate_elf_structure(path: Path) -> None:
    try:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            file_type = elf.header["e_type"]
            if file_type not in EXECUTABLE_TYPES:
                raise ValidationError(
                    "The ELF file is not an executable or position-independent executable."
                )
            if elf.num_segments() < 1:
                raise ValidationError(
                    "The ELF file has no loadable program structure."
                )
            # Materialize headers now so malformed offsets fail before analysis.
            list(elf.iter_segments())
            list(elf.iter_sections())
    except ValidationError:
        raise
    except (ELFError, OSError, ValueError, TypeError, OverflowError) as exc:
        raise ValidationError(
            "The ELF file is truncated, malformed, or unsupported."
        ) from exc
