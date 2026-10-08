from __future__ import annotations

import io

import pytest
from werkzeug.datastructures import FileStorage

from revlearn.errors import ValidationError
from revlearn.services.validation import store_and_validate

from conftest import minimal_elf64


def upload(data: bytes, filename: str = "sample.elf") -> FileStorage:
    return FileStorage(stream=io.BytesIO(data), filename=filename)


def test_valid_elf_is_stored_with_random_name(tmp_path):
    result = store_and_validate(
        upload(minimal_elf64(), "../../student sample.elf"),
        str(tmp_path),
        4096,
    )
    try:
        assert result.path.exists()
        assert result.path.name.endswith(".upload")
        assert result.display_name == "student sample.elf"
        assert result.size == len(minimal_elf64())
    finally:
        result.path.unlink()


@pytest.mark.parametrize(
    "data,message",
    [
        (b"", "empty"),
        (b"not an elf", "signature"),
        (b"\x7fELF\x02\x01", "malformed"),
    ],
)
def test_invalid_files_are_rejected_and_removed(tmp_path, data, message):
    with pytest.raises(ValidationError, match=message):
        store_and_validate(upload(data), str(tmp_path), 4096)
    assert list(tmp_path.glob("*.upload")) == []


def test_pe_files_get_specific_scope_message(tmp_path):
    with pytest.raises(ValidationError, match="Windows PE executable"):
        store_and_validate(upload(b"MZ" + b"\x00" * 128, "demo.exe"), str(tmp_path), 4096)
    assert list(tmp_path.glob("*.upload")) == []


def test_manual_size_limit_is_enforced(tmp_path):
    data = minimal_elf64(trailer=b"A" * 500)
    with pytest.raises(ValidationError, match="size"):
        store_and_validate(upload(data), str(tmp_path), 128)
    assert list(tmp_path.glob("*.upload")) == []
