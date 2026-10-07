"""Tests for writing and removing ``.use`` files.

HTCondor's shadow reads ``<creddir>/<user>/<svc>.use`` as root and refuses
files with group/other permission bits (unless TRUST_CREDENTIAL_DIRECTORY),
and must never see a half-written credential -- so writes go through a
temp file in the same directory, mode 0400, then an atomic rename.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from af_credmon.usefile import remove_use_file, write_use_file


def test_writes_content_with_owner_read_only_mode(tmp_path: Path) -> None:
    path = tmp_path / "af_krb5.use"

    write_use_file(path, b"\x05\x04ccache-bytes")

    assert path.read_bytes() == b"\x05\x04ccache-bytes"
    assert stat.S_IMODE(path.stat().st_mode) == 0o400


def test_replaces_an_existing_read_only_file(tmp_path: Path) -> None:
    path = tmp_path / "af_x509.use"
    write_use_file(path, b"old proxy")

    write_use_file(path, b"new proxy")

    assert path.read_bytes() == b"new proxy"
    assert stat.S_IMODE(path.stat().st_mode) == 0o400


def test_leaves_no_temp_files_behind(tmp_path: Path) -> None:
    write_use_file(tmp_path / "af_krb5.use", b"x")

    assert sorted(p.name for p in tmp_path.iterdir()) == ["af_krb5.use"]


def test_failed_write_keeps_old_file_and_cleans_up_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "af_krb5.use"
    write_use_file(path, b"old")

    def _boom(self: Path, target: Path) -> Path:  # noqa: ARG001
        raise OSError("disk full (test)")

    monkeypatch.setattr(Path, "replace", _boom)
    with pytest.raises(OSError, match="disk full"):
        write_use_file(path, b"new")

    assert path.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["af_krb5.use"]


def test_remove_deletes_the_file(tmp_path: Path) -> None:
    path = tmp_path / "af_krb5.use"
    write_use_file(path, b"x")

    remove_use_file(path)

    assert not path.exists()


def test_remove_of_missing_file_is_a_noop(tmp_path: Path) -> None:
    remove_use_file(tmp_path / "af_krb5.use")
