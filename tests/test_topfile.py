"""Tests for discovering and reading credd-written top-token files.

credd stores the broker's top token as ``<creddir>/<user>/<prefix><kind>.top``
(a JSON object with ``access_token``) when the af-mcp-platform storer pushes
it with ``refresh=true``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from af_credmon.topfile import TopCredential, TopFileError, discover, read_top_token

if TYPE_CHECKING:
    from pathlib import Path


def _top(cred_dir: Path, user: str, name: str, token: str = "tok") -> Path:
    user_dir = cred_dir / user
    user_dir.mkdir(exist_ok=True)
    path = user_dir / name
    path.write_text(json.dumps({"access_token": token}))
    return path


def test_discovers_prefixed_top_files_per_user(tmp_path: Path) -> None:
    _top(tmp_path, "alice", "af_krb5.top")
    _top(tmp_path, "alice", "af_x509.top")
    _top(tmp_path, "bob", "af_servicex.top")

    found = discover(tmp_path, prefix="af_")

    assert found == [
        TopCredential(
            user="alice", kind="krb5", top_path=tmp_path / "alice" / "af_krb5.top"
        ),
        TopCredential(
            user="alice", kind="x509", top_path=tmp_path / "alice" / "af_x509.top"
        ),
        TopCredential(
            user="bob", kind="servicex", top_path=tmp_path / "bob" / "af_servicex.top"
        ),
    ]


def test_use_path_sits_next_to_the_top_file(tmp_path: Path) -> None:
    top = TopCredential(
        user="alice", kind="krb5", top_path=tmp_path / "alice" / "af_krb5.top"
    )

    assert top.use_path == tmp_path / "alice" / "af_krb5.use"


def test_ignores_other_credmons_files(tmp_path: Path) -> None:
    """Files that don't carry our prefix belong to other credmons (scitokens,
    Vault, ...) and must never be touched."""
    _top(tmp_path, "alice", "scitokens.top")
    _top(tmp_path, "alice", "myvault_handle.top")
    (tmp_path / "alice" / "af_krb5.use").write_text("existing")

    assert discover(tmp_path, prefix="af_") == []


def test_skips_unknown_kinds(tmp_path: Path) -> None:
    _top(tmp_path, "alice", "af_panda.top")

    assert discover(tmp_path, prefix="af_") == []


def test_ignores_credd_bookkeeping_entries(tmp_path: Path) -> None:
    """The credential directory also holds credd/credmon bookkeeping (pid,
    CREDMON_COMPLETE, <user>.mark sweep markers, 64-hex web-flow files)."""
    (tmp_path / "pid").write_text("123")
    (tmp_path / "CREDMON_COMPLETE").write_text("")
    (tmp_path / "alice.mark").write_text("")
    _top(tmp_path, "alice", "af_krb5.top")

    assert [t.user for t in discover(tmp_path, prefix="af_")] == ["alice"]


def test_missing_cred_dir_discovers_nothing(tmp_path: Path) -> None:
    assert discover(tmp_path / "absent", prefix="af_") == []


def test_reads_access_token(tmp_path: Path) -> None:
    path = _top(tmp_path, "alice", "af_krb5.top", token="eyJ.top.token")

    assert read_top_token(path) == "eyJ.top.token"


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("not json", "not valid JSON"),
        (json.dumps({"other": "x"}), "no access_token"),
        (json.dumps({"access_token": ""}), "no access_token"),
        (json.dumps(["access_token"]), "no access_token"),
    ],
)
def test_malformed_top_file_raises(tmp_path: Path, content: str, reason: str) -> None:
    path = tmp_path / "af_krb5.top"
    path.write_text(content)

    with pytest.raises(TopFileError, match=reason):
        read_top_token(path)
