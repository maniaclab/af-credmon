"""Atomic writes of the ``.use`` files HTCondor's shadow ships to jobs."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Owner read-only. The shadow rejects .use files with any group/other bit
# unless TRUST_CREDENTIAL_DIRECTORY is set; running as root, the owner is
# root, which is what its SECURE_FILE_VERIFY_ALL check expects.
_USE_FILE_MODE = 0o400


def write_use_file(path: Path, content: bytes) -> None:
    """Atomically replace *path* with *content* at mode 0400.

    The temp file lives in the same directory so the final ``Path.replace`` is
    a same-filesystem rename: the shadow sees either the old credential or
    the new one, never a partial write. On any failure the temp file is
    removed and the existing ``.use`` file is left untouched.
    """
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as tmp:
            os.fchmod(tmp.fileno(), _USE_FILE_MODE)
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
        Path(tmp_name).replace(path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def remove_use_file(path: Path) -> None:
    """Delete *path* if it exists (e.g. the user's identity is no longer linked)."""
    path.unlink(missing_ok=True)
