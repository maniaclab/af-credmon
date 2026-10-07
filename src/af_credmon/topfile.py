"""Discover and read the top-token files credd writes for the af-mcp-platform storer.

credd stores each top token as ``<creddir>/<user>/<prefix><kind>.top``: a
JSON object whose ``access_token`` is an AF Broker Identity Token with
``aud=af-credmon/<kind>``. The matching ``.use`` file next to it is what
this credmon writes and what HTCondor's shadow ships to the job.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pathlib import Path

# Credential kinds the broker can redeem (POST /v1/credentials/<kind>/redeem).
KINDS: Final = ("x509", "krb5", "servicex")


class TopFileError(Exception):
    """A top-token file exists but cannot be used."""


@dataclass(frozen=True)
class TopCredential:
    """One user's top token for one credential kind."""

    user: str
    kind: str
    top_path: Path

    @property
    def use_path(self) -> Path:
        """The ``.use`` file HTCondor ships to the job, next to the ``.top`` file."""
        return self.top_path.with_suffix(".use")


def discover(cred_dir: Path, *, prefix: str) -> list[TopCredential]:
    """Return every ``<user>/<prefix><kind>.top`` under *cred_dir*, sorted by user then kind.

    Only per-user subdirectories are scanned, so credd's own bookkeeping at
    the top level (``pid``, ``CREDMON_COMPLETE``, ``<user>.mark``, web-flow
    request files) is never mistaken for a credential. Files without
    *prefix*, or with a kind the broker cannot redeem, belong to someone
    else and are skipped.
    """
    if not cred_dir.is_dir():
        return []
    found: list[TopCredential] = []
    for user_dir in sorted(p for p in cred_dir.iterdir() if p.is_dir()):
        for top_path in sorted(user_dir.glob(f"{prefix}*.top")):
            kind = top_path.stem[len(prefix) :]
            if kind in KINDS:
                found.append(
                    TopCredential(user=user_dir.name, kind=kind, top_path=top_path)
                )
    return found


def read_top_token(path: Path) -> str:
    """Return the ``access_token`` stored in the top-token file at *path*."""
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise TopFileError(f"{path} is not valid JSON") from exc
    token = data.get("access_token") if isinstance(data, dict) else None
    if not isinstance(token, str) or not token:
        raise TopFileError(f"{path} has no access_token")
    return token
