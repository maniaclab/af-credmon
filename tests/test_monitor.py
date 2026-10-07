"""Tests for one credmon scan over the credential directory."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from af_credentials.proxy import ProxyNotAvailableError, ProxyRedeemError

from af_credmon.monitor import CredentialMonitor
from af_credmon.redeem import RedeemedCredential

if TYPE_CHECKING:
    from pathlib import Path

T0 = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


class _FakeRedeemer:
    """Scriptable stand-in for ``Redeemer``: per-(kind, token) results."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.lifetime = timedelta(hours=3)
        self.errors: dict[str, Exception] = {}
        self.now = T0

    async def redeem(self, kind: str, top_token: str) -> RedeemedCredential:
        self.calls.append((kind, top_token))
        if top_token in self.errors:
            raise self.errors[top_token]
        content = f"{kind}:{top_token}:{len(self.calls)}".encode()
        return RedeemedCredential(content, self.now + self.lifetime)


def _top(cred_dir: Path, user: str, kind: str, token: str) -> Path:
    user_dir = cred_dir / user
    user_dir.mkdir(exist_ok=True)
    path = user_dir / f"af_{kind}.top"
    path.write_text(json.dumps({"access_token": token}))
    return path


@pytest.fixture
def redeemer() -> _FakeRedeemer:
    return _FakeRedeemer()


def _monitor(cred_dir: Path, redeemer: _FakeRedeemer) -> CredentialMonitor:
    return CredentialMonitor(cred_dir, prefix="af_", redeemer=redeemer)  # type: ignore[arg-type]


async def test_first_scan_writes_use_files_for_every_top(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    _top(tmp_path, "alice", "krb5", "tok-a")
    _top(tmp_path, "bob", "x509", "tok-b")

    report = await _monitor(tmp_path, redeemer).scan_once(now=T0)

    assert report.refreshed == 2
    assert (tmp_path / "alice" / "af_krb5.use").read_bytes().startswith(b"krb5:tok-a")
    assert (tmp_path / "bob" / "af_x509.use").read_bytes().startswith(b"x509:tok-b")


async def test_fresh_credentials_are_not_redeemed_again(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    _top(tmp_path, "alice", "krb5", "tok-a")
    monitor = _monitor(tmp_path, redeemer)
    await monitor.scan_once(now=T0)

    report = await monitor.scan_once(now=T0 + timedelta(hours=1))

    assert report.current == 1
    assert len(redeemer.calls) == 1


async def test_credential_is_renewed_in_its_last_third(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    _top(tmp_path, "alice", "krb5", "tok-a")
    monitor = _monitor(tmp_path, redeemer)
    await monitor.scan_once(now=T0)
    first = (tmp_path / "alice" / "af_krb5.use").read_bytes()

    later = T0 + timedelta(hours=2, minutes=1)  # 59 min of a 3h lifetime left
    redeemer.now = later
    report = await monitor.scan_once(now=later)

    assert report.refreshed == 1
    assert (tmp_path / "alice" / "af_krb5.use").read_bytes() != first


async def test_missing_use_file_is_rewritten(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    _top(tmp_path, "alice", "krb5", "tok-a")
    monitor = _monitor(tmp_path, redeemer)
    await monitor.scan_once(now=T0)
    (tmp_path / "alice" / "af_krb5.use").unlink()

    report = await monitor.scan_once(now=T0 + timedelta(minutes=1))

    assert report.refreshed == 1
    assert (tmp_path / "alice" / "af_krb5.use").exists()


async def test_not_linked_removes_stale_use_file(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    _top(tmp_path, "alice", "krb5", "tok-a")
    monitor = _monitor(tmp_path, redeemer)
    await monitor.scan_once(now=T0)

    redeemer.errors["tok-a"] = ProxyNotAvailableError("no Kerberos ticket")
    redeemer.now = T0 + timedelta(hours=2, minutes=30)
    report = await monitor.scan_once(now=redeemer.now)

    assert report.removed == 1
    assert not (tmp_path / "alice" / "af_krb5.use").exists()


async def test_other_failures_keep_the_existing_use_file(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    """A broker outage or an expired top token must not strip a still-valid
    credential from running jobs; the next scan retries."""
    _top(tmp_path, "alice", "krb5", "tok-a")
    monitor = _monitor(tmp_path, redeemer)
    await monitor.scan_once(now=T0)
    before = (tmp_path / "alice" / "af_krb5.use").read_bytes()

    redeemer.errors["tok-a"] = ProxyRedeemError(502, "broker unavailable")
    redeemer.now = T0 + timedelta(hours=2, minutes=30)
    report = await monitor.scan_once(now=redeemer.now)

    assert report.failed == 1
    assert (tmp_path / "alice" / "af_krb5.use").read_bytes() == before


async def test_one_users_failure_does_not_block_others(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    _top(tmp_path, "alice", "krb5", "tok-a")
    _top(tmp_path, "bob", "krb5", "tok-b")
    redeemer.errors["tok-a"] = ProxyRedeemError(401, "expired top token")

    report = await _monitor(tmp_path, redeemer).scan_once(now=T0)

    assert report.failed == 1
    assert report.refreshed == 1
    assert (tmp_path / "bob" / "af_krb5.use").exists()


async def test_malformed_top_file_is_counted_as_failed(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    (tmp_path / "alice").mkdir()
    (tmp_path / "alice" / "af_krb5.top").write_text("not json")

    report = await _monitor(tmp_path, redeemer).scan_once(now=T0)

    assert report.failed == 1
    assert redeemer.calls == []


async def test_orphaned_use_file_is_removed(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    """credd deleted the top token (user unlinked, or the absent-owner sweep);
    our .use for it must not outlive it. Other credmons' files stay."""
    (tmp_path / "alice").mkdir()
    (tmp_path / "alice" / "af_krb5.use").write_text("stale")
    (tmp_path / "alice" / "scitokens.use").write_text("not ours")

    report = await _monitor(tmp_path, redeemer).scan_once(now=T0)

    assert report.removed == 1
    assert not (tmp_path / "alice" / "af_krb5.use").exists()
    assert (tmp_path / "alice" / "scitokens.use").exists()


async def test_expired_credential_is_removed_when_refresh_fails(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    """Once the top token itself expires (e.g. the user unlinked and the storer
    stopped refreshing it), the broker answers 401 rather than 404. A .use whose
    credential has already expired is useless to jobs and must not linger."""
    _top(tmp_path, "alice", "krb5", "tok-a")
    monitor = _monitor(tmp_path, redeemer)
    await monitor.scan_once(now=T0)

    redeemer.errors["tok-a"] = ProxyRedeemError(
        401, "Invalid or expired broker identity token"
    )
    report = await monitor.scan_once(now=T0 + timedelta(hours=3, minutes=1))

    assert report.removed == 1
    assert report.failed == 1
    assert not (tmp_path / "alice" / "af_krb5.use").exists()


async def test_expired_credential_is_removed_when_top_file_is_unreadable(
    tmp_path: Path, redeemer: _FakeRedeemer
) -> None:
    top = _top(tmp_path, "alice", "krb5", "tok-a")
    monitor = _monitor(tmp_path, redeemer)
    await monitor.scan_once(now=T0)

    top.write_text("not json")
    report = await monitor.scan_once(now=T0 + timedelta(hours=4))

    assert report.removed == 1
    assert not (tmp_path / "alice" / "af_krb5.use").exists()
