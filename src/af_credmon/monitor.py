"""One credmon scan: keep every ``<prefix><kind>.use`` in step with its ``.top``."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from af_credentials.proxy import ProxyNotAvailableError, ProxyRedeemError

from af_credmon.topfile import TopCredential, TopFileError, discover, read_top_token
from af_credmon.usefile import remove_use_file, write_use_file

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from af_credmon.redeem import Redeemer

log = logging.getLogger(__name__)

# Renew once less than this fraction of a credential's lifetime (measured
# from when it was redeemed) remains -- the same "renew at 2/3 of lifetime"
# point HTCondor's own local credmon uses.
_RENEW_REMAINING_FRACTION = 1 / 3


@dataclass(frozen=True)
class _Issued:
    redeemed_at: datetime
    expires_at: datetime


@dataclass
class ScanReport:
    """Outcome counts of one ``CredentialMonitor.scan_once``."""

    refreshed: int = 0
    current: int = 0
    removed: int = 0
    failed: int = 0


class CredentialMonitor:
    """Redeems top tokens into ``.use`` files and renews them before they expire.

    What was issued is remembered in memory only: after a restart every
    credential is redeemed once more, which costs one broker call per user
    and kind and avoids writing any bookkeeping into credd's directory.
    """

    def __init__(self, cred_dir: Path, *, prefix: str, redeemer: Redeemer) -> None:
        self._cred_dir = cred_dir
        self._prefix = prefix
        self._redeemer = redeemer
        self._issued: dict[Path, _Issued] = {}

    async def scan_once(self, *, now: datetime) -> ScanReport:
        """Bring every ``.use`` file up to date; per-credential failures are counted, never raised."""
        report = ScanReport()
        tops = discover(self._cred_dir, prefix=self._prefix)
        # Users are handled one after another: a scan is a handful of broker
        # calls per user every minute, and a slow broker only delays the
        # next scan, never a credential HTCondor already holds.
        for top in tops:
            await self._sync(top, now, report)
        self._remove_orphans({top.use_path for top in tops}, report)
        log.info(
            "scan complete: refreshed=%d current=%d removed=%d failed=%d",
            report.refreshed,
            report.current,
            report.removed,
            report.failed,
        )
        return report

    def _is_due(self, top: TopCredential, now: datetime) -> bool:
        issued = self._issued.get(top.use_path)
        if issued is None or not top.use_path.exists():
            return True
        lifetime = issued.expires_at - issued.redeemed_at
        return issued.expires_at - now < lifetime * _RENEW_REMAINING_FRACTION

    async def _sync(
        self, top: TopCredential, now: datetime, report: ScanReport
    ) -> None:
        if not self._is_due(top, now):
            report.current += 1
            return
        try:
            token = read_top_token(top.top_path)
            cred = await self._redeemer.redeem(top.kind, token)
            write_use_file(top.use_path, cred.content)
        except ProxyNotAvailableError as exc:
            # The broker has nothing to serve: the identity is unlinked (or
            # its credential is too close to expiry to be useful). A stale
            # .use would only hand jobs a dead credential.
            log.warning(
                "%s for %s not available, removing .use: %s", top.kind, top.user, exc
            )
            remove_use_file(top.use_path)
            self._issued.pop(top.use_path, None)
            report.removed += 1
        except (ProxyRedeemError, TopFileError, OSError) as exc:
            # Broker outage, expired top token, unreadable file: keep any
            # existing .use while it may still be valid, and retry next scan.
            log.error("refreshing %s for %s failed: %s", top.kind, top.user, exc)  # noqa: TRY400
            report.failed += 1
            issued = self._issued.get(top.use_path)
            if issued is not None and issued.expires_at <= now:
                # Its credential has expired, so it can only hand jobs a dead
                # one. (After a restart nothing is known about an existing
                # .use's expiry, so it is kept until a refresh succeeds or
                # the broker answers 404.)
                log.warning("removing expired %s for %s", top.kind, top.user)
                remove_use_file(top.use_path)
                self._issued.pop(top.use_path, None)
                report.removed += 1
        else:
            self._issued[top.use_path] = _Issued(
                redeemed_at=now, expires_at=cred.expires_at
            )
            log.info(
                "refreshed %s for %s (expires %s)", top.kind, top.user, cred.expires_at
            )
            report.refreshed += 1

    def _remove_orphans(self, live: set[Path], report: ScanReport) -> None:
        """Delete our ``.use`` files whose ``.top`` credd has removed; other credmons' files are left alone."""
        if not self._cred_dir.is_dir():
            return
        for user_dir in (p for p in self._cred_dir.iterdir() if p.is_dir()):
            for use_path in user_dir.glob(f"{self._prefix}*.use"):
                if use_path not in live:
                    log.info("removing %s: its top token is gone", use_path)
                    remove_use_file(use_path)
                    self._issued.pop(use_path, None)
                    report.removed += 1
