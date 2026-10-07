"""The af-credmon process: scan on a timer or on SIGHUP, with HTCondor's credmon bookkeeping.

Started by condor_master, typically as ``CREDMON_OAUTH``::

    DAEMON_LIST = $(DAEMON_LIST) CREDD CREDMON_OAUTH
    CREDMON_OAUTH = /opt/af-credmon/.pixi/envs/default/bin/af-credmon
    CREDMON_OAUTH_ARGS = --broker-url https://mcp.example.org

``--mode primary`` (the default) is the credmon credd talks to: it owns
``<creddir>/pid`` (credd SIGHUPs that pid after every store), touches
``CREDMON_COMPLETE`` after each scan and sends condor_master its ready
message after the first one. ``--mode alongside`` runs next to another
credmon that owns those files (e.g. condor_credmon_oauth) and only polls.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import htcondor2

from af_credmon.monitor import CredentialMonitor
from af_credmon.redeem import Redeemer

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

log = logging.getLogger(__name__)

_PID_FILE = "pid"
_COMPLETE_FILE = "CREDMON_COMPLETE"


class Daemon:
    """Runs ``CredentialMonitor`` scans every *interval* seconds, or immediately on ``wake()``."""

    def __init__(
        self,
        cred_dir: Path,
        *,
        monitor: CredentialMonitor,
        mode: str,
        interval: float,
        set_ready: Callable[[str], object] = htcondor2.set_ready_state,
    ) -> None:
        self._cred_dir = cred_dir
        self._monitor = monitor
        self._primary = mode == "primary"
        self._interval = interval
        self._set_ready = set_ready
        self._ready_sent = False
        self._wake = asyncio.Event()
        self._stopping = False

    def prepare(self) -> None:
        """In primary mode, claim the credd-facing pid file and clear a stale completion marker."""
        if not self._primary:
            return
        (self._cred_dir / _COMPLETE_FILE).unlink(missing_ok=True)
        (self._cred_dir / _PID_FILE).write_text(f"{os.getpid()}\n")

    async def run_once(self) -> None:
        """One scan, plus (primary mode) the completion marker and the one-time ready message."""
        await self._monitor.scan_once(now=datetime.now(timezone.utc))
        if not self._primary:
            return
        (self._cred_dir / _COMPLETE_FILE).touch()
        if not self._ready_sent:
            self._ready_sent = True
            try:
                self._set_ready("Ready")
            except Exception:  # noqa: BLE001 -- best-effort, like condor_credmon_oauth
                log.warning("could not send the ready message to condor_master")

    async def run_forever(self) -> None:
        """Scan until ``stop()``; a scan failure is logged and retried next interval."""
        while not self._stopping:
            try:
                await self.run_once()
            except Exception:
                log.exception("scan failed")
            # stop() also sets the wake event, so this returns at once when
            # stopping and the loop condition ends the run.
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=self._interval)
            self._wake.clear()

    def wake(self) -> None:
        """Rescan now (credd sends SIGHUP after storing a credential)."""
        self._wake.set()

    def stop(self) -> None:
        """End ``run_forever`` after the current scan."""
        self._stopping = True
        self._wake.set()


def _default_cred_dir() -> Path | None:
    try:
        return Path(htcondor2.param["SEC_CREDENTIAL_DIRECTORY_OAUTH"])
    except KeyError:
        return None


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the command line; ``--cred-dir`` defaults to HTCondor's ``SEC_CREDENTIAL_DIRECTORY_OAUTH``."""
    parser = argparse.ArgumentParser(
        prog="af-credmon", description=__doc__.splitlines()[0]
    )
    parser.add_argument("--broker-url", required=True, help="AF MCP broker base URL")
    parser.add_argument(
        "--cred-dir",
        type=Path,
        help="credd's OAuth credential directory (default: from HTCondor config)",
    )
    parser.add_argument(
        "--prefix", default="af_", help="credd service-name prefix (default: af_)"
    )
    parser.add_argument("--mode", choices=["primary", "alongside"], default="primary")
    parser.add_argument(
        "--interval", type=float, default=60.0, help="seconds between scans"
    )
    parser.add_argument(
        "--min-remaining",
        type=float,
        default=600.0,
        help="refuse credentials expiring sooner than this many seconds (default: 600, "
        "twice HTCondor's default SEC_CREDENTIAL_REFRESH)",
    )
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)
    if args.cred_dir is None:
        args.cred_dir = _default_cred_dir()
        if args.cred_dir is None:
            parser.error(
                "--cred-dir is required when SEC_CREDENTIAL_DIRECTORY_OAUTH is not set"
            )
    return args


async def _amain(args: argparse.Namespace) -> None:
    monitor = CredentialMonitor(
        args.cred_dir,
        prefix=args.prefix,
        redeemer=Redeemer(args.broker_url, min_remaining=args.min_remaining),
    )
    daemon = Daemon(
        args.cred_dir, monitor=monitor, mode=args.mode, interval=args.interval
    )
    daemon.prepare()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGHUP, daemon.wake)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT):
        loop.add_signal_handler(sig, daemon.stop)
    log.info("af-credmon started: mode=%s cred_dir=%s", args.mode, args.cred_dir)
    await daemon.run_forever()
    log.info("af-credmon stopped")


def main(argv: Sequence[str] | None = None) -> None:
    """Console entry point."""
    args = parse_args(argv)
    logging.basicConfig(
        level=args.log_level.upper(),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(_amain(args))
