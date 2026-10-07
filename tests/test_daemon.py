"""Tests for the credmon daemon loop and its HTCondor bookkeeping.

primary mode is the credd-facing credmon: it owns ``<creddir>/pid`` (credd
SIGHUPs that pid after every store), touches ``CREDMON_COMPLETE`` after each
scan, and tells condor_master it is ready after the first one. alongside
mode coexists with another credmon (e.g. condor_credmon_oauth) that owns
those files, so it only polls.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from af_credmon.daemon import Daemon, configure_logging, parse_args
from af_credmon.monitor import ScanReport

if TYPE_CHECKING:
    from pathlib import Path


class _FakeMonitor:
    def __init__(self) -> None:
        self.scans: list[datetime] = []

    async def scan_once(self, *, now: datetime) -> ScanReport:
        self.scans.append(now)
        return ScanReport()


def _daemon(
    cred_dir: Path, mode: str, ready_calls: list[str], interval: float = 60.0
) -> tuple[Daemon, _FakeMonitor]:
    monitor = _FakeMonitor()
    daemon = Daemon(
        cred_dir,
        monitor=monitor,  # type: ignore[arg-type]
        mode=mode,
        interval=interval,
        set_ready=ready_calls.append,
    )
    return daemon, monitor


async def test_primary_writes_pid_and_complete_and_signals_ready_once(
    tmp_path: Path,
) -> None:
    ready: list[str] = []
    daemon, monitor = _daemon(tmp_path, "primary", ready)

    daemon.prepare()
    await daemon.run_once()
    await daemon.run_once()

    assert (tmp_path / "pid").read_text().strip().isdigit()
    assert (tmp_path / "CREDMON_COMPLETE").exists()
    assert ready == ["Ready"]
    assert len(monitor.scans) == 2


async def test_primary_clears_stale_complete_marker_before_first_scan(
    tmp_path: Path,
) -> None:
    """A CREDMON_COMPLETE left from a previous run must not tell condor_master
    the new process is ready before it has scanned anything."""
    (tmp_path / "CREDMON_COMPLETE").write_text("")
    daemon, _ = _daemon(tmp_path, "primary", [])

    daemon.prepare()

    assert not (tmp_path / "CREDMON_COMPLETE").exists()


async def test_alongside_never_touches_credd_bookkeeping(tmp_path: Path) -> None:
    (tmp_path / "pid").write_text("4242")
    (tmp_path / "CREDMON_COMPLETE").write_text("")
    ready: list[str] = []
    daemon, monitor = _daemon(tmp_path, "alongside", ready)

    daemon.prepare()
    await daemon.run_once()

    assert (tmp_path / "pid").read_text() == "4242"
    assert ready == []
    assert len(monitor.scans) == 1


async def test_ready_signal_failure_is_not_fatal(tmp_path: Path) -> None:
    """Outside condor_master (e.g. run by hand) the ready message cannot be
    delivered; the credmon must keep working."""

    def _fail(_state: str) -> None:
        raise RuntimeError("not started by condor_master")

    daemon = Daemon(
        tmp_path,
        monitor=_FakeMonitor(),  # type: ignore[arg-type]
        mode="primary",
        interval=60.0,
        set_ready=_fail,
    )

    await daemon.run_once()

    assert (tmp_path / "CREDMON_COMPLETE").exists()


async def test_wake_triggers_an_immediate_rescan_and_stop_ends_the_loop(
    tmp_path: Path,
) -> None:
    daemon, monitor = _daemon(tmp_path, "alongside", [], interval=3600.0)

    task = asyncio.create_task(daemon.run_forever())
    for _ in range(100):
        if monitor.scans:
            break
        await asyncio.sleep(0.01)
    daemon.wake()
    for _ in range(100):
        if len(monitor.scans) >= 2:
            break
        await asyncio.sleep(0.01)
    daemon.stop()
    await asyncio.wait_for(task, timeout=1.0)

    assert len(monitor.scans) == 2


async def test_scan_times_are_timezone_aware_utc(tmp_path: Path) -> None:
    daemon, monitor = _daemon(tmp_path, "alongside", [])

    await daemon.run_once()

    assert monitor.scans[0].tzinfo == timezone.utc


def test_parse_args_requires_broker_url_and_defaults(tmp_path: Path) -> None:
    args = parse_args(
        ["--broker-url", "https://mcp.example.org", "--cred-dir", str(tmp_path)]
    )

    assert args.broker_url == "https://mcp.example.org"
    assert args.cred_dir == tmp_path
    assert args.prefix == "af_"
    assert args.mode == "primary"
    assert args.interval == 60.0
    assert args.min_remaining == 600.0


def test_parse_args_rejects_unknown_mode(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        parse_args(
            [
                "--broker-url",
                "https://x",
                "--cred-dir",
                str(tmp_path),
                "--mode",
                "sideways",
            ]
        )


def test_log_file_option_sends_logs_to_that_file(tmp_path: Path) -> None:
    """condor_master does not capture a daemon's stderr; like
    condor_credmon_oauth's CREDMON_OAUTH_LOG, the credmon needs its own log."""
    log_file = tmp_path / "AfCredmonLog"
    args = parse_args(
        [
            "--broker-url",
            "https://x",
            "--cred-dir",
            str(tmp_path),
            "--log-file",
            str(log_file),
        ]
    )
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        configure_logging(args)
        logging.getLogger("af_credmon.test").warning("hello from the credmon")
        for handler in root.handlers:
            handler.flush()
    finally:
        for handler in root.handlers[:]:
            if handler not in before:
                root.removeHandler(handler)
                handler.close()

    assert "hello from the credmon" in log_file.read_text()
