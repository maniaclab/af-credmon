"""Integration test: the real ``af-credmon`` process against a local broker stand-in.

Runs the installed console script as a subprocess in primary mode with a
fast interval, serving the broker's redeem contract from a local HTTP
server, and checks the files credd and the shadow rely on, SIGHUP-driven
rescans, and a clean SIGTERM shutdown. (End-to-end against a real broker
and credd is the deployment acceptance test, not this.)
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_CCACHE = b"\x05\x04integration-ccache"


class _BrokerHandler(BaseHTTPRequestHandler):
    seen_tokens: list[str] = []  # noqa: RUF012 -- class-level request log shared with the test

    def do_POST(self) -> None:
        self.seen_tokens.append(self.headers.get("Authorization", ""))
        if self.path != "/v1/credentials/krb5/redeem":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(
            {
                "ccache_b64": base64.b64encode(_CCACHE).decode(),
                "principal": "tuser@CERN.CH",
                "realm": "CERN.CH",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "remaining_seconds": 86400,
                "renew_until": None,
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep test output quiet


@pytest.fixture
def broker_url() -> Iterator[str]:
    _BrokerHandler.seen_tokens = []
    server = HTTPServer(("127.0.0.1", 0), _BrokerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _wait_for(predicate: object, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():  # type: ignore[operator]
            return True
        time.sleep(0.05)
    return False


def test_primary_mode_end_to_end_against_local_broker(
    tmp_path: Path, broker_url: str
) -> None:
    exe = shutil.which("af-credmon")
    assert exe is not None, (
        "af-credmon console script not installed in this environment"
    )
    user_dir = tmp_path / "alice"
    user_dir.mkdir()
    (user_dir / "af_krb5.top").write_text(json.dumps({"access_token": "top-a"}))

    proc = subprocess.Popen(
        [
            exe,
            "--broker-url",
            broker_url,
            "--cred-dir",
            str(tmp_path),
            "--interval",
            "30",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        use = user_dir / "af_krb5.use"
        assert _wait_for(use.exists), "credmon never wrote the .use file"
        assert use.read_bytes() == _CCACHE
        assert oct(use.stat().st_mode & 0o777) == oct(0o400)
        assert _wait_for((tmp_path / "CREDMON_COMPLETE").exists)
        assert (tmp_path / "pid").read_text().strip() == str(proc.pid)

        # credd SIGHUPs the credmon after storing a credential: a new user's
        # top token must be picked up without waiting for the 30s interval.
        (tmp_path / "bob").mkdir()
        (tmp_path / "bob" / "af_krb5.top").write_text(
            json.dumps({"access_token": "top-b"})
        )
        os.kill(proc.pid, signal.SIGHUP)
        assert _wait_for((tmp_path / "bob" / "af_krb5.use").exists, timeout=5.0)

        proc.send_signal(signal.SIGTERM)
        _, stderr = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()

    assert proc.returncode == 0, stderr
    assert "Bearer top-a" in _BrokerHandler.seen_tokens
    assert "Bearer top-b" in _BrokerHandler.seen_tokens
    assert "af-credmon stopped" in stderr
    # Outside condor_master the ready message cannot be delivered; that is
    # expected here and must only be a warning.
    assert "Traceback" not in stderr
