"""End-to-end test: a personal HTCondor pool with credd and af-credmon as its OAuth credmon.

Starts ``condor_master`` (collector, negotiator, schedd, startd, credd and
af-credmon as ``CREDMON_OAUTH``) from a private ``CONDOR_CONFIG``, stores a
top token per credential kind the way the broker does (as a
``CRED_SUPER_USERS`` identity, on the submitter's behalf), submits a job
with ``use_oauth_services`` and checks the job's stdout shows the redeemed
credentials in ``$_CONDOR_CREDS``.

Only the broker is a stand-in: a local HTTP server answering its redeem
contract. Everything HTCondor does is real, so the pool must run as root
(credd and the shadow check that ``.use`` files are root-owned), and jobs
are submitted as the non-root user who invoked sudo::

    sudo env "PATH=$PATH" pytest tests/test_e2e_htcondor.py

The test is skipped when ``condor_master`` is not installed, when not root,
or when ``SUDO_USER`` is unset.
"""

from __future__ import annotations

import base64
import grp
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_SUBMIT_USER = os.environ.get("SUDO_USER", "")

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        shutil.which("condor_master") is None, reason="HTCondor is not installed"
    ),
    pytest.mark.skipif(os.geteuid() != 0, reason="the HTCondor pool must run as root"),
    pytest.mark.skipif(
        not _SUBMIT_USER or _SUBMIT_USER == "root",
        reason="run via sudo from the non-root user that submits the job",
    ),
]

# Long enough that no timed scan happens during the test: every redeem must
# be triggered by credd's SIGHUP after a store.
_CREDMON_INTERVAL = 3600
_CCACHE = b"\x05\x04e2e-ccache"
# condor_store_cred -u wants account@domain.
_UID_DOMAIN = "af-credmon.e2e"
# Plays the broker's identity: a distinct, unprivileged account listed in
# CRED_SUPER_USERS. (root cannot: HTCondor tools run by root authenticate
# as the condor user.)
_BROKER_USER = "nobody"


class _BrokerHandler(BaseHTTPRequestHandler):
    seen_tokens: list[str] = []  # noqa: RUF012 -- class-level request log shared with the test

    def do_POST(self) -> None:
        bearer = self.headers.get("Authorization", "")
        self.seen_tokens.append(bearer)
        expiry = {
            "expires_at": "2099-01-01T00:00:00+00:00",
            "remaining_seconds": 86400,
        }
        if self.path == "/v1/credentials/servicex/redeem":
            payload = {"access_token": f"servicex-for[{bearer}]", **expiry}
        elif self.path == "/v1/credentials/krb5/redeem":
            payload = {
                "ccache_b64": base64.b64encode(_CCACHE).decode(),
                "principal": "tuser@CERN.CH",
                "realm": "CERN.CH",
                "renew_until": None,
                **expiry,
            }
        else:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(payload).encode()
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


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def _system_param(name: str) -> str:
    """*name* from the installed HTCondor's own configuration (install layout differs per distro)."""
    env = {k: v for k, v in os.environ.items() if k != "CONDOR_CONFIG"}
    return subprocess.run(
        ["condor_config_val", name],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()


def _wait_for(predicate: Callable[[], bool], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


class _Pool:
    """A running personal pool rooted at *local_dir*."""

    def __init__(self, local_dir: Path, env: dict[str, str]) -> None:
        self.local_dir = local_dir
        self.env = env
        self.cred_dir = local_dir / "oauth_credentials"
        self.log_dir = local_dir / "log"

    def run(self, *cmd: str, user: str | None = None, cwd: Path | None = None) -> str:
        """Run an HTCondor tool against this pool, as *user* when given; return stdout."""
        argv = ["runuser", "-u", user, "--", *cmd] if user else list(cmd)
        result = subprocess.run(
            argv, capture_output=True, text=True, env=self.env, cwd=cwd, check=False
        )
        assert result.returncode == 0, (
            f"{cmd} failed:\n{result.stdout}\n{result.stderr}\n{self.logs()}"
        )
        return result.stdout

    def logs(self, lines: int = 40) -> str:
        """The tail of every daemon log, for assertion messages."""
        return "\n".join(
            f"===== {path.name}\n"
            + "\n".join(path.read_text(errors="replace").splitlines()[-lines:])
            for path in sorted(self.log_dir.iterdir())
            if path.is_file()
        )


@pytest.fixture
def pool(broker_url: str) -> Iterator[_Pool]:
    af_credmon = shutil.which("af-credmon")
    assert af_credmon is not None, (
        "af-credmon console script not installed in this environment"
    )
    condor = pwd.getpwnam("condor")
    local_dir = Path(tempfile.mkdtemp(prefix="af-credmon-e2e-"))
    # The condor user and the submitter must be able to reach their dirs.
    local_dir.chmod(0o755)
    for name in ("log", "spool", "execute", "lock", "run"):
        (local_dir / name).mkdir()
        os.chown(local_dir / name, condor.pw_uid, condor.pw_gid)
    # credd creates the per-user subdirectories with condor privileges, so
    # the credential directory is group-writable by condor (and setgid so
    # what it creates stays in that group), as packaged HTCondor lays it out.
    cred_dir = local_dir / "oauth_credentials"
    cred_dir.mkdir()
    os.chown(cred_dir, 0, grp.getgrnam("condor").gr_gid)
    cred_dir.chmod(0o2770)

    port = _free_port()
    layout = "\n".join(
        f"{name} = {_system_param(name)}"
        for name in ("BIN", "SBIN", "LIB", "LIBEXEC", "SHARE")
    )
    config = local_dir / "condor_config"
    config.write_text(
        f"""\
{layout}
LOCAL_DIR = {local_dir}
LOG = $(LOCAL_DIR)/log
SPOOL = $(LOCAL_DIR)/spool
EXECUTE = $(LOCAL_DIR)/execute
LOCK = $(LOCAL_DIR)/lock
RUN = $(LOCAL_DIR)/run

CONDOR_HOST = 127.0.0.1
UID_DOMAIN = {_UID_DOMAIN}
COLLECTOR_HOST = 127.0.0.1:{port}
NETWORK_INTERFACE = 127.0.0.1
USE_SHARED_PORT = False

SEC_DEFAULT_AUTHENTICATION_METHODS = FS
ALLOW_READ = *
ALLOW_WRITE = *
ALLOW_NEGOTIATOR = *
ALLOW_ADMINISTRATOR = *
ALLOW_DAEMON = *

use POLICY : ALWAYS_RUN_JOBS
NUM_CPUS = 1
RUNBENCHMARKS = False
SCHEDD_INTERVAL = 1
NEGOTIATOR_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1
UPDATE_INTERVAL = 1
STARTER_UPDATE_INTERVAL = 1
SHADOW_QUEUE_UPDATE_INTERVAL = 1

DAEMON_LIST = MASTER COLLECTOR NEGOTIATOR SCHEDD STARTD CREDD CREDMON_OAUTH
SEC_CREDENTIAL_DIRECTORY_OAUTH = $(LOCAL_DIR)/oauth_credentials
# The broker stores top tokens on users' behalf.
CRED_SUPER_USERS = {_BROKER_USER}
CREDMON_OAUTH = {af_credmon}
CREDMON_OAUTH_ARGS = --broker-url {broker_url} --log-file $(LOG)/AfCredmonLog --interval {_CREDMON_INTERVAL}
"""
    )
    env = {**os.environ, "CONDOR_CONFIG": str(config)}
    master = subprocess.Popen(
        ["condor_master", "-f"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pool = _Pool(local_dir, env)
    try:
        pool.run("condor_who", "-wait:60", 'IsReady && STARTD_State =?= "Ready"')
        yield pool
    finally:
        master.send_signal(signal.SIGQUIT)  # fast shutdown of every daemon
        try:
            master.wait(timeout=30)
        except subprocess.TimeoutExpired:
            master.kill()
            master.wait()
        shutil.rmtree(local_dir, ignore_errors=True)


_JOB_SCRIPT = """\
#!/bin/sh
echo "creds=$_CONDOR_CREDS"
echo "servicex=$(cat "$_CONDOR_CREDS/af_servicex.use")"
echo "krb5=$(tail -c +3 "$_CONDOR_CREDS/af_krb5.use")"
"""

_SUBMIT_FILE = """\
executable = job.sh
use_oauth_services = af_servicex, af_krb5
should_transfer_files = YES
output = job.out
error = job.err
log = job.log
queue
"""


def test_job_sees_credentials_redeemed_by_af_credmon(pool: _Pool) -> None:
    submitter = pwd.getpwnam(_SUBMIT_USER)

    # credd SIGHUPs whatever pid the credmon wrote into the credential
    # directory: af-credmon must own it.
    pid_file = pool.cred_dir / "pid"
    assert _wait_for(pid_file.exists, timeout=30)
    credmon_pid = pid_file.read_text().strip()
    cmdline = Path(f"/proc/{credmon_pid}/cmdline").read_bytes()
    assert b"af-credmon" in cmdline

    for kind in ("servicex", "krb5"):
        top = pool.local_dir / f"top-{kind}.json"
        top.write_text(json.dumps({"access_token": f"top-{kind}-{_SUBMIT_USER}"}))
        pool.run(
            "condor_store_cred",
            "add-oauth",
            "-s",
            f"af_{kind}",
            "-u",
            f"{_SUBMIT_USER}@{_UID_DOMAIN}",
            "-i",
            str(top),
            user=_BROKER_USER,
        )

    user_creds = pool.cred_dir / _SUBMIT_USER
    for kind in ("servicex", "krb5"):
        use = user_creds / f"af_{kind}.use"
        assert _wait_for(use.exists, timeout=10), (
            f"af-credmon never wrote {use.name}\n{pool.logs()}"
        )
        st = use.stat()
        assert (st.st_uid, st.st_mode & 0o777) == (0, 0o400)
    assert sorted(_BrokerHandler.seen_tokens) == [
        f"Bearer top-krb5-{_SUBMIT_USER}",
        f"Bearer top-servicex-{_SUBMIT_USER}",
    ]

    job_dir = pool.local_dir / "job"
    job_dir.mkdir()
    (job_dir / "job.sh").write_text(_JOB_SCRIPT)
    (job_dir / "job.sh").chmod(0o755)
    (job_dir / "job.sub").write_text(_SUBMIT_FILE)
    os.chown(job_dir, submitter.pw_uid, submitter.pw_gid)
    pool.run("condor_submit", "job.sub", user=_SUBMIT_USER, cwd=job_dir)
    pool.run("condor_wait", "-wait", "60", "job.log", user=_SUBMIT_USER, cwd=job_dir)

    stdout = (job_dir / "job.out").read_text()
    assert (job_dir / "job.err").read_text() == ""
    assert (
        f'servicex={{"access_token": "servicex-for[Bearer top-servicex-{_SUBMIT_USER}]"}}'
        in stdout
    ), f"{stdout}\n{pool.logs()}"
    assert "krb5=e2e-ccache" in stdout, f"{stdout}\n{pool.logs()}"

    credmon_log = (pool.log_dir / "AfCredmonLog").read_text()
    assert "Traceback" not in credmon_log
    assert " ERROR " not in credmon_log
