---
icon: lucide/code
---

# Contributing

## Architecture

```
credd ── writes ──> <creddir>/<user>/af_<kind>.top
                         │
af_credmon.daemon.Daemon (scan every --interval, or on SIGHUP)
  └─ af_credmon.monitor.CredentialMonitor.scan_once
       ├─ af_credmon.topfile.discover / read_top_token
       ├─ af_credmon.redeem.Redeemer ──HTTPS──> AF broker /v1/credentials/<kind>/redeem
       │    (af_credentials.proxy.ProxyClient)
       └─ af_credmon.usefile.write_use_file ──> <creddir>/<user>/af_<kind>.use
                                                     │
                         shadow ── ships ──> $_CONDOR_CREDS/af_<kind>.use on the EP
```

`af-credmon` holds no credential logic of its own: minting, renewal and
authorization all live in the broker, and the redeem call is af-credentials'
`ProxyClient`, unchanged. The daemon only keeps each `.use` file in step with
its `.top` file and follows HTCondor's credmon conventions (`pid`,
`CREDMON_COMPLETE`, SIGHUP, the ready message to condor_master).

## Development setup

```bash
git clone https://github.com/maniaclab/af-credmon
cd af-credmon
pixi install
pixi run pre-commit-install
```

## Build and test commands

```bash
pixi run -e py313 test   # run tests (py311 ... py314)
pixi run lint            # pre-commit + pylint
pixi run build           # build sdist + wheel
pixi run docs-serve      # build and serve docs locally
```

## Tests

- `tests/test_topfile.py`: discovering and reading credd's `.top` files
- `tests/test_usefile.py`: atomic, mode-0400 `.use` writes
- `tests/test_redeem.py`: `.use` content per kind, against a mocked broker
  (`httpx2.MockTransport`)
- `tests/test_monitor.py`: renewal timing, 404 removal, failure isolation,
  orphan cleanup
- `tests/test_daemon.py`: primary/alongside bookkeeping, SIGHUP wake, readiness,
  logging
- `tests/test_cli_integration.py`: the installed `af-credmon` script as a
  subprocess against a local broker stand-in

## Releasing

```bash
pixi run -e dev tbump X.Y.Z   # bumps, commits and tags vX.Y.Z
git push --follow-tags
```

Then publish a GitHub release for the tag; the CD workflow builds the sdist and
wheel and publishes them to PyPI through trusted publishing.
