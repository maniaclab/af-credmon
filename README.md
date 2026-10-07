# af-credmon

An HTCondor credential monitor (credmon) that places a user's AF MCP broker-held
credentials -- x509/VOMS proxy, CERN Kerberos ticket, ServiceX access token --
on worker nodes, without the job submitter (human or LLM agent) ever handling
them.

It is the access-point half of the
[af-mcp-platform](https://github.com/maniaclab/af-mcp-platform) HTCondor credmon
integration; see that repository's `docs/credmon.md` for the broker side. In
short:

1. The broker stores a per-user, per-kind **top token** in credd as
   `<creddir>/<user>/af_<kind>.top`.
2. af-credmon presents it to the broker's `POST /v1/credentials/<kind>/redeem`
   and writes the credential to `<creddir>/<user>/af_<kind>.use`, renewing it
   before it expires.
3. A job with `use_oauth_services = af_krb5, af_x509` gets
   `$_CONDOR_CREDS/af_krb5.use` (a krb5 ccache) and `$_CONDOR_CREDS/af_x509.use`
   (a VOMS proxy PEM) on the worker node, refreshed by HTCondor every
   `SEC_CREDENTIAL_REFRESH` (default 300s).

## Installing on the access point

af-credmon runs as root on the access point (the schedd host), next to credd.
Install it as a pixi environment:

```bash
git clone https://github.com/maniaclab/af-credmon /opt/af-credmon
cd /opt/af-credmon && pixi install
# -> /opt/af-credmon/.pixi/envs/default/bin/af-credmon
```

## HTCondor configuration

The access point needs credd, an OAuth credential directory, and the identity
the broker stores with listed as a credential super-user:

```
DAEMON_LIST = $(DAEMON_LIST) CREDD CREDMON_OAUTH
SEC_CREDENTIAL_DIRECTORY_OAUTH = /var/lib/condor/oauth_credentials
CRED_SUPER_USERS = <identity of the broker's htcondor-api token>

CREDMON_OAUTH = /opt/af-credmon/.pixi/envs/default/bin/af-credmon
CREDMON_OAUTH_ARGS = --broker-url https://mcp.example.org --log-file $(LOG)/AfCredmonLog
```

This is **primary mode** (the default): af-credmon is the credmon credd talks
to. It owns `<creddir>/pid` (credd sends SIGHUP after every store, which
triggers an immediate rescan), touches `CREDMON_COMPLETE` after each scan, and
sends condor_master its ready message after the first one.

### Next to an existing credmon

If the access point already runs `condor_credmon_oauth` (for SciTokens, an
OAuth2 provider, ...), it keeps owning `CREDMON_OAUTH`, the `pid` file and
`CREDMON_COMPLETE`. Run af-credmon as a separate daemon in **alongside mode**,
which only polls:

```
DAEMON_LIST = $(DAEMON_LIST) AF_CREDMON
AF_CREDMON = /opt/af-credmon/.pixi/envs/default/bin/af-credmon
AF_CREDMON_ARGS = --mode alongside --broker-url https://mcp.example.org --log-file $(LOG)/AfCredmonLog
```

The existing credmons never touch `af_*` files, with one exception: if the Vault
credmon is enabled with its default `VAULT_CREDMON_PROVIDER_NAMES = *`, it
claims every unclaimed `.top` file. Set an explicit list instead.

## Options

| Option            | Default                                     | Meaning                                                                                    |
| ----------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `--broker-url`    | (required)                                  | AF MCP broker base URL                                                                     |
| `--cred-dir`      | HTCondor's `SEC_CREDENTIAL_DIRECTORY_OAUTH` | credd's OAuth credential directory                                                         |
| `--prefix`        | `af_`                                       | credd service-name prefix; must match the broker's `CREDMON_SERVICE_PREFIX`                |
| `--mode`          | `primary`                                   | `primary` or `alongside` (see above)                                                       |
| `--interval`      | `60`                                        | seconds between scans                                                                      |
| `--min-remaining` | `600`                                       | refuse a credential expiring sooner than this (twice the default `SEC_CREDENTIAL_REFRESH`) |
| `--log-file`      | stderr                                      | log destination; condor_master does not capture a daemon's stderr                          |
| `--log-level`     | `INFO`                                      | Python logging level                                                                       |

## What a scan does

For every `<creddir>/<user>/<prefix><kind>.top` (kinds `x509`, `krb5`,
`servicex`):

- **redeem** the top token when the `.use` file is missing, not yet issued since
  startup, or in the last third of its lifetime, and write the `.use` atomically
  (temp file, mode 0400, rename);
- **remove** the `.use` when the broker answers 404 (the identity is no longer
  linked), and any `af_*.use` whose `.top` credd has deleted;
- **keep** the existing `.use` on any other failure (broker outage, expired top
  token) and retry on the next scan, so running jobs never lose a still-valid
  credential.

Files without the prefix belong to other credmons and are never touched. Nothing
besides `.use` files (and, in primary mode, `pid` and `CREDMON_COMPLETE`) is
written to the credential directory.

## Keeping credentials out of job output

HTCondor does not redact job stdout/stderr, and tools that read job output back
(including LLM agents through condor-mcp) see it verbatim. Job scripts should
reference the credentials by path only:

```bash
export KRB5CCNAME="FILE:${_CONDOR_CREDS}/af_krb5.use"
export X509_USER_PROXY="${_CONDOR_CREDS}/af_x509.use"
```

and never `cat`, `base64` or `echo` them. Keep `SEC_DEBUG_PRINT_KEYS` off on the
access point; it writes credentials into the ShadowLog.

## Development

```bash
pixi run -e dev pytest     # unit + integration tests
pixi run -e dev typecheck  # mypy
pixi run lint              # pre-commit hooks
```
