# af-credmon

An HTCondor credential monitor (credmon) that places a user's AF MCP
broker-held credentials -- x509/VOMS proxy, CERN Kerberos ticket, ServiceX
access token -- on worker nodes, without the job submitter (human or LLM
agent) ever handling them.

It is the access-point half of the
[af-mcp-platform](https://github.com/maniaclab/af-mcp-platform) HTCondor
credmon integration; see that repository's `docs/credmon.md` for the full
chain. In short:

1. The broker stores a per-user, per-kind **top token** in credd as
   `<creddir>/<user>/af_<kind>.top`.
2. af-credmon presents it to the broker's
   `POST /v1/credentials/<kind>/redeem` and writes the credential to
   `<creddir>/<user>/af_<kind>.use`.
3. A job with `use_oauth_services = af_krb5, af_x509` gets
   `$_CONDOR_CREDS/af_krb5.use` (a krb5 ccache) and
   `$_CONDOR_CREDS/af_x509.use` (a VOMS proxy PEM) on the worker node.

Documentation of configuration and operation follows once the daemon lands.
