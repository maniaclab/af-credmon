"""Tests for turning a broker redeem into ``.use`` file content.

The broker's ``POST /v1/credentials/<kind>/redeem`` accepts the top token
as its Bearer (af-mcp-platform maps ``aud=af-credmon/<kind>`` to the kind's
default identity) and answers with the same JSON af-credentials already
parses. The ``.use`` content is what a job reads from ``$_CONDOR_CREDS``:
the proxy PEM, the raw krb5 ccache, or a ServiceX ``{"access_token"}``
JSON object (HTCondor's own convention for OAuth ``.use`` files).
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import httpx2
import pytest
from af_credentials.proxy import ProxyNotAvailableError, ProxyRedeemError

from af_credmon.redeem import Redeemer

_BROKER = "https://mcp.example.org"
_EXPIRES = "2099-01-01T00:00:00+00:00"
_EXPIRES_DT = datetime(2099, 1, 1, tzinfo=UTC)

_RESPONSES = {
    "x509": {
        "pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
        "dn": "/DC=ch/DC=cern/CN=Test",
        "voms_attributes": ["/atlas"],
        "expires_at": _EXPIRES,
        "remaining_seconds": 86400,
        "nickname": "tuser",
    },
    "krb5": {
        "ccache_b64": base64.b64encode(b"\x05\x04ccache").decode(),
        "principal": "tuser@CERN.CH",
        "realm": "CERN.CH",
        "expires_at": _EXPIRES,
        "remaining_seconds": 86400,
        "renew_until": None,
    },
    "servicex": {
        "access_token": "sx-access-token",
        "expires_at": _EXPIRES,
        "remaining_seconds": 3600,
    },
}


def _redeemer(
    status: int = 200,
    body: object | None = None,
    seen: list[httpx2.Request] | None = None,
) -> Redeemer:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if seen is not None:
            seen.append(request)
        kind = request.url.path.split("/")[3]
        return httpx2.Response(
            status, json=body if body is not None else _RESPONSES[kind]
        )

    return Redeemer(
        _BROKER,
        min_remaining=600.0,
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
    )


async def test_presents_top_token_as_bearer_to_the_kind_redeem_endpoint() -> None:
    seen: list[httpx2.Request] = []

    await _redeemer(seen=seen).redeem("krb5", "top-token")

    assert str(seen[0].url) == f"{_BROKER}/v1/credentials/krb5/redeem"
    assert seen[0].headers["Authorization"] == "Bearer top-token"


async def test_x509_use_content_is_the_proxy_pem() -> None:
    cred = await _redeemer().redeem("x509", "t")

    assert cred.content == _RESPONSES["x509"]["pem"].encode()  # type: ignore[attr-defined]
    assert cred.expires_at == _EXPIRES_DT


async def test_krb5_use_content_is_the_raw_ccache() -> None:
    cred = await _redeemer().redeem("krb5", "t")

    assert cred.content == b"\x05\x04ccache"
    assert cred.expires_at == _EXPIRES_DT


async def test_servicex_use_content_is_access_token_json() -> None:
    cred = await _redeemer().redeem("servicex", "t")

    assert json.loads(cred.content) == {"access_token": "sx-access-token"}
    assert cred.expires_at == _EXPIRES_DT


async def test_not_linked_404_surfaces_as_not_available() -> None:
    with pytest.raises(ProxyNotAvailableError):
        await _redeemer(404, {"detail": "no Kerberos ticket"}).redeem("krb5", "t")


async def test_rejected_token_surfaces_as_redeem_error() -> None:
    with pytest.raises(ProxyRedeemError):
        await _redeemer(
            401, {"detail": "Invalid or expired broker identity token"}
        ).redeem("krb5", "t")


async def test_unknown_kind_is_rejected() -> None:
    with pytest.raises(ValueError, match="panda"):
        await _redeemer().redeem("panda", "t")
