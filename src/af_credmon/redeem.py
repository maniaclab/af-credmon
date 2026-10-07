"""Redeem a top token at the broker and render the result as ``.use`` file content.

Uses af-credentials' ``ProxyClient`` unchanged: the broker's redeem
endpoints accept the top token (``aud=af-credmon/<kind>``) exactly like the
per-request identity tokens backends present.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from af_credentials.proxy import ProxyClient

from af_credmon.topfile import KINDS

if TYPE_CHECKING:
    from datetime import datetime

    import httpx2


@dataclass(frozen=True)
class RedeemedCredential:
    """``.use`` file bytes plus when the credential inside them expires."""

    content: bytes
    expires_at: datetime


class Redeemer:
    """Exchanges top tokens for credentials, one ``ProxyClient`` per kind."""

    def __init__(
        self,
        broker_url: str,
        *,
        min_remaining: float,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        """*min_remaining* (seconds) rejects a credential that would expire before HTCondor's next ``.use`` refresh reaches the job."""
        self._clients = {
            kind: ProxyClient(
                broker_url,
                kind=kind,
                min_remaining=min_remaining,
                http_client=http_client,
            )
            for kind in KINDS
        }

    async def redeem(self, kind: str, top_token: str) -> RedeemedCredential:
        """Redeem *top_token* for a *kind* credential.

        Raises af-credentials' ``ProxyNotAvailableError`` when the broker has
        nothing to serve (identity not linked, or too close to expiry) and
        ``ProxyRedeemError`` for any other refusal (e.g. an expired top token).
        """
        client = self._clients.get(kind)
        if client is None:
            raise ValueError(f"unknown credential kind {kind!r}")
        if kind == "x509":
            with await client.proxy_file(top_token) as proxy:
                return RedeemedCredential(proxy.path.read_bytes(), proxy.expires_at)
        if kind == "krb5":
            with await client.ticket_file(top_token) as ticket:
                return RedeemedCredential(ticket.path.read_bytes(), ticket.expires_at)
        token = await client.access_token(top_token)
        # HTCondor's convention for OAuth .use files (and what its curl
        # transfer plugin parses): a JSON object carrying access_token.
        content = json.dumps({"access_token": token.access_token}).encode()
        return RedeemedCredential(content, token.expires_at)
