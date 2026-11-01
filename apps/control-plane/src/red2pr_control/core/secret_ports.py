"""Narrow secret capabilities exposed to control-plane domain modules."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from sqlalchemy.ext.asyncio import AsyncSession


class SecretReference(Protocol):
    """Safe metadata returned after storing a secret; it never exposes plaintext."""

    secret_ref: str


@runtime_checkable
class OidcSecretStore(Protocol):
    """Purpose-limited OIDC client-secret operations backed by the Z2 broker."""

    async def store_client_secret(
        self,
        session: AsyncSession,
        *,
        plaintext: bytes,
        secret_ref: str,
        now: datetime,
    ) -> SecretReference: ...

    async def revoke_client_secret(
        self, session: AsyncSession, *, secret_ref: str, now: datetime
    ) -> None: ...

    async def resolve_client_secret(self, session: AsyncSession, *, secret_ref: str) -> bytes: ...
