"""W-10 capability inventory API."""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from red2pr_control.db.base import ExtensionCapabilityModel, OidcProviderModel
from red2pr_control.db.rls import instance_rls_session
from red2pr_control.extensions.registry import (
    CapabilityStatus,
    is_capability_status,
    list_capabilities,
)


class ExtensionCapabilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    status: str
    reason: str


class CapabilityInventoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capabilities: tuple[ExtensionCapabilityResponse, ...]
    oidc_providers: tuple[str, ...] = ()


def build_extensions_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/system", tags=["system"])

    @router.get("/capabilities", operation_id="getSystemCapabilities")
    async def get_system_capabilities(request: Request) -> CapabilityInventoryResponse:
        iam = getattr(request.app.state, "iam_service", None)
        provider_ids: tuple[str, ...] = ()
        oidc_status: CapabilityStatus | None = None
        oidc_reason: str | None = None
        if iam is not None:
            async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
                provider_ids = tuple(
                    await db.scalars(
                        select(OidcProviderModel.id).where(OidcProviderModel.status == "enabled")
                    )
                )
                stored = await db.get(ExtensionCapabilityModel, "iam-03-oidc")
                if not provider_ids and stored is not None and is_capability_status(stored.status):
                    oidc_status = stored.status
                    oidc_reason = stored.reason
        return CapabilityInventoryResponse(
            capabilities=tuple(
                ExtensionCapabilityResponse(id=item.id, status=item.status, reason=item.reason)
                for item in list_capabilities(
                    provider_ids,
                    oidc_status=oidc_status,
                    oidc_reason=oidc_reason,
                )
            ),
            oidc_providers=provider_ids,
        )

    return router
