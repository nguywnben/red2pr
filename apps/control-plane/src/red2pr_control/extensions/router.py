"""W-10 capability inventory API."""

from __future__ import annotations

import json
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Header, Path, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from py_contracts.extensions import (
    RelayPullResponse,
    RelaySubscriptionResponse,
    RelaySubscriptionUpsertRequest,
)
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
    PreconditionFailedError,
    UnprocessableEntityError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.db.base import (
    ConsentModel,
    EndpointRegistrationModel,
    ExtensionCapabilityModel,
    OidcProviderModel,
    ProviderConnectionModel,
    RelaySubscriptionModel,
    SecretEntryModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.extensions.registry import (
    CapabilityStatus,
    is_capability_status,
    list_capabilities,
)
from red2pr_control.extensions.webhook_relay import (
    CustomerWebhookRelayRunner,
    validate_client_certificate_pair,
)
from red2pr_control.iam.rbac import (
    ADMIN_ONLY_ROLES,
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    format_version_etag,
    make_workspace_rbac_dependency,
    parse_if_match_version,
)
from red2pr_control.iam.router import get_iam_service
from red2pr_control.iam.sessions import IamService, extract_client_ip, is_step_up_fresh
from red2pr_control.secrets.broker import (
    SecretBroker,
)

_require_relay_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="relay.read",
)
_require_relay_admin = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="relay.mutate",
)


def _relay_broker(request: Request) -> SecretBroker:
    broker = getattr(request.app.state, "relay_secret_broker", None)
    if not isinstance(broker, SecretBroker):
        raise DependencyUnavailableError(
            code="relay_secret_broker_unavailable",
            detail="Relay credential storage is not configured.",
        )
    return broker


def _relay_runner(request: Request) -> CustomerWebhookRelayRunner:
    runner = getattr(request.app.state, "webhook_relay_runner", None)
    if not isinstance(runner, CustomerWebhookRelayRunner):
        raise DependencyUnavailableError(
            code="relay_runner_unavailable",
            detail="Customer-operated relay runner is not configured.",
        )
    return runner


def _relay_response(row: RelaySubscriptionModel) -> RelaySubscriptionResponse:
    return RelaySubscriptionResponse(
        id=row.id,
        version=row.version,
        workspace_id=row.workspace_id,
        provider_connection_id=row.provider_connection_id,
        endpoint_registration_id=row.endpoint_registration_id,
        consent_id=row.consent_id,
        enabled=row.enabled,
        status=cast(Literal["disabled", "ready", "degraded", "gap_detected"], row.status),
        last_relay_seq=row.last_relay_seq,
        last_received_at=row.last_received_at,
        status_detail=row.status_detail,
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
    router = APIRouter(prefix="/api/v1")

    @router.get("/system/capabilities", operation_id="getSystemCapabilities", tags=["system"])
    async def get_system_capabilities(request: Request) -> CapabilityInventoryResponse:
        iam = getattr(request.app.state, "iam_service", None)
        provider_ids: tuple[str, ...] = ()
        oidc_status: CapabilityStatus | None = None
        oidc_reason: str | None = None
        mcp_enabled = False
        mcp_enabled = getattr(request.app.state, "mcp_extension_enabled", False) is True
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
                    mcp_enabled=mcp_enabled,
                )
            ),
            oidc_providers=provider_ids,
        )

    @router.get(
        "/workspaces/{ws}/integrations/{connection_id}/relay",
        operation_id="getRelaySubscription",
        tags=["integrations"],
        response_model=RelaySubscriptionResponse | None,
    )
    async def get_relay_subscription(
        connection_id: Annotated[str, Path(min_length=36, max_length=36)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_relay_read)],
        iam: Annotated[IamService, Depends(get_iam_service)],
        response: Response,
    ) -> RelaySubscriptionResponse | None:
        async with workspace_rls_session(
            iam.session_factory, workspace_id=ws_ctx.workspace.id
        ) as db:
            row = await db.scalar(
                select(RelaySubscriptionModel).where(
                    RelaySubscriptionModel.workspace_id == ws_ctx.workspace.id,
                    RelaySubscriptionModel.provider_connection_id == connection_id,
                )
            )
            if row is None:
                return None
            response.headers["ETag"] = format_version_etag(row.version)
            return _relay_response(row)

    @router.put(
        "/workspaces/{ws}/integrations/{connection_id}/relay",
        operation_id="putRelaySubscription",
        tags=["integrations"],
        response_model=RelaySubscriptionResponse,
    )
    async def put_relay_subscription(
        connection_id: Annotated[str, Path(min_length=36, max_length=36)],
        payload: RelaySubscriptionUpsertRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_relay_admin)],
        iam: Annotated[IamService, Depends(get_iam_service)],
        broker: Annotated[SecretBroker, Depends(_relay_broker)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        if_match: Annotated[str | None, Header(alias="If-Match", max_length=64)] = None,
    ) -> RelaySubscriptionResponse:
        if ws_ctx.auth.api_token is not None or not is_step_up_fresh(
            ws_ctx.auth.session, now=iam.now()
        ):
            raise ForbiddenError(
                code="step_up_required", detail="Fresh 5-minute step-up is required."
            )
        if not idempotency_key or not idempotency_key.strip():
            raise UnprocessableEntityError(
                code="missing_idempotency_key", detail="Relay setup requires Idempotency-Key."
            )
        if payload.provider_connection_id != connection_id:
            raise UnprocessableEntityError(
                code="relay_connection_mismatch", detail="Relay connection path and body differ."
            )
        credentials_provided = payload.relay_hmac_secret is not None
        async with workspace_rls_session(
            iam.session_factory, workspace_id=ws_ctx.workspace.id
        ) as db:
            connection = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == ws_ctx.workspace.id,
                    ProviderConnectionModel.id == connection_id,
                )
            )
            if connection is None:
                raise NotFoundError(
                    code="integration_not_found", detail="Integration was not found."
                )
            if connection.status != "ready" or connection.provider not in {"github", "gitlab"}:
                raise ConflictError(
                    code="relay_connection_unavailable",
                    detail="Relay requires an active GitHub or GitLab connection.",
                )
            endpoint = await db.scalar(
                select(EndpointRegistrationModel).where(
                    EndpointRegistrationModel.id == payload.endpoint_registration_id,
                    EndpointRegistrationModel.adapter == "webhook",
                    EndpointRegistrationModel.scheme == "wss",
                    EndpointRegistrationModel.revoked_at.is_(None),
                )
            )
            if endpoint is None:
                raise ForbiddenError(
                    code="relay_endpoint_not_registered",
                    detail="Relay requires an active owner-registered WSS webhook endpoint.",
                )
            relay_host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
            relay_origin = f"wss://{relay_host}:{endpoint.port}"
            consent = await db.scalar(
                select(ConsentModel).where(
                    ConsentModel.workspace_id == ws_ctx.workspace.id,
                    ConsentModel.id == payload.consent_id,
                    ConsentModel.purpose == "provider",
                    ConsentModel.scope == "workspace",
                    ConsentModel.revoked_at.is_(None),
                    ConsentModel.destination == relay_origin,
                )
            )
            if consent is None or "webhook_payload" not in consent.data_classes_json:
                raise ForbiddenError(
                    code="relay_consent_required",
                    detail="Active provider consent for webhook_payload at this relay is required.",
                )
            row = await db.scalar(
                select(RelaySubscriptionModel)
                .where(
                    RelaySubscriptionModel.workspace_id == ws_ctx.workspace.id,
                    RelaySubscriptionModel.provider_connection_id == connection_id,
                )
                .with_for_update()
            )
            resource_id = row.id if row is not None else new_uuid7(now=iam.now())
            current_version = row.version if row is not None else 0
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_ctx.workspace.id,
                principal_id=ws_ctx.auth.user.id,
                operation="extension.src05.relay.configure",
                idempotency_key=idempotency_key.strip(),
                request_payload=payload.model_dump(mode="json"),
                logical_effect_key=f"relay:{connection_id}:version:{current_version}",
                resource_id=resource_id,
                correlation_id=current_correlation_id(),
                now=iam.now(),
            )
            if not claim.is_new_claim and claim.cached_response is not None:
                replay = RelaySubscriptionResponse.model_validate(claim.cached_response)
                response.headers["ETag"] = format_version_etag(replay.version)
                return replay
            supplied_version = payload.expected_version
            if if_match is not None:
                supplied_version = parse_if_match_version(if_match)
            if row is None and supplied_version is not None:
                raise PreconditionFailedError(
                    code="relay_version_conflict", detail="Relay subscription does not exist."
                )
            if row is not None and supplied_version != row.version:
                raise PreconditionFailedError(
                    code="relay_version_conflict", detail="Reload the current relay subscription."
                )

            is_new = row is None
            if row is None:
                if not credentials_provided:
                    raise UnprocessableEntityError(
                        code="relay_credentials_required",
                        detail="Initial relay setup requires its HMAC secret and mTLS identity.",
                    )
                secret_ref = f"relay_{new_uuid7(now=iam.now()).replace('-', '')}"
                row = RelaySubscriptionModel(
                    id=resource_id,
                    workspace_id=ws_ctx.workspace.id,
                    provider_connection_id=connection_id,
                    endpoint_registration_id=endpoint.id,
                    consent_id=consent.id,
                    relay_secret_ref=secret_ref,
                    enabled=False,
                    status="disabled",
                    last_relay_seq=0,
                    version=1,
                    created_at=iam.now(),
                    updated_at=iam.now(),
                )
                db.add(row)
            assert row is not None
            if credentials_provided:
                assert payload.client_certificate_pem is not None
                assert payload.client_private_key_pem is not None
                validate_client_certificate_pair(
                    payload.client_certificate_pem, payload.client_private_key_pem
                )
            if credentials_provided:
                assert payload.relay_hmac_secret is not None
                assert payload.client_certificate_pem is not None
                assert payload.client_private_key_pem is not None
                secret_plaintext = json.dumps(
                    {
                        "relay_hmac_secret": payload.relay_hmac_secret,
                        "client_certificate_pem": payload.client_certificate_pem,
                        "client_private_key_pem": payload.client_private_key_pem,
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                if not is_new:
                    entry = await db.scalar(
                        select(SecretEntryModel).where(
                            SecretEntryModel.secret_ref == row.relay_secret_ref,
                            SecretEntryModel.workspace_id == ws_ctx.workspace.id,
                        )
                    )
                    if entry is not None:
                        entry.revoked_at = iam.now()
                        entry.updated_at = iam.now()
                    row.relay_secret_ref = f"relay_{new_uuid7(now=iam.now()).replace('-', '')}"
                metadata = await broker.store_secret(
                    db,
                    plaintext=secret_plaintext,
                    purpose="webhook_auth",
                    workspace_id=ws_ctx.workspace.id,
                    secret_ref=row.relay_secret_ref,
                    now=iam.now(),
                )
                if metadata.revoked_at is not None:
                    raise ConflictError(
                        code="relay_secret_invalid", detail="Relay key storage failed."
                    )
            row.endpoint_registration_id = endpoint.id
            row.consent_id = consent.id
            row.enabled = payload.enabled
            row.status = "ready" if payload.enabled else "disabled"
            row.status_detail = None
            row.updated_at = iam.now()
            if not is_new:
                row.version += 1
            await db.flush()
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=ws_ctx.auth.user.id,
                action="extension.src05.relay.configure",
                target=f"provider_connection:{connection_id}",
                decision="allow",
                reason_code="customer_operated_relay_configured",
                correlation_id=current_correlation_id(),
                workspace_id=ws_ctx.workspace.id,
                client_ip=extract_client_ip(request),
                metadata={
                    "enabled": row.enabled,
                    "endpoint_registration_id": endpoint.id,
                    "version": row.version,
                },
                occurred_at=iam.now(),
            )
            result = _relay_response(row)
            await complete_idempotent_operation(
                db,
                workspace_id=ws_ctx.workspace.id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=result.id,
                response_payload=result.model_dump(mode="json"),
                now=iam.now(),
            )
        response.headers["ETag"] = format_version_etag(result.version)
        if ws_ctx.auth.csrf_cookie_refreshed:
            from red2pr_control.iam.csrf import set_csrf_cookie

            set_csrf_cookie(response, csrf_token=ws_ctx.auth.csrf_token, secure=iam.secure_cookies)
        return result

    @router.post(
        "/workspaces/{ws}/integrations/{connection_id}/relay/pull",
        operation_id="pullRelaySubscription",
        tags=["integrations"],
        response_model=RelayPullResponse,
    )
    async def pull_relay_subscription(
        connection_id: Annotated[str, Path(min_length=36, max_length=36)],
        _request: Request,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_relay_admin)],
        iam: Annotated[IamService, Depends(get_iam_service)],
        runner: Annotated[CustomerWebhookRelayRunner, Depends(_relay_runner)],
    ) -> RelayPullResponse:
        if not is_step_up_fresh(ws_ctx.auth.session, now=iam.now()):
            raise ForbiddenError(
                code="step_up_required", detail="Fresh 5-minute step-up is required."
            )
        return await runner.receive_once(
            workspace_id=ws_ctx.workspace.id,
            connection_id=connection_id,
            correlation_id=current_correlation_id(),
        )

    return router
