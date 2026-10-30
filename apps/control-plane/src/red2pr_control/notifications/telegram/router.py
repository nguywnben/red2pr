"""A-16 account-link and one-use Telegram web-confirmation APIs (U22)."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, timedelta
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Header, Path, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select

from py_contracts import (
    RepositoryUpdateRequest,
    TelegramIntentConfirmationRequest,
    TelegramIntentConfirmationResponse,
    TelegramIntentResponse,
    TelegramIntentTokenRequest,
    TelegramLinkChallengeResponse,
)
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    UnauthorizedError,
    UnprocessableEntityError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.db.base import (
    RepairSessionModel,
    RepositoryModel,
    TelegramLinkChallengeModel,
    TelegramLinkModel,
    UserModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import authorize_workspace_access
from red2pr_control.iam.router import (
    get_iam_service,
    require_authenticated_mutation,
    require_authenticated_read,
)
from red2pr_control.iam.sessions import (
    AuthenticatedContext,
    IamService,
    extract_client_ip,
    is_step_up_fresh,
)
from red2pr_control.notifications.telegram.adapter import validate_webhook_secret
from red2pr_control.notifications.telegram.poller import TelegramBotService

_CHALLENGE_TTL = timedelta(minutes=10)
_ACTION_ROLES: frozenset[Literal["admin", "maintainer"]] = frozenset({"admin", "maintainer"})
_READ_ROLES: frozenset[Literal["admin", "maintainer", "reviewer", "viewer", "auditor"]] = frozenset(
    {"admin", "maintainer", "reviewer", "viewer", "auditor"}
)
_TERMINAL_RETRY_STATES = frozenset(
    {
        "cancelled",
        "blocked",
        "rejected",
        "needs_human",
        "diagnosed_only",
        "unsupported",
        "repro_unconfirmed",
        "remote_failed",
        "remote_unknown",
    }
)


def _bot(request: Request) -> TelegramBotService:
    service = getattr(request.app.state, "telegram_bot_service", None)
    if not isinstance(service, TelegramBotService):
        raise DependencyUnavailableError(
            code="telegram_not_configured",
            detail="Telegram bot credentials and mode are not configured on this instance.",
        )
    return service


def _correlation(request: Request) -> str:
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) and value else current_correlation_id()


def _token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def build_telegram_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.post(
        "/me/telegram-link-challenges",
        operation_id="createTelegramLinkChallenge",
        response_model=TelegramLinkChallengeResponse,
        tags=["notifications"],
        status_code=201,
    )
    async def create_link_challenge(
        request: Request,
        response: Response,
        auth: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> TelegramLinkChallengeResponse:
        bot = _bot(request)
        now = iam.now().astimezone(UTC)
        raw_token = secrets.token_urlsafe(32)
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            await db.execute(
                select(UserModel.id).where(UserModel.id == auth.user.id).with_for_update()
            )
            challenges = list(
                (
                    await db.scalars(
                        select(TelegramLinkChallengeModel)
                        .where(
                            TelegramLinkChallengeModel.bot_id == bot.settings.bot_id,
                            TelegramLinkChallengeModel.user_id == auth.user.id,
                            TelegramLinkChallengeModel.scope == "account_link",
                            TelegramLinkChallengeModel.used_at.is_(None),
                        )
                        .with_for_update()
                    )
                ).all()
            )
            for challenge in challenges:
                challenge.used_at = now
            db.add(
                TelegramLinkChallengeModel(
                    id=new_uuid7(now=now),
                    bot_id=bot.settings.bot_id,
                    user_id=auth.user.id,
                    token_hash=_token_hash(raw_token),
                    scope="account_link",
                    created_at=now,
                    expires_at=now + _CHALLENGE_TTL,
                )
            )
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=auth.user.id,
                action="telegram.link_challenge.created",
                target=f"user:{auth.user.id}",
                decision="allow",
                reason_code="one_use_link_challenge_issued",
                correlation_id=_correlation(request),
                occurred_at=now,
                metadata={"bot_id": bot.settings.bot_id},
            )
        response.headers["Cache-Control"] = "no-store"
        return TelegramLinkChallengeResponse(
            bot_username=bot.settings.username,
            deep_link=f"https://t.me/{bot.settings.username}?start={raw_token}",
            expires_at=now + _CHALLENGE_TTL,
        )

    @router.delete(
        "/me/telegram-link",
        operation_id="deleteTelegramLink",
        tags=["notifications"],
        status_code=204,
    )
    async def delete_link(
        request: Request,
        auth: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> Response:
        bot = _bot(request)
        now = iam.now().astimezone(UTC)
        if not is_step_up_fresh(auth.session, now=now):
            raise ForbiddenError(
                code="step_up_required", detail="A fresh step-up is required to unlink Telegram."
            )
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            row = await db.scalar(
                select(TelegramLinkModel)
                .where(
                    TelegramLinkModel.bot_id == bot.settings.bot_id,
                    TelegramLinkModel.user_id == auth.user.id,
                    TelegramLinkModel.revoked_at.is_(None),
                )
                .with_for_update()
            )
            if row is not None:
                row.revoked_at = now
                row.version += 1
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="telegram.unlink",
                    target=f"user:{auth.user.id}",
                    decision="allow",
                    reason_code="user_revoked_telegram_link",
                    correlation_id=_correlation(request),
                    occurred_at=now,
                    metadata={"bot_id": bot.settings.bot_id},
                )
        return Response(status_code=204)

    @router.post(
        "/me/telegram-intents/preview",
        operation_id="getTelegramIntent",
        response_model=TelegramIntentResponse,
        tags=["notifications"],
    )
    async def get_intent(
        body: TelegramIntentTokenRequest,
        request: Request,
        _auth: Annotated[AuthenticatedContext, Depends(require_authenticated_read)],
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> TelegramIntentResponse:
        bot = _bot(request)
        now = iam.now().astimezone(UTC)
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            row = await db.scalar(
                select(TelegramLinkChallengeModel).where(
                    TelegramLinkChallengeModel.bot_id == bot.settings.bot_id,
                    TelegramLinkChallengeModel.token_hash == _token_hash(body.token),
                    TelegramLinkChallengeModel.scope == "action",
                    TelegramLinkChallengeModel.user_id == _auth.user.id,
                )
            )
            if row is None:
                raise NotFoundError(code="telegram_intent_not_found", detail="Intent not found.")
            if row.expires_at <= now and row.used_at is None:
                raise GoneError(code="telegram_intent_expired", detail="Intent has expired.")
            link = await db.scalar(
                select(TelegramLinkModel.id).where(
                    TelegramLinkModel.bot_id == bot.settings.bot_id,
                    TelegramLinkModel.user_id == _auth.user.id,
                    TelegramLinkModel.revoked_at.is_(None),
                )
            )
            if row.action != "unlink" and link is None:
                raise ForbiddenError(
                    code="telegram_link_revoked", detail="Telegram link is no longer active."
                )
            if row.workspace_id is not None and row.target_id is not None:
                ctx = await authorize_workspace_access(
                    iam.session_factory,
                    auth=_auth,
                    raw_ws=row.workspace_id,
                    allowed_roles=_READ_ROLES,
                    allow_break_glass=False,
                    action="telegram.intent_read",
                    client_ip=extract_client_ip(request),
                    correlation_id=_correlation(request),
                    now=now,
                )
                repo_id = row.target_id
                if row.action == "retry":
                    repair = await db.scalar(
                        select(RepairSessionModel).where(RepairSessionModel.id == row.target_id)
                    )
                    if repair is None:
                        raise NotFoundError(code="repair_not_found", detail="Repair was not found.")
                    repo_id = repair.repository_id
                if not ctx.can_read_repository(repo_id):
                    raise NotFoundError(
                        code="telegram_intent_not_found", detail="Intent not found."
                    )
            description = await _intent_description(db, row)
            return TelegramIntentResponse(
                action=cast(Any, row.action),
                workspace_id=row.workspace_id,
                target_id=row.target_id,
                scope_description=description,
                expires_at=row.expires_at,
                already_confirmed=row.used_at is not None,
            )

    @router.post(
        "/me/telegram-intents/confirm",
        operation_id="confirmTelegramIntent",
        response_model=TelegramIntentConfirmationResponse,
        tags=["notifications"],
    )
    async def confirm_intent(
        body: TelegramIntentConfirmationRequest,
        request: Request,
        auth: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
        iam: Annotated[IamService, Depends(get_iam_service)],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=120)
        ],
    ) -> TelegramIntentConfirmationResponse:
        if not body.confirmed:
            raise UnprocessableEntityError(
                code="confirmation_required", detail="The user must explicitly confirm this action."
            )
        bot = _bot(request)
        now = iam.now().astimezone(UTC)
        if not is_step_up_fresh(auth.session, now=now):
            raise ForbiddenError(
                code="step_up_required", detail="A fresh five-minute step-up is required."
            )
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            challenge = await db.scalar(
                select(TelegramLinkChallengeModel)
                .where(
                    TelegramLinkChallengeModel.bot_id == bot.settings.bot_id,
                    TelegramLinkChallengeModel.token_hash == _token_hash(body.token),
                    TelegramLinkChallengeModel.scope == "action",
                    TelegramLinkChallengeModel.user_id == auth.user.id,
                )
                .with_for_update()
            )
            if challenge is None:
                raise NotFoundError(code="telegram_intent_not_found", detail="Intent not found.")
            if challenge.used_at is not None:
                result = challenge.result_json or {}
                if result.get("idempotency_key") != idempotency_key:
                    raise ConflictError(
                        code="idempotency_mismatch",
                        detail=(
                            "This one-use intent was already confirmed with another request key."
                        ),
                    )
                return TelegramIntentConfirmationResponse(
                    state="confirmed",
                    operation_id=str(result.get("operation_id") or challenge.id),
                    status_url=result.get("status_url"),
                )
            if challenge.expires_at <= now:
                raise GoneError(code="telegram_intent_expired", detail="Intent has expired.")
            link = await db.scalar(
                select(TelegramLinkModel.id).where(
                    TelegramLinkModel.bot_id == bot.settings.bot_id,
                    TelegramLinkModel.user_id == auth.user.id,
                    TelegramLinkModel.revoked_at.is_(None),
                )
            )
            if challenge.action != "unlink" and link is None:
                raise ForbiddenError(
                    code="telegram_link_revoked", detail="Telegram link is no longer active."
                )

        status_url: str | None = None
        if challenge.action == "unlink":
            async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
                link_row = await db.scalar(
                    select(TelegramLinkModel)
                    .where(
                        TelegramLinkModel.bot_id == bot.settings.bot_id,
                        TelegramLinkModel.user_id == auth.user.id,
                        TelegramLinkModel.revoked_at.is_(None),
                    )
                    .with_for_update()
                )
                if link_row is not None:
                    link_row.revoked_at = now
                    link_row.version += 1
                    await append_audit_entry(
                        db,
                        actor_type="user",
                        actor_id=auth.user.id,
                        action="telegram.unlink",
                        target=f"user:{auth.user.id}",
                        decision="allow",
                        reason_code="web_confirmed_telegram_unlink",
                        correlation_id=_correlation(request),
                        occurred_at=now,
                        metadata={"bot_id": bot.settings.bot_id},
                    )
            operation_id = challenge.id
        elif challenge.action in {"pause", "resume"}:
            if challenge.workspace_id is None or challenge.target_id is None:
                raise ConflictError(
                    code="telegram_intent_invalid", detail="Intent scope is invalid."
                )
            ctx = await authorize_workspace_access(
                iam.session_factory,
                auth=auth,
                raw_ws=challenge.workspace_id,
                allowed_roles=_ACTION_ROLES,
                allow_break_glass=False,
                action="telegram.repository_action",
                client_ip=extract_client_ip(request),
                correlation_id=_correlation(request),
                now=now,
            )
            async with workspace_rls_session(
                iam.session_factory, workspace_id=ctx.workspace_id
            ) as db:
                repo = await db.scalar(
                    select(RepositoryModel)
                    .where(
                        RepositoryModel.workspace_id == ctx.workspace_id,
                        RepositoryModel.id == challenge.target_id,
                    )
                    .with_for_update()
                )
                if repo is None or not ctx.can_act_on_repository(
                    repo.id, allowed_roles=_ACTION_ROLES
                ):
                    raise NotFoundError(code="repository_not_found", detail="Repository not found.")
                expected_version = repo.version
            from red2pr_control.repositories.router import _resolve_repository_catalog_service

            catalog = _resolve_repository_catalog_service(request)
            _repo, _version = await catalog.update_repository(
                ctx,
                repository_id=challenge.target_id,
                payload=RepositoryUpdateRequest(paused=challenge.action == "pause"),
                if_match_header=f'"v{expected_version}"',
                client_ip=extract_client_ip(request),
                correlation_id=_correlation(request),
            )
            operation_id = challenge.id
            status_url = f"/w/{challenge.workspace_id}/repositories/{challenge.target_id}"
        elif challenge.action == "retry":
            if challenge.workspace_id is None or challenge.target_id is None:
                raise ConflictError(
                    code="telegram_intent_invalid", detail="Intent scope is invalid."
                )
            ctx = await authorize_workspace_access(
                iam.session_factory,
                auth=auth,
                raw_ws=challenge.workspace_id,
                allowed_roles=_ACTION_ROLES,
                allow_break_glass=False,
                action="telegram.repair_retry",
                client_ip=extract_client_ip(request),
                correlation_id=_correlation(request),
                now=now,
            )
            async with workspace_rls_session(
                iam.session_factory, workspace_id=ctx.workspace_id
            ) as db:
                parent = await db.scalar(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == ctx.workspace_id,
                        RepairSessionModel.id == challenge.target_id,
                    )
                    .with_for_update()
                )
                if parent is None or not ctx.can_act_on_repository(
                    parent.repository_id, allowed_roles=_ACTION_ROLES
                ):
                    raise NotFoundError(code="repair_not_found", detail="Repair was not found.")
                if parent.state not in _TERMINAL_RETRY_STATES:
                    raise ConflictError(
                        code="retry_requires_terminal_parent",
                        detail="Repair must be terminal before retry.",
                    )
                machine_data = (
                    parent.repository_id,
                    parent.ci_run_id,
                    parent.base_sha,
                    parent.target_ref,
                    parent.policy_revision,
                    parent.budget_account_id,
                )
            from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine

            repo_id, run_id, base_sha, target_ref, policy_revision, budget_id = machine_data
            machine = RepairSessionStateMachine(session_factory=iam.session_factory)
            repaired, _created = await machine.create_or_get_session(
                workspace_id=challenge.workspace_id,
                repository_id=repo_id,
                ci_run_id=run_id,
                semantic_trigger_key=f"telegram-intent:{challenge.id}",
                base_sha=base_sha,
                target_ref=target_ref,
                policy_revision=policy_revision,
                budget_account_id=budget_id,
                correlation_id=_correlation(request),
                parent_id=challenge.target_id,
                supersedes_id=challenge.target_id,
                actor=f"user:{auth.user.id}",
            )
            operation_id = repaired.id
            status_url = f"/w/{challenge.workspace_id}/repairs/{repaired.id}"
        else:
            raise ConflictError(code="telegram_intent_invalid", detail="Intent action is invalid.")

        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            challenge_row = await db.scalar(
                select(TelegramLinkChallengeModel)
                .where(TelegramLinkChallengeModel.id == challenge.id)
                .with_for_update()
            )
            if challenge_row is None:
                raise ConflictError(
                    code="telegram_intent_invalid", detail="Intent no longer exists."
                )
            if challenge_row.used_at is None:
                challenge_row.used_at = now
                challenge_row.result_json = {
                    "operation_id": operation_id,
                    "status_url": status_url,
                    "idempotency_key": idempotency_key[:120],
                }
        return TelegramIntentConfirmationResponse(
            state="confirmed", operation_id=operation_id, status_url=status_url
        )

    @router.post(
        "/hooks/telegram/{bot_id}",
        operation_id="receiveTelegramWebhook",
        tags=["webhooks"],
    )
    async def telegram_webhook(
        bot_id: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
    ) -> JSONResponse:
        service = _bot(request)
        if service.settings.mode != "webhook" or bot_id != service.settings.bot_id:
            raise NotFoundError(code="telegram_webhook_not_found", detail="Webhook not found.")
        if "cookie" in request.headers:
            raise BadRequestError(
                code="cookie_auth_forbidden_on_webhook",
                detail="Browser cookies are forbidden on webhook endpoints.",
            )
        received_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if not validate_webhook_secret(received_secret, service.settings.webhook_secret):
            raise UnauthorizedError(
                code="webhook_auth_failed", detail="Webhook authentication failed."
            )
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 256 * 1024:
                return JSONResponse(status_code=413, content={"error": "payload_too_large"})
            body.extend(chunk)
        try:
            import json

            raw = json.loads(bytes(body))
        except (ValueError, UnicodeDecodeError):
            raise BadRequestError(
                code="malformed_json", detail="Webhook body must be UTF-8 JSON."
            ) from None
        if not isinstance(raw, dict) or type(raw.get("update_id")) is not int:
            raise BadRequestError(
                code="invalid_telegram_update", detail="Telegram update is malformed."
            )
        try:
            created = await service.persist_webhook_update(
                raw, correlation_id=_correlation(request)
            )
        except Exception:
            raise DependencyUnavailableError(
                code="webhook_persistence_unavailable",
                detail="Telegram update could not be durably stored.",
            ) from None
        return JSONResponse(status_code=202 if created else 200, content={"accepted": created})

    return router


async def _intent_description(db: Any, row: TelegramLinkChallengeModel) -> str:
    if row.action == "unlink":
        return "Unlink this personal Telegram account from Red2PR."
    if row.action in {"pause", "resume"} and row.target_id:
        repo = await db.scalar(select(RepositoryModel).where(RepositoryModel.id == row.target_id))
        if repo is None:
            raise NotFoundError(code="repository_not_found", detail="Repository not found.")
        return f"{row.action.title()} repository {repo.name}."
    if row.action == "retry" and row.target_id:
        repair = await db.scalar(
            select(RepairSessionModel).where(RepairSessionModel.id == row.target_id)
        )
        if repair is None:
            raise NotFoundError(code="repair_not_found", detail="Repair was not found.")
        return f"Create a new linked repair attempt from {repair.id[:8]}."
    raise ConflictError(code="telegram_intent_invalid", detail="Intent scope is invalid.")
