"""Workspace Server-Sent Events (`A-21`) authorization, replay & revocation cutoff.

Implements `GET /api/v1/workspaces/{ws}/events` (`A-21`, `S-19`, `NFR-04`, `SEC-010`,
`SEC-022`, `SEC-032`):
- Authenticates exclusively via opaque `HttpOnly` session cookies; deterministically
  rejects any bearer token in URL query parameters or `Authorization` header (`400`).
- Verifies signed workspace-bound `Last-Event-ID` cursors (`410 cursor_expired` on
  tampered, cross-workspace, TTL-expired, or compacted cursors).
- Filters every `S-19` `OutboxEventModel` frame by live `repo_grants` (`SEC-010`,
  `SEC-032`), optional `repository_id` / `event_type` query filters, and defense-in-depth
  payload redaction.
- Re-evaluates live session, `user.grant_epoch`, workspace status, membership role,
  `repo_grants`, and `break_glass_grants` on every poll tick so role downgrades, grant
  removals, or membership revocations sever active SSE streams well within `<=5s`
  (`NFR-04`) after emitting a targeted `identity.permission_revoked` frame.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi import Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import canonical_json_bytes
from py_contracts.events import EventEnvelope, EventType, SecurityIdentityEventPayload
from py_contracts.iam import WorkspaceRole
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import BadRequestError, GoneError, NotFoundError
from red2pr_control.core.redaction import DEFAULT_REDACTOR
from red2pr_control.db.base import (
    BreakGlassGrantModel,
    MembershipModel,
    OutboxEventModel,
    RepoGrantModel,
    SessionModel,
    UserModel,
    WorkspaceModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    ROLE_PRIVILEGE_RANK,
    WorkspaceAccessContext,
    derive_iam_subkey,
)

SSE_MEDIA_TYPE = "text/event-stream"
DEFAULT_SSE_CURSOR_TTL = timedelta(hours=24)
DEFAULT_SSE_POLL_INTERVAL_SECONDS = 0.20
DEFAULT_SSE_HEARTBEAT_INTERVAL_SECONDS = 15.0

_FORBIDDEN_SSE_QUERY_TOKEN_KEYS: frozenset[str] = frozenset(
    {
        "token",
        "access_token",
        "session_token",
        "bearer",
        "api_key",
        "auth",
        "jwt",
    }
)


def encode_sse_event_cursor(
    *,
    signing_key: bytes,
    workspace_id: str,
    workspace_seq: int,
    now: datetime,
) -> str:
    """Encode an opaque HMAC-SHA256 signed workspace SSE `id:` / `Last-Event-ID` cursor."""
    subkey = derive_iam_subkey(signing_key, context=b"red2pr:sse-cursor:v1")
    payload_obj = {
        "iat": int(now.astimezone(UTC).timestamp()),
        "seq": workspace_seq,
        "v": 1,
        "ws": workspace_id,
    }
    raw_bytes = canonical_json_bytes(payload_obj)
    b64_part = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
    sig_hex = hmac.new(subkey, b64_part.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{b64_part}.{sig_hex}"


def decode_sse_event_cursor(
    raw_cursor: str,
    *,
    signing_key: bytes,
    expected_workspace_id: str,
    now: datetime,
    ttl: timedelta = DEFAULT_SSE_CURSOR_TTL,
) -> int:
    """Validate an SSE `Last-Event-ID` cursor and return `workspace_seq` (`410` otherwise)."""
    if not raw_cursor or "." not in raw_cursor or len(raw_cursor) > 512:
        raise GoneError(
            code="cursor_expired",
            detail="SSE Last-Event-ID cursor is malformed or expired; refetch REST snapshot.",
        )

    b64_part, sig_part = raw_cursor.split(".", 1)
    if not b64_part or len(sig_part) != 64:
        raise GoneError(
            code="cursor_expired",
            detail="SSE Last-Event-ID cursor is malformed or expired; refetch REST snapshot.",
        )

    subkey = derive_iam_subkey(signing_key, context=b"red2pr:sse-cursor:v1")
    expected_sig = hmac.new(subkey, b64_part.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig_part, expected_sig):
        raise GoneError(
            code="cursor_expired",
            detail="SSE Last-Event-ID cursor signature is invalid; refetch REST snapshot.",
        )

    padding = "=" * ((4 - (len(b64_part) % 4)) % 4)
    try:
        decoded_bytes = base64.urlsafe_b64decode(b64_part + padding)
        parsed = json.loads(decoded_bytes.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GoneError(
            code="cursor_expired",
            detail="SSE Last-Event-ID cursor payload is invalid; refetch REST snapshot.",
        ) from exc

    if not isinstance(parsed, dict) or parsed.get("v") != 1:
        raise GoneError(
            code="cursor_expired",
            detail="Unsupported SSE Last-Event-ID cursor version; refetch REST snapshot.",
        )

    ws_id = parsed.get("ws")
    seq = parsed.get("seq")
    iat = parsed.get("iat")
    if (
        not isinstance(ws_id, str)
        or not isinstance(seq, int)
        or seq < 0
        or not isinstance(iat, int)
    ):
        raise GoneError(
            code="cursor_expired",
            detail="Invalid SSE Last-Event-ID cursor fields; refetch REST snapshot.",
        )

    if ws_id != expected_workspace_id:
        raise GoneError(
            code="cursor_expired",
            detail="SSE Last-Event-ID cursor belongs to a different workspace.",
        )

    issued_at = datetime.fromtimestamp(iat, tz=UTC)
    if now.astimezone(UTC) >= (issued_at + ttl):
        raise GoneError(
            code="cursor_expired",
            detail="SSE Last-Event-ID cursor has expired; refetch REST snapshot.",
        )

    return seq


def assert_no_bearer_token_on_sse(request: Request) -> None:
    """Enforce A-21 rule: SSE never accepts bearer tokens in URL query params or headers."""
    for key in request.query_params:
        if key.strip().lower() in _FORBIDDEN_SSE_QUERY_TOKEN_KEYS:
            raise BadRequestError(
                code="bearer_token_forbidden",
                detail=(
                    "SSE streams authenticate exclusively via HttpOnly session cookies; "
                    "credential query parameters are forbidden."
                ),
            )
    auth_header = request.headers.get("authorization")
    if auth_header is not None and auth_header.strip():
        raise BadRequestError(
            code="bearer_token_forbidden",
            detail=(
                "SSE streams authenticate exclusively via HttpOnly session cookies; "
                "Authorization headers are forbidden."
            ),
        )


def _format_sse_frame(*, cursor_id: str, event_type: str, envelope: EventEnvelope) -> str:
    dumped = envelope.model_dump(mode="json")
    redacted_payload = DEFAULT_REDACTOR.redact_value(
        cast(dict[str, Any], dumped.get("payload", {}))
    )
    dumped["payload"] = redacted_payload
    json_line = json.dumps(dumped, separators=(",", ":"), ensure_ascii=False)
    return f"id: {cursor_id}\nevent: {event_type}\ndata: {json_line}\n\n"


class WorkspaceSseService:
    """Live workspace SSE stream authorization, replay, filtering & revocation (`A-21`)."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        signing_key: bytes,
        cursor_ttl: timedelta = DEFAULT_SSE_CURSOR_TTL,
        poll_interval_seconds: float = DEFAULT_SSE_POLL_INTERVAL_SECONDS,
        heartbeat_interval_seconds: float = DEFAULT_SSE_HEARTBEAT_INTERVAL_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self._signing_key = signing_key
        self._cursor_ttl = cursor_ttl
        self._poll_interval_seconds = max(0.02, poll_interval_seconds)
        self._heartbeat_interval_seconds = max(0.25, heartbeat_interval_seconds)

    async def open_workspace_stream(
        self,
        request: Request,
        ws_ctx: WorkspaceAccessContext,
        *,
        last_event_id: str | None,
        repository_id_filter: str | None,
        event_type_filter: EventType | None,
        max_events: int | None,
        max_duration_seconds: float | None,
        client_ip: str,
        correlation_id: str,
        now_fn: Any,
    ) -> StreamingResponse:
        """Validate cursor & repository scope, then return a live `text/event-stream` response."""
        ref_now: datetime = now_fn().astimezone(UTC)
        ws_id = ws_ctx.workspace_id

        # 1. Verify optional repository_id filter against caller's live repo_grants (SEC-010)
        if repository_id_filter is not None and not ws_ctx.can_read_repository(
            repository_id_filter
        ):
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    repository_id=repository_id_filter,
                    actor_type="user",
                    actor_id=ws_ctx.auth.user.id,
                    action="sse.subscribe",
                    target=f"repository:{repository_id_filter}",
                    decision="deny",
                    reason_code="repository_grant_denied",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
            raise NotFoundError(
                code="repository_not_found",
                detail="Repository not found.",
            )

        if repository_id_filter is not None:
            # Also ensure the requested repository_id is not bound to another workspace (SEC-032)
            async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
                foreign_rg = await db.scalar(
                    select(RepoGrantModel.id)
                    .where(
                        RepoGrantModel.repository_id == repository_id_filter,
                        RepoGrantModel.workspace_id != ws_id,
                    )
                    .limit(1)
                )
                if foreign_rg is not None:
                    raise NotFoundError(
                        code="repository_not_found",
                        detail="Repository not found.",
                    )

        # 2. Resolve initial workspace_seq & validate Last-Event-ID cursor (410 on stale/compacted)
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            ws_row = await db.scalar(select(WorkspaceModel).where(WorkspaceModel.id == ws_id))
            if ws_row is None or ws_row.status != "active" or ws_row.deleted_at is not None:
                raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")
            head_seq = int(ws_row.last_event_seq)

            if last_event_id is not None and last_event_id.strip():
                try:
                    decoded_seq = decode_sse_event_cursor(
                        last_event_id.strip(),
                        signing_key=self._signing_key,
                        expected_workspace_id=ws_id,
                        now=ref_now,
                        ttl=self._cursor_ttl,
                    )
                except GoneError:
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=ws_ctx.auth.user.id,
                        action="sse.subscribe",
                        target=f"workspace:{ws_id}",
                        decision="deny",
                        reason_code="cursor_expired",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                    raise

                if decoded_seq > head_seq:
                    raise GoneError(
                        code="cursor_expired",
                        detail="SSE Last-Event-ID cursor ahead of workspace sequence; resync.",
                    )

                if decoded_seq > 0 and head_seq > 0:
                    min_retained_seq = await db.scalar(
                        select(func.min(OutboxEventModel.workspace_seq)).where(
                            OutboxEventModel.workspace_id == ws_id
                        )
                    )
                    if min_retained_seq is not None and decoded_seq < (int(min_retained_seq) - 1):
                        raise GoneError(
                            code="cursor_expired",
                            detail="Requested SSE cursor precedes retained outbox history.",
                        )
                start_seq = decoded_seq
            else:
                start_seq = head_seq

        initial_grant_epoch = ws_ctx.auth.user.grant_epoch
        initial_session_id = ws_ctx.auth.session.id
        initial_user_id = ws_ctx.auth.user.id
        initial_role = ws_ctx.effective_role
        initial_repo_grants = ws_ctx.repository_grants

        async def _stream_generator() -> AsyncIterator[str]:
            current_seq = start_seq
            emitted_events = 0
            loop = asyncio.get_running_loop()
            started_mono = loop.time()
            last_heartbeat_mono = started_mono

            init_now: datetime = now_fn().astimezone(UTC)
            init_cursor = encode_sse_event_cursor(
                signing_key=self._signing_key,
                workspace_id=ws_id,
                workspace_seq=current_seq,
                now=init_now,
            )
            yield f": connected cursor={init_cursor}\n\n"

            while True:
                if await request.is_disconnected():
                    return

                tick_now: datetime = now_fn().astimezone(UTC)

                # Re-verify live session, grant_epoch, workspace status, membership & break-glass
                revoked_reason: str | None = None
                live_wide_read = False
                live_repo_grants: frozenset[str] = frozenset()
                live_user_version = 1

                async with instance_rls_session(
                    self._session_factory, mode="instance_only"
                ) as auth_db:
                    sess_row = await auth_db.scalar(
                        select(SessionModel).where(SessionModel.id == initial_session_id)
                    )
                    user_row = await auth_db.scalar(
                        select(UserModel).where(UserModel.id == initial_user_id)
                    )
                    if (
                        sess_row is None
                        or sess_row.revoked_at is not None
                        or tick_now >= sess_row.expires_at.astimezone(UTC)
                        or tick_now >= sess_row.idle_expires_at.astimezone(UTC)
                    ):
                        revoked_reason = "session_revoked"
                    elif user_row is None or user_row.status != "active":
                        revoked_reason = "user_disabled"
                    else:
                        live_user_epoch = user_row.grant_epoch
                        live_user_version = user_row.version
                        live_is_owner = user_row.is_instance_owner

                if revoked_reason is None:
                    async with workspace_rls_session(
                        self._session_factory, workspace_id=ws_id
                    ) as ws_db:
                        live_ws = await ws_db.scalar(
                            select(WorkspaceModel).where(WorkspaceModel.id == ws_id)
                        )
                        if (
                            live_ws is None
                            or live_ws.status != "active"
                            or live_ws.deleted_at is not None
                        ):
                            revoked_reason = "workspace_inactive"
                        else:
                            live_mem = await ws_db.scalar(
                                select(MembershipModel).where(
                                    MembershipModel.workspace_id == ws_id,
                                    MembershipModel.user_id == initial_user_id,
                                )
                            )
                            if live_mem is not None:
                                rgs = (
                                    await ws_db.scalars(
                                        select(RepoGrantModel.repository_id).where(
                                            RepoGrantModel.workspace_id == ws_id,
                                            RepoGrantModel.membership_id == live_mem.id,
                                        )
                                    )
                                ).all()
                                live_repo_grants = frozenset(rgs)

                            live_bg: BreakGlassGrantModel | None = None
                            if live_is_owner:
                                live_bg = await ws_db.scalar(
                                    select(BreakGlassGrantModel)
                                    .where(
                                        BreakGlassGrantModel.workspace_id == ws_id,
                                        BreakGlassGrantModel.user_id == initial_user_id,
                                        BreakGlassGrantModel.revoked_at.is_(None),
                                        BreakGlassGrantModel.expires_at > tick_now,
                                    )
                                    .order_by(BreakGlassGrantModel.expires_at.desc())
                                    .limit(1)
                                )

                            if live_mem is None and live_bg is None:
                                revoked_reason = "membership_or_break_glass_revoked"
                            else:
                                live_wide_read = (
                                    live_mem is not None and live_mem.role == "admin"
                                ) or live_bg is not None
                                if (
                                    initial_role != "break_glass"
                                    and live_mem is not None
                                    and ROLE_PRIVILEGE_RANK[cast(WorkspaceRole, live_mem.role)]
                                    < ROLE_PRIVILEGE_RANK[initial_role]
                                ):
                                    revoked_reason = "role_downgraded"
                                elif not live_wide_read and (
                                    (
                                        live_user_epoch != initial_grant_epoch
                                        and bool(initial_repo_grants - live_repo_grants)
                                    )
                                    or (
                                        repository_id_filter is not None
                                        and repository_id_filter not in live_repo_grants
                                    )
                                ):
                                    revoked_reason = "repository_grant_revoked"

                if revoked_reason is not None:
                    rev_env = EventEnvelope(
                        event_id=new_uuid7(now=tick_now),
                        type="identity.permission_revoked",
                        occurred_at=tick_now,
                        workspace_id=ws_id,
                        aggregate_id=initial_user_id,
                        aggregate_version=max(1, live_user_version),
                        correlation_id=correlation_id,
                        payload=SecurityIdentityEventPayload(
                            target_id=initial_user_id,
                            reason_code=revoked_reason,
                        ),
                    )
                    rev_cursor = encode_sse_event_cursor(
                        signing_key=self._signing_key,
                        workspace_id=ws_id,
                        workspace_seq=current_seq,
                        now=tick_now,
                    )
                    yield _format_sse_frame(
                        cursor_id=rev_cursor,
                        event_type="identity.permission_revoked",
                        envelope=rev_env,
                    )
                    return

                # Fetch committed workspace outbox events strictly inside workspace RLS
                async with workspace_rls_session(
                    self._session_factory, workspace_id=ws_id
                ) as ws_db:
                    outbox_rows = list(
                        (
                            await ws_db.scalars(
                                select(OutboxEventModel)
                                .where(
                                    OutboxEventModel.workspace_id == ws_id,
                                    OutboxEventModel.workspace_seq > current_seq,
                                )
                                .order_by(OutboxEventModel.workspace_seq.asc())
                                .limit(100)
                            )
                        ).all()
                    )

                for row in outbox_rows:
                    assert row.workspace_seq is not None
                    current_seq = int(row.workspace_seq)

                    # Only deliver identity.permission_revoked to the targeted user or workspace
                    if row.event_type == "identity.permission_revoked":
                        target_id = row.payload.get("target_id")
                        if target_id not in {initial_user_id, ws_id}:
                            continue

                    # Enforce per-event repo_grants visibility (SEC-010, SEC-032)
                    if (
                        row.repository_id is not None
                        and not live_wide_read
                        and row.repository_id not in live_repo_grants
                    ):
                        continue

                    if (
                        repository_id_filter is not None
                        and row.repository_id != repository_id_filter
                    ):
                        continue

                    if event_type_filter is not None and row.event_type != event_type_filter:
                        continue

                    envelope = EventEnvelope(
                        event_id=row.id,
                        schema_version=1,
                        type=cast(EventType, row.event_type),
                        occurred_at=row.occurred_at,
                        workspace_id=row.workspace_id,
                        repository_id=row.repository_id,
                        session_id=row.session_id,
                        aggregate_id=row.aggregate_id,
                        aggregate_version=row.aggregate_version,
                        correlation_id=row.correlation_id,
                        causation_id=row.causation_id,
                        payload=cast(Any, row.payload),
                    )
                    frame_cursor = encode_sse_event_cursor(
                        signing_key=self._signing_key,
                        workspace_id=ws_id,
                        workspace_seq=current_seq,
                        now=tick_now,
                    )
                    yield _format_sse_frame(
                        cursor_id=frame_cursor,
                        event_type=row.event_type,
                        envelope=envelope,
                    )
                    last_heartbeat_mono = loop.time()
                    emitted_events += 1

                    if envelope.type == "identity.permission_revoked":
                        return
                    if max_events is not None and emitted_events >= max_events:
                        return

                now_mono = loop.time()
                if (
                    max_duration_seconds is not None
                    and (now_mono - started_mono) >= max_duration_seconds
                ):
                    return

                if (now_mono - last_heartbeat_mono) >= self._heartbeat_interval_seconds:
                    hb_iso = tick_now.isoformat().replace("+00:00", "Z")
                    yield f": heartbeat {hb_iso}\n\n"
                    last_heartbeat_mono = now_mono

                await asyncio.sleep(self._poll_interval_seconds)

        headers = {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "X-Accel-Buffering": "no",
        }
        return StreamingResponse(
            _stream_generator(),
            media_type=SSE_MEDIA_TYPE,
            headers=headers,
        )
