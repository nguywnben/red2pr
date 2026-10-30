"""Telegram command processing and web-confirmation intent creation (U22)."""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import sha256_canonical_json
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.redaction import DEFAULT_REDACTOR
from red2pr_control.db.base import (
    ApprovalRequestModel,
    MembershipModel,
    RepairSessionModel,
    RepoGrantModel,
    RepositoryModel,
    TelegramLinkChallengeModel,
    TelegramLinkModel,
    TelegramUpdateModel,
    UserModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.notifications.telegram.adapter import (
    TelegramApiClient,
    normalize_update,
)

_READ_COMMANDS = frozenset(
    {"help", "status", "repos", "repairs", "repair", "approvals", "settings"}
)
_ACTION_COMMANDS = {"pause": "pause", "resume": "resume", "retry": "retry", "unlink": "unlink"}
_ID_RE = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", re.IGNORECASE)
_CHALLENGE_TTL = timedelta(minutes=10)
_INTENT_TTL = timedelta(minutes=5)
_SEND_LEASE = timedelta(minutes=2)


@dataclass(frozen=True, slots=True)
class TelegramBotSettings:
    bot_id: str
    username: str
    mode: str
    public_base_url: str
    token: str = field(repr=False)
    webhook_secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.bot_id):
            raise ValueError("Telegram bot identifier is invalid.")
        if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", self.username):
            raise ValueError("Telegram bot username is invalid.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", self.webhook_secret):
            raise ValueError("Telegram webhook secret must be a high-entropy Bot API secret_token.")
        if self.mode not in {"polling", "webhook"}:
            raise ValueError("Telegram delivery mode must be polling or webhook.")
        parsed_base = urlsplit(self.public_base_url)
        if (
            parsed_base.scheme != "https"
            or not parsed_base.hostname
            or parsed_base.username is not None
            or parsed_base.password is not None
            or parsed_base.query
            or parsed_base.fragment
        ):
            raise ValueError("Telegram requires an HTTPS base URL without credentials or query.")


@dataclass(frozen=True, slots=True)
class NormalizedTelegramUpdate:
    update_id: int
    payload_digest: str
    data: dict[str, Any]


def normalize_for_storage(raw: dict[str, Any], *, bot_username: str) -> NormalizedTelegramUpdate:
    """Drop all Telegram fields except the IDs and command data Red2PR consumes."""
    update_id = raw.get("update_id")
    if not isinstance(update_id, int) or update_id < 0:
        raise ValueError("Telegram update_id is invalid.")
    parsed = normalize_update(raw, bot_username=bot_username)
    if parsed is None:
        data: dict[str, Any] = {"ignored": True}
    elif parsed.forwarded:
        data = {
            "chat_id": parsed.chat_id,
            "telegram_user_id": parsed.telegram_user_id,
            "forwarded": True,
        }
    else:
        args = list(parsed.arguments)
        if parsed.command == "start" and args:
            args[0] = hashlib.sha256(args[0].encode("utf-8")).hexdigest()
        data = {
            "chat_id": parsed.chat_id,
            "telegram_user_id": parsed.telegram_user_id,
            "command": parsed.command,
            "arguments": args,
        }
    # Digest the raw update for idempotency evidence; the raw update is never persisted.
    return NormalizedTelegramUpdate(
        update_id=update_id,
        payload_digest=sha256_canonical_json(raw),
        data=data,
    )


def persist_update_values(
    *,
    bot_id: str,
    update: NormalizedTelegramUpdate,
    correlation_id: str,
    now: datetime,
) -> TelegramUpdateModel:
    return TelegramUpdateModel(
        id=new_uuid7(now=now),
        bot_id=bot_id,
        update_id=update.update_id,
        payload_digest=update.payload_digest,
        normalized_json=update.data,
        state="received" if not update.data.get("ignored") else "ignored",
        correlation_id=correlation_id[:120],
        received_at=now.astimezone(UTC),
    )


class TelegramCommandProcessor:
    def __init__(
        self,
        *,
        settings: TelegramBotSettings,
        session_factory: async_sessionmaker[AsyncSession],
        api: TelegramApiClient,
        clock: Any = None,
    ) -> None:
        self.settings = settings
        self._sessions = session_factory
        self._api = api
        self._clock = clock or (lambda: datetime.now(UTC))

    async def process_pending(self, *, limit: int = 25) -> int:
        """Send replies for persisted updates once; ambiguous sends are not blindly retried."""
        now = self._clock().astimezone(UTC)
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            await db.execute(
                update(TelegramUpdateModel)
                .where(
                    TelegramUpdateModel.bot_id == self.settings.bot_id,
                    TelegramUpdateModel.state == "processing",
                    TelegramUpdateModel.processing_started_at.is_not(None),
                    TelegramUpdateModel.processing_started_at <= now - _SEND_LEASE,
                )
                .values(state="unknown", processed_at=now, processing_started_at=None)
            )
            rows = list(
                (
                    await db.scalars(
                        select(TelegramUpdateModel)
                        .where(
                            TelegramUpdateModel.bot_id == self.settings.bot_id,
                            TelegramUpdateModel.state == "received",
                        )
                        .order_by(TelegramUpdateModel.update_id)
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
            )
            for row in rows:
                row.state = "processing"
                row.processing_started_at = now
            await db.flush()
            work = [(row.id, dict(row.normalized_json), row.correlation_id) for row in rows]
        sent = 0
        for row_id, data, correlation_id in work:
            chat_id = data.get("chat_id")
            processing_error = False
            try:
                response_text = await self._reply_for(data, correlation_id=correlation_id)
            except Exception:
                response_text = None
                processing_error = True
            state = "unknown" if processing_error else "ignored"
            if isinstance(chat_id, str) and response_text:
                try:
                    result = await self._api.call(
                        "sendMessage",
                        {
                            "chat_id": chat_id,
                            "text": response_text[:4000],
                            "disable_web_page_preview": True,
                        },
                    )
                    state = "sent" if result.ok else "unknown"
                    sent += int(result.ok)
                except Exception:
                    state = "unknown"
            async with instance_rls_session(self._sessions, mode="instance_admin") as db:
                update_row = await db.scalar(
                    select(TelegramUpdateModel)
                    .where(
                        TelegramUpdateModel.id == row_id,
                        TelegramUpdateModel.bot_id == self.settings.bot_id,
                        TelegramUpdateModel.state == "processing",
                    )
                    .with_for_update()
                )
                if update_row is not None:
                    update_row.state = state
                    update_row.processed_at = self._clock().astimezone(UTC)
                    update_row.processing_started_at = None
        return sent

    async def _reply_for(self, data: dict[str, Any], *, correlation_id: str) -> str | None:
        if data.get("ignored") or data.get("forwarded"):
            return None
        chat_id, tg_user_id = data.get("chat_id"), data.get("telegram_user_id")
        command, args = data.get("command"), data.get("arguments")
        if not isinstance(chat_id, str) or not isinstance(tg_user_id, str):
            return None
        if not isinstance(command, str) or not isinstance(args, list):
            return None
        now = self._clock().astimezone(UTC)
        if command == "start":
            return await self._redeem_link_challenge(
                chat_id=chat_id,
                telegram_user_id=tg_user_id,
                args=args,
                now=now,
                correlation_id=correlation_id,
            )
        if command == "help":
            return (
                "Red2PR: /status, /repos, /repairs, /repair <id>, /approvals, /settings. "
                "Actions (/pause, /resume, /retry, /unlink) require web sign-in, "
                "step-up and confirmation."
            )
        linked_user = await self._linked_user(chat_id=chat_id, telegram_user_id=tg_user_id)
        if linked_user is None:
            return "Link this private chat from your authenticated Red2PR Account page first."
        if command == "status":
            return (
                "Red2PR is connected. Local and remote verification are reported "
                "separately in the web dashboard."
            )
        if command == "settings":
            return f"Account settings: {self.settings.public_base_url.rstrip('/')}/account"
        if command in _ACTION_COMMANDS:
            return await self._create_action_challenge(
                user_id=linked_user,
                chat_id=chat_id,
                telegram_user_id=tg_user_id,
                command=command,
                args=args,
                now=now,
                correlation_id=correlation_id,
            )
        if command in _READ_COMMANDS:
            return await self._read_command(user_id=linked_user, command=command, args=args)
        return "Unsupported command. Use /help to see the available commands."

    async def _redeem_link_challenge(
        self,
        *,
        chat_id: str,
        telegram_user_id: str,
        args: list[Any],
        now: datetime,
        correlation_id: str,
    ) -> str:
        if (
            len(args) != 1
            or not isinstance(args[0], str)
            or not re.fullmatch(r"[0-9a-f]{64}", args[0])
        ):
            return (
                "Open the one-time link from your authenticated Red2PR Account page "
                "to link this private chat."
            )
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            challenge = await db.scalar(
                select(TelegramLinkChallengeModel)
                .where(
                    TelegramLinkChallengeModel.bot_id == self.settings.bot_id,
                    TelegramLinkChallengeModel.token_hash == args[0],
                    TelegramLinkChallengeModel.scope == "account_link",
                )
                .with_for_update()
            )
            if challenge is None or challenge.used_at is not None or challenge.expires_at <= now:
                return (
                    "That account-link challenge is invalid, expired, or already used. "
                    "Start again from Account."
                )
            existing = await db.scalar(
                select(TelegramLinkModel)
                .where(
                    TelegramLinkModel.bot_id == self.settings.bot_id,
                    TelegramLinkModel.user_id == challenge.user_id,
                )
                .with_for_update()
            )
            collision = await db.scalar(
                select(TelegramLinkModel.id).where(
                    TelegramLinkModel.bot_id == self.settings.bot_id,
                    TelegramLinkModel.telegram_user_id == telegram_user_id,
                    TelegramLinkModel.revoked_at.is_(None),
                    TelegramLinkModel.user_id != challenge.user_id,
                )
            )
            if collision is not None:
                return "This Telegram account is already linked to another Red2PR user."
            if existing is None:
                db.add(
                    TelegramLinkModel(
                        id=new_uuid7(now=now),
                        bot_id=self.settings.bot_id,
                        user_id=challenge.user_id,
                        telegram_user_id=telegram_user_id,
                        private_chat_id=chat_id,
                        linked_at=now,
                    )
                )
            else:
                if existing.revoked_at is None and existing.telegram_user_id != telegram_user_id:
                    return (
                        "Unlink the current Telegram account from the web page "
                        "before linking a new one."
                    )
                existing.telegram_user_id = telegram_user_id
                existing.private_chat_id = chat_id
                existing.linked_at = now
                existing.revoked_at = None
                existing.version += 1
            challenge.used_at = now
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=challenge.user_id,
                action="telegram.link",
                target=f"user:{challenge.user_id}",
                decision="allow",
                reason_code="one_use_private_chat_challenge_redeemed",
                correlation_id=correlation_id,
                occurred_at=now,
                metadata={"bot_id": self.settings.bot_id},
            )
        return "Telegram is linked to your Red2PR account. Private read commands are now available."

    async def _linked_user(self, *, chat_id: str, telegram_user_id: str) -> str | None:
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            user_id = await db.scalar(
                select(TelegramLinkModel.user_id)
                .join(UserModel, UserModel.id == TelegramLinkModel.user_id)
                .where(
                    TelegramLinkModel.bot_id == self.settings.bot_id,
                    TelegramLinkModel.telegram_user_id == telegram_user_id,
                    TelegramLinkModel.private_chat_id == chat_id,
                    TelegramLinkModel.revoked_at.is_(None),
                    UserModel.status == "active",
                )
            )
            return user_id

    async def _user_workspaces(self, user_id: str) -> list[tuple[str, str, str]]:
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            rows = (
                await db.execute(
                    select(
                        MembershipModel.workspace_id, MembershipModel.id, MembershipModel.role
                    ).where(MembershipModel.user_id == user_id)
                )
            ).all()
            return [(str(ws), str(mid), str(role)) for ws, mid, role in rows]

    async def _read_command(self, *, user_id: str, command: str, args: list[Any]) -> str:
        workspaces = await self._user_workspaces(user_id)
        if not workspaces:
            return "Your Red2PR account has no active workspace memberships."
        granted: list[tuple[str, str, str]] = []
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            for workspace_id, membership_id, role in workspaces:
                repo_ids = set(
                    (
                        await db.scalars(
                            select(RepoGrantModel.repository_id).where(
                                RepoGrantModel.workspace_id == workspace_id,
                                RepoGrantModel.membership_id == membership_id,
                            )
                        )
                    ).all()
                )
                if role == "admin":
                    repo_ids = set(
                        (
                            await db.scalars(
                                select(RepositoryModel.id).where(
                                    RepositoryModel.workspace_id == workspace_id,
                                    RepositoryModel.active.is_(True),
                                )
                            )
                        ).all()
                    )
                for repo_id in repo_ids:
                    granted.append((workspace_id, str(repo_id), role))
            if command == "repos":
                approval_rows = (
                    await db.scalars(
                        select(RepositoryModel)
                        .where(RepositoryModel.id.in_([repo for _, repo, _ in granted]))
                        .limit(50)
                    )
                ).all()
                if not approval_rows:
                    return "No repositories are currently granted to your account."
                return (
                    "Repositories: "
                    + "; ".join(
                        f"{_safe(row.name)} [{row.mode}{', paused' if row.paused else ''}]"
                        for row in approval_rows
                    )[:3500]
                )
            repair_query = select(RepairSessionModel).where(
                RepairSessionModel.repository_id.in_([repo for _, repo, _ in granted])
            )
            if command == "repair":
                if len(args) != 1 or not isinstance(args[0], str) or not _ID_RE.fullmatch(args[0]):
                    return "Usage: /repair <repair-id>"
                repair_query = repair_query.where(RepairSessionModel.id == args[0])
            repairs = list(
                (
                    await db.scalars(
                        repair_query.order_by(RepairSessionModel.created_at.desc()).limit(20)
                    )
                ).all()
            )
            if command in {"repairs", "repair"}:
                if not repairs:
                    return "No currently visible repairs were found."
                return (
                    "Repairs (local proof and remote CI are separate): "
                    + "; ".join(
                        f"{row.id[:8]} {row.state}, local={row.proof_grade}, "
                        f"remote={row.remote_status}"
                        for row in repairs
                    )[:3500]
                )
            if command == "approvals":
                rows = (
                    await db.scalars(
                        select(ApprovalRequestModel)
                        .where(
                            ApprovalRequestModel.repository_id.in_(
                                [repo for _, repo, _ in granted]
                            ),
                            ApprovalRequestModel.status == "pending",
                        )
                        .order_by(ApprovalRequestModel.created_at.desc())
                        .limit(20)
                    )
                ).all()
                if not rows:
                    return "No pending approvals are currently visible to your account."
                base = self.settings.public_base_url.rstrip("/")
                return (
                    "Pending approvals: "
                    + "; ".join(
                        f"{row.id[:8]} {base}/w/{row.workspace_id}/approvals" for row in rows
                    )[:3500]
                )
        if command == "status":
            return (
                "Red2PR is connected. Local and remote verification are reported "
                "separately in the dashboard."
            )
        return "Unsupported command. Use /help to see the available commands."

    async def _create_action_challenge(
        self,
        *,
        user_id: str,
        chat_id: str,
        telegram_user_id: str,
        command: str,
        args: list[Any],
        now: datetime,
        correlation_id: str,
    ) -> str:
        if command == "unlink":
            workspace_id = None
            target_id = None
        elif command in {"pause", "resume"}:
            if len(args) != 1 or not isinstance(args[0], str):
                return f"Usage: /{command} <repository-id>"
            async with instance_rls_session(self._sessions, mode="instance_admin") as db:
                repo = await db.scalar(
                    select(RepositoryModel).where(
                        or_(RepositoryModel.id == args[0], RepositoryModel.name == args[0]),
                        RepositoryModel.active.is_(True),
                    )
                )
                if repo is None:
                    return "Repository not found or not currently granted."
                workspace_id, target_id = repo.workspace_id, repo.id
                membership = await db.scalar(
                    select(MembershipModel).where(
                        MembershipModel.workspace_id == workspace_id,
                        MembershipModel.user_id == user_id,
                        MembershipModel.role.in_(("admin", "maintainer")),
                    )
                )
                if membership is None:
                    return "You do not have current maintainer access to that repository."
                grant = None
                if membership.role != "admin":
                    grant = await db.scalar(
                        select(RepoGrantModel.id).where(
                            RepoGrantModel.workspace_id == workspace_id,
                            RepoGrantModel.repository_id == repo.id,
                            RepoGrantModel.membership_id == membership.id,
                        )
                    )
                if membership.role != "admin" and grant is None:
                    return "You do not have current maintainer access to that repository."
        else:
            if len(args) != 1 or not isinstance(args[0], str) or not _ID_RE.fullmatch(args[0]):
                return "Usage: /retry <repair-id>"
            async with instance_rls_session(self._sessions, mode="instance_admin") as db:
                repair = await db.scalar(
                    select(RepairSessionModel).where(RepairSessionModel.id == args[0])
                )
                if repair is None:
                    return "Repair not found or not currently granted."
                workspace_id, target_id = repair.workspace_id, repair.id
                membership = await db.scalar(
                    select(MembershipModel).where(
                        MembershipModel.workspace_id == workspace_id,
                        MembershipModel.user_id == user_id,
                        MembershipModel.role.in_(("admin", "maintainer")),
                    )
                )
                if membership is None:
                    return "You do not have current maintainer access to that repair."
                grant = None
                if membership.role != "admin":
                    grant = await db.scalar(
                        select(RepoGrantModel.id).where(
                            RepoGrantModel.workspace_id == workspace_id,
                            RepoGrantModel.repository_id == repair.repository_id,
                            RepoGrantModel.membership_id == membership.id,
                        )
                    )
                if membership.role != "admin" and grant is None:
                    return "You do not have current maintainer access to that repair."
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        challenge_id = new_uuid7(now=now)
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            db.add(
                TelegramLinkChallengeModel(
                    id=challenge_id,
                    bot_id=self.settings.bot_id,
                    user_id=user_id,
                    token_hash=token_hash,
                    scope="action",
                    workspace_id=workspace_id,
                    action=command,
                    target_id=target_id,
                    created_at=now,
                    expires_at=now + _INTENT_TTL,
                )
            )
        if workspace_id is not None:
            async with workspace_rls_session(self._sessions, workspace_id=workspace_id) as audit_db:
                await append_audit_entry(
                    audit_db,
                    workspace_id=workspace_id,
                    repository_id=target_id if command in {"pause", "resume"} else None,
                    actor_type="user",
                    actor_id=user_id,
                    action="telegram.intent.requested",
                    target=f"{command}:{target_id or user_id}",
                    decision="allow",
                    reason_code="web_confirmation_required",
                    correlation_id=correlation_id,
                    occurred_at=now,
                    metadata={"bot_id": self.settings.bot_id, "scope": "telegram"},
                )
        else:
            async with instance_rls_session(self._sessions, mode="instance_admin") as audit_db:
                await append_audit_entry(
                    audit_db,
                    actor_type="user",
                    actor_id=user_id,
                    action="telegram.intent.requested",
                    target=f"{command}:{target_id or user_id}",
                    decision="allow",
                    reason_code="web_confirmation_required",
                    correlation_id=correlation_id,
                    occurred_at=now,
                    metadata={"bot_id": self.settings.bot_id, "scope": "telegram"},
                )
        action_href = f"{self.settings.public_base_url.rstrip('/')}/telegram/confirm#{raw_token}"
        # Return plain text: do not interpret any untrusted Telegram content as Markdown/HTML.
        return (
            f"Confirm /{command} in your signed-in Red2PR web session "
            f"(5-minute step-up required): {action_href}"
        )


def _safe(value: str) -> str:
    text = DEFAULT_REDACTOR.redact_text(value)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    return text[:120]
