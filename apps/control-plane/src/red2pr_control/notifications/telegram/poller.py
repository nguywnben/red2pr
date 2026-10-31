"""Fenced durable Telegram polling, webhook inbox and runtime service (U22)."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.primitives import new_uuid7
from red2pr_control.db.base import (
    TelegramLinkChallengeModel,
    TelegramUpdateModel,
    TelegramUpdateOffsetModel,
)
from red2pr_control.db.rls import instance_rls_session
from red2pr_control.notifications.telegram.adapter import (
    TelegramApiClient,
    TelegramNotificationChannelAdapter,
)
from red2pr_control.notifications.telegram.commands import (
    TelegramBotSettings,
    TelegramCommandProcessor,
    normalize_for_storage,
    persist_update_values,
)

_POLL_TIMEOUT_SECONDS = 25
_POLL_LEASE = timedelta(seconds=45)
_COMMAND_SEND_TIMEOUT = timedelta(minutes=2)


class TelegramBotService:
    """Runtime for exactly one configured bot; modes are exclusive by construction."""

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
        self.api = api
        self._clock = clock or (lambda: datetime.now(UTC))
        self.commands = TelegramCommandProcessor(
            settings=settings,
            session_factory=session_factory,
            api=api,
            clock=self._clock,
        )
        self.notification_adapter = TelegramNotificationChannelAdapter(api)

    async def reconcile_mode(self) -> bool:
        """Apply exactly one Bot API receive mode without dropping pending updates."""
        if self.settings.mode == "webhook":
            result = await self.api.call(
                "setWebhook",
                {
                    "url": (
                        f"{self.settings.public_base_url.rstrip('/')}/api/v1/hooks/telegram/"
                        f"{self.settings.bot_id}"
                    ),
                    "secret_token": self.settings.webhook_secret,
                    "allowed_updates": ["message"],
                    "drop_pending_updates": False,
                },
            )
            if result.ok:
                await self._activate_mode("webhook")
            return result.ok
        info = await self.api.call("getWebhookInfo", {})
        webhook = info.result if info.ok and isinstance(info.result, dict) else None
        if webhook is None:
            return False
        url = webhook.get("url")
        if not isinstance(url, str) or not url:
            await self._activate_mode("polling")
            return True
        removed = await self.api.call("deleteWebhook", {"drop_pending_updates": False})
        if removed.ok:
            await self._activate_mode("polling")
        return removed.ok

    async def _activate_mode(self, mode: str) -> None:
        now = self._clock().astimezone(UTC)
        credential_fingerprint = hashlib.sha256(self.settings.token.encode("ascii")).hexdigest()
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            await db.execute(
                pg_insert(TelegramUpdateOffsetModel)
                .values(
                    bot_id=self.settings.bot_id,
                    mode=mode,
                    credential_fingerprint=credential_fingerprint,
                    next_update_id=0,
                    lease_epoch=0,
                    updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=[TelegramUpdateOffsetModel.bot_id])
            )
            offset = await db.scalar(
                select(TelegramUpdateOffsetModel)
                .where(TelegramUpdateOffsetModel.bot_id == self.settings.bot_id)
                .with_for_update()
            )
            assert offset is not None
            if offset.credential_fingerprint != credential_fingerprint:
                await db.execute(
                    update(TelegramLinkChallengeModel)
                    .where(
                        TelegramLinkChallengeModel.bot_id == self.settings.bot_id,
                        TelegramLinkChallengeModel.scope == "account_link",
                        TelegramLinkChallengeModel.used_at.is_(None),
                    )
                    .values(used_at=now)
                )
                offset.credential_fingerprint = credential_fingerprint
            offset.mode = mode
            offset.updated_at = now

    async def persist_webhook_update(self, raw: dict[str, Any], *, correlation_id: str) -> bool:
        normalized = normalize_for_storage(raw, bot_username=self.settings.username)
        now = self._clock().astimezone(UTC)
        row = persist_update_values(
            bot_id=self.settings.bot_id,
            update=normalized,
            correlation_id=correlation_id,
            now=now,
        )
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            mode_row = await db.scalar(
                select(TelegramUpdateOffsetModel)
                .where(TelegramUpdateOffsetModel.bot_id == self.settings.bot_id)
                .with_for_update()
            )
            if mode_row is None or mode_row.mode != "webhook":
                raise RuntimeError("Telegram webhook mode is not active for this bot.")
            statement = (
                pg_insert(TelegramUpdateModel)
                .values(
                    id=row.id,
                    bot_id=row.bot_id,
                    update_id=row.update_id,
                    payload_digest=row.payload_digest,
                    normalized_json=row.normalized_json,
                    state=row.state,
                    correlation_id=row.correlation_id,
                    received_at=row.received_at,
                )
                .on_conflict_do_nothing(constraint="uq_telegram_updates_bot_update")
                .returning(TelegramUpdateModel.id)
            )
            created = await db.scalar(statement)
            return created is not None

    async def poll_once(self) -> int:
        if self.settings.mode != "polling":
            return 0
        owner = secrets.token_urlsafe(24)
        now = self._clock().astimezone(UTC)
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            await db.execute(
                pg_insert(TelegramUpdateOffsetModel)
                .values(
                    bot_id=self.settings.bot_id,
                    mode=self.settings.mode,
                    credential_fingerprint=hashlib.sha256(
                        self.settings.token.encode("ascii")
                    ).hexdigest(),
                    next_update_id=0,
                    lease_epoch=0,
                    updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=[TelegramUpdateOffsetModel.bot_id])
            )
            offset = await db.scalar(
                select(TelegramUpdateOffsetModel)
                .where(TelegramUpdateOffsetModel.bot_id == self.settings.bot_id)
                .with_for_update()
            )
            assert offset is not None
            if offset.mode != "polling":
                return 0
            if offset.lease_until is not None and offset.lease_until > now:
                return 0
            offset.lease_owner = owner
            offset.lease_epoch += 1
            epoch = offset.lease_epoch
            next_update_id = offset.next_update_id
            offset.lease_until = now + _POLL_LEASE
            offset.updated_at = now

        payload: dict[str, Any] = {
            "limit": 100,
            "timeout": _POLL_TIMEOUT_SECONDS,
            "allowed_updates": ["message"],
        }
        if next_update_id:
            payload["offset"] = next_update_id
        result = await self.api.call(
            "getUpdates", payload, timeout_seconds=_POLL_TIMEOUT_SECONDS + 10
        )
        if not result.ok or not isinstance(result.result, list):
            await self._release_lease(owner=owner, epoch=epoch)
            return 0
        updates = [item for item in result.result if isinstance(item, dict)]
        max_update_id = next_update_id - 1
        now = self._clock().astimezone(UTC)
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            offset = await db.scalar(
                select(TelegramUpdateOffsetModel)
                .where(
                    TelegramUpdateOffsetModel.bot_id == self.settings.bot_id,
                    TelegramUpdateOffsetModel.lease_owner == owner,
                    TelegramUpdateOffsetModel.lease_epoch == epoch,
                    TelegramUpdateOffsetModel.lease_until > now,
                )
                .with_for_update()
            )
            if offset is None:
                return 0
            for raw in updates:
                try:
                    normalized = normalize_for_storage(raw, bot_username=self.settings.username)
                except (TypeError, ValueError):
                    continue
                row = persist_update_values(
                    bot_id=self.settings.bot_id,
                    update=normalized,
                    correlation_id=new_uuid7(now=now),
                    now=now,
                )
                await db.execute(
                    pg_insert(TelegramUpdateModel)
                    .values(
                        id=row.id,
                        bot_id=row.bot_id,
                        update_id=row.update_id,
                        payload_digest=row.payload_digest,
                        normalized_json=row.normalized_json,
                        state=row.state,
                        correlation_id=row.correlation_id,
                        received_at=row.received_at,
                    )
                    .on_conflict_do_nothing(constraint="uq_telegram_updates_bot_update")
                )
                max_update_id = max(max_update_id, normalized.update_id)
            if max_update_id >= next_update_id:
                # Telegram confirms these only on the next getUpdates call with this offset.
                offset.next_update_id = max_update_id + 1
            offset.lease_owner = None
            offset.lease_until = None
            offset.updated_at = now
        await self.commands.process_pending(limit=100)
        return len(updates)

    async def _release_lease(self, *, owner: str, epoch: int) -> None:
        async with instance_rls_session(self._sessions, mode="instance_admin") as db:
            offset = await db.scalar(
                select(TelegramUpdateOffsetModel)
                .where(
                    TelegramUpdateOffsetModel.bot_id == self.settings.bot_id,
                    TelegramUpdateOffsetModel.lease_owner == owner,
                    TelegramUpdateOffsetModel.lease_epoch == epoch,
                )
                .with_for_update()
            )
            if offset is not None:
                offset.lease_owner = None
                offset.lease_until = None
                offset.updated_at = self._clock().astimezone(UTC)

    async def run_forever(self) -> None:
        """Run durable inbox dispatch in both modes; only polling mode calls getUpdates."""
        from red2pr_control.operations.runtime import shared_operation_lease

        configured = False
        while True:
            try:
                async with shared_operation_lease(self._sessions) as state:
                    if state.enabled:
                        configured = False
                    else:
                        if not configured:
                            configured = await self.reconcile_mode()
                            if not configured:
                                await asyncio.sleep(5.0)
                                continue
                        if self.settings.mode == "polling":
                            await self.poll_once()
                        else:
                            await self.commands.process_pending(limit=100)
                await asyncio.sleep(
                    2.0 if state.enabled else 1.0 if self.settings.mode == "webhook" else 0.25
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                # Avoid logging upstream exception text because HTTP URLs include the bot token.
                await asyncio.sleep(2.0)
