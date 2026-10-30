"""Host composition for U23 notification adapters using the shared egress and secret services."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from red2pr_control.core.egress import EgressPolicyEngine, EgressSafeHttpClient
from red2pr_control.notifications.channels.common import NotificationSecretResolver
from red2pr_control.notifications.channels.discord_adapter import DiscordNotificationAdapter
from red2pr_control.notifications.channels.slack_adapter import SlackNotificationAdapter
from red2pr_control.notifications.channels.smtp_adapter import SmtpNotificationAdapter
from red2pr_control.notifications.channels.webhook_signer import SignedWebhookNotificationAdapter
from red2pr_control.operations.setup_wizard import DbEndpointAllowlistProvider
from red2pr_control.secrets.broker import SecretBroker


def build_external_notification_adapters(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    secret_broker: SecretBroker,
) -> dict[str, object]:
    """Build TLS clients whose every destination is checked by the active ADR-037 registry."""
    egress = EgressPolicyEngine(allowlist_provider=DbEndpointAllowlistProvider(session_factory))
    resolve_secret = NotificationSecretResolver(
        session_factory=session_factory,
        secret_broker=secret_broker,
    )
    slack_client = EgressSafeHttpClient(
        adapter="slack", policy_engine=egress, timeout_seconds=10, max_redirects=0
    )
    discord_client = EgressSafeHttpClient(
        adapter="discord", policy_engine=egress, timeout_seconds=10, max_redirects=0
    )
    webhook_client = EgressSafeHttpClient(
        adapter="webhook", policy_engine=egress, timeout_seconds=10, max_redirects=0
    )
    return {
        "email": SmtpNotificationAdapter(resolve_secret=resolve_secret, egress_policy=egress),
        "slack": SlackNotificationAdapter(http_client=slack_client, resolve_secret=resolve_secret),
        "discord": DiscordNotificationAdapter(
            http_client=discord_client, resolve_secret=resolve_secret
        ),
        "webhook": SignedWebhookNotificationAdapter(
            http_client=webhook_client, resolve_secret=resolve_secret
        ),
    }
