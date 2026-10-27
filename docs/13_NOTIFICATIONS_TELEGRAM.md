# Notifications + Telegram, email, Slack, Discord, webhooks

## Product rule
Notifications are projections of authoritative internal events; delivery failures **never** change whether patch verified. External channels opt-in; in-app security/audit visibility is mandatory; per-user/workspace routing, quiet hours, severity, re-delivery, unsubscribe, avoid sensitive payloads. Notifications have stable ID, ack/read status and links to RBAC protected pages.

## Event catalog
Canonical event names/payloads live in [08](08_EVENTS_STATE_MACHINES.md) and S-19 [36](36_CANONICAL_CONTRACTS.md); per-event audience, outcome filters and delivery rules live in [32](32_NOTIFICATION_EVENT_MATRIX.md). UI labels are not separate domain events.

## Telegram architecture
Bot adapter supports `getUpdates` long polling for private/local instance or `setWebhook` with HTTPS and Telegram secret header on public server. These modes are mutually exclusive per bot. Admin connects bot token in secure wizard (secret in store), tests message to an explicitly selected destination; connection status and delivery log UI. Verify actual chat ID and account mapping with expiring link code; handle group privacy, forged callbacks and forwarded messages.

### Commands, permissions, outputs
| Command | Role / behavior |
|---|---|
| `/start` | association instructions, minimal public info |
| `/help` | supported commands, no credentials |
| `/status` | authenticated linked user, instance health summary |
| `/repos` | only authorized repos + current auto mode |
| `/repairs` | recent authorized repairs, no raw logs |
| `/repair <id>` | status + safe summary + dashboard URL |
| `/pause <repo>` | create short-lived web confirmation URL; requires maintainer scope |
| `/resume <repo>` | web challenge, same authorization |
| `/retry <id>` | web challenge, safe idempotency and limits |
| `/approvals` | list authorized pending approvals with web links; Telegram click alone not write authority |
| `/settings` | link authenticated browser preferences page |

### Notification formatting
`🔴 CI failed — repo#run/attempt` / `🔍 Investigating` / `🧪 Reproduced` / `✅ Locally verified` / `📬 Draft PR created` / `🟢 Remote CI passed` / `⚠️ Needs attention`. Always explicit distinction of local vs remote proof. Include repo alias, job, status, time, redacted cause, secure URL. No raw traceback, env vars, private secrets or untrusted markdown injection; escape Telegram formatting/URLs.

### Delivery resilience
At-least-once outbox with stable dedup key; 429 Retry-After, 5xx bounded backoff, disable invalid chat/token only after classification, DLQ and admin warnings. Private/group notification permissions separate. Bot API token never injected into sandbox or LLM. Bulk routing throttles to avoid flooding.

## Additional channel adapters
- **In-app:** notification inbox, unread/read, filters and history; required.
- **SMTP/email:** TLS, templates and confirmed recipients, suppression lists; opt-in; no marketing.
- **Slack/Discord:** app/webhook authorization, payload escaping, signed callbacks where supported, read-only by default.
- **Outgoing webhooks:** tenant-generated signing secret, timestamp/nonce/replay window, test delivery, disable on repeated failures.
- **Future channels:** adapter interface with event schema/route rules, not direct coupling to repair engine.

## Setup & acceptance
Channel setup test is explicit; failure means `degraded` not falsely `healthy`. User disconnect/revocation prevents future sends. API tests: fake/forwarded Telegram updates, duplicate callbacks, unauthorized commands, markdown injection, redaction, quiet hours/timezone DST, web challenge replay, outage/429, bulk storm limits.

## P2 definitive contract
[32 Notification event matrix](32_NOTIFICATION_EVENT_MATRIX.md) defines canonical domain events, destination consent, all six channel adapters, exact retry/unknown semantics and outgoing signature. Any shorter event label here is UI copy, not another emitted event. In-app security visibility is mandatory; **external destinations** opt in. User linking and read-only commands never replace web RBAC/step-up for dangerous actions. Credentials/test deliveries are not configured or invoked during this documentation phase.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
