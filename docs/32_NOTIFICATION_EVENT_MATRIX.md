# Notifications & Telegram — common event contracts and delivery policies

## Supported target channels
In-app inbox, per-instance Telegram bot, SMTP email, Slack, Discord and outgoing signed HTTPS webhooks. Channel-specific credentials/config are optional; disabled channel has visible `not_configured` status, not silently dropped event. Each destination has verification/test send, preferences, quiet hours, severity filters, throttle and retry/DLQ.

## Event source of truth
Notification dispatcher consumes **committed domain outbox** after state transition. No direct send within DB transaction; one logical delivery is persisted per `(event_id, destination_id, template_revision)` logical delivery. Templates use redacted immutable snapshots and authorized web links; no raw private log/secret/source in push message by default.

| Event | Example severity | Audience | Default channels | Required content |
|---|---|---|---|---|
| `provider.run.failed` | warning | repo maintainers | in-app + opted Telegram | repo, branch/SHA, failing job, deep-link |
| `repair.session.created` | info | interested watchers | in-app | repair ID, current phase |
| `repair.reproduction.completed` | warning | maintainers | in-app | reason + fidelity, not fake fix |
| `repair.approval.requested` | action | eligible approvers | in-app + opted external | scope/expiry/decision link |
| `repair.verification.completed` | info | maintainers | in-app | evidence grade + pending remote |
| `repair.publication.created` | success | repo maintainers | in-app + opted external | draft URL and local status |
| `repair.remote_ci.completed (outcome=passed)` | success | maintainers | in-app + opted external | authoritative provider CI ref |
| `repair.remote_ci.completed (outcome=failed)` | error | maintainers | in-app + opted external | failure reason and recovery link |
| `repair.blocked` | warning | maintainers | in-app | policy blocked reason |
| `integration.disconnected` | error | admins | in-app + opted email | impacted integration, remediation |
| `worker.quarantined` | critical | instance owner | in-app + opted external | affected worker/session and security link |
| `backup.failed` | critical | instance owner | in-app + opted external | backup ID and recovery docs |
| `release.update_available` | info | instance owner | in-app | version, release notes, no auto-install |

## Telegram bot contract
Commands: `/start` begins one-time owner-to-account linking; `/help`, `/status`, `/repos`, `/repairs`, `/repair <id>` read only and scoped; `/pause`, `/resume`, `/retry <id>` start *web approval challenge* with expiry, not execute write based solely on Telegram callback. Admin policy controls bot in groups/channels; avoid sending private repo identifiers to shared groups unless explicitly approved. Telegram polling vs webhook are mutually exclusive per token; signed/secret validation as API supports. Token rotation, bot blocked, 429 and chat migration are explicit error states.

## Delivery semantics
`pending → sending → accepted | retry_wait | unknown | failed_final | suppressed`; accepted → delivered/bounced only when channel provides evidence; provider IDs and failure reasons stored sanitized; backoff + jitter, per-provider rate limits. Assume at-least-once delivery; user-visible duplicate suppression and idempotency. SMTP bounce and opt-out, Slack/Discord invalid destination, generic webhook signature, replay detection and SSRF validation must be tested.

## UI settings
Workspace notification rules, personal delivery preferences, quiet hours/time zones, event subscriptions, destination management, masked credentials, send test, delivery logs, suppression reason, rate counters. Events delivered externally include stable correlation and minimal personal data; comply with repository inference/data-sharing policy.

## P2 delivery/channel contract
Canonical events are [08](08_EVENTS_STATE_MACHINES.md), payload S-19 [36](36_CANONICAL_CONTRACTS.md). Table outcome filters above are predicates, not new event names. In-app records represent durable event visibility; user may mute informational push routing but cannot delete required security/audit records through unsubscribe. External adapters are all P0 required release capabilities; each installation may leave credentials not_configured.

Delivery is at-least-once with one logical DB record; no end-to-end exactly-once promise. Dispatcher claims lease, checks current recipient grant/destination consent, renders allowlisted versioned template, records request digest then sends. Network timeout after send → unknown; only a provider idempotency/reconciliation capability can safely establish whether retry duplicates. Operator sees possible_duplicate; do not falsely mark SENT. Acknowledged transport accepted is not human read or inbox delivery. Attempt budget8/24h TARGET, exponential jitter honoring provider Retry-After; permanent auth/address400/403 fails_final,429/transient5xx retry, unknown evaluated per channel. Retention and requeue do not reset logical event identity.

| Channel | Linking/credentials and actions | Failure, consent and validation |
|---|---|---|
| In-app | recipient user ID; unread/read state; authenticated evidence/action links | revoked membership removes visibility immediately; event persisted even if stream offline |
| Telegram | personal link challenge bound web user/workspace/bot, single-use10min; confirm Telegram user_id+private chat_id back on web; token secret ref | numeric IDs opaque strings; group/channel routing explicit admin + destination consent, minimal content; blocked bot403, migrate_to_chat_id reverify,429 retry_after; no dangerous callback execution |
| SMTP/email | verified recipient; configured submission host/TLS and auth secret; text+HTML escaped templates, fixed sender, no CRLF headers | SMTP250 means relay accepted; delivery/bounce only verified callback/DSN, otherwise accepted/unknown; permanent bounce suppress destination and notify in-app; opt-out applies marketing/info, operational critical routing visibly managed |
| Slack | owner supplies scoped incoming webhook for selected channel; URL is credential; link opens authenticated web | no bot token required for outbound-only path; 429/backoff, revoked URL quarantine; no @everyone/channel mention from untrusted text; interactive callbacks if enabled require Slack HMAC+timestamp then web confirmation |
| Discord | owner-scoped incoming webhook secret; execute with wait=true to obtain message receipt where supported | allowed_mentions empty by default, sanitize embeds/links; bucket/global rate limits respected; ambiguous transport stays unknown; no reaction becomes approval |
| Outgoing HTTPS webhook | per-destination random signing key and key ID, proof-of-control test, explicit data-sharing consent | SSRF endpoint registry, no redirects with credentials, response/body cap, signature/replay receiver contract below; never include raw secrets/source/logs |

Template variables: event_id, correlation_id, localized title, permitted repository display name, abbreviated SHA, phase/proof_grade, severity, occurred_at, authorized deep_link, optional action expiry. Default no private snippets, diff contents, emails, internal hostnames or bearer/signed download links. Redact *before* enqueue snapshot and again before dispatch; changed grants purge sensitive queued payload/refetch safe fields. Language fallback EN, locale/timezone explicit, quiet hours and escalation override audited. Test-send UI clearly shows recipient/content/channel and requires direct user action; disabling channel does not stop repair.

### Telegram command details
/start <challenge> proves possession of one-time code, not ownership of a workspace role. /help gives safe usage; /status, /repos, /repairs, /repair <id>, /approvals and /settings return only current grants and safe web links. /pause, /resume, /retry only create short-lived intent. Callback carries opaque nonce, no secret/action arguments granting power. Web must authenticate same linked account, re-evaluate RBAC/repo/policy, CSRF and step-up, show scope and obtain one-use confirmation. Replay or role downgrade denies; GET link/scanner preview never mutates. /unlink revokes personal association only after web confirmation; users can always revoke from /account.
One bot token uses getUpdates OR setWebhook, never both. Poller uses durable update_id offset only after commit; lease prevents concurrent pollers. Webhook uses Telegram secret_token header (not a fabricated Telegram body HMAC), TLS, bounded inbox and update_id dedup. Switching mode drains/records offset and reports potential gaps; Telegram pending updates are not an unlimited recovery store. Token rotation invalidates link challenges and reconciles webhook registration only with operator-authorized action.

### Outgoing signature and replay protocol (Red2PR design v1)
Headers: Red2PR-Event-Id, Red2PR-Delivery-Id, Red2PR-Timestamp (Unix seconds), Red2PR-Key-Id, Red2PR-Signature = v1,<base64 HMAC-SHA256>. Signed bytes: ASCII timestamp + "." + delivery_id + "." + exact UTF-8 JSON body. Body S-19 redacted; content type application/json. Timestamp fresh per attempt; stable delivery_id/event_id across retries. Receiver constant-time verifies key and raw bytes, rejects absolute clock skew>300s TARGET, dedups delivery_id and persists before2xx. Receiver can accept overlap old/new keys for configured rotation window; unknown key denied, no unsigned fallback. Replay-protection semantics are receiver responsibility documented in integration setup; Red2PR cannot guarantee an arbitrary receiver implements them.
Key material never appears in notification body/config export/audit. Signing establishes sender/integrity, not authorization to execute arbitrary operations at recipient. No automatic remote command callbacks.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
