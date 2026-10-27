# CLI lifecycle, backups, recovery and system operations

## Unified CLI
Expected cross-platform `red2pr` executable after successful installer:

| Command | Expected semantics |
|---|---|
| `red2pr status` | version, service health, active session count, provider readiness |
| `red2pr start/stop/restart` | lifecycle with graceful queue drain and warning |
| `red2pr doctor` | safe diagnostics, preflight of runtime, network, DB, worker and credentials metadata |
| `red2pr logs [--since --component]` | authorized sanitized logs |
| `red2pr update [--channel stable]` | signed release, backup, migrations, health + rollback |
| `red2pr backup [--output]` | consistent encrypted DB + artifact snapshot + manifest |
| `red2pr restore <bundle> [--dry-run]` | verify version/key/dependencies, safe restore gated confirmation |
| `red2pr config validate` | schema and policy validation without secret output |
| `red2pr worker list/drain` | secure worker administration |
| `red2pr repair reconcile` | dedup/reconcile orphaned tasks and publication intents |
| `red2pr uninstall` | confirm services and data retention/purge independently |

## Configuration and versions
- Strict schema and precedence: instance default < persisted settings < workspace/repo policy; process env only for safe bootstrap pointers and secrets injection, never universal overrides of global deny.
- Pinned release versions and image digests; semantic versioning; DB migration compatibility policy, support windows and migration safety.
- Update channel stable/beta, no background auto-upgrade without operator opt-in. Notification about security patches allowed.

## Backup and restore
- Back up PostgreSQL, object store, policies, encryption metadata and deployment manifest in consistent snapshot. Master encryption key/backups protected separately and documented.
- Scheduled retention/rotation with encryption, restore drill, integrity manifest and status notification.
- Restore preflight blocks overwriting live data without confirmations, checks schema version, encryption key availability, and last-known external publisher intents. A restore must NOT blindly replay PR creation.

## Operational incidents
| Incident | Detection | Recovery |
|---|---|---|
| GitHub/GitLab 429 | provider error trend | backoff, reduce polling, bounded queue |
| Provider auth revoked | failed token refresh/permission | suspend integration, notify admin; don't delete data |
| Meta unavailable | timeouts/rate limit | pause agent stage; diagnosis history preserved |
| Worker disconnected | heartbeat gap | drain lease/fencing, schedule resumption only if safe |
| Postgres unavailable | readiness failure | stop writes, retries, no false success |
| Redis failure | queue health | republish from DB transactional outbox |
| Storage full | quota alert | pause new sandboxes, cleanup, evidence retention safeguards |
| PR creation timeout | publishing ambiguous | provider reconcile before any retry |
| Malicious repo detected | isolation/security alert | quarantine worker, revoke creds, preserve evidence |
| Upgrade regression | health, canary failure | rollback compatible code, restore if necessary |

## Monitoring/maintenance
Document port map, TLS renewal, resource sizing and workload quotas, cron sweeps, data retention, token rotation, dependency patching, stale approvals, backup success and worker upgrades. System pause mode should keep read-only dashboard usable and not auto-merge or publish during maintenance.

## P2 operational command contract
All commands are **designed**, no executable exists. CLI authenticates to same operation service A-18 or local owner recovery mode; no bypass of RBAC/approval.
status reports component/readiness/last observation, doctor is read-only probes by default (external/paid probes opt-in); logs require scope/redaction/time bounds; start/stop/restart explain in-flight drain; update verifies signed manifest and dry-run compatibility; backup records consistent manifest; restore requires isolated dry-run then confirmed digest; uninstall preserves data unless explicit purge. Output supports human and JSON schema_version with operation/correlation IDs; secrets never in argv/history.
Proposed stable exits:0 successful requested operation (not merely queued);2 invalid args/config;3 auth/permission;4 prerequisite/unsupported;5 dependency unavailable;6 verification/integrity;7 partial/unknown outcome;8 operation conflict. Async submit prints receipt/status URL, exit0 means accepted only when --async explicitly selected. Poll/status indicates final outcome separately; Ctrl-C cancels waiting, not automatically remote operation.
Runbooks must include symptom, diagnostic command, containment, authorized recovery, verification, escalation and data-loss implications for each incident in [37](37_NFR_AND_RECOVERY.md). Backup/update/restore/uninstall tests must use disposable isolated test installation after implementation approval; none executed now.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
