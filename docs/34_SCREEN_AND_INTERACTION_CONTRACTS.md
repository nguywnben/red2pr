# Detailed screen and interaction contracts — UI specification extension

All routes refer to `docs/04_UI_UX_SPEC.md` and use Red2PR-wrapped Astryx primitives. Backend API owns authorization and state. Each page must handle loading/empty/error/permission/offline/degraded states, localization, keyboard navigation, and safe feedback.

| Screen | Mandatory flows, inputs and actions | Validation / edge cases |
|---|---|---|
| First-run wizard | deployment mode, one-time admin, consent Meta inference, model probe, provider connections, repo selection, worker test, finish | token expiry, interrupted/refresh resume, optional step skip, cannot enable unsafe auto-repair |
| Login/account | session login/logout, password reset method, MFA readiness, session/device list | lockout, CSRF, timed out sessions, credential stuffing limits |
| Overview | status cards, cost/fix funnel, last failures, alerts, provider health, search | truthful denominators, stale data marker, timezone |
| Repositories | filters, org grouping, add/revoke, sync, bulk select, per-repo mode | provider pagination, no unauthorized repo leaks, revocation |
| Repository detail | CI jobs, failure history, effective policy, branch/file rules, members, audit | policy dry-run, revision conflict, user-role changes |
| Pipelines | provider run, matrix jobs, attempts, raw/sanitized logs, artifacts | truncation, missing log, unavailable artifacts, expired provider token |
| Repair sessions | phases, budget, cause, test evidence, diff and live updates, replay log | partial proof, actor permission, reconnect/resync, massive logs |
| PR/MR explorer | draft status, remote CI results, provider deep link, comments | failed provider publish reconcile, user-edited PR |
| Approvals | risk grade, scope, diff SHA, expiry, approve/reject, comments | stale approval, diff changed, double-click/replay, MFA step-up |
| AI models | key reference, model availability, rate budgets, escalation rules, capability probe | unavailable Wonder, provider outage, secret never displayed |
| Worker/sandbox | certified isolation, heartbeat, draining, quota, quarantine, logs | disconnected, stale lease, unsafe runtime prevents activation |
| Queue | pending/running/retry/DLQ/cancel, fair scheduling, backpressure | visible correlation, no double execution |
| Notifications | in-app history, Telegram pairing, email/Slack/Discord/webhook routes | unauthorized channel, secret masking, opt-out, rate limit |
| Members & IAM | workspace invite, role, repo scope, revoke, audit | BOLA/IDOR, stale cached authorization |
| Security & audit | policy history, token rotation, evidence retention, event export | readonly auditor, masked secrets, export privacy |
| Analytics | fix rate, remote rate, costs, false-green rate, time-to-fix, export | bounded interval, filter denominators, aggregate authorization |
| Instance admin | status/doctor, server URL, TLS, updates, backup/restore, system pause | data preservation and destructive confirmations |

## Cross-screen interaction rules
- Every mutation is optimistic only if backed by revision precondition and rollback on 409/403.
- Entity IDs are links to canonical detail views; all navigation preserves workspace context.
- Notifications deep link to original events, but endpoint re-authorizes every view.
- Use unified timestamp serialization (UTC API ISO 8601; display per user timezone).
- Live repair progress SSE can disconnect; restore from last authoritative REST snapshot and cursor.
- Danger zones require explicit typed confirmation; system settings can be edited only by instance owner.

## Design test identifiers
`UX-SETUP-001`, `UX-LOGIN-001`, `UX-REPO-001`, `UX-POLICY-001`, `UX-REPAIR-001`, `UX-APPROVAL-001`, `UX-NOTIFY-001`, `UX-SECURITY-001`, `UX-OPS-001`, `UX-ACCESS-001`. Each expands to happy/unhappy and accessibility cases before feature marked complete.

## P2 route → action → API → persistence contract
All route IDs below use /w/:ws prefix unless explicit. Column test maps into feature tests in [38](38_REQUIREMENTS_TRACEABILITY.md); common UX tests apply to every route. No product screens exist yet.

| UI ID / route | Principal action and validation | API / entities | Acceptance test family |
|---|---|---|---|
| UI-S01 /setup/* | owner claim/resume, prereq checks, cost/egress consent, ready_monitor vs ready_repair | A-01,A-06,A-13,A-18,A-20 / instances,consents,connections | UX-SETUP-001, INS-02 |
| UI-S02 /login | login/MFA/recovery; generic errors, no account enumeration | A-02 / users,sessions,recovery_codes | UX-LOGIN-001, IAM-01 |
| UI-S03 /overview | scoped funnel, failures, cost, timestamps and unresolved count | A-09,A-17,A-21 / repairs,usage_ledger | ANL-01 |
| UI-S04 /repositories | paginated discovery/sync, filters/tags, explicit bulk policy preview | A-06,A-07 / repositories,provider_sync_cursors | UX-REPO-001, REP-01 |
| UI-S05 /repositories/:repo | effective mode/branch/file rules, dry-run, revision conflict | A-07,A-08,A-09 / policies,runs,repairs | UX-POLICY-001, REP-02,REP-03 |
| UI-S06 /pipelines | attempt/matrix selector, source SHA, truncated/expired logs | A-08,A-10 / ci_runs,ci_jobs,artifacts | TRI-01 |
| UI-S07 /repairs | filters proof/phase/remote state; no “fixed” aggregate conflation | A-09,A-21 / repair_sessions | APP-01 |
| UI-S08 /repairs/:id | Cause/Repro/Diff/Verification/PR/Logs/Audit tabs; pause/cancel/retry and missing evidence | A-09,A-10,A-12,A-21 / diagnostics,patches,verification,publication | UX-REPAIR-001, FIX-02 |
| UI-S09 /prs | draft remote link, exact commit checks, unknown publish reconciliation | A-12 / publication_records,remote_ci_checks | FIX-03 |
| UI-S10 /approvals | show base/patch/policy SHA, risk,expiry;step-up approve/reject | A-11 / approval_requests,approval_votes | UX-APPROVAL-001,APP-02 |
| UI-S11 /agents | tool/model profile, bounded steps, deny explanation, no arbitrary prompt-power switch | A-20,A-10 / agent_steps,profile_revisions | AGT-02 |
| UI-S12 /models | masked key status, account capability, max-cost probe confirmation | A-20 / capability_snapshots,budget_accounts | AGT-01,AGT-03 |
| UI-S13 /workers | owner global registry; others only scoped readiness; drain/quarantine confirmation | A-13 / workers,sandbox_leases | SAN-01,JOB-02 |
| UI-S14 /queues | eligible/leased/DLQ, budget, scoped replay preview | A-14 / task_jobs,dead_letter_jobs | JOB-01,JOB-02 |
| UI-S15 /integrations | App install,GitLab host/auth,grant diff,revoke/rotate; provider callback state | A-06,A-23 / connections,consents | SRC-01,SRC-02 |
| UI-S16 /notifications | inbox, routing, linking,quiet hours,test-send preview,unknown receipt | A-15,A-16,A-24 / events,destinations,deliveries | UX-NOTIFY-001,NOT-01…04 |
| UI-S17 /analytics | bounded time range, denominators, stale watermark, CSV/JSON export | A-17 / usage_ledger,report_exports | ANL-01,ANL-02 |
| UI-S18 /security | audit search, grants,scoped tokens,retention,consent and masked key rotation | A-17,A-19,A-06 / audit_log,api_tokens,consents | UX-SECURITY-001,OPS-03 |
| UI-S19 /members | invite,role/repo grant changes; last-admin protection; immediate revoke | A-05 / memberships,invitations,repo_grants | IAM-02,UX-ACCESS-001 |
| UI-S20 /system | owner status/doctor/update/backup/restore/pause; dry-run digest before irreversible action | A-18,A-24 / operations,backups,migrations | UX-OPS-001,OPS-02 |
| UI-S21 /account | sessions,MFA,recovery,preferences,Telegram unlink and current grants | A-03,A-16 / sessions,mfa_credentials,telegram_links | IAM-01,NOT-02 |

### Shared states and accessible actions
Loading: skeleton with labelled progress, no fake values; empty: distinguish no data/no filters/no permission/not configured and one permitted next step; error: safe reason+correlation and retry only when safe; stale/offline: show snapshot timestamp and disable mutations needing fresh grants; degraded: explain missing provider/model/worker and partial capability; forbidden404/403: no private object details; validation: field-linked errors + focus summary, preserve nonsecret input. Every optimistic update rolls back on conflict; approval/publish/restore never optimistic.
Data grids use server sort/filter/page, stable selection by authorized IDs, visible current filter and bulk scope, keyboard focus retained after refresh, text alternative to badge/chart. Virtualization requires accessible row count/position and nonvirtual paged fallback; never render huge artifact into DOM. Diff has file list/hunks, accessible text view and unchanged baseline compare; log viewer bounds ranges, can pause tail, search across fetched/indexed ranges explicitly, strips unsafe ANSI and renders plain text. Copy/export confirms scope and redacts; no HTML execution or terminal commands triggered from logs.
Dark/light/system preference persists per user without losing contrast; contrast and focus ring tested across warning/error/disabled states. Responsive admin at320/768/1280px supports all permitted functions through stacked forms/drawers and review summaries; complex diff/grid can scroll or switch text view. Earlier “mobile read-only” is superseded by this proposed responsive-admin contract: dangerous actions require same full review/step-up, never reduced controls. Screen readers receive throttled phase announcements, not every log line; dialogs trap/restore focus and provide accessible title. Reduced motion respected, no color-only proof status.
All UI IDs require empty/loading/error/stale/reconnect/revoked-role/keyboard/dark-light assertions in T-UI-01-P/N and T-UI-02-P/N; exact production component libraries beyond Astryx are PROPOSED, not preinstalled.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
