# Feature catalog and acceptance standards

**Status:** Every ID represents a **designed** feature, not an implementation. `P0` = mandatory before v1.0.0; `P1` = extensions **designed fully from the outset**, with an explicit v1.0.0 status and support claims only after testing; `P2` = extensions outside the initial release. The owner may promote P1 to P0 during specification review; never silently demote an item to P2. This does not require implementing everything in one pass or postponing testing until the end.

| ID | P | Module / feature | Acceptance summary |
|---|---|---|---|
| INS-01 | P0 | One-command installer Windows, Linux, macOS | OS prereq + idempotent rerun + verified release + healthy UI URL |
| INS-02 | P0 | Bootstrap wizard | unique admin bootstrap, license/egress disclosure, checks |
| INS-03 | P0 | update/doctor/backup/restore/uninstall | verified restore & rollback path, preserve data defaults |
| IAM-01 | P0 | Local admin account + sessions + MFA-ready | lockout, re-auth, CSRF, secure session cookies |
| IAM-02 | P0 | Multiple workspaces, RBAC, repo-level access and local invitations (ADR-034 proposal) | cross-tenant access denied in tests |
| IAM-03 | P1 | OIDC/SSO + federated provisioning (local invites proposed under IAM-02) | IdP integration and role synchronization tests |
| SRC-01 | P0 | GitHub App install & repo discovery | least privilege, installation refresh, selected repos |
| SRC-02 | P0 | GitLab project integration | scoped auth, hooks/polling, MR lifecycle |
| SRC-03 | P0 | Webhook verification and reconciliation | duplicate/out-of-order/missing events handled |
| SRC-04 | P0 | Polling mode for local/NAT | durable cursor, API rate-limits/backoff |
| SRC-05 | P1 | Optional relay mode | secure outbound opt-in, no hidden vendor dependency |
| REP-01 | P0 | Repo catalog + filters/tags | only authorized repos; sync status and last CI |
| REP-02 | P0 | Per-repo modes and policies | Monitor/Approval/Auto-Repair persisted & audited |
| REP-03 | P0 | Branch/file allow/deny policies | protected branches, workflows, tests, infra flags |
| TRI-01 | P0 | Failed run ingestion, job logs, artifacts | correct head SHA/attempt/matrix, partial log handling |
| TRI-02 | P0 | Classification and unsupported abstention | infra/auth/network failures do not spawn patch |
| TRI-03 | P0 | Flaky test analysis/history fingerprint | evidence-backed repeated-run classification with unknown class |
| AGT-01 | P0 | Meta inference test + model registry | model availability checks, per-agent profiles |
| AGT-02 | P0 | Diagnosis agent and bounded patch agent | typed tool calls, context scopes, model trace |
| AGT-03 | P0 | Token/time/cost budget, attempts | explicit stop; no unlimited agent loops |
| AGT-04 | P1 | Multi-model fallback | capabilities verified, no silent provider switch |
| SAN-01 | P0 | Isolated ephemeral sandbox workers | no control credentials, quotas, cleanup |
| SAN-02 | P0 | Baseline reproduction + fidelity record | SHA, env, command, exit, logs, image digest |
| SAN-03 | P0 | Python pytest, Node Jest/Vitest profiles | dependency lockfile, service restrictions, profile tests |
| SAN-04 | P1 | Advanced gVisor/VM fleet profiles beyond mandatory P0 worker isolation | isolation attestation and threat assessment |
| FIX-01 | P0 | Patch scope and integrity checks | skipped/deleted tests and weakened gates blocked |
| FIX-02 | P0 | Verification red→green + regression | exact baseline/patched evidence + status distinction |
| FIX-03 | P0 | Draft PR/MR publish + sync remote CI | no duplicate PR, no auto-merge, correct commit association |
| FIX-04 | P0 | Unconfirmed/blocked/human review; no unverified publication | truthful status and gated actions |
| APP-01 | P0 | Repair timeline + evidence viewer | log ranges, diff, artifacts, approvals, model steps |
| UI-01 | P0 | React 19/TypeScript/Vite frontend with Astryx | typed design wrappers, navigation, theme, accessibility, contract tests |
| UI-02 | P0 | Astryx design tokens + Red2PR theme with fallback strategy | tokens, dark/light, responsive, visual regression and beta upgrade gate |
| APP-02 | P0 | Approvals: publish/retry/config changes | RBAC, expiry, revocation, audit |
| NOT-01 | P0 | In-app notifications + routing preferences | dedup, retry, actionable links, unsubscribe per channel |
| NOT-02 | P0 | Telegram bot notifications + read-only commands | chat linking; scoped `/status`, `/repos`, `/repairs` |
| NOT-03 | P0 | Telegram privileged controls via web confirmation | no blind mutation from channel callbacks |
| NOT-04 | P0 | SMTP/email, Slack, Discord, outgoing webhooks | independently tested adapters; individual channels can be disabled without breaking repair |
| JOB-01 | P0 | Durable task queue & concurrency | restart recovery, priority/fair scheduling |
| JOB-02 | P0 | Cancel/pause/resume/retry and DLQ | bounded retries, safe side-effect reconciliation |
| OPS-01 | P0 | Health, metrics, traces, logs and alerts | end-to-end correlation, failure alerts |
| OPS-02 | P0 | Backup, migration, restore and upgrade | dry-run, no silent destructive migration |
| OPS-03 | P0 | Secrets, credential rotation, retention | encrypted storage, redaction, revoke test |
| ANL-01 | P0 | Efficiency/quality/usage dashboards | clear denominators, no conflated fix statuses |
| ANL-02 | P0 | Export audit/usage reports | private data scope, CSV/JSON formats |
| EXT-01 | P0 | API tokens / outgoing events | scoped tokens, signed delivery and quotas |
| EXT-02 | P2 | MCP server adapter exposing read/status/actions | least privilege; not runtime dependency |

## Common acceptance rule for every feature
- Positive + negative cases, role matrix, audit, retry/timeout/cancellation, accessible UI states, redaction, migrations, observability, contract checks.
- Feature not installed/configured => honest `not_configured`/`unsupported`, not false success.
- Every feature has an owning module in the architecture documents and test IDs in [18_TESTING_ACCEPTANCE.md](18_TESTING_ACCEPTANCE.md).

## Product modes
- `monitor`: ingest + diagnose/report only, no sandbox mutation or publish.
- `approval`: reproduce/patch/verify, publisher blocked pending authorized approval.
- `auto_repair`: scoped patch and draft PR only after verification+policy. Never merge.
- Maintenance pause overrides every repo mode; operator may cancel after explicit confirmation.


## Coverage expansion (v4)
The following feature families have detailed contracts in annex documents: frontend Astryx (`29`), authorization (`30`), policy automation (`31`), notification matrix (`32`), release evidence (`33`), screen interactions (`34`), vendor capability probes (`35`). A feature ID is not satisfied by scaffolding or mocked fixtures alone.

**Scope control:** P0 features are v1.0.0 release gates, including channel adapters NOT-04. P1 extensions are designed and tracked but never represented as supported before independent E2E evidence. Any reprioritization requires owner approval and ADR.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
