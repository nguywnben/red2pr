# Frontend UX flow blueprint — clean rebuild

**Status:** Implementation baseline for the owner-approved UI rebuild, 2026-11-02.  
**Scope:** `apps/web` presentation and interaction architecture only. Backend, OpenAPI, generated clients, authentication contracts, persistence and release infrastructure remain authoritative and unchanged.

## Authority and constraints

This blueprint maps the approved screen contracts in [04](04_UI_UX_SPEC.md) and [34](34_SCREEN_AND_INTERACTION_CONTRACTS.md) to the current API catalogue and typed client. Accepted [ADR-025](20_DECISIONS_ADR.md) and [ADR-040](20_DECISIONS_ADR.md) require React 19, strict TypeScript, Vite, Astryx Core 0.7.4 and Neutral Theme 0.7.4. `docs/23_PROGRESS.md` records IG-06 locally verified before the rebuild. This work stops before U31.

The server remains the authorization and state authority. UI role checks only control affordances; every view and mutation is reauthorized by the API. Preserve workspace identity in routes and query keys, typed API methods, idempotency keys, `If-Match` revisions, step-up, audit context, CSRF, SSE replay/reconciliation, and all current failure semantics. Do not invent endpoints or mutate OpenAPI/client contracts in this phase.

## Product navigation and shell

- **Unauthenticated:** dedicated sign-in, callback and recovery flows; no operational navigation or theme control. First-owner claim is only in permitted first-run setup.
- **Workspace shell:** app-level task groups rather than API modules. `Work` contains Overview, Repositories, Pipelines, Repairs and Pull requests; `Review` contains Approvals; `Operations` contains Agents, Models, Workers, Queue, Integrations, Notifications and Analytics; `Access` contains Members and Security. Account preferences remain a personal menu; instance operations remain owner-only under `/system`.
- **Detail surfaces:** repository and repair detail routes retain workspace context and return paths. Entity links never expose another workspace's labels or IDs. Advanced or destructive actions appear contextually with explicit scope and confirmation.
- **Frame-first responsive behavior:** Astryx `AppShell` owns landmarks, skip link and mobile navigation. Desktop uses grouped, collapsible navigation and one content column; small viewports retain the same permitted actions through a menu/drawer and stacked review forms. Wide diffs/logs keep a bounded horizontal/text alternative.
- **Visual direction:** Neutral, restrained developer SaaS. Clear title/action hierarchy, deliberate density, plain language, semantic status text, and theme tokens. No dashboard mock data, decorative hero, card-per-row lists, or all-actions toolbar.

## Screen-to-journey contract map

| UI ID / route | User goal and entry | Primary action / progressive disclosure | API contract families and required behavior | Acceptance anchors |
|---|---|---|---|---|
| UI-S01 `/setup/*` | Instance owner completes first-run readiness from the setup entry | Resume the persisted step; expose optional provider/model consent only when that step is reached; finish as `ready_monitor` or `ready_repair` only from server state | A-01, A-06, A-13, A-18, A-20; setup state, owner claim, consents, endpoint registrations, step submission; resume, expiry, optional skip and unsafe-mode denial | UX-SETUP-001, INS-02, UI-01 |
| UI-S02 `/login` and recovery route | Member signs in or recovers access | Password sign-in is the sole initial form; MFA/step-up appears only when challenged; recovery has its own route; no owner-claim tab | A-02/A-03; CSRF, local login, OIDC callback, recovery and generic credential errors | UX-LOGIN-001, IAM-01, IAM-03, SEC-038 |
| UI-S03 `/w/:ws/overview` | Member checks current scoped CI health | Open the most urgent unresolved failure; show truthful counts, period, denominators and stale time | A-09/A-17/A-21 analytics, repairs and activity; preserve workspace/timezone scope | ANL-01, UX-02 |
| UI-S04 `/w/:ws/repositories` | Maintainer finds and safely onboards repositories | Search/filter then add or sync one repository; bulk policy is a separate preview→confirm path | A-06/A-07 repository discovery, provider cursors, bulk preview/update; authorized IDs only | UX-REPO-001, REP-01, SEC-032 |
| UI-S05 `/w/:ws/repositories/:repo` | Maintainer inspects a repository and its effective policy | Show status and next action first; policy editing/dry-run and advanced branch/file rules are secondary; removals require step-up | A-07/A-08/A-09 repository, CI and policy reads/writes; revision conflict, effective precedence and audit | UX-POLICY-001, REP-02/03, FIX-03 |
| UI-S06 `/w/:ws/pipelines` | Engineer locates the failing provider run/job | Filter and select an attempt; inspect commit SHA and bounded sanitized logs; fetch artifacts only on demand | A-08/A-10 runs/jobs/log ranges/artifacts; missing, expired and truncated states | TRI-01, SEC-032 |
| UI-S07 `/w/:ws/repairs` | Engineer tracks diagnosis and proof state | Start a repair only from an eligible failed run with explicit mode/reason; distinguish local proof from remote CI | A-09/A-21 repair sessions and analytics; no aggregate “fixed” shortcut | APP-01, FIX-04 |
| UI-S08 `/w/:ws/repairs/:id` | Reviewer follows one repair from cause to remote outcome | Timeline is primary; Cause, Reproduction, Diff, Verification, PR, Logs and Audit are focused sections; actions remain phase- and permission-gated | A-09/A-10/A-12/A-21; evidence, patch, logs, action, SSE replay and REST reconciliation | UX-REPAIR-001, FIX-01/02/04, APP-01 |
| UI-S09 `/w/:ws/prs` | Reviewer verifies draft publication and remote CI | Open provider draft; inspect exact SHA and each required remote check; unknown outcome stays unknown | A-12 publication records and remote-check reconciliation | FIX-03, SEC-011/015/016 |
| UI-S10 `/w/:ws/approvals` | Authorized reviewer decides a high-impact action | Review actor, target, risk, base/patch/policy SHA and expiry; step-up then approve/reject once | A-11 approval detail/decision; stale revision, changed diff, replay and double-submit fail closed | UX-APPROVAL-001, APP-02, NOT-03 |
| UI-S11 `/w/:ws/agents` | Owner/maintainer configures bounded agent behavior | Inspect active profile and deny reasons; edit capabilities and bounded steps as a reviewed change | A-10/A-20 profile and agent-step contracts; no arbitrary prompt-power control | AGT-02, SEC-028 |
| UI-S12 `/w/:ws/models` | Owner configures and probes model capability/budget | Probe only after explicit max-cost confirmation; key material never leaves masked status | A-20 model settings, consent, capability probes and budgets | AGT-01/03, SEC-033 |
| UI-S13 `/w/:ws/workers` | Operator checks worker readiness and fleet trust | Show readiness before enrollment; self-test, drain or quarantine only with scope and confirmation | A-13 worker readiness, registry, enrollment, test and action contracts | SAN-01/04, JOB-02 |
| UI-S14 `/w/:ws/queues` | Operator investigates a queued, leased or dead-letter job | Inspect lease, correlation and budget; preview authorized cancel/replay, then confirm | A-14/A-09 job action and receipt/cancellation contracts; fencing and deduplication remain server-owned | JOB-01/02, SEC-021 |
| UI-S15 `/w/:ws/integrations` | Maintainer connects, probes or reconciles a source provider | Show provider connection and grant state first; reveal setup/edit/revoke and relay configuration contextually | A-06/A-23 connections, callback, probe, sync and customer-operated relay; no hosted relay claim | SRC-01/02, SEC-014/017 |
| UI-S16 `/w/:ws/notifications` | Member reviews alerts and manages destinations | Inbox first; preferences and destinations are separate; test-send requires preview/consent and clearly shows unknown receipts | A-15/A-16/A-24 inbox, preferences, destination/credential/delivery contracts | NOT-01..04, UX-NOTIFY-001 |
| UI-S17 `/w/:ws/analytics` | Owner evaluates repair quality and usage | Bounded time-range funnel with denominators and stale watermark; export is an explicit scoped action | A-17 analytics and expiring CSV/JSON export | ANL-01/02, SEC-032/040 |
| UI-S18 `/w/:ws/security` | Security reviewer audits access, keys and retention | Audit and masked metadata are read surfaces; rotate/revoke/export are contextual, scoped and confirmed | A-06/A-17/A-18/A-19 audit, token, consent, release-exception, secret metadata/rotation APIs | UX-SECURITY-001, OPS-03, EXT-01 |
| UI-S19 `/w/:ws/members` | Workspace admin manages members, invitations and grants | Invite and scoped role/repository grant; destructive changes show affected scope and last-admin guard | A-04/A-05/A-21 memberships, invitations, repo grants, break-glass and OIDC mapping | IAM-02/03, UX-ACCESS-001, SEC-010/022/032/038 |
| UI-S20 `/system` | Instance owner performs safe operations | Status/doctor first; backup, restore, maintenance and support export require preview/digest then confirmation | A-18/A-24 status, capability, backup, restore dry-run, maintenance and export contracts | UX-OPS-001, OPS-02, INS-03, SEC-019/035 |
| UI-S21 `/account` | User manages personal session, MFA, preferences and Telegram link | Personal settings only; session revoke/MFA changes and link/unlink show clear consequences | A-03/A-16 personal sessions, MFA, preferences and Telegram challenge/link | IAM-01, NOT-02, SEC-038 |

## State, security and accessibility invariants

Every screen models only applicable loading, empty/not-configured, ready, stale, degraded/offline, error, unauthorized/forbidden, validation and reconciliation states. Never invent values or expose raw exceptions, hidden tenant details, secrets, full tokens, or internal security implementation copy. Errors use safe remediation and correlation ID. Retry is offered only for idempotent/reconcilable operations.

Use typed generated-client methods; keep secrets out of browser storage and logs; retain CSRF/Origin checks and step-up; mutations use documented idempotency/revision headers; failed/conflicting writes roll back; approvals, publishing, restore and tests are never optimistic. SSE disconnection resumes from an authoritative REST snapshot and cursor. Plain text only for logs/diffs, bounded by range and sanitized before display.

All controls have accessible names, visible keyboard focus, logical order, field-associated errors and appropriate live announcements. Dialogs use Astryx Dialog focus/dismissal semantics. Light/dark/system modes preserve contrast; reduced motion, 320/768/1280/1440 widths and 200% zoom are part of the test matrix. No status relies on color alone.

## Implementation and verification slices

1. Preserve source snapshot and this route/API/test inventory; verify Astryx 0.7.4 exports and component contracts.
2. Replace bootstrap, auth entry and app frame; establish typography, density, navigation and responsive behavior with real API state.
3. Rebuild the core journey (repositories → pipeline failure → repair proof → approval → draft/remote checks) against current typed APIs.
4. Rebuild configuration and operations surfaces with contextual permissioned actions.
5. Rebuild account, notification, security and instance operations surfaces; remove old presentation source and tests only after corresponding replacements pass.
6. Run strict typecheck, lint, production build, all frontend integration/regression tests and actual headless browser journeys/screenshots. Record source SHA, commands, exit codes, screenshot paths and limitations in progress/evidence. Do not start U31.

