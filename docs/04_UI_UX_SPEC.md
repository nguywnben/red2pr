# UI/UX specification: information architecture and screens

## Frontend implementation decision
**React 19 + TypeScript + Vite + Astryx Design System** is the target frontend. Continue Python/FastAPI in backend and execution plane. Design tokens and selected Astryx component APIs are validated using official Astryx docs/CLI; see [29_FRONTEND_ASTRYX.md](29_FRONTEND_ASTRYX.md). Red2PR wrappers shield beta API churn; do not overbuild another design system.

## Design rules
Responsive desktop-first layout, dark/light mode, English first with i18n support; accessible semantics, focus rings and a WCAG AA target. Display local time zones and identify UTC in exports. Never communicate status through color alone. Use shared design tokens and a component library, with standardized toasts, confirmation dialogs and audit context.

## Sitemap / route proposal
| Path | Page | Required components, states, interactions |
|---|---|---|
| `/setup/*` | Bootstrap Wizard | progress, secure admin, environment, model, provider, repo selection, worker test, finish |
| `/login` | Sign-in | local credentials, MFA recovery, rate limiting, lockout state |
| `/w/:ws/overview` | Overview | health tiles, failure funnel, current activity, costs, provider status |
| `/w/:ws/repositories` | Repo catalog | filter provider, search, sync, policy mode, unread failures |
| `/w/:ws/repositories/:id` | Repo detail | tabs Overview, Runs, Repairs, Policies, Branches, Access, History |
| `/w/:ws/pipelines` | CI runs | provider/job matrices, attempts, commit SHA, failure classification |
| `/w/:ws/repairs` | Sessions | status, class, repair proof grade, owner, timing, cost, filters |
| `/w/:ws/repairs/:id` | Repair detail | timeline, tabs Cause, Repro, Diff, Verification, PR, Logs, Audit |
| `/w/:ws/prs` | PR/MR | provider links, local proof status, remote CI, review state |
| `/w/:ws/approvals` | Inbox | actions requiring approval, expiry, risk/scope diff, approve/reject |
| `/w/:ws/agents` | AI & agent | model slots, capabilities, budgets, attempt rules, connectivity |
| `/w/:ws/models` | Model catalog | model availability probes, provider auth status, token budgets, capability flags |
| `/w/:ws/workers` | Worker inventory | version, isolation, queue, leases, resources, revoke/drain |
| `/w/:ws/queues` | Task queue | state, retries, priority, cancel/pause permissions, DLQ |
| `/w/:ws/integrations` | Integrations | GitHub/GitLab/Telegram/email/Slack/Discord/webhooks statuses |
| `/w/:ws/notifications` | Notification inbox | preferences, templates, destinations, test-send, history |
| `/w/:ws/analytics` | Analytics | quality funnel, costs, time-to-fix, flaky and provider drilldowns |
| `/w/:ws/security` | Security | secrets metadata, key rotation, policy, audit exports |
| `/w/:ws/members` | Workspace IAM | invite/roles/repo grants, access reviews |
| `/system` | Instance admin | updates, backups, storage, health, proxy, certificates, retention |
| `/account` | Personal settings | sessions, MFA, Telegram link, timezone, notification preferences |

## Repair Session page behavior
Header: provider/repo/branch/SHA/run attempt, eligibility, current repair state, actions role-gated. Main timeline immutable events; side panel steps/fidelity/budget. Evidence viewer: baseline vs patched tabs, command + sandbox image digest, log source ranges, diff redactions, detached artifact checksum. PR creation shown as a separate gate; remote CI never conflated with local verification. Failure reasons can be expanded with next steps and correlation IDs.

## Repo policy editor
- Mode selector `monitor`/`approval`/`auto_repair`; branch allowlist and denylist; file protected patterns; allow test/config edits toggle gated; permitted language profiles; time/token/compute budgets.
- Preview effective policy (global > workspace > repo, deny wins); 'simulate' using historical event, show why blocked. Save requires diff preview + audit.

## Setup Wizard stages
1) Preflight and deployment type (local/server/distributed); 2) create admin using one-time bootstrap secret; 3) Meta API key + test connection + egress consent; 4) GitHub/GitLab connect; 5) optional Telegram/notification; 6) select repos and enable policies; 7) worker isolation readiness; 8) final health summary. Provider/connect steps may be skipped with `not_configured`, never incorrectly mark all systems ready.

## Unified UI states
Loading (skeleton), Empty (clear CTA), Success, Partial evidence, Degraded, Offline, Permission denied, Rate limited, Human approval required, Unsupported runtime, Reconciliation in progress, Interrupted. Error UI always shows safe remediation and request ID; never raw exception stack or secrets.

## Localization, mobile, performance
- Responsive administration with full review summaries on phones; critical approvals require equivalent RBAC/step-up confirmation (P2 proposal, doc34).
- Pagination/cursor for logs, repos and sessions; virtualized log viewer; lazy artifact fetch by authorization and expiry.
- Accessibility: keyboard traversable tab panes, live region for status, text labels for charts; no auto-scroll hijack.

## Design acceptance examples
- `UX-01`: Owner performs first-run setup with no manually edited `.env`.
- `UX-02`: Repo A viewer cannot infer Repo B via autocomplete, report, direct URL, downloadable evidence.
- `UX-03`: Failed remote CI displayed as failed even if local proof green.
- `UX-04`: Retry after network loss does not submit repeated approval or create duplicate PR.

## P2 complete route contract
[34](34_SCREEN_AND_INTERACTION_CONTRACTS.md) enumerates UI-S01…21 with action, API, persistence and state/a11y acceptance. Responsive administration is proposed for all supported widths with equivalent security review; any earlier read-only-mobile shortcut is superseded in this draft. [29](29_FRONTEND_ASTRYX.md) separates source-verified Astryx props from untested integration assumptions.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
