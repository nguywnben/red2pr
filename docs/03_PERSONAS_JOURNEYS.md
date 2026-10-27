# Personas, journeys, use cases

## Roles
- **Instance owner**: system lifecycle, encryption, global security settings, bootstrap.
- **Workspace admin**: invitations, integrations, repo access, billing/usage policies.
- **Maintainer**: repo settings, repair policy, approve patches, cancel jobs.
- **Reviewer**: view, comment and approve gated actions allowed by policy.
- **Viewer/Auditor**: read authorized sessions/evidence/audit; no mutating actions.
- **Service identity**: provider integration, worker, publisher; each minimal independent scopes.

## Journey A — first installation on a laptop
1. Run the OS installer; if the environment is unsupported, explain prerequisite remediation rather than reporting false success.
2. Open the loopback web interface using a one-time bootstrap token; the owner creates the admin account.
3. Select local polling and enter the Meta key securely; the system tests it with a small, bounded request.
4. Connect the GitHub App, select the intended repositories and start in `monitor` mode.
5. Enable `approval`/`auto_repair` per repository after reviewing the risk notice and worker readiness.
6. View the repair timeline and optionally Telegram notifications; restarts/redelivery must not lose state.

## Journey B — server team
1. Installer Linux server; HTTPS domain + reverse proxy; instance owner creates workspace; MFA policy proposed ADR-034, SSO P1.
2. GitHub/GitLab hook secret signing configured, provider permissions checked.
3. Separate the worker host; configure policies, roles, resource quotas, retention and outbound model consent.
4. Invite the reviewers; each sees only the authorized repositories in their workspace.
5. CI events arrive, the bot sends notifications according to preferences, and PRs are created only after gates pass.

## Journey C — a repairable failure
1. CI run failed; provider event verified; idempotent session.
2. The evidence collector retrieves jobs, stack traces and relevant diffs without exposing raw secrets.
3. Diagnosis produces a hypothesis with source references; triage establishes eligibility.
4. The baseline test fails at the original SHA in the sandbox. If it cannot be reproduced, terminate as repro_unconfirmed with diagnosis/human handoff only; do not create a patch or PR/MR (ADR-031).
5. The agent prepares a patch in an independent clone, with attempts bounded by policy.
6. The verifier inspects the diff, runs targeted and regression tests, and reports fidelity.
7. The publisher creates a draft PR/MR against the correct base/ref without duplicates after an API timeout.
8. When remote CI completes, update the session; do not auto-merge. The reviewer decides.

## Journey D — an unrepairable failure
- Registry outages, missing credentials, disk exhaustion, unsupported ARM/macOS jobs, flaky races and unknown upstream issues lead to `diagnosed_only`, `needs_human` or `unsupported`. Do not fabricate a patch. Provide actionable remediation notes.

## Journey E — control through Telegram
- Telegram `/status` shows health, `/repos` lists authorized repositories, and `/repairs` shows active sessions.
- `/pause` or `/retry` only initiates a one-time web challenge, requiring session/role/CSRF validation and audit. A group command alone cannot approve an action.
- Rotating the bot token degrades the integration without interrupting the repair engine.

## Journey F — incident recovery
- If the API connection is lost during publication, reconcile by branch/PR markers instead of creating two PRs.
- On worker restart, lease expiry allows eligible jobs to be requeued after inspecting prior artifacts; side effects must not execute twice.
- On upgrade failure, use the backup/snapshot and a compatible rollback image; record restore drills.

## UX acceptance
Every destructive action requires confirmation and a summary. Provide keyboard navigation, understandable statuses, and empty/loading/degraded/permission-denied states. Notifications must not display secrets or raw private logs by default.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
