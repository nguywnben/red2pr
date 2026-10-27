# Full-scope engineering delivery plan (not an MVP specification)

## Principle
**Freeze the overall feature scope; deliver vertical slices with continuous testing.** A slice is complete only with migrations, API, authorization, basic UI, telemetry, security and negative tests. Release to production only when all `P0` features in the certified support matrix pass their gates. A hackathon checkpoint may demonstrate an end-to-end path, but must not claim that the entire scope is complete while work remains.

## Sequence by dependency
| Milestone | Deliverable and dependencies | Exit criteria |
|---|---|---|
| D0: spec & threat review | Review ADRs, open questions, support matrix and release plan | Repository owner approves; no unresolved platform-level blockers |
| D1: foundations | repo scaffold, lint/type CI, DB migrations, auth, config, events/outbox, health/telemetry | tests unit/contract + install developer environment |
| D2: source providers | GitHub App + GitLab connection, repo sync, hook/polling, log collector | event fixtures, E2E provider test repos, signature/replay |
| D3: triage/inference | Meta model probe, diagnostics, typed tools, evidence store, budgets | diagnosis/abstention benchmark and secret filters |
| D4: sandbox/repro | remote isolated worker protocol, Python/Node profiles, reproducer | hostile fixtures deny credentials, F1/F2 proof captured |
| D5: patch/verification | bounded patch agent, strict diff policy, red-green engine | targeted+regression suite, false-green negative tests |
| D6: publishing/reconciliation | write identity separate, draft PR/MR, remote CI tracking | timeout/retry/no duplicate PR, branch protection respected |
| D7: Astryx dashboard, IAM | React 19/Vite/TypeScript UI, Astryx wrappers/theme, repo/repair/approval/settings screens, roles | contract tests, dark/light, WCAG AA target, cross-repo RBAC and UX state tests |
| D8: notifications | Telegram long poll/webhook, in-app, email/SMTP, Slack, Discord, signed outgoing webhooks | authenticated commands, signature/secret controls, per-channel delivery contract, redaction, retries |
| D9: self-host platform | one-command OS installers, wizard, CLI, backups, updates, restore | smoke on certified OS, interruption/recovery drills |
| D10: operations hardening | metrics, audit, performance, threat tests, docs, version release | security review, full P0 matrix green, release sign-off |

## Module ownership boundaries
One module = coherent responsibility and explicit contracts; avoid deploying 20 microservices simply because there are 20 feature groups. Control plane modular monolith + isolated worker process, publisher credential boundary, and optional adapters. Each milestone must update feature coverage matrix and progress. Early stubs return explicit `not_implemented`, never fake success or test artifacts.

## Dependencies critical path
D0 → D1 → D2/D3 → D4 → D5 → D6. Dashboard can begin on stable API schemas; onboarding/installer can start on container manifests while CI repair verified. Notifications depend on authoritative event schema, not direct business callbacks. Real provider connectivity and paid API usage need separate owner authorization.

## Project planning per deliverable
For each feature track: requirement IDs, owning module, human API/UI, DB schema/migrations, event contract, security policy, positive/negative cases, risk, integration tests, documentation, operator troubleshooting, rollback. `DONE` only if evidence links recorded in [23_PROGRESS.md](23_PROGRESS.md).

## Hackathon delivery strategy
Prioritize an honest end-to-end GitHub+Python demo with red→green proof and live/deterministic recording, while keep complete product specification. Never pretend production grade for unimplemented GitLab/Windows/distributed components. Project status in submission distinguishes implemented and designed parts.

## Preventing agents from coding entire system before testing
At each milestone: implement+test+review, then proceed. Unverified P0 failures block subsequent integration if they impact trust boundaries. Nightly provider E2E on test repos; staged release candidate on clean deployments; no giant end-only test cliff.

## P2 scope note
This document's existing D0…D10 outline is retained as history and orientation, **not a newly approved detailed master plan**. D7 UI consolidation cannot mean postponing authentication, accessible states, API contracts or tests from earlier slices. Owner must approve a later integrated plan and exact execution unit; P2 only updates specification and traceability. No implementation tasks/schedule are added here.

## P3 master implementation plan linkage — 2026-10-27
The authoritative, unit-level execution schedule for `v1.0.0` is defined in [40_EXECUTION_MASTER_PLAN.md](40_EXECUTION_MASTER_PLAN.md) (`PLAN-2026-10-27-v1`), decomposing the `D0`–`D10` conceptual tracks into **36 immutable Execution Units (`U01`–`U36`)** across **7 waves (`W0`–`W6`)** and **6 integration checkpoints (`IG-01`–`IG-06`)**, with Astryx UI screens delivered alongside their vertical backend slices rather than deferred to the end. Approved by the owner under [ADR-039](20_DECISIONS_ADR.md) for unit-by-unit P4 execution; see [23_PROGRESS.md](23_PROGRESS.md) for live implementation truth.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
