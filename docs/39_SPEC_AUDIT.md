# P2 specification audit — before/after gap analysis

**Date:** 2026-10-27 (Asia/Saigon). **Scope:** research public documentation and edit specification Markdown; no product code, detailed implementation master plan, dependency installation, sandbox execution, paid API calls, account configuration or notifications. **Conclusion:** the design has been expanded and aligned for owner review; this does not establish a working or production-ready product.

## Actual repository state and levels of evidence
Workspace: the `red2pr` project directory on Windows (the personal path was removed when preparing public publication). At the time of the P2 audit, Git metadata did not exist; `git status --short` reported “not a git repository”. P2 findings used the initial content/hash snapshot rather than a Git diff. The owner separately requested Git initialization and publication after P2; see [progress](23_PROGRESS.md).
Before P2: 38 official documents (AGENTS, README, docs00…35) + 34 skill/metadata files = 72 files. There was no product source, test suite, manifest, lockfile, migration, CI configuration or Dockerfile. The skill shell utility is not product code and was not executed. P2 added four Markdown documents, docs36…39; AGENTS and the skills were preserved.
Environment: PowerShell7.6.5; Git, a Python3.12 executable path, Node/npm and WSL were found; Docker was not on PATH. Discovering an executable does not certify a working daemon, WSL distribution, virtualization or runtime. No repository code, installer or worker was executed. Detailed version/hardware checks and runtime readiness require later authorized verification.

| Level | Supported conclusion | Must not be inferred |
|---|---|---|
| DESIGNED | Feature/flow/contract/security/test/release requirements are documented; some remain PROPOSED | The owner has approved the entire design |
| IMPLEMENTED | **0 product modules** | API/tool/schema tables are executable code |
| TESTED | **0 product test suites** | Markdown validation is product testing |
| OPERATIONALLY_VALIDATED | **0 deployments / 0 integration validations / 0 release gates pass** | Public vendor documentation or Astryx source proves runtime behavior |
| DOC/SOURCE_VERIFIED | Official pages and an Astryx source snapshot were read; document link/ID checks were performed separately | Meta account quotas, provider grants or component rendering have been verified |

## Complete baseline reading record
All 38 files below were read in full during intake/P2, not merely listed. The requirements column summarizes the central decisions reviewed; Cxx references the gap register below. Long documents were read in batches. Skill instructions were read separately and are not counted as product specifications.

| File | Role | Main requirements reviewed | Conflict/gap |
|---|---|---|---|
| [AGENTS.md](../AGENTS.md) | Operating contract | docs-only, proof, least privilege, exact owner-approved scope, no overwrite | Preserved during P2; no self-authorized implementation |
| [README.md](../README.md) | Product entry point | production-first full product, chosen stack, approval before code | C01,C16 |
| [00_INDEX.md](00_INDEX.md) | Index/status | ADR precedence, complete product scope | C01 |
| [01_PRODUCT_VISION.md](01_PRODUCT_VISION.md) | Vision/personas | Self-hosted repair with proof; no auto-merge | C04 |
| [02_FEATURE_CATALOG.md](02_FEATURE_CATALOG.md) | 46 feature IDs/priority | 41P0/4P1/1P2, product-wide acceptance | C06,C07 |
| [03_PERSONAS_JOURNEYS.md](03_PERSONAS_JOURNEYS.md) | User journeys | Local/team/repair/refusal/Telegram/recovery | C02,C04,C06 |
| [04_UI_UX_SPEC.md](04_UI_UX_SPEC.md) | IA/screens/states | 21routes, access, dark/light, responsive | C13 |
| [05_SYSTEM_ARCHITECTURE.md](05_SYSTEM_ARCHITECTURE.md) | Modules/trust/topology | Python/FastAPI, boundaries, DB/outbox/worker | C01,C07 |
| [06_DATA_MODEL.md](06_DATA_MODEL.md) | Entity relationships | Tenant constraints/indexes, immutable evidence, retention | C10 |
| [07_API_CONTRACTS.md](07_API_CONTRACTS.md) | Public/internal API | Auth/errors/paging/idempotency/typed worker tools | C02,C05,C10 |
| [08_EVENTS_STATE_MACHINES.md](08_EVENTS_STATE_MACHINES.md) | Domain transitions/events | Durable inbox/outbox, lease, publish reconciliation | C04,C05,C08 |
| [09_AI_AGENT_META.md](09_AI_AGENT_META.md) | AI/model/tools | Bounded diagnosis/patch, no model self-certification | C05,C14 |
| [10_SANDBOX_REPRODUCTION.md](10_SANDBOX_REPRODUCTION.md) | Isolation/fidelity | A/B controlled tests, runtime quotas, no secrets | C07,C10 |
| [11_REPAIR_VERIFICATION.md](11_REPAIR_VERIFICATION.md) | Proof/publishing | V-01…08, safe diff, approval, remote CI | C04,C10 |
| [12_PROVIDER_INTEGRATIONS.md](12_PROVIDER_INTEGRATIONS.md) | GitHub/GitLab | Scopes, version, attempts, retry/revocation, PR/MR | C12,C14 |
| [13_NOTIFICATIONS_TELEGRAM.md](13_NOTIFICATIONS_TELEGRAM.md) | Channels/commands | Opt-in external sends, link, web-confirmed dangerous action | C05,C08 |
| [14_SECURITY_IDENTITY.md](14_SECURITY_IDENTITY.md) | Threat/auth/secrets | Least privilege, consent, SSRF, session security | C06,C12 |
| [15_INSTALL_DEPLOY_ONBOARDING.md](15_INSTALL_DEPLOY_ONBOARDING.md) | Installer/wizard | 3OS entrypoints, prereq, TLS, recovery readiness | C15 |
| [16_OPERATIONS_CLI.md](16_OPERATIONS_CLI.md) | Operations/CLI | doctor/update/backup/restore/uninstall safe recovery | C15 |
| [17_OBSERVABILITY_ANALYTICS.md](17_OBSERVABILITY_ANALYTICS.md) | Metrics/SLO | Truthful funnels, budgets, logs/traces/alerts | C15 |
| [18_TESTING_ACCEPTANCE.md](18_TESTING_ACCEPTANCE.md) | Acceptance suites | Positive/negative/e2e + security/UX evidence | C16 |
| [19_DELIVERY_PLAN.md](19_DELIVERY_PLAN.md) | Existing outline D0…D10 | Full scope, continuous testing, owner approval | C11 |
| [20_DECISIONS_ADR.md](20_DECISIONS_ADR.md) | Decision authority | 16accepted original retained; proposals/open separated | C01,C04,C09 |
| [21_OPEN_QUESTIONS.md](21_OPEN_QUESTIONS.md) | Uncertainty/risk | Owner vs verifiable issues, no invented facts | C14,C15 |
| [22_OFFICIAL_REFERENCES.md](22_OFFICIAL_REFERENCES.md) | Vendor sources | Official URLs/read date/version/account caveats | C14 |
| [23_PROGRESS.md](23_PROGRESS.md) | Truthful status | Designed vs implemented/tested/operationally_validated | C16 |
| [24_RELEASE_READINESS.md](24_RELEASE_READINESS.md) | Production policy | All gates, no false-green, security thresholds | C09 |
| [25_CONFIG_SCHEMA.md](25_CONFIG_SCHEMA.md) | Config/policy keys | Precedence, immutable invariant, secrets by reference | C04,C05 |
| [26_SECURITY_TEST_MATRIX.md](26_SECURITY_TEST_MATRIX.md) | Adversarial cases | SEC-001…025 existing and trust boundary attacks | C10,C12,C16 |
| [27_SUPPORT_MATRIX.md](27_SUPPORT_MATRIX.md) | Support envelope | 3OS/cloud selfhost providers/certified runtime claims | C07,C14,C15 |
| [28_BENCHMARK_DEMO.md](28_BENCHMARK_DEMO.md) | Repair evaluation | 20+cases, denominators, abstention not fake demo | C04,C16 |
| [29_FRONTEND_ASTRYX.md](29_FRONTEND_ASTRYX.md) | Frontend/library contract | React19/TS/Vite/Astryx, Python unchanged, AGENTS safe | C01,C13,C14 |
| [30_ACCESS_CONTROL_MATRIX.md](30_ACCESS_CONTROL_MATRIX.md) | Role/action matrix | Repo scope/service authority/step-up/revocation | C02,C06 |
| [31_POLICY_AND_AUTOMATION.md](31_POLICY_AND_AUTOMATION.md) | Policy/approvals | Modes, deny precedence, bounded automation | C03,C04,C05 |
| [32_NOTIFICATION_EVENT_MATRIX.md](32_NOTIFICATION_EVENT_MATRIX.md) | Event/delivery contract | All channels, retry/redaction/link/replay | C05,C08 |
| [33_RELEASE_EVIDENCE_LEDGER.md](33_RELEASE_EVIDENCE_LEDGER.md) | Gate/provenance record | R-01…15 all NOT RUN, evidence/sign-off | C09,C16 |
| [34_SCREEN_AND_INTERACTION_CONTRACTS.md](34_SCREEN_AND_INTERACTION_CONTRACTS.md) | Interactions/UI details | Screen actions/form states/a11y tests | C10,C13 |
| [35_INTEGRATION_DEPENDENCIES.md](35_INTEGRATION_DEPENDENCIES.md) | Capability probe contract | Account/version/permission limits, authorized tests | C14 |

## Before/after gap analysis
“Corrected” here refers to the **specification**, not a remediated software vulnerability. Where the owner has not settled a decision, its status is a proposed resolution, not ACCEPTED.

| Gap | Before: file/section evidence | After: change and impact | Status / remaining work |
|---|---|---|---|
| C01 | doc05 Accepted language boundary included a DB recommendation; doc29 used React>=19 | Preserve React major19/TS/Vite/Astryx + Python/FastAPI; classify PostgreSQL/outbox topology as PROPOSED ADR-013/035 without changing accepted rows | Classification corrected; infrastructure awaits owner approval |
| C02 | doc07 allowed Owner/Admin workspace creation versus owner-only in doc30; journeyB assigned it to an admin | A-04 and the journey require the instance owner; workspace admins manage existing scope; owners do not automatically read every repository | Contract corrected; R-06 not run |
| C03 | doc02 prohibited monitor execution while doc31 allowed a sandbox exception | ADR-033 proposes ingest/diagnose-only monitor mode, audited web mode changes and a separate pause override | PROPOSED, not silently accepted |
| C04 | doc08 (REPRO_*)→PATCHING; doc11 provisional drafts; doc25 had two keys | Owner accepted ADR-031: only a confirmed baseline permits patching; unconfirmed terminates with diagnosis; remove provisional options and reject legacy keys | ACCEPTED direction, negative proof pending |
| C05 | docs07/09 tool aliases,08/32 event aliases,09 waiting model,25 budget aliases | Canonical S-20 toolset, S-19 event registry, suspension reasons and namespace keys; schema/code generation deferred | ADR-033 PROPOSED; no existing data migration |
| C06 | IAM-03 invitationsP1 versus team journeyP0; optional MFA in doc14 versus step-up in doc30 | ADR-034 proposes local invitations under IAM-02P0, federationP1, mandatory TOTP/step-up for privileged roles and recovery/last-admin contracts | Owner review required; no priority removed |
| C07 | SAN-04 P1 “multi-tenant” vs mandatory isolated hostile workers | ADR-030 accepted tenancy; SAN-01P0 baseline isolation, SAN-04 advanced fleet extension; guest keys/control separated | implementation backend PROPOSED; independent R-05 |
| C08 | doc32 “publish only once” vs at-least-once external channels | logical DB uniqueness, sending/accepted/unknown/bounced states; replay and perchannel receipt limits | spec corrected; R-08 needs live consented validation |
| C09 | doc24 Critical/High waiver clause | ADR-032 Critical closed, High expiry/mitigation/owner; invariant non-waivable; SEC-039 | ACCEPTED;30day default PROPOSED |
| C10 | docs06/07 broad tables, no complete fields/FKs/SSE/worker/evidence signing contract | doc36 A-01…24/S-01…22; composite tenant FKs/indexes; supervisor signing/tamper-evident checkpoint and explicit trust limitations | design filled; schemas/code/crypto/runtime not tested |
| C11 | doc19 D7 UI could imply UI/auth deferred | clarify cross-cutting UI/auth/tests in every affected slice, retain original D0…D10 | no detailed master plan created |
| C12 | private GitLab support vs blanket private-IP SSRF denial | ADR-037 exact owner-registered adapter/host/CIDR/CA exception with pinned DNS/egress; never arbitrary URL exemption | PROPOSED;SEC-033 required |
| C13 | UI17 detailed rows vs21routes; mobile readonly vs responsive admin; speculative Astryxprops | all21 screen actions/API/data mapping, full states/a11y; source-verified component props at pinned commit, export/runtime gaps stated | design filled; actualUI/build/browser NOT RUN |
| C14 | vendor general links without version/account distinction | official ledger2026-10-27 with observed models/API version/GL signing and source snapshot; exact-account limitations | DOC/SOURCE_VERIFIED only; real probes pending authorization |
| C15 | SLO/hardware/restore fields vague, one-command could overpromise | doc37 sixteen numeric TARGETS+measurement/recovery; candidate3OS/distributed profiles; prereq/admin/reboot and key+object backup consistency | PROPOSED; no measured SLA/support claim |
| C16 | tests and gates not linked per feature; “complete design” wording too strong | doc38 all46features positive/negative + reverse15gates;40SEC cases; status/progress explicit design awaiting review | doc structural checks only; all product gates NOT RUN |

## Product and architecture review
Red2PR serves maintainers, reviewers, platform/SRE and security teams managing multiple repositories/workspaces. Its value is reducing CI diagnosis/repair cycles with auditable evidence, rather than acting as an error-answering chatbot. Flow: authenticated CI→normalized attempts/matrix→diagnosis/abstention→isolated baseline→bounded Meta patch→independent verifier→policy/approval→draft PR/MR→provider-confirmed CI at the exact SHA. Stop without a reproduced baseline; never merge/deploy. The architecture and trust map are in [05](05_SYSTEM_ARCHITECTURE.md).
React19/TypeScript/Vite/Astryx presents data through typed API/SSE; Python/FastAPI owns orchestration, authorization, budgets, verification and publication. Meta inference is normally outbound and requires consent; the sandbox has no provider write tokens or Meta key. PostgreSQL/outbox/storage/transport remain technical ADR proposals awaiting approval. In-app, Telegram, SMTP, Slack, Discord and signed webhooks are all P0; leaving a channel unconfigured neither disables the engine nor permits a false delivery claim.
Windows/Linux/macOS installers use preflight, a wizard and checkpoints; server webhooks and local polling both reconcile. Distributed deployments separate workers without implicitly promising control-plane HA. Administration is responsive and keyboard accessible, with truthful proof/remote states. Release requires evidence for every P0 feature and all 15 gates against the published matrix.

## New supporting documents and review outcome
| File | Reason for a separate document | Contents reread/reconciled |
|---|---|---|
| [36 Canonical contracts](36_CANONICAL_CONTRACTS.md) | Prevent duplicated schemas and naming drift across06/07/08/09 |24API families,22schema families, typed tools,worker,evidence/SSE |
| [37 NFR/recovery](37_NFR_AND_RECOVERY.md) | Targets need a shared workload, measurement and recovery contract |16NFR targets, DB/queue/worker/model/provider/storage recovery |
| [38 Traceability](38_REQUIREMENTS_TRACEABILITY.md) | Product-wide requirements need forward and reverse traceability |46feature pairs of acceptance cases,15reverse gates |
| [39 Audit](39_SPEC_AUDIT.md) | Preserve reading evidence and before/after gaps |38baseline files,16gaps, accepted/proposed/open separation |

## Open decisions and P2 research order
1. Settle ADR-034 identity/isolation: privileged MFA, local invitations, independent review/break-glass and operational trust domains.
2. Review ADR-035/012/013 control/queue/storage/evidence-signing architecture; choose key custody and recovery ownership.
3. Review ADR-033 canonical contracts and ADR-037 private-endpoint/consent exceptions; do not hide identified conflicts behind implementation.
4. Review ADR-036 capacity/retention/RPO-RTO/High-waiver targets, then measure them in an authorized environment before making support claims.
5. Resolve ADR-021 license/domain/publisher/market privacy and ADR-024 relay ownership; the owner must provide business context.
Vendor account/model quotas, exact OS/runtime versions, scopes and CLI effects are **verifiable facts**, not matters for the owner to guess. License intent, customer regions and accepted operating risk **require project-owner decisions**. P1 extensions retain their design/capability boundaries; freeze detailed federation/relay/MCP protocols before enabling support, rather than inferring them from the core API.

## Documentation validation
The final P2 check exited0: 272 internal links, 55 tables and 46features/92acceptance cases, with no structural or ID errors in the checked groups. The original 16ACCEPTED rows and AGENTS/skills were preserved during P2. Hash/scope results and actual commands are recorded in [23](23_PROGRESS.md). These checks validate documents, not implemented contracts. No commit/push occurred during P2 because Git metadata did not yet exist and the user had not requested publication. P2 ended by waiting for owner specification approval.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
