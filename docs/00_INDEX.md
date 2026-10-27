# Red2PR specification index

**Specification version:** SPEC-2026-10-27-v5 (P2 review) + PLAN-2026-10-27-v1 (P3 execution master plan awaiting owner approval) · **Status:** design and master plan baseline, not an implementation · **Language:** English.

## Recommended reading order
| File | Contents |
|---|---|
| [01_PRODUCT_VISION.md](01_PRODUCT_VISION.md) | Product positioning, users, principles, scope |
| [02_FEATURE_CATALOG.md](02_FEATURE_CATALOG.md) | Feature catalog, IDs, permissions, priorities and acceptance |
| [03_PERSONAS_JOURNEYS.md](03_PERSONAS_JOURNEYS.md) | User stories, journeys and edge cases |
| [04_UI_UX_SPEC.md](04_UI_UX_SPEC.md) | IA, sitemap, screen specs, states, accessibility |
| [05_SYSTEM_ARCHITECTURE.md](05_SYSTEM_ARCHITECTURE.md) | Modules, trust zones, topology, protocols |
| [06_DATA_MODEL.md](06_DATA_MODEL.md) | Entities, ER relationships, constraints, retention |
| [07_API_CONTRACTS.md](07_API_CONTRACTS.md) | Public/internal APIs, pagination, errors, auth |
| [08_EVENTS_STATE_MACHINES.md](08_EVENTS_STATE_MACHINES.md) | Webhook, repair, review, CI, outbox, retries |
| [09_AI_AGENT_META.md](09_AI_AGENT_META.md) | Models, agent loop, tools, evaluation, budget |
| [10_SANDBOX_REPRODUCTION.md](10_SANDBOX_REPRODUCTION.md) | Build sandbox, fidelity, isolation, worker protocol |
| [11_REPAIR_VERIFICATION.md](11_REPAIR_VERIFICATION.md) | Diff policy, red-green proof, evidences, PR |
| [12_PROVIDER_INTEGRATIONS.md](12_PROVIDER_INTEGRATIONS.md) | GitHub, GitLab, OAuth/App, webhook vs polling |
| [13_NOTIFICATIONS_TELEGRAM.md](13_NOTIFICATIONS_TELEGRAM.md) | Notifications routing, Telegram bot, email, other |
| [14_SECURITY_IDENTITY.md](14_SECURITY_IDENTITY.md) | Threat model, secrets, RBAC, compliance posture |
| [15_INSTALL_DEPLOY_ONBOARDING.md](15_INSTALL_DEPLOY_ONBOARDING.md) | One-command install, OS variants, wizard, hosting |
| [16_OPERATIONS_CLI.md](16_OPERATIONS_CLI.md) | CLI, update, backup, restore, operational playbooks |
| [17_OBSERVABILITY_ANALYTICS.md](17_OBSERVABILITY_ANALYTICS.md) | Metrics, reporting, cost, tracing, SLO |
| [18_TESTING_ACCEPTANCE.md](18_TESTING_ACCEPTANCE.md) | Verification pyramid, fixtures, release gates |
| [19_DELIVERY_PLAN.md](19_DELIVERY_PLAN.md) | Full-scope implementation slices and dependencies |
| [20_DECISIONS_ADR.md](20_DECISIONS_ADR.md) | Decisions, proposed defaults, explicit unknowns |
| [21_OPEN_QUESTIONS.md](21_OPEN_QUESTIONS.md) | Assumptions, vendor-dependent checks, risks |
| [22_OFFICIAL_REFERENCES.md](22_OFFICIAL_REFERENCES.md) | Official technical docs and last checked dates |
| [23_PROGRESS.md](23_PROGRESS.md) | Truthful status: docs vs implementation |
| [24_RELEASE_READINESS.md](24_RELEASE_READINESS.md) | Formal exit criteria and support level |
| [25_CONFIG_SCHEMA.md](25_CONFIG_SCHEMA.md) | Settings, precedence, secrets and policy configuration |
| [26_SECURITY_TEST_MATRIX.md](26_SECURITY_TEST_MATRIX.md) | Abuse cases, invariants and regression scenarios |
| [27_SUPPORT_MATRIX.md](27_SUPPORT_MATRIX.md) | Certified runtimes, OS, provider and limitations |
| [28_BENCHMARK_DEMO.md](28_BENCHMARK_DEMO.md) | Hackathon demo and independent quality benchmark |
| [29_FRONTEND_ASTRYX.md](29_FRONTEND_ASTRYX.md) | React/Vite/TypeScript/Astryx, component strategy and frontend contracts |
| [30_ACCESS_CONTROL_MATRIX.md](30_ACCESS_CONTROL_MATRIX.md) | Permission matrix and authorization invariants by role/action |
| [31_POLICY_AND_AUTOMATION.md](31_POLICY_AND_AUTOMATION.md) | Repair automation policies, eval precedence, approvals and protected operations |
| [32_NOTIFICATION_EVENT_MATRIX.md](32_NOTIFICATION_EVENT_MATRIX.md) | Per-event channels, localization, privacy, retries and Telegram commands |
| [33_RELEASE_EVIDENCE_LEDGER.md](33_RELEASE_EVIDENCE_LEDGER.md) | Release proofs, decision record, traceability and sign-off template |
| [34_SCREEN_AND_INTERACTION_CONTRACTS.md](34_SCREEN_AND_INTERACTION_CONTRACTS.md) | Page-level actions, forms, validations, accessibility and status states |
| [35_INTEGRATION_DEPENDENCIES.md](35_INTEGRATION_DEPENDENCIES.md) | Vendor capability probes, versions, rollout dependencies, external auth risk |
| [36_CANONICAL_CONTRACTS.md](36_CANONICAL_CONTRACTS.md) | Typed schemas, API catalogue, SSE/tools/worker/evidence canonical contracts |
| [37_NFR_AND_RECOVERY.md](37_NFR_AND_RECOVERY.md) | Measurable TARGETS, workload, recovery, backup consistency |
| [38_REQUIREMENTS_TRACEABILITY.md](38_REQUIREMENTS_TRACEABILITY.md) |46feature positive/negative acceptance and reverse15release gates |
| [39_SPEC_AUDIT.md](39_SPEC_AUDIT.md) | Full read inventory, before/after gaps, actual repo state, review decisions |
| [40_EXECUTION_MASTER_PLAN.md](40_EXECUTION_MASTER_PLAN.md) | Frozen 36-unit master implementation plan (`U01`–`U36`), DAG, contracts, tests, release gates and P4 change control |

## Decision status
- **Accepted:** explicitly settled by the owner and recorded as `ACCEPTED` in the ADRs. In particular, ADR-025 selects React 19/Vite/TypeScript/Astryx for the frontend and Python for the backend.
- **Design pending review:** this is a **product-wide contract**, with proposed ADRs and vendor verification still outstanding. Every feature family within v1.0.0 scope requires acceptance evidence before release; mocks are not sufficient proof.
- **Proposed default:** a recommended technical choice to validate, which may be replaced before implementation.
- **Open:** requires verification or a decision by the project owner.

## Scope vs implementation
The design covers the entire platform. A release may be called production-ready only after its gates pass against a **published support matrix**. Do not promise to repair every CI failure or install on every machine without prerequisites. Testing accompanies implementation rather than being postponed until the end.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
