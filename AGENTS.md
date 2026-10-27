# Red2PR — Agent operating contract

## Status and precedence
- Maintain repository documentation in English, as requested by the owner.
- This repository is **in the design phase**. Documentation must not be treated as existing code. Inspect the actual tree, Git status and environment in every session.
- The owner requires **no product source implementation** until the plan is approved; read and update documentation when instructed. Permission to write code does NOT authorize live API calls, pushing commits, creating PRs/MRs, sending messages, purchasing compute or processing third-party repositories.
- Source of truth: `docs/20_DECISIONS_ADR.md` (decisions) > the relevant requirements/architecture specifications > README. Surface conflicts and propose an ADR; never silently change scope.

## Read before starting work
Read `docs/00_INDEX.md`, `docs/01_PRODUCT_VISION.md`, `docs/02_FEATURE_CATALOG.md`, `docs/05_SYSTEM_ARCHITECTURE.md`, `docs/14_SECURITY_IDENTITY.md`, `docs/18_TESTING_ACCEPTANCE.md`, `docs/20_DECISIONS_ADR.md`, `docs/21_OPEN_QUESTIONS.md` and `docs/23_PROGRESS.md`. Open the relevant module documents through the index. Propose implementation only after consolidating requirement IDs, API/data contracts, permissions, negative cases, tests and migrations.

## Non-negotiable principles
1. **Proof over prose:** An LLM may reason and propose changes; it must not certify tests as passing, grant permissions, approve actions or create PRs itself. Evidence comes from verified executor results.
2. **Least privilege:** Separate the control plane/publisher and sandbox runner trust boundaries. Repository code, dependency hooks, CI logs and webhook payloads are untrusted. Never expose write tokens or Meta keys to the sandbox, share the host Docker socket or use privileged containers.
3. **No dangerous autonomy:** No auto-merge, branch-protection bypass, production deployment, autonomous file-scope expansion or test edits merely to make CI green. Legitimate test/config changes require additional policy checks and review.
4. **No false completion:** Distinguish `designed`, `implemented`, `tested` and `operationally_validated`. `locally_verified` differs from `remotely_verified`; failures that cannot be reproduced are `unconfirmed`.
5. **No blind retry:** Require idempotency for webhooks, jobs, patch publication, notifications and callbacks. Every side effect has a correlation ID and audit record.
6. **No secret leakage:** Redact before sending data to models, logs, artifacts or notifications; restrict egress. Private repositories require owner consent for outbound inference.
7. **No invented capabilities:** Check official Meta/GitHub/GitLab/Telegram APIs before coding; feature availability depends on the account, version and permissions.
8. **Self-hosted ≠ offline:** Meta inference is usually a cloud dependency. If the provider is unavailable, show paused/degraded status; do not claim offline support by default.

## Development after approval
- Break work into vertical slices according to `docs/19_DELIVERY_PLAN.md`, without removing mandatory production features. Write tests alongside code for each milestone, including unhappy paths and security cases.
- Define migrations, contracts, schema validation, observability, audit, explicit errors and rollback from the outset. Do not build a mock-only happy path and call it production.
- For every milestone, update `docs/23_PROGRESS.md` with the diff summary, actual test commands, exit status, known risks and evidence references. Update ADRs when new decisions are made.
- The frontend must use React 19 + TypeScript + Vite + Astryx according to `docs/29_FRONTEND_ASTRYX.md`; the backend and AI agents remain Python. Astryx CLI `init` may write `AGENTS.md`: **never allow it to overwrite this file or lose its contents**; integrate generated guidance in a safe location. Do not invent unverified Astryx component APIs.
- Once the owner approves an implementation plan, execute **the exact milestone/task identifier and scope specified by the owner**. Do not repartition the plan, omit requirements or add features outside scope. If a dependency is missing, report the blocker and its impact instead of silently inventing another roadmap.
- At project completion, run independent tests and evidence-backed release gates, then iterate on fixes within the authorized scope. Do not report “production-ready” when conditions are unmet; truthful reporting of blockers is mandatory.
- Before any external or destructive operation, obtain user approval for the specific scope, destination, cost and impact.
- Do not modify repository files outside the task scope. Do not execute untrusted repository source/code on the control host.
