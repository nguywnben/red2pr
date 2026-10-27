# Policy engine — repair eligibility, approvals and execution guarantees

## Policy scope
Immutable security invariants > instance-wide baseline > workspace controls > repository controls > run-specific consent. Deny > allow. A repair session pins the effective policy revision at creation, but every privilege escalation and publication re-evaluates currently effective restrictions. Policies are **versioned**, have dry-run simulation and audit history.

## Automation modes
- `monitor`: ingest/diagnosis/report. No sandbox execution, mutation or publication; changing to approval mode requires authorized web policy action (ADR-033 PROPOSED resolves previous conflict).
- `approval`: investigation and safe local patch verification can occur; human with adequate role must authorize publication. Configured provider reads/model calls remain subject to consent and budgets, not a new approval for every request.
- `auto_repair`: approved categories, branches, paths, budgets and certified runtime can run automatically; creating **draft** PR/MR allowed only after verification policy and safety gates.
- `paused` is a separate safety override, not a fourth repository mode: instance/workspace/repo no new repair jobs/publishing while active, existing workers safely drained or cancelled.

## Eligibility decision sequence
1. Webhook/provider event authenticated, repo installed/granted; source SHA pinned to run attempt.
2. De-duplicate logical failure and check bot-loop correlation.
3. Apply repo mode and user-consent rules, query latest pipeline attempt.
4. Classify code regression vs CI config vs dependency vs transient/infra/credential/flaky/unknown; unsupported cases abstain.
5. Check protected branch policy, runtime support, required network and secrets availability, sandbox readiness, model egress consent.
6. Enforce resource, token, compute, time and total spend quotas, concurrency and queue priority.
7. Baseline reproduction; uncertain result downgraded, never falsely `reproduced`.
8. Patch attempt applies file-scope, diff-size, sensitive-file/test modification and generated code policy.
9. Verification checks original failure, regression, patch integrity and environment fidelity.
10. Publication approval and recent permissions/branch revision; create idempotent draft intent; monitor remote CI separately.

## Approval object contract
`approval_id`, `workspace_id`, `repo_id`, `repair_id`, `intent_type`, `requested_by`, `effective_policy_version`, `risk_level`, `diff_digest`, `scope_description`, `expires_at`, `allowed_reviewers`, `status`, `decision`, `decision_actor`, `decided_at`, `audit_correlation`. Decision requires live authenticated web session + CSRF/step-up where relevant; bot messages only deep-link. Re-review if patch SHA, target branch or policy changed. Approval expiry revokes side effect.

## Protected operations
Production deployment, changing branch protections, editing CI to remove security steps, modifying secrets, force pushes, automatically merging PR/MR and privileged runner execution are **not** standard auto-repair. Any future support would require separate explicit architecture, owner consent and new attack tests. A test/code/config change that weakens verification is blocked and escalated.

## Quota/race controls
Leases with fencing tokens, outbox and publication intent idempotency keys; agent retries never directly retry an ambiguous payment/write-like remote side effect. Cancellation transitions are durable, worker checked; provider 429 uses rate policy/backoff; duplicate webhook and reorder do not reset budgets or create new publication intent.

## Operational truthfulness
UI/report exposes `diagnosed_only`, `repro_unconfirmed`, `locally_verified`, `remote_verified`, `remote_failed`, `blocked`, `needs_human`, `unsupported` distinctly. `confidence` from LLM is not calibrated probability and never overrides deterministic gate. Scoped exceptions require reviewer signed approval and remain visible forever in audit.

## P2 non-waivable gates
ADR-031 forbids publication without baseline; ADR-032 forbids release with Critical or invariant failure. Any earlier reference to scoped exceptions applies only to policy choices explicitly waivable under approved ADR, never V-01, secret boundaries, authorization, cross-workspace isolation or truthful proof. Approval cannot broaden a grant or invent evidence. S-12 binds base SHA/target in addition to patch and policy.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
