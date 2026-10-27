# Architectural Decision Records — baseline 2026-10-26

**Status meaning:** `ACCEPTED` (user explicitly settled direction), `PROPOSED` (tech lead design default to confirm before code), `OPEN` (no decision/needs verification). Future changes append versioned ADR and cross-references, don't silently edit prior behavior.

| ID | Status | Decision | Rationale / consequences |
|---|---|---|---|
| ADR-001 | ACCEPTED | Product = Red2PR, self-hosted automated CI repair with evidence-backed draft PR/MR | differentiate from generic coding agent |
| ADR-002 | ACCEPTED | Production-first full feature **design**, not MVP-only scope | complete functional/UX/API/security plan before code |
| ADR-003 | ACCEPTED | Implement in incremental verified milestones; not defer all tests | prevents systemic rework and false readiness |
| ADR-004 | ACCEPTED | Linux/macOS one-command entrypoint, Windows one-command entrypoint + web wizard | simple operational UX; prerequisites may require interaction |
| ADR-005 | ACCEPTED | User manages multiple repositories and per-repo auto-repair toggles/policies via web | real product UX |
| ADR-006 | ACCEPTED | GitHub Actions & GitLab CI both in target product | provider adapters, support matrix required |
| ADR-007 | ACCEPTED | Telegram + notifications + admin/analytics/integrations in full functional spec | communications are first-class, not merely optional hacks |
| ADR-008 | ACCEPTED | Meta Muse models primary AI engine; coding/diagnosis/reasoning | model API connected outbound; self-host app != offline AI |
| ADR-009 | ACCEPTED | Verification evidence separate from model text, baseline before/after, remote CI independent | reliable claims |
| ADR-010 | ACCEPTED | No auto-merge / no bypass approval | safety, least privilege |
| ADR-011 | ACCEPTED | User approves before any implementation begins; current kit is docs only | no unrequested code/deploy |
| ADR-012 | PROPOSED | Modular monolith control plane (FastAPI) + isolated worker + privileged publisher | simpler to self-host than service sprawl |
| ADR-013 | PROPOSED | PostgreSQL + transactional outbox, Redis transport and S3-compatible or local encrypted artifacts | self-host operations and reliable event delivery; verify actual queue/runtime choice |
| ADR-025 | ACCEPTED | Frontend React 19 + TypeScript + Vite + Astryx Design System; Python/FastAPI control plane/agents | user chose Astryx; static SPA simplifies self-host, no need to rewrite backend in JS |
| ADR-026 | ACCEPTED | Final artifact kit contains only repository documents; Codex operating prompts are external, never embedded in repo ZIP | repo clean, planning prompts can change without touching product files |
| ADR-027 | ACCEPTED | Complete integrated specification and owner-approved master plan before implementation; execute exact chosen plan unit, test continuously | maintain whole-product alignment without end-only test cliff |
| ADR-028 | ACCEPTED | 1.0.0 production claim only after evidence-backed release gates pass; no pressured green reporting | guard user and customers from false readiness |
| ADR-014 | PROPOSED | Local polling default, server HTTPS webhook + reconciliation; opt-in relay later | local NAT and event robustness |
| ADR-015 | PROPOSED | New repo defaults Monitor Only; 3 modes Monitor/Approval/Auto-Repair | safe activation |
| ADR-016 | PROPOSED | Local single-host allowed for trusted repos with risk warning; isolated worker VM mandatory for untrusted code | honest security boundary |
| ADR-017 | PROPOSED | Telegram read-only commands; mutations require secure web confirmation | Telegram identity alone not enough for privileged action |
| ADR-029 | ACCEPTED | Notification channels include in-app, Telegram, email, Slack, Discord and outgoing signed webhook with a common dispatcher | full product suite with consistent event controls; integration credentials remain optional |
| ADR-018 | PROPOSED | Strict support matrix: Linux Python pytest & Node Jest/Vitest, unsupported jobs abstain | release claims must be tested |
| ADR-019 | PROPOSED | Secure release installer with signatures/checksums, updates/backup/restore CLI | supportable self-host operations |
| ADR-020 | PROPOSED | First-party Meta model profiles Spark triage and Wonder optional complex patch, with live account feature checks | cost/capability fit |
| ADR-021 | OPEN | Final public domain, publishing identity, software license and trademark availability | required prior external launch |
| ADR-022 | OPEN | Exact minimum RAM/CPU/WSL/macOS versions, supported GitLab versions and provider API scopes | benchmark + test |
| ADR-023 | OPEN | Multi-org tenancy in one instance vs one-workspace-first support, SSO auth mode | requirements need owner sign-off |
| ADR-024 | OPEN | Cloud relay operated by Red2PR vs self-hosted relay only | privacy, security and operating cost trade-off |

## Change protocol
Any change to an ACCEPTED principle requires explicit owner approval and PR to this document; PROPOSED changes require ADR with trade-off/risks/test impact and owner review for platform-affecting decisions; OPEN entries resolved after official docs/test/environment facts.

## P2 decision records — 2026-10-27

ADR-001…029 above are retained as decision history. The following records explicitly identify what they resolve or supersede; proposals are not automatically promoted to owner decisions.

| ID | Status | Decision | Rationale / consequences |
|---|---|---|---|
| ADR-030 | ACCEPTED | Multiple workspaces per instance in 1.0.0 | Explicit owner answer on 2026-10-27. Resolves the tenancy portion of ADR-023; SSO remains OPEN. Every tenant entity/query/cache/artifact/event/job must be scoped; R-06 must test cross-workspace isolation. This does not imply public SaaS or that shared containers sufficiently isolate hostile code. |
| ADR-031 | ACCEPTED | If the baseline cannot be reproduced, provide diagnosis and human handoff only; never create a draft PR/MR | Explicit owner answer on 2026-10-27. Replaces the provisional option in docs 11/25; V-01 cannot be waived and approval cannot override an invariant. This reduces automatic repair coverage but prevents claims without evidence. |
| ADR-032 | ACCEPTED | Critical findings must be closed; High exceptions require an expiry, owner and mitigation | Explicit owner answer on 2026-10-27. Invariant failures (secret exposure, unauthorized access, false-green, workspace leakage, escape) always block release. Expired exceptions automatically block release; reassess every release. |

### ADR-033 — PROPOSED: canonical modes, contracts and identifiers
Conflict: monitor mode prohibits sandbox execution in doc02 but previously permitted it in doc31; state/event/config/tool names also differ. Proposal: monitor only ingests and diagnoses; switch to approval mode through the web to execute. Pause is a separate override. Use the canonical schemas/events/tools in [36](36_CANONICAL_CONTRACTS.md) and workflows in [08](08_EVENTS_STATE_MACHINES.md). Benefit: a testable contract without hidden execution. Impact: canonical draft names replace earlier names; no existing code/data needs migration. Alternative: an explicit reproduction mode would add UI/policy complexity. Owner approval is required before implementation.

### ADR-034 — PROPOSED: multi-workspace identity and mandatory isolation baseline
Keep local onboarding/invitations under IAM-02 at P0; IAM-03 P1 covers federation/OIDC provisioning. Propose TOTP and single-use recovery at P0 for owners/admins and publishers/approvers, with a 5-minute step-up window for privileged operations; passkeys and OIDC remain P1. An instance owner does not automatically gain read access to every workspace's repositories; break-glass access requires a temporary grant, reason, audit and notification.
ADR-030 requires SAN-01 P0 to separate the worker host/VM from the control plane for untrusted code. SAN-04 P1 covers advanced fleet hardening/backends, not postponement of basic isolation. Workspaces are not trusted by default; pooled hostile workloads require an ephemeral VM per job or a proven dedicated worker trust domain. Alternative: a shared Docker host is cheaper but provides insufficient boundaries for hostile tenancy. Impact: operations, MFA recovery and capacity require R-05/R-06; SAN-04 priority is unchanged.

### ADR-035 — PROPOSED: durable control plane and evidence trust
Refines ADR-012/013: Python/FastAPI modular monolith, PostgreSQL as source of truth, transactional inbox/outbox. Redis + Dramatiq is transport only; losing Redis must not lose accepted jobs. Use a local encrypted object store for local deployments and S3-compatible storage for distributed deployments. Do not require Temporal without demonstrating the need.
A trusted supervisor outside the guest signs manifests; the control verifier authenticates them, appends an audit hash chain and signed checkpoints, and stores checkpoints beyond the writer's control. A hash alone does not prove authorship; a signature does not prove that a compromised host reported truthfully. Temporal is an alternative that reduces custom orchestration logic but increases the operational footprint. Crash/replay/forgery tests are required before pinning the runtime.

### ADR-036 — PROPOSED: operating targets and certification envelope
Values in [37](37_NFR_AND_RECOVERY.md) are TARGETS, not measured SLAs. Candidate profiles in [27](27_SUPPORT_MATRIX.md) become CERTIFIED only after R-09/R-10/R-13; not every OS/CPU/job is supported. A single local control node does not promise HA; distributed means worker separation, not automatic PostgreSQL HA.
Propose a maximum 30-day High waiver, signed by the security reviewer and release owner and reassessed when the artifact changes. The owner must approve the duration; this does not relax ADR-032.

### ADR-037 — PROPOSED: private integration endpoints and outbound consent
Resolve private GitLab/S3/SMTP access versus SSRF protection through owner-registered service endpoints and explicit CIDR/CA settings authorized by step-up. The egress proxy grants access only to the intended adapter, never arbitrary URLs from repositories/models/artifacts. Remote fetchers always deny link-local, metadata and loopback destinations. Redirects do not inherit credentials. External channels require per-destination opt-in; security/audit inbox events cannot be unsubscribed from to erase their trace.
Impact: enables private deployments but adds endpoint-registry, audit and network tests; it is not blanket permission for private IPs.

### Review order (decisions, not implementation plan)
1. ADR-034 identity/isolation and trust levels between workspaces.
2. ADR-035/012/013 queue, storage, signing/recovery ownership.
3. ADR-033 canonical contracts; ADR-037 egress/consent policy.
4. ADR-036 operating budgets/retention/support envelope.
5. ADR-021 license/domain/publisher and ADR-024 relay operating model.
Verify vendor versions/capabilities through [22](22_OFFICIAL_REFERENCES.md); do not ask the owner to guess API behavior. No source implementation is authorized by this document update.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
