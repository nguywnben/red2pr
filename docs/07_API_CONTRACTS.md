# Proposed REST API and internal protocol contract

**Design only.** No API server, generated OpenAPI or executed contract tests exist. [36 Canonical contracts](36_CANONICAL_CONTRACTS.md) is the single field/operation registry: A-01…A-24 and S-01…S-22. This document describes integration rules rather than maintaining a second set of endpoint aliases.

## Public HTTP boundary
Prefix /api/v1, JSON UTF-8, RFC3339 UTC. Singular response is the named S-schema directly; paginated response is S-04 Page; asynchronous mutation returns202 S-05 ActionReceipt; errors use application/problem+json S-03. Response headers include correlation ID; no separate request_id/meta envelope. Worker protocol is internal, never accessible via browser session.

| Operation family | Canonical registry | Required behavior |
|---|---|---|
| Bootstrap/auth/account | A-01…A-03 | one-use bootstrap, CSRF, MFA/step-up, recovery and session revocation |
| Workspaces/members | A-04…A-05 | create/delete instance owner only; membership administration workspace-scoped |
| Integrations/repositories/runs | A-06…A-08,A-23 | selected repository grants, capability/version facts, immutable attempts/log ranges |
| Repair/evidence/approval/publication | A-09…A-12 | independent proof, patch/base/policy-bound approval, reconcile unknown writes |
| Workers/queue | A-13…A-14 | owner enrollment, scoped operator controls, fencing and no blind replay |
| Notifications/account linking | A-15…A-16,A-24 | consent, safe test-send, delivery unknown and recipient reauthorization |
| Analytics/audit/lifecycle/tokens/models | A-17…A-20 | bounded scope, dry-run for privileged operations, reserve budget before model call |
| SSE/hooks | A-21…A-22 | versioned events/replay cursor; provider raw-body authentication before inbox commit |

## Input, authorization and concurrency
Typed inputs validate bounds, enums and extra keys at boundary; service rechecks resource relationships, live grants, policy and transition. Browser roles are presentation only. API tokens cannot satisfy step-up/approval. Cookie writes use CSRF token and Origin validation; secrets are write-only references, never returned in resource DTO.
Cursor paging is stable and tenant/principal/query-bound (S-04). Mutable aggregates use ETag/If-Match or an explicitly named expected_version; stale revision cannot overwrite. Atomic idempotency key/request hash and permanent logical-effect uniqueness are S-05. Same key/different payload409; duplicate running receipt202; expired key rejected. Remote side-effect timeout remains unknown until authenticated reconciliation, not automatic retry.
GET/download/SSE never execute action; evidence reads reauthorize and enforce retention. 404 on inaccessible resources prevents enumeration; list count/filters must use same grants as items. Object storage URLs are short-lived and scope-checked; no private bearer tokens in links.

## Events, model tools and worker contracts
Ingress routes A-22 accept bounded **raw** provider bytes; authenticate pinned GitHub/GitLab/Telegram scheme, then durable inbox and semantic dedup. Domain events are S-19/doc08; outgoing notification signatures include timestamp + delivery ID + exact body as specified in doc32. No duplicate UI event-name registry.
Frontend SSE A-21 reconciles REST snapshot on expired cursor, version gap or revocation. S-20 typed tools replace earlier run_targeted_tests/get_run_result aliases; model cannot invoke publish or modify a gate. S-21 SandboxJobV1/ResultV1 and S-22 manifest are canonical; there is no alternative SandboxResultV1/fencing_token sketch.

## Compatibility and validation obligations
Versioned API v1 must round-trip against future generated Python/OpenAPI/TypeScript schemas; incompatible field/semantics change requires new version and migration. Test all documented response branches, unknown enums, extra fields, huge input, invalid cursor, duplicate side effects, out-of-order events, cross-workspace IDs and permission changes during execution. A JSON table is not runtime validation. Required positive/negative tests and release mappings are [38](38_REQUIREMENTS_TRACEABILITY.md).

[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
