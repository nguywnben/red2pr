# Events, workflows, idempotency, state transitions

## Event ingestion
1. TLS ingress → verify signature/token (on raw body) → replay/idempotency dedup → installation/repo authorization.
2. Persist provider envelope + normalized event in transactional inbox. Return quickly; queue triage outbox.
3. Resolve actual provider state via API (do not trust event to be complete/authoritative).
4. Normalize provider run + attempt + SHA; ignore irrelevant/success/cancelled, bot loops; store and metrics.
5. Start repair session only if policy triggers and logical key unused.
6. Periodic reconcile missing webhooks, orphaned leases, stale publications and remote CI status.

## Repair state machine
```text
RECEIVED -> AUTHORIZED -> COLLECTING -> TRIAGING
  TRIAGING -> DIAGNOSED_ONLY | UNSUPPORTED | REPRODUCING
  REPRODUCING -> REPRO_CONFIRMED | REPRO_UNCONFIRMED | BLOCKED
  REPRO_UNCONFIRMED -> terminal diagnosis + human handoff (no patch/publication)
  REPRO_CONFIRMED -> PATCHING -> VERIFYING
  VERIFYING -> PATCHING (bounded attempt) | REJECTED | POLICY_GATE
  POLICY_GATE -> BLOCKED | AWAITING_APPROVAL | PUBLISHING
  AWAITING_APPROVAL -> REJECTED | PUBLISHING | EXPIRED
  PUBLISHING -> REMOTE_VALIDATING | PUBLISH_RECONCILE
  PUBLISH_RECONCILE -> REMOTE_VALIDATING | NEEDS_HUMAN
  REMOTE_VALIDATING -> REMOTE_VERIFIED | REMOTE_FAILED | REMOTE_UNKNOWN
Every cancellable state -> CANCEL_REQUESTED -> CANCELLED
Global maintenance mode -> suspension checkpoint (resume only authorized)
```
Each transition: timestamp, causation event ID, expected previous state+version, actor, policy revision, evidence refs; atomic DB guard. Never move back from terminal to active in same session; create linked retry attempt session if needed.

## Checkpoints and leases
- Durable checkpoint for source/evidence/diagnosis/base repro/patch/test/publisher. Retry only safe idempotent stages.
- Worker lease fencing token protects from slow/duplicated workers writing results; heartbeats and independent orphan sweeper.
- PR publication is a saga: record `publish_intent`, deterministic branch `red2pr/<run-id>/<attempt-hash>`, push, query PR/MR by unique marker, create-if-absent; ambiguous timeout triggers reconcile, never retry blindly.

## External event types (versioned)
`provider.connection.created`, `provider.run.failed`, `provider.run.retried`, `repair.session.created`, `repair.diagnosed`, `repair.reproduction.completed`, `repair.patch.proposed`, `repair.verification.completed`, `repair.approval.requested`, `repair.approval.decided`, `repair.publication.created`, `repair.remote_ci.completed`, `repair.blocked`, `repair.cancelled`, `worker.offline`, `integration.disconnected`, `usage.budget.exceeded`, `security.policy.denied`.

**Event JSON sample**:
```json
{
  "event_id": "evt_...", "schema_version": 1,
  "type": "repair.verification.completed",
  "occurred_at": "2026-10-26T08:00:00Z",
  "workspace_id": "ws_...", "repository_id": "repo_...",
  "session_id": "rep_...", "correlation_id": "corr_...",
  "aggregate_id": "rep_...", "aggregate_version": 5,
  "payload": {"repair_id": "rep_...", "outcome": "locally_verified", "manifest_id": "art_..."}
}
```

## Notification outbox
Notification deliveries are derived from authoritative events, sent at least once with dedup keys. Routes may filter by severity, repo, events, quiet hours; emergency alerts override quiet hours only by explicit policy. Retries bounded with jitter; DLQ on permanent failures; secrets and private excerpts redacted.

## Race, reruns, branches
- One run may have matrix jobs; failure class per job. New run attempts are distinct logical events.
- A newer push/rerun can supersede sessions; stale SHA should not automatically be published into moving default branch.
- CI on bot-created PR/MR correlated to originating session; repair loops limited globally and per session.
- Host offline: local polling resumes cursor; gaps reported (API history TTL), not assumed recovered.

## Canonical workflow contract (P2; ADR-033 PROPOSED)
Machine states serialize **lower_snake_case** versions of the diagram labels; uppercase diagram labels are notation, not a second API enum. Session `state` represents the phase/outcome; `proof_grade=none|baseline_confirmed|locally_verified|remotely_verified` increases only when the verifier has evidence. `remote_status=not_published|pending|passed|failed|unknown` is independent; cancellation does not erase existing proof. Approval and notification-delivery statuses are not repair states.

| Workflow ID | Input → durable output | Recovery / terminal rule |
|---|---|---|
| W-01 | Bootstrap, identity, workspace grant → authorized session + audit | bootstrap lock and one-use token; no active owner deletion |
| W-02 | Provider connection → discovered authorized repositories + cursor | revoked grant stops reads/new jobs/publisher; reconnect never restores grants silently |
| W-03 | Authenticated CI event/poll → normalized run/jobs + one repair session | inbox unique delivery + semantic key; reconcile overlap handles missed events |
| W-04 | Frozen context → diagnosis/classification → baseline result | unsupported/infra/auth/unknown abstain; unconfirmed terminates without patch |
| W-05 | Confirmed baseline → bounded patch → deterministic local proof | immutable baseline; failed integrity cannot be overridden by LLM |
| W-06 | Proof + policy + approval when required → draft publication intent → remote CI verdict | unknown write → reconcile; newer base/patch/policy invalidates approval |
| W-07 | Committed event → scoped inbox and external deliveries | dispatch reauthorizes recipient; unknown network outcome explicit |
| W-08 | Lifecycle/worker/job operations → checkpoint, backup or recovery receipt | fenced restore; no automatic replay of remote writes |
| W-09 | Read scoped evidence/analytics/export → redacted view or expiring artifact | membership revocation invalidates SSE/download/export |
| W-10 | Extension capability negotiation → scoped adapter request | disabled/unsupported returns explicit error; P1/P2 never inferred supported |

Pause uses `suspension={reason, checkpoint_state, requested_by, at}` on a nonterminal session; reasons include maintenance, model_unavailable, quota and worker_unavailable. Resuming requires reauthorization and checkpoint validation; do not add `WAITING_MODEL`/DEGRADED to the state enum. A model outage is an availability condition in the UI, not proof. `blocked`, `rejected`, `expired`, `unsupported`, `diagnosed_only`, `repro_unconfirmed`, `needs_human`, `remote_verified`, `remote_failed`, `remote_unknown` and `cancelled` are terminal; retry creates a new session with parent_id, retaining the shared budget and loop cap.
Cancellation before publication revokes the capability, stops the task and confirms worker termination. During publication, do not promise to undo an external write. Keep cancel_requested until reconciliation identifies the branch/PR; if already published, preserve the publication record and finish as cancelled with the actual remote_status. Do not close the PR automatically.
Reconciling remote_unknown may update remote_ci_checks/read projections; it does not reopen a terminal session. A new observation has a new event/version. The UI upgrades proof only when the SHA matches and all expected checks are present.

### Canonical event registry
The External event types list above, plus `worker.quarantined`, `backup.failed`, `release.update_available`, `identity.permission_revoked`, `notification.delivery.failed` and `operations.restore.completed`, forms registry version 1. Previous names `ci.failure_detected`, `repair.started`, `repair.needs_approval`, `repair.pr_created` and `integration.auth_revoked` are legacy UI labels, not additional emitted events. Local verification is an outcome payload of `repair.verification.completed`; remote pass/fail is an outcome payload of `repair.remote_ci.completed`.
Event schemas, SSE replay and ordering are defined in [36](36_CANONICAL_CONTRACTS.md). Events contain no raw logs, diffs or secrets. W-03 reordered webhook/polling duplicates, W-05 unconfirmed stopping, W-06 unknown publication and W-08 lease expiry are mapped in [38](38_REQUIREMENTS_TRACEABILITY.md).


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
