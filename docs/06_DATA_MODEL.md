# Logical data model, relationships and integrity

## Cross-entity design
All IDs UUIDv7/ULID or opaque UUID; provider IDs stored as strings (can exceed signed int). Common: `id`, `created_at`, `updated_at`, `version` (optimistic concurrency), `deleted_at` only where soft-delete safe. Encrypt secrets, never expose columns in APIs. `workspace_id` must be enforced with repository grants on every relevant query; include composite indexes and DB constraints.

| Entity | Important columns | Constraints / relationships |
|---|---|---|
| `instances` | id, deployment_mode, initialized_at, config_revision | singleton within install |
| `users` | id, email/username, password_hash, mfa_state, disabled_at | unique normalized identity |
| `sessions` | user_id, refresh_hash, expires_at, revoked_at | revocation & rotation |
| `workspaces` | id, name, owner_id, retention_policy | multi-workspace logical separation |
| `memberships` | workspace_id, user_id, role, invited_by | unique(workspace,user) |
| `repo_grants` | user/role, repository_id, permission | deny by default |
| `provider_connections` | workspace_id, kind, external_installation_id, config, credential_ref | unique provider+installation+workspace |
| `repositories` | workspace_id, provider_connection_id, external_repo_id, full_name, default_branch, active | provider identity immutable |
| `repository_policies` | repository_id, revision, mode, branch/file rules, budgets, approval | immutable version snapshots for sessions |
| `webhook_inbox` | provider, delivery_key, signature_valid, received_at, payload_digest, status | unique(provider, delivery_key) |
| `provider_sync_cursors` | connection_id, last_seen_id/time, etag, last_scan | resumable polling |
| `ci_runs` | repository_id, external_run_id, attempt, head_sha, workflow, conclusion | unique(repo, external run, attempt) |
| `ci_jobs` | run_id, external_job_id, matrix_json, status, logs_ref | distinct matrix job identities |
| `repair_sessions` | repository_id, ci_run_id, idempotency_key, target_sha, policy_revision, state, seq, owner, correlation_id | unique(logical repair key) |
| `diagnostics` | session_id, failure_category, fingerprint, hypotheses, model_ref, evidence_refs | trace source refs |
| `agent_steps` | session_id, attempt_id, tool, args_digest, outcome_ref, token_usage | no raw secret args |
| `sandbox_leases` | session_id, worker_id, lease_until, profile, image_digest, status | fencing token/heartbeat |
| `reproduction_runs` | session_id, baseline_sha, command, exit_code, environment, fidelity, artifact_refs | immutable after finish |
| `patch_attempts` | session_id, number, base_sha, diff_ref, diff_hash, files_changed | unique(session, number) |
| `verification_runs` | patch_attempt_id, checks_json, baseline_link, policy_decision, evidence_bundle_ref | no LLM authored pass flags |
| `approval_requests` | session_id, policy_action, diff/risk snapshot, requested_by, expires_at, status | one-use tokens; expiry enforced |
| `approval_votes` | approval_request_id, user_id, decision, reason, at | unique vote according to approval policy |
| `publication_records` | session_id, provider, remote_branch, pr_mr_id, remote_sha, state | unique(session, provider, operation) |
| `remote_ci_checks` | publication_id, external_ci_run_id, commit_sha, status | mapping verification run |
| `workers` | id, host_id, attested_mode, runtime, cpu/memory limits, last_seen | schedulable iff healthy |
| `task_jobs` | id, kind, payload_ref, attempts, lease, state, priority, dedup_key | unique active dedup |
| `dead_letter_jobs` | original_job_id, error_code, attempts, recoverable | managed requeue |
| `notification_destinations` | workspace_id, type, secret_ref, verified, policy | Telegram chat/email/etc |
| `notification_events` | event_id, event_type, route_scope, payload_ref | normalized event |
| `notification_deliveries` | event_id, destination_id, dedup_key, status, attempts | unique(event,destination,dedup_key) |
| `usage_ledger` | session_id, model, input/output tokens, cost_estimate, compute_duration | additive immutable ledger |
| `artifacts` | workspace/repo ID, object_key, content_hash, size, mime, retention, encryption | signed short-lived access |
| `audit_log` | actor_type/id, workspace/repo, action, resource, result, ip, at, integrity_hash | append-only/immutable exports |
| `outbox_events` | aggregate_id, type, schema_version, payload, published_at | transactional with state |
| `schema_migrations` | version/checksum/applied_at | forward/backward compat gate |

## Relationship sketch
`workspace 1:N repositories, members, integrations`; `repository 1:N ci_runs`; `ci_run 0:N repair_sessions` (dedup logical attempt); `repair_session 1:N patch_attempts/reproductions/approval_requests`; `patch_attempt 0:N verifications`; `repair_session 0:1 publication` per successful logical publish; artifacts link by resource scopes; notification and audit via outbox.

## Critical constraints
- Idempotency keys for hook delivery, logical session, issue/patch attempt, publishing and outgoing notifications are distinct.
- Stale `policy_revision` or changed `head_sha` before publication => explicit state/fresh approval; never silently rebase patch.
- Rows linked to workspace/repo must be filtered by authorization *before* artifact URL issuance.
- Sanitized summaries in queryable JSONB; raw logs reside in secured object store with retention.
- Deleting a workspace revokes tokens/webhooks and schedules artifact purge after retention; audit handling documented.

## Migrations, backups and audit
Backwards-compatible expand/contract migrations; DB backups and object store consistency snapshots; encryption master key must be backed up separately. Restore drills verify referential integrity and recovery of operation states without replaying old external writes. Audit append-only event chain can detect tamper, but do not claim tamper-proof if trust model does not support it.

## P2 relational contract — proposed PostgreSQL, ADR-035
[Canonical schema types](36_CANONICAL_CONTRACTS.md) define DTOs; tables are not returned wholesale. PostgreSQL choice remains PROPOSED ADR-013/035, not owner-approved solely because architecture mentions it. All timestamps timestamptz UTC; budgets numeric decimal + currency; tokens hashed/encrypted by purpose, no generic plaintext JSON secrets. UUIDv7 is proposed internal key; provider identifiers text. All mutable aggregates have version for compare-and-swap.

Tenant tables carry workspace_id NOT NULL plus UNIQUE(workspace_id,id). Every relationship between tenant records uses composite FK (workspace_id,parent_id); repository-bound records also enforce matching repository, not just workspace. Users, instance settings, signing key metadata, worker registry are instance-scoped; memberships joins users/workspaces. Worker assignment is tenant-scoped even when worker registry global. PostgreSQL RLS defense-in-depth proposed: transaction-local workspace context; application role not owner/BYPASSRLS; background jobs establish context before query; pool reset tests required. RLS does not replace service authorization.

| Group / relationship | Additional required entities/fields | Constraints and read/write indexes |
|---|---|---|
| Identity: users → sessions; workspaces → memberships → repo_grants | invitations(token_hash,recipient,role,expires_at,used_at); mfa_credentials(encrypted_secret,key_version); recovery_codes(code_hash,used_at); api_tokens(secret_hash,scopes,expires_at,revoked_at,grant_epoch) | unique workspace/user membership; unique active invitation per workspace/recipient; session/token expiry and user indexes; one-use redemption atomic; prevent last-owner/admin loss in transaction |
| Integration: connections → repositories → policies | endpoint_registrations(owner,scheme,host,port,cidrs,ca_ref,allowed_adapter); consents(actor,scope,data_classes,destination,purpose,revision,revoked_at); capability_snapshots | unique (workspace,connection,provider_repository_id); provider installation may link multiple workspaces only with explicit grants and distinct scopes, never implicit share; (workspace,status,updated_at,id) |
| CI: inbox → runs → jobs → repairs | attempt_key text; job_retry_of_id; matrix_dimensions JSONB validated; repair parent_id and supersedes_id | unique (connection,provider_delivery_id) with body digest; unique (workspace,repository,provider_run_id,attempt_key); job external ID unique per connection; repair semantic trigger unique incl pinned policy; (workspace,repository,created_at,id) |
| Agent/repro: repairs → steps,leases,runs,patches,verification | profile_revisions; budget_accounts; budget_reservations(status,reserved_amount,settled_amount,pricing_revision); context_manifests | unique (repair,step_number), (repair,patch_attempt); reservation atomic update under account lock, no overspend under concurrency; lease(job_id,epoch) unique; active leases index expires_at |
| Proof/publication: verification → approvals → intent → remote_checks | evidence_manifests; signing_keys(public_key,key_id,validity,revocation); approval intents bind base/patch/policy/target; required_check_sets | one active publication intent per repair/patch/target; unique connection/provider_PR_ID; remote checks unique provider/check-ID/attempt/SHA; approvals index(workspace,status,expires_at); missing evidence FK cannot pass |
| Queue/outbox: task_jobs → attempts / dead_letters | idempotency_records(principal,operation,key,request_hash,response_ref,expires_at); effect_tombstones; operation_receipts; outbox_claims | unique logical effect key; ready-job index(state,not_before,priority,id); sweeper index lease_expires; outbox(status,next_attempt,id); transaction commits domain state+outbox together |
| Notifications: events → recipient inbox / destinations → deliveries | user_notification_preferences; telegram_links(user_id,bot_id,chat_id,verified_at,revoked_at); link_challenges(hash,scope,expires_at,used_at); delivery_attempts | unique (event,destination,template_revision); unique per-user inbox(event,user); telegram chat binding explicit, migration reverify; dispatch index(state,next_retry_at); recipients rechecked |
| Storage/ops: artifacts → manifest entries; backups → manifests | artifact_deletion_jobs; backup_records(checkpoint,db_lsn,object_watermark,key_refs,manifest_digest); migration_runs; release_exceptions(severity,artifact_digest,owner,mitigation,expires_at) | artifacts unique(workspace,digest,access_class) only within tenant; never global dedup oracle; expiry indexes; High expiry indexed; no Critical exception accepted |
| Audit/analytics | audit_checkpoints; scoped report_exports; usage_ledger append entries referencing reservation; reporting projections | audit (workspace,occurred_at,id), (correlation_id); usage(workspace,repository,occurred_at); reports expire_at; projection watermark recorded, rebuild from authoritative ledger |

Delete behavior: no cascade delete of immutable evidence/audit from deleting user or repository. Soft-tombstone resource, revoke capabilities, then retention purge objects and personal fields with audit proof; retained audit uses pseudonymous actor where permissible. FK RESTRICT on live publication/evidence/backup references. Workspace deletion is explicit owner workflow: freeze, revoke, export optional, enumerate retained records, confirm deadline, purge with bounded job and tombstone. DB+object store are not one atomic transaction: upload staged object → verify checksum → DB reference commit → finalization; orphan sweeper deletes only unreferenced expired staged objects. Reader never treats missing blob as passing evidence.

Migration contract: expand/backfill/validate/contract in separate bounded steps; constraints checked before enforcing. Compatible N/N-1 binaries only while explicitly declared; incompatible worker drained before upgrade. Backup before irreversible migration; failed migration leaves maintenance/read-only status. Rollback binary only if schema compatible; otherwise restore entire consistent backup. Physical partitioning and exact ORM remain vendor/performance decisions, not fabricated implemented indexes. R-06/R-07/R-10 require migration, FK escape, pool-context leakage and interrupted purge tests.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
