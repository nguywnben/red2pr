# GitHub and GitLab integrations — operational spec

## Unified adapter interface
`list_repos`, `get_run`, `list_jobs`, `get_job_log`, `get_artifact_metadata`, `get_commit_diff`, `resolve_workflow_config`, `get_permissions`, `create_branch`, `push_commit`, `create_draft_review`, `find_review_by_marker`, `get_remote_checks`, `verify_webhook`, `sync_cursor`, `revoke_connection`. Return normalized typed provider errors `RATE_LIMIT`, `FORBIDDEN`, `NOT_FOUND`, `REVOKED`, `STALE_SHA`, `TRANSIENT`, `UNSUPPORTED`.

## GitHub Actions
- GitHub App first-class; per-installation short-lived tokens. Subscribe `workflow_run` completed (filter `conclusion=failure`) and optionally `workflow_job`; verify raw `X-Hub-Signature-256`, delivery ID, installation ownership. Query jobs/logs/diffs via official Actions/REST endpoints; redirects to log archives expire; never persist temporary URL as durable proof.
- Fine-grained permissions for actions/logs, contents, PRs; **workflow file changes may require additional privileges**. Ask only needed permissions, never blanket org admin.
- Web UI guides GitHub App creation/manifest registration, selected repositories, token refresh/installation revoke, webhook URL secret and callback readiness. Local polling cannot receive direct public hook; avoid forcing public HTTPS for laptop.
- Race handling: attempts, reruns, matrices, PR fork permissions, artifact expiry, branch protection, base head changes, bot-triggered workflows, fork security and protected default branches.
- Publisher must honor branch protections and provider workflows; does not bypass approvals, merge or force push protected developer branches.

## GitLab CI
- Project/group integration according to actual GitLab version/host and supported scopes. Pipeline/job webhooks and failure conditions normalized; authentication mode (shared token vs signing token) negotiated from running GitLab instance and verified from docs.
- Fetch job trace, pipeline job list, MR diff and CI status via supported API, including pagination and access scopes. Handle self-managed GitLab domains, TLS trust settings and API limitations; SSRF guard against malicious host URLs.
- Use GitLab commits/MR API for automated branch and draft MR according to supported API; reconcile on retries; prevent unintentional commit into source branch.

## Event delivery modes
- **Server:** verified HTTPS webhooks are preferred; periodic API reconciliation catches losses.
- **Local:** API polling with last seen cursor, ETag/cache, provider rate limits, backoff; not realtime and requires laptop powered on.
- **Relay (optional):** outbound encrypted connection to user-controlled or opt-in vendor relay; stronger authentication and trust/documentation; never silently proxy private webhook payload through Red2PR-hosted relay.

## Authorization and policy
- Credentials connection-scoped in secret store; token refresh/expiry/status UI; least privilege; user selects repos to activate; forbid treating repo discovery as permission to auto-repair.
- `monitor` default; enable `auto_repair` requires confirmation and preflight worker check.
- On uninstall: disable hooks/connection and revoke scope where available; don't silently remove external GitHub/GitLab Apps without user confirmation.

## Provider test matrix
- Good/bad signature; duplicate delivery; webhook outage and polling recon; repo permission lost; token expired; API 429/5xx; insufficient Actions/job log privilege; forks and matrices; self-hosted GitLab URL input SSRF; MR/PR duplicate retry; remote CI completion correlation; branch deleted/rebased mid-repair.

## Compatibility principle
Exact event fields and permission names MUST be checked against official docs at implementation and continuously with provider updates. Internal event types cannot be blindly mapped from provider events without adapter tests.

## P2 connection lifecycle and authorization contract
Connection states: not_configured → checking → ready; degraded (transient), revoked (credential/grant), unsupported (capability) remain distinct. A connection binds workspace, provider host/identity and approved repo IDs, not merely owner/repository display names. Discovery paginates all authorized repos and records cursor/time/partial results; missing repo on one failed page is not revocation. Explicit provider removal/revocation suspends new jobs, rechecks ongoing work before publish, closes streams and suppresses external content; reconnection requires grant review, not automatic mode restoration.

### GitHub App setup and scopes
Offer manual App registration for self-hosted domain; manifest-based flow only after capability/redirect validation. Wizard distinguishes App ID/private signing key, user OAuth callback and post-install setup URL. Nonce state single-use, bind initiating user/workspace/origin, TTL10min TARGET; installation_id query string alone proves nothing. Verify accessible installation, actual selected repositories and requested vs granted permissions via provider reads. No org-wide admin/secret-management permission.
Proposed minimum: Metadata read, Actions read (runs/jobs/logs/artifacts), Contents read for diagnosis; publisher Contents write + Pull requests write only for selected repos. Checks read / Commit statuses read when needed to evaluate required CI; request only after adapter endpoint permission review. Actions write/rerun is not baseline ingestion permission. Workflow file write is excluded by default, not silently obtained through Contents write. New permission request returns degraded until installation owner grants it. User OAuth token, App JWT and installation token are separate credentials; never use one as universal auth.
Installation tokens minted just-in-time with repository/permission subset, encrypted in broker memory/cache, expiry honored; no fixed token length assumption. App private key only broker; sandbox gets materialized source, never bearer token. Candidate REST header X-GitHub-Api-Version: 2026-03-10 from official docs read 2026-10-27; pin and test compatibility before certification ([references](22_OFFICIAL_REFERENCES.md)).

### Event, attempt and artifact semantics
workflow_run completed with failure is a trigger, not complete source truth; record repository, head_repository, head_sha, event, run ID and run_attempt. Fetch attempt-specific jobs/logs, preserve every matrix job and pagination, excluded/skipped/cancelled conclusions and missing artifacts. GitHub rerun increments run_attempt; job IDs and partial reruns retained, never stitch latest log into old failure. Artifact download redirect is provider-mediated but still untrusted URL: validate host/network, strip authorization, bound decompression/files/bytes, reject paths/symlinks; expired/deleted logs yield incomplete diagnosis and no invented repro.
GitHub webhook raw-body HMAC SHA-256 + constant-time comparison; delivery ID + payload digest dedup. GitHub signatures do not inherently bind freshness timestamp: durable delivery tombstones, semantic run dedup and current provider state reconciliation prevent replay execution. Unknown installation cannot trigger work. Retry transport uses Retry-After/rate headers, jitter and per-installation budgets; exhausted quota pauses without losing cursor.

### Forks, branch protection and downstream side effects
An untrusted fork/head repository is not automatically granted because base repo is installed. Pin actual failure source SHA/repo; no executing fork with target repo secrets. Fork workflows requiring approval remain waiting/human, never approve them automatically. Branch permissions checked before intent, before push and before create; no force push, protection changes or bypass.
**Draft PR creation can trigger CI with external consequences.** Repository onboarding must review target workflows, privileged workflow_run/pull_request_target patterns, environment approvals and deploy hooks. Auto-repair allowed only when publication-triggered CI is within approved safe scope; otherwise require human or refuse. Red2PR never assumes draft means deployment cannot run. Config changes that alter gates are sensitive and default denied pending independent review.
Publisher namespaced branch, unique marker and expected commit digest; on timeout query known branch/object marker and compare source/target before retry. If API cannot prove absence, keep unknown/needs_human. Existing PR/MR adopted only with matching stored intent/digest; no unrelated object overwrite. Local approval never grants provider permission absent in installation.

### GitLab contract and version compatibility
GitLab.com and separately registered self-managed base URLs are different connections. Negotiate server version, edition, project role, API capability and configured auth scheme; pin recorded capability snapshot. Propose project-scoped token with API access for API operations and repository write only as required by selected push method; exact role/scopes depend on server/version and must be verified, not claim read_api can create MR. Support short expiry/rotation; no mandatory admin/system-hook credential. Polling usable when project webhook management unavailable; do not falsely report webhook installed.
Persist pipeline ID, pipeline source, ref/SHA, child/downstream pipeline relations and job IDs; include retried jobs when collecting history, keep retry_of where provable, never synthesize GitHub run_attempt. Trace/artifacts follow expiry/partial handling above. MR is draft, source branch/project and target branch/project explicit; draft presentation/fields must match negotiated API, no assuming deprecated wip field remains supported.
Official GitLab docs: signing headers introduced19.0, flag removed19.1. For signed mode validate webhook-id + webhook-timestamp + raw body according to documented HMAC format and timestamp window; key rotation accepts explicitly configured key IDs only. For legacy mode validate X-Gitlab-Token constant-time over TLS, then semantic dedup/reconcile; legacy has weaker freshness protection. **Pin auth_mode at registration; never downgrade to legacy when signature header absent.** Idempotency-Key exists from17.4; X-Gitlab-Event-UUID alone is insufficient for recursive delivery uniqueness. Server-specific support requires fixtures and authorized real validation; API version v4 does not prove uniform behavior across all GitLab releases.

### Polling, reconciliation and remote CI
Poll cursor stores provider host/repo, updated_at window, last stable page and high-water mark; overlap window5min TARGET with semantic dedup. Advance only after durable inbox writes; rate/permission/timeout leave checkpoint. Webhook deployments also reconcile; long offline beyond provider history marks gap with actionable human resync. Deletion/uninstallation reconciles grant removals.
Remote verifier records expected required workflow/job/context set from reviewed policy + provider protections, event type, exact published head SHA, rerun attempt and merge-result SHA relation where relevant. Green requires every required item complete/pass, no missing/unknown/skipped/neutral surrogate; allowed optional checks recorded separately. Required-check configuration changed→re-evaluate expectation, not silently narrow set. Cancelled/timed-out/missing/manual/scheduled delayed pipelines remain failed or unknown according to explicit policy, never locally_verified promoted by elapsed time. Stale run callbacks cannot overwrite newer attempt. Only provider-confirmed status can produce remotely_verified; a webhook hint triggers authenticated read.
Publication failure never discards proof; remote failure can create a budgeted linked session after triage, with loop cap across chain. No auto-merge or deployment endpoints.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
