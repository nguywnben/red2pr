# Quality strategy and acceptance criteria

## Test pyramid (continuous from first code, not postponed)
- Unit: parser, signature verification, idempotency keys, policy, RBAC, inference schema, diff safety, event transitions, config validation, cost budget, Telegram parser.
- Contract: GitHub/GitLab webhooks and API response fixtures, Meta tool schema, worker protocol, DB/outbox event schemas, notification adapters, API OpenAPI.
- Integration: Postgres migrations, Redis recovery from outbox, object store scoped artifacts, secrets, fake provider, worker sandbox, failed transaction/retry.
- E2E: real test GitHub and GitLab repos, CI fails → webhook/polling → baseline → patch → deterministic validation → draft PR/MR → remote CI check; **never use production repositories without consent**.
- Security/adversarial: sandbox escape attempts, prompt injection, CI log secret canary, forged callbacks, test tampering, path traversal, SSRF, privileges, supply chain.
- Ops/recovery: clean install each OS, interrupted upgrade, restore, reboot, provider API outage, loss of worker/network/DB/queue, mixed versions, performance/load.
- UX: setup first run, keyboard/a11y, empty/loading/error, repo access restrictions, mobile read-only.

## Test IDs cross-ref
| Test suite ID | Features validated |
|---|---|
| T-INGEST | SRC-01..05 / TRI-01 webhook signature, duplicates, polling cursor |
| T-IAM | IAM-01..03 / APP-02 cross-repo access, approval replay |
| T-AGENT | TRI-02 / AGT-01..04 structured model outputs, budgets, malicious prompt in log |
| T-SANDBOX | SAN-01..04 host secret isolation, restricted egress, resource caps, cleanup |
| T-PROOF | FIX-01..04 baseline vs patched, tests removed, PR text correctness |
| T-PUBLISH | FIX-03 intents, API 500/timeouts, branch movement, remote CI matching |
| T-NOTIFY | NOT-01..04 Telegram auth, duplicate callback, private text redaction |
| T-OPS | INS-01..03 / OPS-01..03 install/upgrade/restore/migration |
| T-ANALYTICS | ANL-01..02 count denominator, cost budget, data scope |
| T-UX | APP-01/REP-01 etc screen state and accessibility |

## Adversarial fixtures
Malicious webhook replay, out-of-order attempt, source comment attempting to steal token, script printing secrets, install `postinstall` shell, symbolic link to `/.env`, archive with `../`, logging ANSI escapes, enormous traceback, Windows path case folding, flaky test random delay, lost webhook, PR create timeout after remote success, code changing tests to `skip`, user role downgraded mid-approval, expired bot token.

## Grading labels and proof
- **`diagnosed`** = attributed causes with references, not verified.
- **`reproduced`** = baseline failure observed in scoped profile.
- **`locally_verified`** = patched test/regression + policy passed, as supported and recorded.
- **`remotely_verified`** = provider check suite for specific published commit succeeded.
- **`needs_human`/`unsupported`/`unverified`** = no inferred success.
False-green must be treated as critical defect and trigger release block.

## Release conditions
All mandatory `P0` feature scenarios from support matrix pass positive/negative tests; full GitHub and GitLab flows; clean OS installs; documented isolation and security review; upgrade/backup restore drills; telemetry and alerts; operator usability review; docs and residual risks; version owner sign-off. See formal checklist [24_RELEASE_READINESS.md](24_RELEASE_READINESS.md).

## Benchmark baseline and reporting
Use >=20 curated failures spanning fixable, non-fixable, flaky, language versions and provider; record all failures, not cherry picked. Compare to non-AI baseline and optionally competitor with comparable cost/time constraints. Metrics: patch candidate rate, proof-confirmed repair rate, remote CI pass, false fix, correct abstention, median repair time and cost/verified patch. Published benchmark must disclose environment/model/budgets.


## Frontend/Astryx release tests (v4 addition)
- `FE-01`: Build production assets under pinned Node/pnpm versions; typecheck, ESLint and independent Astryx wrappers tests pass.
- `FE-02`: Smoke all protected routes (no anonymous access, direct-link authorization, session-expiry handling, error states).
- `FE-03`: Browser E2E covering setup, repo grant, per-repo policy, repair drilldown, approval, export, notifications, backup/status.
- `FE-04`: Test theme dark/light, OS preference, contrast, focus trap, keyboard-only flows, screen reader live regions and reduced motion.
- `FE-05`: Verify Astryx upgraded components against contract and visual baselines; don't silently upgrade Beta package in production.

## Evidence audit obligation
For **each** release gate record test command, tested source SHA/container digest, timestamp, sanitized log/artifact path, result, scope, responsible reviewer; see [33_RELEASE_EVIDENCE_LEDGER.md](33_RELEASE_EVIDENCE_LEDGER.md).

## P2 trace and measurable acceptance
[38](38_REQUIREMENTS_TRACEABILITY.md) defines T-<feature>-P/N for every46 feature IDs and reverse R-01…15 mapping; [37](37_NFR_AND_RECOVERY.md) adds T-NFR-01…16 with explicit workload/thresholds; [26](26_SECURITY_TEST_MATRIX.md) extends negative corpus through SEC-040. All are NOT RUN. P0 release requires real applicable E2E and independent negative proof, not merely authored test names. Critical cannot be waived, High only ADR-032 exception; no baseline means no publication. Candidate support profiles must become exact tested certificates before release.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
