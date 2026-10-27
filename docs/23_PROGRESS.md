# Development progress — authoritative truth

**As of 2026-10-27:** Phase `P4` Wave `W0` (`IG-01`) completed under [ADR-039](20_DECISIONS_ADR.md) and [ADR-040](20_DECISIONS_ADR.md): **4 of 36 execution units completed (`U01`, `U02`, `U03`, `U04` — `LOCALLY_VERIFIED`)**. Monorepo manifests, `Z1`/`Z2`/`Z3` import-boundary linters, `AGENTS.md` SHA-256 guard, canonical contracts `S-01`..`S-22`, cryptographic primitives (AES-256-GCM envelope encryption, domain-separated Ed25519 manifest/result/checkpoint signing, constant-time HMAC-SHA256), FastAPI `/api/v1` shell (`GET /api/v1/system/health` `A-18` + `S-03` `Problem` handlers + `1 MiB` body guard), exported `contracts/schemas/*.json` & `contracts/openapi/openapi.v1.json`, generated `@red2pr/ts-client`, the PostgreSQL 16 foundation persistence spine (`0001_foundation_spine`, `ENABLE` + `FORCE ROW LEVEL SECURITY` with non-`BYPASSRLS` runtime role & pool reset guards, atomic `S-05` idempotency + `>=90d` `effect_tombstones`, transactional `S-19` outbox + `lease_epoch`-fenced claims, `Z2` `SecretBroker`, and SHA-256 hash-chained `audit_log` + Ed25519 external checkpoints), and the `apps/web` React 19 + TypeScript strict + Vite + pinned Astryx `0.7.4` frontend foundation (isolated `Button`/`Dialog`/`Table`/`AppShell` wrappers, light/dark/system WCAG 2.2 AA semantic tokens, 15 unified UX states + `UX-03` proof-distinction badges, sanitized `50,000`-line virtualized/paged `SafeLogViewer` & `SafeDiffViewer`, `ChartWithTableFallback`, and `S-19` `useWorkspaceSse` cursor/410/heartbeat/403 reconciler) are implemented and locally tested (`58` Python + `24` TypeScript tests passed). **`UI-01` and `UI-02` foundation wrappers are `LOCALLY_VERIFIED` (release gate `R-11` awaits all 21 domain screens and real browser certification); 0 domain UI screens, 0 live provider integrations, 0 production deployments, and 0 release gates (`R-01`..`R-15` all `NOT RUN`) are completed.**

| Area | Designed | Implemented | Tested | Production validated |
|---|---|---|---|---|
| Product and feature specifications | yes | no | no | no |
| User flows/UI | yes | partial (`U02` `@red2pr/ts-client` + `U04` React 19/Vite/Astryx `0.7.4` shell, semantic tokens, 15 UX states, sanitized `50k` log/diff viewers, chart+table fallback, `S-19` SSE cursor reconciler; `0` of `21` domain screens) | partial (`locally_verified` unit/a11y/scale/contract) | no |
| GitHub/GitLab integrations | yes | partial (`U02` `S-08..S-10` DTO schemas only; `0` adapters) | partial (`locally_verified` contract/unit) | no |
| Meta agent runtime | yes | partial (`U02` `S-20` typed 8-tool schemas only; `0` broker/loops) | partial (`locally_verified` contract/unit) | no |
| Worker sandbox / reproduction | yes | partial (`U02` `S-15`, `S-21` `SandboxJobV1`/`ResultV1` schemas & Ed25519 signing only) | partial (`locally_verified` contract/unit) | no |
| Patch verification and PR/MR | yes | partial (`U02` `S-12..S-14`, `S-22` `EvidenceManifestV1` & `SEC-030` signature verifier only) | partial (`locally_verified` contract/unit) | no |
| Telegram and notifications | yes | partial (`U02` `S-16` DTO schemas & `v1` webhook HMAC primitive only) | partial (`locally_verified` contract/unit) | no |
| Auth/RBAC/security | yes | partial (`U01`–`U03` redaction, `Z1`/`Z2`/`Z3` linters, crypto, PostgreSQL 16 RLS + pool reset guards, `Z2` `SecretBroker`, hash-chained `audit_log` & signed checkpoints; no auth/RBAC HTTP routes yet) | partial (`locally_verified` unit/property/contract/PostgreSQL-16 integration) | no |
| Installers/setup/CLI/operations | yes | partial (`U01`–`U03` config schema, `S-18` DTOs, `A-18` `/api/v1/system/health`, Alembic `0001_foundation_spine`, `S-05` idempotency/tombstone store & `S-19` fenced outbox only) | partial (`locally_verified` unit/property/contract/PostgreSQL-16 integration) | no |
| Metrics, backups, release process | yes | partial (`U01`–`U03` JSON/OTel ingress scrubbing, `S-17` hash-chained `audit_log` & `verify_audit_chain` only; `R-01`..`R-15` `NOT RUN`) | partial (`locally_verified` unit/property/contract/PostgreSQL-16 integration) | no |

## Change log template after approved coding
`Date/time | milestone/feature IDs | code paths | actual commands executed | exit codes & test summaries | changed contracts/migrations | evidence artifact | known gaps/security risks | owner approval | next step`.

Do not fill with predicted outcomes. For each release gate, link reproducible evidence and hardware/provider version; if not run, mark `NOT RUN`.


## v4 spec update (documentation only)
- [x] Product baseline extended with React 19 + Vite + TypeScript + Astryx; Python backend unchanged.
- [x] Added requirements for permissions, policy, notification events, page contracts and release evidence.
- [x] Only repository specification documents were prepared in this ZIP; no product source code was created, compiled, installed or tested by this preparation.
- [ ] All vendor capabilities, owner environment support and release gates must be verified by implementing agent.

## P2 specification audit completed for owner review — 2026-10-27
**Documentation work only; no implementation approval inferred.** Read inventory and before/after gaps: [39](39_SPEC_AUDIT.md); full trace: [38](38_REQUIREMENTS_TRACEABILITY.md).

- Baseline38official documents reviewed;37existing Markdown documents updated (README + docs00…35), AGENTS unchanged;4new Markdown documents36…39. No deleted files. Skills/metadata unchanged. Total official documents42; actual workspace files76.
- Preserved original16ACCEPTED ADR rows verbatim. Added owner-approved ADR-030 (multi-workspace), ADR-031 (no unconfirmed publication), ADR-032 (Critical closed / bounded High exception). Added5PROPOSED records ADR-033…037 with tradeoffs; no prior ACCEPTED record silently changed.
- Canonical24API families/22schema families,21screen routes,40security negative scenarios,16measurable NFR TARGETS,46feature rows with92named positive/negative acceptance cases and15release-gate mappings.
- Official public vendor sources and pinned Astryx source inspected; ledger records versions/date/access limits. No paid model request, provider account mutation, message, dependency install, repository code, installer or sandbox execution.
- Found and corrected docs conflicts in baseline→patch flow, provisional policy, Critical exceptions, owner rights, state/event/tool/config names, delivery semantics, Astryx props and responsive-screen coverage. Other architectural choices clearly PROPOSED, pending review.

### Actual documentation validation and environment checks
| Check / actual command form | Result / exit status | Evidence and limits |
|---|---|---|
| Get-Location; rg --files (Markdown inventory) | success0 | actual workspace path,42official Markdown files after edit |
| git status --short | native failure128: not a git repository (PowerShell wrapper may report1) | no Git metadata, no branch/commit/push; no Git diff claimed |
| Get-Command git,python,node,npm,docker,wsl -ErrorAction SilentlyContinue; PowerShell version | discovery completed | Git/Python/Node/npm/WSL found; Docker not on PATH; daemon/distro/readiness untested |
| Inline Python via PowerShell here-string piped to python -I -B - (read-only Markdown validator; no saved script) | exit0 on first structural pass |42docs,270local links and54tables checked at that pass; no missing target/table-width/fence error;46feature priorities matched |
| SHA-256 inventory via inline Python + initial-session snapshot comparison | exit0; no unexpected edit/deletion |37changed existing docs +4new docs only; AGENTS and34skill/metadata files byte-identical |
| In-memory comparison against original ADR text |16/16original ACCEPTED rows preserved | three new owner decisions separate; no product behavior tested |
| Final link/ID/table/scope check after acceptance-ID/progress edits: inline python -I -B - | exit0; errors=[] |42docs,272local links,55tables,46features,92acceptance cases,40SEC,16NFR,21screens,24API families;15gates still NOT RUN;16original ACCEPTED unchanged;37existing changes+4new Markdown only |

**Implementation remains:**0source modules,0product test suites executed,0integration resources provisioned,0production deployments,0release gates passed. Designed requirements may be ACCEPTED or PROPOSED; neither is IMPLEMENTED/TESTED/OPERATIONALLY_VALIDATED.

Known remaining decisions: ADR-033…037; SSO/relay/license/domain/customer region; exact certified versions/hardware and authorized account probes. Target metrics not measured. Formal generated OpenAPI, database migrations and runtime tests await a later approved implementation phase. Detailed master plan not created; existing D0…D10 outline retained without repartitioning. **Stop for owner specification approval.**


## Initial public repository publication — authorized after P2

On 2026-10-27 the owner explicitly requested creation of a public repository and commit/push of the current project. Destination: `nguywnben/red2pr` on GitHub, default branch `main`. This authorization covers publication of the specification and installed project skills; it does not approve product implementation or pending architecture proposals.

Preparation: exclude local secrets/generated files with `.gitignore`, remove the personal workspace path from the public audit, preserve upstream skill attribution/license, and use the authenticated GitHub account's noreply commit address. The earlier no-Git inventory and file counts above describe the completed P2 snapshot, before publication preparation. Repository creation/push outcomes must be verified against GitHub; this entry records authorization and preparation, not a product release or passed gate.

## English documentation — 2026-10-27

The owner requested an English repository after the initial public publication. Translated the remaining Vietnamese prose in README, AGENTS and docs00…39, including navigation, decisions, acceptance criteria and the audit report. Existing English contracts and third-party skills remain unchanged apart from translated navigation labels in project documents. This is a language-only update: requirement identifiers, priorities, decision statuses, links, operating limits and product verification status are preserved.

Validation uses an inline read-only Python check against the previous commit for identifiers, link targets, status labels, feature priorities, Markdown structure and remaining Vietnamese characters, followed by Git whitespace checks. No product code, dependencies or runtime tests are introduced.

Validation result: Python check exit0 with 42 documents, 273 valid internal links, 54 tables and 46 feature rows; no changed identifiers, link targets, status labels or fenced code blocks. Git whitespace check exit0. These results validate the documentation update only.

## P3 master implementation plan prepared for owner review — 2026-10-27

**Planning work only; zero source code, packages, migrations, commits or external calls executed.**

- Created single authoritative Master Implementation Plan at [40_EXECUTION_MASTER_PLAN.md](40_EXECUTION_MASTER_PLAN.md) (`PLAN-2026-10-27-v1`, preserving `36_CANONICAL_CONTRACTS.md`..`39_SPEC_AUDIT.md` intact): **36 immutable Execution Units (`U01`–`U36`)** across **7 waves (`W0`–`W6`)** and **6 integration checkpoints (`IG-01`–`IG-06`)**, acyclic topological DAG (26-node full critical path; 25-node `P0`-only critical path), locked React 19 + TypeScript strict + Vite + pinned Astryx (`0.7.5`) / Python 3.12 + FastAPI + Meta Muse / PostgreSQL 16 / Redis 7 + Dramatiq / isolated mTLS worker stack, 100% 46-feature (`41 P0`, `4 P1`, `1 P2`) non-overlapping primary unit ownership, 92 `T-*-P/N` test mappings, 40 `SEC-*` adversarial scenarios, 16 `NFR-*` targets, 15 `R-*` release certification gates, blocked external dependency schedule, and strict P4 Change Control (`CR-XXX`).
- Updated [00_INDEX.md](00_INDEX.md), [19_DELIVERY_PLAN.md](19_DELIVERY_PLAN.md), [20_DECISIONS_ADR.md](20_DECISIONS_ADR.md) (appending `ADR-038` `PROPOSED` while keeping all 19 prior `ACCEPTED` rows verbatim), [38_REQUIREMENTS_TRACEABILITY.md](38_REQUIREMENTS_TRACEABILITY.md), [23_PROGRESS.md](23_PROGRESS.md), and `README.md`. `AGENTS.md` and `.agents/skills/` remain byte-identical.
- Read-only validation (`python -I -B -X utf8 -` + `git diff --check`): `exit 0`, `errors=[]` across **43** official Markdown documents, **356** valid internal links, **60** valid Markdown tables, **36/36** unit specifications with all 12 mandatory fields, **0** DAG cycles or dependency mismatches, **46/46** features mapped with exact priority parity, and **0** non-English characters.
- **Authoritative implementation truth remains:** `0` source modules built, `0` product test suites executed, `0` integrations provisioned, `0` production deployments, `0` release gates passed (`R-01`..`R-15` all `NOT RUN`). **Stopped awaiting explicit owner approval of `PLAN-2026-10-27-v1`, `ADR-033`..`038`, and an authorized unit ID before starting P4.**

## P4 execution log — U01 completed (`LOCALLY_VERIFIED`) — 2026-10-27

- **Unit ID & Title:** `U01` — Monorepo Workspace, Boundary Linters, Config & Redaction Primitives ([40_EXECUTION_MASTER_PLAN.md](40_EXECUTION_MASTER_PLAN.md)).
- **Owner Approval & Authorization:** Master Plan `PLAN-2026-10-27-v1` and baseline ADRs approved in [ADR-039](20_DECISIONS_ADR.md); explicit owner authorization granted for `U01` execution only.
- **Requirement, Contract & Test IDs Covered:** Wire primitives `S-01`..`S-05` ([36_CANONICAL_CONTRACTS.md](36_CANONICAL_CONTRACTS.md)); canonical configuration schema and retired/invariant enforcement ([25_CONFIG_SCHEMA.md](25_CONFIG_SCHEMA.md), `ADR-010`, `ADR-025`, `ADR-031`); foundation primitives for `OPS-01`, `OPS-03`, `NFR-06` (budget hierarchy caps), `NFR-13` (structured JSON + OpenTelemetry ingress correlation and redaction), and `SEC-017` (raw/URL/Base64 secret canary scrubbing). Release gates `R-01`..`R-15` remain `NOT RUN`.
- **Files Changed / Created:**
  - Modified: `.gitignore`, `docs/23_PROGRESS.md`.
  - Created workspace & lockfile manifests: `pyproject.toml`, `uv.lock`, `pnpm-workspace.yaml`, `package.json`, `pnpm-lock.yaml`, `.nvmrc`, `.npmrc`, `.env.example`.
  - Created `packages/py-contracts`: `packages/py-contracts/pyproject.toml`, `packages/py-contracts/src/py_contracts/{__init__.py,py.typed,primitives.py}`, `packages/py-contracts/tests/.gitkeep`.
  - Created `apps/control-plane`: `apps/control-plane/pyproject.toml`, `apps/control-plane/src/red2pr_control/{__init__.py,py.typed}`, `apps/control-plane/src/red2pr_control/core/{__init__.py,config.py,errors.py,integrity.py,logging.py,redaction.py}`, trust-boundary packages `apps/control-plane/src/red2pr_control/{orchestrator,verification,secrets,publisher,inference}/__init__.py`, and test suite `apps/control-plane/tests/unit/test_config_and_redaction.py`.
  - Created isolated workspace package skeletons: `apps/worker-supervisor/{pyproject.toml,src/red2pr_worker/__init__.py,src/red2pr_worker/py.typed,tests/.gitkeep}` and `apps/cli/{pyproject.toml,src/red2pr_cli/__init__.py,src/red2pr_cli/py.typed,tests/.gitkeep}`.
- **Executed Verification Commands & Measured Results:**

| Command executed | Actual exit code | Measured result & evidence |
|---|---|---|
| `uv lock --check` | `0` | `Resolved 34 packages in 1ms`; `uv.lock` deterministic and synchronized with workspace members |
| `uv run ruff check .` | `0` | `All checks passed!` across all workspace packages and tests |
| `uv run mypy --strict packages/ apps/` | `0` | `Success: no issues found in 17 source files` (`pydantic.mypy` strict plugin enabled) |
| `uv run lint-imports` | `0` | `Analyzed 38 files, 50 dependencies. Contracts: 4 kept, 0 broken` (`contracts-remain-pure`, `worker-zero-control-imports`, `control-plane-z1-z2-boundaries`, `cli-no-secret-or-worker-internals`) |
| `uv run pytest apps/control-plane/tests/unit/test_config_and_redaction.py -v` | `0` | `30 passed in 1.27s` (includes `AGENTS.md` SHA-256 baseline/tamper checks, `S-01`..`S-05` wire contracts, `hypothesis` Decimal & budget hierarchy property tests, `CONFIG_RETIRED_KEY` & `CONFIG_INVARIANT` negative cases, and raw/Base64/URL canary scrubbing across JSON logs & OpenTelemetry spans) |
| `pnpm --frozen-lockfile install && pnpm build && pnpm typecheck && pnpm lint && pnpm test` | `0` | `pnpm v9.15.9` frozen lockfile verified (`404ms`); workspace recursive build/typecheck/lint/test commands exit `0` |
| `git diff HEAD -- AGENTS.md` | `0` | Empty diff; `AGENTS.md` LF-normalized SHA-256 remains `1fe195214a28f40d3b621a75da55390d8033aadeace35e9aefa4599146b97509` |

- **Artifacts Produced:** Committed deterministic lockfiles `uv.lock` and `pnpm-lock.yaml`.
- **Known Limitations & Security Risks:** `U01` provides library primitives, configuration validation, boundary linters, and log/span ingress scrubbing only. No HTTP API server (`U02`), cryptographic secret broker (`U02`/`U04`), PostgreSQL schema (`U03`), isolated sandbox execution (`U10`), or Astryx frontend (`U05`) exists yet.
- **Blockers & Decision Changes:** Blockers for `U01`: `NONE`. Decision changes: `NONE` (no ADR conflicts encountered). Execution halted cleanly after `U01` awaiting owner dispatch of `U02`.

## P4 execution log — U02 completed (`LOCALLY_VERIFIED`) — 2026-10-27

- **Unit ID & Title:** `U02` — Canonical Domain Contracts (`S-06`..`S-22`), Crypto Primitives & OpenAPI/TS Codegen ([40_EXECUTION_MASTER_PLAN.md](40_EXECUTION_MASTER_PLAN.md)).
- **Owner Approval & Authorization:** Master Plan `PLAN-2026-10-27-v1` approved under [ADR-039](20_DECISIONS_ADR.md); explicit owner authorization granted for `U02` execution only.
- **Requirement, Contract & Test IDs Covered:** Full canonical contract suite `S-01`..`S-22` ([36_CANONICAL_CONTRACTS.md](36_CANONICAL_CONTRACTS.md)), including `auditor` in `S-07` `Membership.role` and the 10-phase `S-18` setup wizard enum (`ADR-038`), `require_baseline=true` invariant (`ADR-031`), `A-18` public minimal liveness (`GET /api/v1/system/health`), `S-03` `application/problem+json` error handlers (`400/401/403/404/409/410/412/413/422/429/500/503`), `1 MiB` request body ceiling (`S-01`), cryptographic foundation for `OPS-03` (versioned AES-256-GCM envelope encryption), `FIX-02` / `SEC-030` (domain-separated Ed25519 signing/verification over canonical JSON with key-ring revocation and trust-domain checks), and `SEC-028` (strict 8-tool `S-20` protocol rejecting retired/privileged tools and path traversal). Release gates `R-01`..`R-15` remain `NOT RUN`.
- **Files Changed / Created / Deleted:**
  - Modified: `.gitignore`, `pyproject.toml`, `uv.lock`, `pnpm-lock.yaml`, `packages/py-contracts/pyproject.toml`, `packages/py-contracts/src/py_contracts/__init__.py`, `apps/control-plane/pyproject.toml`, `apps/control-plane/src/red2pr_control/core/errors.py`, `docs/23_PROGRESS.md`.
  - Deleted superseded placeholder: `packages/py-contracts/tests/.gitkeep`.
  - Created `packages/py-contracts` modules & tests: `packages/py-contracts/src/py_contracts/{iam.py,integrations.py,repairs.py,events.py,tools.py,worker.py,evidence.py,crypto.py,schema_export.py}`, `packages/py-contracts/tests/test_schemas_and_crypto.py`.
  - Created exported JSON Schemas & OpenAPI v1 contract: `contracts/schemas/{s19-event-envelope.v1.schema.json,s20-agent-tool-protocol.v1.schema.json,s21-sandbox-worker.v1.schema.json,s22-evidence-manifest.v1.schema.json}`, `contracts/openapi/openapi.v1.json`.
  - Created FastAPI `/api/v1` shell & contract tests: `apps/control-plane/src/red2pr_control/api/{__init__.py,app.py}`, `apps/control-plane/tests/contract/test_openapi_roundtrip.py`.
  - Created `@red2pr/ts-client` generated TypeScript package & tests: `packages/ts-client/{package.json,tsconfig.json,tsconfig.build.json}`, `packages/ts-client/src/{schema.d.ts,client.ts,index.ts}`, `packages/ts-client/tests/client.test.ts`.
- **Executed Verification Commands & Measured Results:**

| Command executed | Actual exit code | Measured result & evidence |
|---|---|---|
| `uv lock --check` | `0` | `Resolved 51 packages in 2ms`; `uv.lock` synchronized across all workspace members |
| `uv run ruff check .` | `0` | `All checks passed!` across all `packages/` and `apps/` files |
| `uv run mypy --strict packages/ apps/` | `0` | `Success: no issues found in 30 source files` (`pydantic.mypy` strict plugin enabled) |
| `uv run lint-imports` | `0` | `Analyzed 53 files, 130 dependencies. Contracts: 4 kept, 0 broken` |
| `uv run pytest packages/py-contracts/tests/ apps/control-plane/tests/contract/test_openapi_roundtrip.py apps/control-plane/tests/unit/test_config_and_redaction.py -v` | `0` | `52 passed in 1.80s` (`8` `py-contracts` schema/crypto/property/drift suites + `14` FastAPI/OpenAPI/Problem/size-limit contract tests + `30` `U01` regression tests) |
| `pnpm --filter @red2pr/ts-client run codegen && pnpm --filter @red2pr/ts-client build && pnpm --filter @red2pr/ts-client typecheck && pnpm --filter @red2pr/ts-client test` | `0` | `openapi-typescript 7.13.0` generated `src/schema.d.ts` (`0` drift); strict `tsc` build/typecheck exit `0`; `node --test` `3/3 passed` (`125ms`) |
| `pnpm build && pnpm typecheck && pnpm lint && pnpm test` | `0` | Monorepo recursive TypeScript build, strict typecheck, lint, and test gates all exit `0` |
| `git diff HEAD -- AGENTS.md` | `0` | Empty diff; `AGENTS.md` LF-normalized SHA-256 remains `1fe195214a28f40d3b621a75da55390d8033aadeace35e9aefa4599146b97509` |

- **Artifacts Produced:** `contracts/openapi/openapi.v1.json`, `contracts/schemas/s19-event-envelope.v1.schema.json`, `contracts/schemas/s20-agent-tool-protocol.v1.schema.json`, `contracts/schemas/s21-sandbox-worker.v1.schema.json`, `contracts/schemas/s22-evidence-manifest.v1.schema.json`, `packages/ts-client/src/schema.d.ts`, updated `uv.lock` and `pnpm-lock.yaml`.
- **Known Limitations & Security Risks:** `U02` establishes canonical wire schemas, cryptographic primitives, OpenAPI/TypeScript codegen, and `/api/v1/system/health` minimal liveness only. Persistent database tables, RLS policies, transactional outbox, idempotency store, and hash-chained `audit_log` await `U03`; React 19 + Astryx frontend wrappers and SSE cursor reconciler await `U04`; authentication/RBAC/CSRF enforcement awaits `U05`–`U06`.
- **Blockers & Decision Changes:** Blockers for `U02`: `NONE`. Decision changes: `NONE` (all `ADR-031`, `ADR-033`, `ADR-038`, `ADR-039` contracts enforced verbatim). Execution halted cleanly after `U02` awaiting owner dispatch of the next unit.

## P4 execution log — U03 completed (`LOCALLY_VERIFIED`) — 2026-10-27

- **Unit ID & Title:** `U03` — PostgreSQL Schema Spine, RLS Context, Outbox, Idempotency & Audit Hash Chain ([40_EXECUTION_MASTER_PLAN.md](40_EXECUTION_MASTER_PLAN.md)).
- **Owner Approval & Authorization:** Master Plan `PLAN-2026-10-27-v1` approved under [ADR-039](20_DECISIONS_ADR.md); explicit owner authorization granted for `U03` execution only.
- **Requirement, Contract & Test IDs Covered:** Foundation persistence spine ([06_DATA_MODEL.md](06_DATA_MODEL.md)) for `OPS-01` (append-only hash-chained `audit_log` & signed checkpoint verification), `OPS-03` (`Z2` AES-256-GCM envelope-encrypted `SecretBroker` with external `RED2PR_MASTER_KEY_FILE`, AAD tenant/purpose binding, caller capabilities, live KEK rotation, revocation, and automatic `Redactor` canary registration), `JOB-01` (transactional `S-19` `outbox_events` & `FOR UPDATE SKIP LOCKED` + `lease_epoch`-fenced `outbox_claims`), `NFR-01` (PostgreSQL `>= 16` + `fsync = on` durability gate), `NFR-07` (`S-05` `Idempotency-Key` atomic claim/7-day response cache + `>=90d` `effect_tombstones`), `SEC-032` (non-superuser / non-`BYPASSRLS` runtime role, `ENABLE` + `FORCE ROW LEVEL SECURITY`, composite `(workspace_id, id)` tenant FKs, and pooled connection `reset`/`checkout` GUC scrubbing), and `SEC-037` (`AuditCheckpointV1` Ed25519 signing under `DOMAIN_AUDIT_CHECKPOINT_V1` replicated to `ExternalCheckpointStore` + `verify_audit_chain` tamper/truncation detection). Release gates `R-01`..`R-15` remain `NOT RUN`.
- **Files Changed / Created:**
  - Modified: `pyproject.toml`, `uv.lock`, `apps/control-plane/pyproject.toml`, `apps/control-plane/src/red2pr_control/secrets/__init__.py`, `docs/23_PROGRESS.md`.
  - Created Alembic migration spine: `apps/control-plane/alembic.ini`, `apps/control-plane/alembic/{env.py,script.py.mako}`, `apps/control-plane/alembic/versions/0001_foundation_spine.py`.
  - Created persistence, RLS, idempotency & outbox modules: `apps/control-plane/src/red2pr_control/db/{__init__.py,base.py,engine.py,rls.py,idempotency.py,outbox.py}`.
  - Created `Z2` encrypted secret broker: `apps/control-plane/src/red2pr_control/secrets/broker.py`.
  - Created tamper-evident audit hash chain & external checkpoint verifier: `apps/control-plane/src/red2pr_control/analytics_audit/{__init__.py,audit_chain.py}`.
  - Created real PostgreSQL 16 integration & security test suite: `apps/control-plane/tests/integration/test_db_rls_outbox_audit.py`.
- **Executed Verification Commands & Measured Results:**

| Command executed | Actual exit code | Measured result & evidence |
|---|---|---|
| `uv lock --check` | `0` | `Resolved 64 packages in 1ms`; `uv.lock` deterministic and synchronized across all workspace members |
| `uv run ruff check .` | `0` | `All checks passed!` across all `packages/`, `apps/`, and Alembic migration files |
| `uv run mypy --strict packages/ apps/` | `0` | `Success: no issues found in 42 source files` (`pydantic.mypy` strict plugin enabled) |
| `uv run lint-imports` | `0` | `Analyzed 69 files, 210 dependencies. Contracts: 4 kept, 0 broken` (`red2pr_control.db` and `red2pr_control.analytics_audit` added to `control-plane-z1-z2-boundaries` forbidding `Z2` secret/publisher/inference imports) |
| `uv run pytest apps/control-plane/tests/integration/test_db_rls_outbox_audit.py -v` | `0` | `6 passed in 13.62s` against real PostgreSQL `16.2` (`fsync=on`): `0001_foundation_spine` `upgrade -> downgrade -> upgrade` reversibility & singleton guard, `SEC-032` non-`BYPASSRLS` role + single-connection pool reuse + hostile session-GUC scrub + composite tenant FK rejection, atomic domain+outbox+audit rollback & `lease_epoch` fencing + `dead_letter`, 10-way concurrent `S-05` idempotency race + `409` payload mismatch + `+8d` cache purge with `>=90d` `effect_tombstones` anti-replay, `Z2` `SecretBroker` AAD transplant defense + `v1->v2` KEK rotation + revocation + canary redaction, and `SEC-037` append-only triggers + row-rewrite/tail-truncation/checkpoint-forgery detection |
| `uv run pytest -v` | `0` | `58 passed in 14.28s` (`U01` + `U02` + `U03` full Python regression suite) |
| `pnpm build && pnpm typecheck && pnpm lint && pnpm test` | `0` | `@red2pr/ts-client` build/typecheck/lint/test `3/3 passed` (`106ms`) |
| `git diff HEAD -- AGENTS.md` | `0` | Empty diff; `AGENTS.md` LF-normalized SHA-256 remains `1fe195214a28f40d3b621a75da55390d8033aadeace35e9aefa4599146b97509` |

- **Artifacts Produced:** Reversible expand-phase Alembic migration `apps/control-plane/alembic/versions/0001_foundation_spine.py` (`10` RLS-enforced tables) and updated `uv.lock`.
- **Known Limitations & Security Risks:** `U03` delivers the foundational PostgreSQL 16 schema spine (`10` tables), RLS session/pool guards, `S-05` idempotency/tombstone store, `S-19` transactional outbox, `Z2` `SecretBroker`, and `SEC-037` audit hash chain/checkpoint verifier. Domain tables for users/sessions/RBAC (`U05`–`U06`), repositories/webhooks (`U08`–`U09`), repair sessions/sandbox jobs (`U10`–`U15`), notifications (`U19`), and HTTP API persistence wiring are scheduled in their respective downstream units. Local integration tests execute against disposable real PostgreSQL `16.2` (`pgserver`, `fsync=on`) and support external `RED2PR_TEST_ADMIN_DATABASE_URL` overrides for containerized CI gates.
- **Blockers & Decision Changes:** Blockers for `U03`: `NONE`. Decision changes: `NONE` (all `ADR-030`, `ADR-033`, `ADR-035`, `ADR-039` invariants preserved verbatim). Execution halted cleanly after `U03` awaiting owner dispatch of the next unit.

## P4 execution log — U04 completed (`LOCALLY_VERIFIED`) — 2026-10-27

- **Unit ID & Title:** `U04` — Frontend Foundation: React 19 + Vite + Pinned Astryx Wrappers, Theme Tokens & SSE Client ([40_EXECUTION_MASTER_PLAN.md](40_EXECUTION_MASTER_PLAN.md)).
- **Owner Approval & Authorization:** Master Plan `PLAN-2026-10-27-v1` approved under [ADR-039](20_DECISIONS_ADR.md); explicit owner authorization granted for `U04` execution only, plus explicit owner approval of `CR-001` / [ADR-040](20_DECISIONS_ADR.md) pinning exact stable `@astryxdesign/core@0.7.4` + `@astryxdesign/theme-neutral@0.7.4` (since non-prerelease `0.7.5` is unpublished `HTTP 404` on npm while `0.7.4` is `latest` stable with identical component prop contracts).
- **Requirement, Contract & Test IDs Covered:** `UI-01` (`P0`, `T-UI-01-P`, `T-UI-01-N`), `UI-02` (`P0`, `T-UI-02-P`, `T-UI-02-N`), `FE-01`, `FE-04`, `FE-05` ([29_FRONTEND_ASTRYX.md](29_FRONTEND_ASTRYX.md)), `UX-03` ([15_UX_DESIGN_SYSTEM.md](15_UX_DESIGN_SYSTEM.md)), `NFR-11` (`< 350 KiB` gzipped initial JS bundle), `NFR-12` (`50,000` log/diff lines virtualized in `< 2 s` with paged keyboard fallback), `SEC-032` (workspace-scoped SSE cursor/dedup state purge on tenant switch and `403`/`identity.permission_revoked`), `SEC-040` (ANSI CSI/OSC-52/OSC-8, C0 control, Trojan-Source bidi, and `javascript:`/`data:`/`vbscript:`/`file:` sanitization without `dangerouslySetInnerHTML`), `OQ-20` (`AGENTS.md` byte-identical preservation), and `S-19` `EventEnvelope` SSE stream reconciliation (`Last-Event-ID`, `event_id` deduplication, `aggregate_version` gap detection, `410` cursor-expiry snapshot refetch, and `15 s` missed-heartbeat recovery). Satisfies Wave `W0` Integration Gate `IG-01`. Release gates `R-01`..`R-15` remain `NOT RUN`.
- **Files Changed / Created:**
  - Modified: `pnpm-lock.yaml`, `docs/20_DECISIONS_ADR.md`, `docs/29_FRONTEND_ASTRYX.md`, `docs/40_EXECUTION_MASTER_PLAN.md`, `docs/23_PROGRESS.md`.
  - Created `apps/web` configuration & entrypoint: `apps/web/{package.json,tsconfig.json,vite.config.ts,eslint.config.js,index.html}`, `apps/web/src/{vite-env.d.ts,main.tsx}`, `apps/web/src/app/{App.tsx,AppErrorBoundary.tsx}`, `apps/web/src/shared/test/setup.ts`.
  - Created `apps/web` i18n, theme & API providers: `apps/web/src/shared/i18n/{messages.en.ts,I18nProvider.tsx,index.ts}`, `apps/web/src/shared/theme/{tokens.css,ThemeProvider.tsx,index.ts}`, `apps/web/src/shared/api/{ApiClientProvider.tsx,index.ts}`.
  - Created `apps/web` isolated Astryx wrappers, unified UX states & sanitized viewers: `apps/web/src/shared/ui/{sanitizeText.ts,Button.tsx,Dialog.tsx,Table.tsx,StateViews.tsx,AppShell.tsx,SafeLogViewer.tsx,SafeDiffViewer.tsx,ChartWithTableFallback.tsx,index.ts}`.
  - Created `apps/web` deterministic `S-19` SSE client: `apps/web/src/shared/events/useWorkspaceSse.ts`.
  - Created `apps/web` verification suites: `apps/web/src/shared/ui/__tests__/{astryxWrappersAndStates.test.tsx,securityAndScaleViewers.test.tsx,useWorkspaceSse.test.tsx,bundleAndBoundaryIntegrity.test.ts}`.
- **Executed Verification Commands & Measured Results:**

| Command executed | Actual exit code | Measured result & evidence |
|---|---|---|
| `pnpm --frozen-lockfile install` | `0` | `Scope: all 3 workspace projects. Lockfile is up to date` (`830ms`, `pnpm v9.15.9`) |
| `pnpm --filter @red2pr/web typecheck` | `0` | `tsc --noEmit` (`strict: true`, `noUncheckedIndexedAccess: true`) passed with `0` errors |
| `pnpm --filter @red2pr/web lint` | `0` | `eslint . --max-warnings 0` passed (`0` errors, `0` warnings; `FE-05` `@astryxdesign/*` import boundary & `SEC-040` `dangerouslySetInnerHTML`/`no-eval` enforced) |
| `pnpm --filter @red2pr/web build` | `0` | `2461 modules transformed`, built in `3.77s`; `0` `.map` files in `dist/`; total gzipped JS = `190.28 kB` (`<< 350 KiB` `NFR-11` ceiling) |
| `pnpm --filter @red2pr/web run test '--' --run` | `0` | `4 passed (4)` suites, `21 passed (21)` tests (`0` stderr warnings): `axe-core` WCAG 2.2 AA `0` violations across light & dark themes, `Dialog` Tab trap + `Escape` + `required` `alertdialog`, `Table` `plugins` record + sorting + pagination, all `15` UX states, `UX-03` proof distinction, `50,000` log lines (`~315ms`) & `50,000` diff lines (`< 50ms`) `<< 2000ms` (`NFR-12`), XSS/ANSI/OSC-52/bidi/URL sanitization (`SEC-040`), `S-19` SSE dedup/gap/`410`/`15s` heartbeat/`403` tenant purge (`SEC-032`), and `AGENTS.md` SHA-256 + bundle checks |
| `pnpm build && pnpm typecheck && pnpm lint && pnpm test` | `0` | Full monorepo TypeScript build, strict typecheck, lint, and test gates passed (`3` `@red2pr/ts-client` + `21` `@red2pr/web` = `24` TS tests) |
| `uv lock --check && uv run ruff check . && uv run mypy --strict packages/ apps/ && uv run lint-imports && uv run pytest -q` | `0` | `64` Python packages locked, `ruff` clean, `mypy --strict` clean (`42` files), `lint-imports` `4 kept, 0 broken`, `pytest` `58 passed in 18.38s` |
| `git diff HEAD -- AGENTS.md` | `0` | Empty diff; `AGENTS.md` LF-normalized SHA-256 remains `1fe195214a28f40d3b621a75da55390d8033aadeace35e9aefa4599146b97509` |

- **Artifacts Produced:** Updated deterministic lockfile `pnpm-lock.yaml` and verified production bundle configuration in `apps/web/vite.config.ts` (`dist/` gitignored).
- **Known Limitations & Security Risks:** `U04` establishes the React 19 + Vite + Astryx `0.7.4` frontend shell foundation, isolated component wrappers, theme tokens, sanitized `50k` log/diff viewers, chart+table fallback, and `S-19` SSE cursor reconciler (`LOCALLY_VERIFIED` in `jsdom` + Node unit/contract suites). The 21 domain product screens (`UI-S01`..`UI-S21`) are scheduled across downstream units (`U07`, `U21`–`U27`), and real Chromium/Playwright browser certification for `R-11` (`UI-01`, `UI-02`, `NFR-11`, `NFR-12`) awaits Wave `W6` (`U34`).
- **Blockers & Decision Changes:** Blockers for `U04`: `NONE`. Decision changes: `CR-001` / [ADR-040](20_DECISIONS_ADR.md) approved by owner prior to coding (`@astryxdesign/core@0.7.4` + `@astryxdesign/theme-neutral@0.7.4` exact pin). Wave `W0` (`U01`–`U04`) and Integration Gate `IG-01` are now satisfied. Execution halted cleanly after `U04` awaiting owner dispatch of the next unit.

[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
