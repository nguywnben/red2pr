# Red2PR Quick Start, Configuration & User Guide (`v0.1.0-beta.1`)

This guide covers installing Red2PR locally, completing the 10-phase Setup Wizard, connecting GitHub or GitLab repositories, configuring Meta Muse inference and USD budgets, reviewing repair evidence, and operating the `red2pr` CLI.

> **Status note:** `v0.1.0-beta.1` is an early-access pre-release covering implemented units `U01`–`U30` and the full 21-screen React 19 + Meta Astryx web console. Wave 6 (`U31`–`U36`) OS/isolation host certification and `v1.0.0` production sign-off remain deferred.

---

## 1. Prerequisites & System Requirements

### Local Source Quick Start (Recommended for Evaluation & Demos)
- **OS:** Windows 11 x86_64 (PowerShell), Ubuntu 22.04+/Debian 12+ (`x86_64` / `arm64`), or macOS 15+ (`arm64`)
- **Resources:** Minimum 4 CPU cores, 8 GB RAM, and 10 GB free disk space
- **Tooling:**
  - Git
  - Python `3.12.x` (`>=3.12,<3.13`) and [`uv`](https://docs.astral.sh/uv/)
  - Node.js `>= 22.12.0` and `pnpm` `9.15.x` (`corepack enable && corepack prepare pnpm@9.15.9 --activate`)

### Container Compose Topologies (`deploy/compose/`)
- Docker Engine with Compose v2 (`docker compose`) or Podman (`podman compose`)
- OpenSSL 3.x and Python 3.12+ on the host when running `deploy/install/install.sh` (offline Ed25519 manifest verification)
- For `server` mode: a public FQDN with DNS pointing to the host for Caddy TLS termination

---

## 2. Installation & First Launch

### 2.1 One-Command Local Launch from Source

**Windows (PowerShell):**
```powershell
git clone https://github.com/nguywnben/red2pr.git
cd red2pr
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1
```

**Linux / macOS (Bash):**
```bash
git clone https://github.com/nguywnben/red2pr.git
cd red2pr
./scripts/quickstart.sh
```

**What the quickstart script automates safely:**
1. Verifies Node.js, `pnpm`, and Python 3.12 (`.venv`); runs `uv sync --frozen` and `pnpm install --frozen-lockfile` only if dependencies are missing.
2. Builds `@red2pr/ts-client` and `@red2pr/web` (`apps/web/dist`) if not already built.
3. Initializes non-destructive instance state under `.local-data/red2pr` (configurable via `--data-dir` / `-DataDir` or `RED2PR_DATA_DIR`), generating `master.key`, `bootstrap_issuer`, and `app_db_password` only when absent. Existing files are **never overwritten**.
4. Starts a confined PostgreSQL 16 instance (or connects to `RED2PR_ADMIN_DATABASE_URL` / `RED2PR_DATABASE_URL` if provided), runs Alembic migrations `0001..0025`, and provisions the least-privilege `red2pr_app` RLS database role.
5. Starts the single-origin FastAPI + Astryx SPA server on `http://127.0.0.1:4280` (configurable via `--port` / `-Port` or `RED2PR_HTTP_PORT`).
6. Issues a **one-use 15-minute setup URL** (`http://127.0.0.1:4280/setup#bootstrap_token=...`) to claim the instance owner account. The URL fragment (`#bootstrap_token=...`) stays in browser memory and is never sent in HTTP request lines or server access logs (`ADR-045`).

### 2.2 Preflight & Disposable Smoke Testing

Before starting a persistent instance, you can validate wiring or run a self-cleaning end-to-end smoke test on an ephemeral loopback port:

```powershell
# Windows PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -CheckOnly
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -SmokeTest
```

```bash
# Linux / macOS Bash
./scripts/quickstart.sh --check-only
./scripts/quickstart.sh --smoke-test
```

### 2.3 Signed Container Installer (`deploy/install/`)

For containerized deployments using a signed release bundle (`release-manifest.json` + `release-manifest.sig` verified against `deploy/install/trust-root.pub`):

```bash
# Verify Ed25519 signature and manifest schema only (offline)
./deploy/install/install.sh --manifest release-manifest.json --signature release-manifest.sig --verify-only

# Run full OS/resource/port/Compose preflight without writing files
./deploy/install/install.sh --mode local --manifest release-manifest.json --signature release-manifest.sig --dry-run
```

On Windows hosts using WSL2, `deploy/install/install.ps1` validates the Windows host build/resources and offline trust root, persists a non-secret reboot checkpoint (`install-state.json`) if WSL2 setup requires a restart (`exit 3`), and resumes cleanly with `-Resume`.

---

## 3. Initial 10-Phase Setup Wizard (`/setup`)

Open the one-use bootstrap link in your browser to walk through the durable, resumable 10-phase wizard (`UI-S01`):

1. **`owner_claim`** — Claim the initial instance owner account using the one-use bootstrap token, configure a strong password, and enroll TOTP MFA + recovery codes.
2. **`deployment_topology`** — Confirm `local` (`http://127.0.0.1:4280`, polling-first) or `server` (`https://<fqdn>`, webhook + reconciliation) mode.
3. **`storage_and_keys`** — Verify `AES-256-GCM` master key custody and encrypted artifact storage (`local` directory or `ADR-037`-allowlisted S3-compatible object store).
4. **`workspace_bootstrap`** — Create your first tenant workspace (e.g., `acme`) and initial local admin anchor (`ADR-048`).
5. **`source_provider`** — Connect a GitHub App or GitLab instance (`16.11+`), or skip temporarily to start in unlinked setup state.
6. **`model_consent`** — Configure outbound data-sharing consent, workspace daily USD cap, and per-session USD cap (synced directly to the workspace model configuration and budget ledger).
7. **`worker_readiness`** — Select and verify your worker isolation profile (`oci_rootless`, `gvisor`, or `microvm` / remote attested worker).
8. **`repository_policy`** — Establish default repository mode (`Monitor` recommended initially) and protected-path defaults.
9. **`notifications`** — Optionally configure Telegram bot notifications or outbound webhooks, or leave external channels disabled.
10. **`readiness_review`** — Inspect the split readiness verdict:
    - **`ready_monitor`**: Identity, database, and source ingestion are operational.
    - **`ready_repair`**: Consent, Meta Model API credential + pricing, budget accounts, and eligible `Z3` worker checks have all passed.

---

## 4. Connecting GitHub & GitLab (`Integrations`)

Navigate to **Work → Repositories** or **Operations → Integrations** (`/w/<workspace>/integrations`):

- **GitHub App:** Register or connect a GitHub App with least-privilege permissions (`Actions: read`, `Checks: read`, `Contents: write` for repair branches only, `Metadata: read`, `Pull requests: write`). Webhooks validate `X-Hub-Signature-256` over raw request bytes.
- **GitLab (`16.11+`):** Configure a GitLab instance URL (registered in `ADR-037` endpoint allowlist if self-hosted) and project/group token + webhook secret token.
- **Local / NAT Polling & Reconciliation:** In `local` mode where public GitHub/GitLab webhooks cannot reach `127.0.0.1`, Red2PR's resumable 60-second poller (with 5-minute overlap window, ETag caching, and `429 Retry-After` backoff) ingests failed CI runs automatically.
- **Optional Customer-Operated Webhook Relay (`ADR-049`):** Workspace admins can connect a customer-operated outbound WebSocket relay (`wss://`) with pinned signature verification; Red2PR never routes private webhooks through a shared third-party relay.

---

## 5. Meta Model API & Budget Governance (`Models` & `Agents`)

Navigate to **Operations → Models** (`/w/<workspace>/models`):

1. **Rotate Meta API Key:** Requires fresh TOTP step-up. Credentials are sealed inside `Z2` `SecretBroker` (`AES-256-GCM`) and never returned in API responses or exposed to `Z3` sandboxes.
2. **Allowlisted Models:**
   - `meta/muse-spark-1.3` — Default primary model for CI triage, root-cause diagnosis, and standard single/few-file patch synthesis.
   - `meta/muse-wonder-1.0` — Optional model for complex multi-file synthesis when enabled on the workspace agent profile.
3. **Pricing Catalog & Cost Caps (`ADR-051`):**
   - Red2PR refreshes allowlisted Meta chat model token rates from the LiteLLM pricing catalog (`pricing_catalog` HTTPS egress, 6-hour ETag refresh, 48-hour freshness bound, `Decimal` ceiling conversion to USD per 1M tokens), falling back to workspace-configured rates if the catalog has no fresh entry.
   - Unpriced or zero-priced models **fail closed** and block paid inference rather than running unbounded.
   - Every model call atomically reserves estimated spend against **both** the dedicated `repair_session` budget account and the `workspace_daily` budget account before outbound execution, settling actual token usage on completion.

---

## 6. Repair Workflow, Evidence & Approvals

### 6.1 Operating Modes & `SEC-031` Guardrails
Each repository operates in one of three modes (**Work → Repositories**):
- **`Monitor`:** Ingests CI runs, redacts logs, and classifies failures without running sandboxes or proposing patches.
- **`Approval`:** Runs diagnosis, isolated Sandbox A/B reproduction, and `V-01`–`V-07` verification, then pauses at `policy_gate` / `awaiting_approval` until an authorized reviewer approves Draft PR publication.
- **`Auto-Repair`:** Publishes a **Draft PR/MR** automatically *only* when all `V-01`–`V-07` deterministic gates pass, no protected paths/tests were modified, and `SEC-031` workflow hazard status is `clean`. **Draft PRs are never auto-merged.**

### 6.2 Understanding Proof Grades & Gates (`Repair Detail`)
Every repair session displays three independent status dimensions:
- **Phase (`state`):** Lifecycle stage across the canonical 25-state repair state machine (e.g., `triaging`, `diagnosing`, `reproducing`, `patching`, `verifying`, `policy_gate`, `awaiting_approval`, `publishing`, `remote_verified`).
- **Proof Grade (`proof_grade`):**
  - `none`: Diagnosis only or reproduction not yet confirmed.
  - `baseline_confirmed`: Sandbox A deterministically reproduced the CI failure at `base_sha`.
  - `locally_verified`: Sandbox B passed all local gates (`V-01` Baseline Red Repro, `V-02` Patched Target Green, `V-03` Broader Suite, `V-04` Static Lint/Typecheck, `V-05` Policy & Protected Paths, `V-06` No Test Deletion/Weakening, `V-07` Ed25519-Signed `EvidenceManifestV1`).
  - `remotely_verified`: Provider CI (`V-08`) passed every configured required check name on the exact published commit SHA (`ADR-042`).
- **Remote Status (`remote_status`):** `not_published`, `pending`, `passed`, `failed`, or `unknown` (when no required check names are configured on the repository policy).

### 6.3 Reviewing, Approving & Reconciling Draft PRs
- **Approvals Inbox (`/w/<workspace>/approvals`):** Inspect diff scope, signed verification summary, and policy escalation reasons; approve or reject with fresh step-up verification and idempotency protection. Optional Telegram or MCP (`ADR-050`) approval intents always redirect to an authenticated web confirmation screen and cannot bypass RBAC or step-up.
- **Pull Requests (`/w/<workspace>/prs`):** View published `red2pr/repair/*` branches, open the provider Draft PR/MR, inspect per-check exact-SHA observations, and trigger `Reconcile remote CI` if a webhook delivery was delayed or interrupted.

---

## 7. Unified CLI Reference (`red2pr`)

Set `RED2PR_API_URL` to your local loopback (`http://127.0.0.1:4280`) or HTTPS server URL:

| Command | Purpose |
|---|---|
| `red2pr setup --bootstrap-link` | Issue a one-use 15-minute `/setup#bootstrap_token=...` owner claim URL over loopback (`ADR-045`). |
| `red2pr status` | Inspect application version, schema revision, maintenance state, and component readiness. |
| `red2pr doctor` | Run read-only diagnostic checks across database, storage, worker fleet, and configuration. |
| `red2pr logs` | Read bounded, secret-redacted local operational log lines. |
| `red2pr worker` | List registered workers, isolation profiles, lease states, and fleet attestation health. |
| `red2pr config` | Validate instance configuration and policy schemas without printing secrets. |
| `red2pr repair` | Reconcile orphaned queue tasks or interrupted publication intents. |
| `red2pr backup` / `red2pr restore` | Create or dry-run/verify encrypted database + artifact snapshots with manifest integrity checks. |
| `red2pr start` / `stop` / `restart` | Coordinate graceful maintenance drain and lifecycle transitions. |
| `red2pr update` | Validate target release schema and worker protocol compatibility before upgrade. |
| `red2pr uninstall` | Stop managed services while preserving instance data unless explicit purge is confirmed. |

**Exit Codes:** `0` OK · `2` Usage/Config error · `3` Auth/Step-up required · `4` Prerequisite/Unsupported · `5` Runtime/Dependency degraded · `6` Verification/Backup integrity failure · `7` Partial/Unknown outcome · `8` Conflict/Version mismatch.

---

## 8. Troubleshooting

- **Port `4280` is already in use:** Pass a custom port to quickstart (`.\scripts\quickstart.ps1 -Port 4290` or `./scripts/quickstart.sh --port 4290`).
- **Bootstrap setup link expired or returns `409`:** Bootstrap tokens expire after 15 minutes and are single-use. If the owner has not been claimed yet, re-issue one locally via `RED2PR_API_URL=http://127.0.0.1:4280 RED2PR_DATA_DIR=.local-data/red2pr uv run red2pr setup --bootstrap-link`. If `409` is returned, the instance owner is already claimed—sign in at `/login` or use `/login/recovery`.
- **Repository cannot switch to `Auto-Repair`:** Check `Readiness Gates` on the repository detail page. `Auto-Repair` is blocked fail-closed if `SEC-031` flagged a workflow hazard, outbound inference consent is missing, or no attested isolated worker matches the workspace trust domain.
- **Model call blocked as `unpriced` or `budget_exceeded`:** Ensure a valid Meta API key is rotated under **Operations → Models**, confirm per-1M-token fallback rates or LiteLLM catalog connectivity (`pricing_catalog`), and verify sufficient remaining balance on both the session cap and daily workspace cap.
- **Windows `psycopg` event loop errors when embedding custom scripts:** Red2PR's `red2pr-control` and `scripts/dev_stack.py` automatically configure `WindowsSelectorEventLoopPolicy` / `asyncio.SelectorEventLoop`. Always launch via `quickstart.ps1` or `red2pr-control` rather than bare `uvicorn` without a selector loop factory on Windows.
