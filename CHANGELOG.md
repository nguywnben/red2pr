# Changelog

All notable changes to Red2PR are documented in this file.

This project follows [Semantic Versioning 2.0.0](https://semver.org/):
- **`v0.1.0-beta.x`**: Early-access beta releases (implemented `U01`–`U30` core platform, UI/UX console, and local/fixture verification; Wave 6 production certification deferred).
- **`v0.1.0`**: Initial stable early-adopter milestone.
- **`v1.0.0`**: Production-certified release gated on Wave 6 (`U31`–`U36`), `R-01`–`R-15` release evidence, `P5` independent audit, and `ADR-021` licensing sign-off.

> *Note:* Canonical REST API and JSON Schema contracts (`contracts/openapi/openapi.v1.json`) carry target specification version `1.0.0` independently of package distribution versions (`0.1.0`).

---

## [0.1.0-beta.1] - 2026-11-04 *(Pre-Release Candidate — Pending Owner Tag Approval)*

### Added
- **Foundations, Identity & Multi-Tenant Governance (`U01`–`U09`):**
  - Canonical Pydantic v2 contracts (`packages/py-contracts`, `S-01`–`S-22`), OpenAPI 3.1 export (`openapi.v1.json`), and generated TypeScript client (`@red2pr/ts-client`).
  - PostgreSQL 16 schema (`0001`–`0025`) with `FORCE ROW LEVEL SECURITY` (`red2pr_app` role), transactional outbox, idempotency tombstones (`ADR-044`), and SHA-256 hash-chained audit logs.
  - Local authentication, TOTP MFA + recovery codes, fresh step-up verification, workspace RBAC (`admin`, `maintainer`, `reviewer`, `viewer`, `auditor`), break-glass owner grants, and PKCE (`S256`) OIDC federation (`ADR-046`–`ADR-048`).
  - `Z2` `SecretBroker` (`AES-256-GCM` envelope encryption with key rotation) and `ADR-037` SSRF-hardened outbound egress policy engine.
- **Source Integrations, Triage & Isolated Reproduction (`U10`–`U15`):**
  - GitHub App and GitLab (`16.11+`) adapters supporting webhook signature verification, resumable 60-second local polling, missed-event reconciliation, and optional customer-operated webhook relays (`ADR-049`).
  - Repository catalog with `Monitor`, `Approval`, and `Auto-Repair` modes, immutable policy revisions, dry-run policy simulator, and `SEC-031` CI workflow hazard scanning.
  - Encrypted artifact store (`LocalEncryptedArtifactStore` and SigV4 `S3CompatibleArtifactStore`, `ADR-041`), redacted CI job log chunking (`redaction-v1`), and flaky-history tracking.
  - Zero-control-import `Z3` `red2pr-worker` supervisor (`oci_rootless`, `gvisor`, `microvm` profiles) with mTLS lease fencing and Sandbox A/B baseline reproduction.
- **Meta Muse Reasoning, Deterministic Proof & Draft PR Publishing (`U16`–`U21`):**
  - Multi-stage diagnosis and bounded patch synthesis integrating allowlisted Meta chat models (`meta/muse-spark-1.3`, `meta/muse-wonder-1.0`) with outbound repository consent, optional consented model fallback, atomic session + daily USD token budgets, and LiteLLM model-price catalog caching (`ADR-051`).
  - Deterministic verifier (`V-01`–`V-07`) enforcing baseline red reproduction, patched green target + broader suite runs, static checks, protected-path/diff limits, anti-test-weakening guards, and Ed25519-signed `EvidenceManifestV1` (`ADR-043`).
  - Human-in-the-loop approval service, idempotent Draft PR/MR publisher saga (never auto-merging), and exact-SHA remote CI check reconciliation (`V-08`, `ADR-042`).
- **Web Console, Multi-Channel Operations & Quick Start (`U22`–`U30` + UX Rebuild & Polish):**
  - Complete 21-screen React 19 + TypeScript + Vite + Meta Astryx (`0.7.4`) Neutral-theme web console (`UI-S01`–`UI-S21`) with SSE live updates, responsive layouts, Light/Dark themes, and `axe-core` accessibility verification.
  - Optional Telegram bot notifications with web-confirmed approval links, outbound signed webhooks, and read/intent-scoped MCP `2025-11-25` Streamable HTTP adapter (`ADR-050`).
  - Unified `red2pr` operator CLI (`status`, `doctor`, `setup --bootstrap-link`, `logs`, `worker`, `config`, `repair`, `backup`, `restore`, `update`, `uninstall`), signed release manifest validator (`deploy/security/sign_release.py`), Compose stacks, and one-command local source quickstart (`scripts/quickstart.ps1`, `scripts/quickstart.sh`, `scripts/dev_stack.py`).

### Fixed
- Stabilized single-origin SPA + FastAPI runtime serving (`red2pr-control`), Windows `SelectorEventLoop` async PostgreSQL compatibility, `ci_run.triage` durable intake, `policy_gate` → `publishing` / `rejected` / `cancelled` state transitions, dedicated per-session budget isolation on retries, and Setup Wizard Phase 6/7 synchronization.

### Known Limitations in `0.1.0-beta.1`
- Wave 6 (`U31`–`U36`: benchmark calibration, Chaos/DR drills, live multi-OS isolation host certification, SBOM/provenance publication, and `P5` independent audit) is deferred to the `v1.0.0` release track.
- Final public software license selection remains tracked under `ADR-021` (`OPEN`) pending repository owner sign-off.
