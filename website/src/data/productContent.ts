export const GITHUB_REPO_URL = "https://github.com/nguywnben/red2pr";

export const DOC_LINKS = {
  repo: GITHUB_REPO_URL,
  latestRelease: `${GITHUB_REPO_URL}/releases/tag/v0.1.0-beta.1`,
  license: `${GITHUB_REPO_URL}/blob/main/LICENSE`,
  ghcrControl: "https://github.com/users/nguywnben/packages/container/package/red2pr-control",
  ghcrWorker: "https://github.com/users/nguywnben/packages/container/package/red2pr-worker",
  quickstartGuide: `${GITHUB_REPO_URL}/blob/main/docs/QUICKSTART_AND_USER_GUIDE.md`,
  specIndex: `${GITHUB_REPO_URL}/blob/main/docs/00_INDEX.md`,
  architecture: `${GITHUB_REPO_URL}/blob/main/docs/05_SYSTEM_ARCHITECTURE.md`,
  metaAgent: `${GITHUB_REPO_URL}/blob/main/docs/09_AI_AGENT_META.md`,
  verification: `${GITHUB_REPO_URL}/blob/main/docs/11_REPAIR_VERIFICATION.md`,
  securityDoc: `${GITHUB_REPO_URL}/blob/main/docs/14_SECURITY_IDENTITY.md`,
  cliOps: `${GITHUB_REPO_URL}/blob/main/docs/16_OPERATIONS_CLI.md`,
  adrDecisions: `${GITHUB_REPO_URL}/blob/main/docs/20_DECISIONS_ADR.md`,
  progressLedger: `${GITHUB_REPO_URL}/blob/main/docs/23_PROGRESS.md`,
  securityPolicy: `${GITHUB_REPO_URL}/blob/main/SECURITY.md`,
  contributing: `${GITHUB_REPO_URL}/blob/main/CONTRIBUTING.md`,
  changelog: `${GITHUB_REPO_URL}/blob/main/CHANGELOG.md`,
} as const;

export interface HeroPillar {
  readonly code: string;
  readonly title: string;
  readonly detail: string;
}

export const HERO_PILLARS: readonly HeroPillar[] = [
  {
    code: "V-01 – V-08",
    title: "Red-to-green & exact-SHA proof",
    detail: "Baseline failure confirmed before any candidate diff can advance.",
  },
  {
    code: "Zone Z3",
    title: "Zero-credential sandboxes",
    detail: "No GitHub/GitLab tokens, Meta keys, or host Docker sockets in execution.",
  },
  {
    code: "Ed25519",
    title: "Signed EvidenceManifestV1",
    detail: "Cryptographic verification verdicts—language models never self-certify.",
  },
  {
    code: "Draft PRs Only",
    title: "Human-reviewed publication",
    detail: "Never auto-merges or bypasses repository branch protection.",
  },
];

export interface ContrastRow {
  readonly dimension: string;
  readonly conventionalBot: string;
  readonly red2prApproach: string;
  readonly guardrailRef: string;
}

export const CONTRAST_ROWS: readonly ContrastRow[] = [
  {
    dimension: "Baseline reproduction",
    conventionalBot:
      "Guesses patches directly from truncated CI logs without ever reproducing the failing commit.",
    red2prApproach:
      "Checks out the exact base SHA in Sandbox A and confirms deterministic red failure. Unreproduced runs stop at diagnosis.",
    guardrailRef: "ADR-031 · V-01",
  },
  {
    dimension: "Test suite integrity",
    conventionalBot:
      "Deletes assertions, skips failing cases, or loosens snapshots merely to force a green exit code.",
    red2prApproach:
      "Enforces AST anti-test-weakening checks and protected-path rules before signing local proof.",
    guardrailRef: "V-05 · V-06",
  },
  {
    dimension: "Secrets & outbound inference",
    conventionalBot:
      "Forwards raw build logs, tokens, and private source context to external APIs without cost ceilings.",
    red2prApproach:
      "Runs versioned secret redaction (redaction-v1), checks per-repository outbound consent, and reserves atomic USD token budgets.",
    guardrailRef: "SEC-017 · ADR-051",
  },
  {
    dimension: "Transient & infra failures",
    conventionalBot:
      "Hallucinates unrelated code edits during registry outages, flaky tests, or expired credentials.",
    red2prApproach:
      "Classifies flaky (TRI-03), credential, runner, and unsupported failures explicitly—abstaining instead of fabricating diffs.",
    guardrailRef: "TRI-03 · AGT-01",
  },
  {
    dimension: "Branch & merge safety",
    conventionalBot:
      "Pushes commits to active branches or auto-merges before exact-commit remote checks finish.",
    red2prApproach:
      "Opens Draft PRs/MRs on isolated red2pr/repair/* branches after policy or TOTP step-up approval, then reconciles V-08 on the exact head SHA.",
    guardrailRef: "ADR-042 · V-08",
  },
];

export interface PipelineStage {
  readonly step: string;
  readonly id: string;
  readonly shortTitle: string;
  readonly title: string;
  readonly proofGrade: string;
  readonly proofTone: "neutral" | "info" | "success";
  readonly summary: string;
  readonly invariant: string;
  readonly abstentionPath: string;
  readonly artifacts: readonly string[];
}

export const PIPELINE_STAGES: readonly PipelineStage[] = [
  {
    step: "01",
    id: "ingest",
    shortTitle: "Ingest & Redact",
    title: "Webhook or polling intake with pre-storage secret scrubbing",
    proofGrade: "proof: none",
    proofTone: "neutral",
    summary:
      "Verified GitHub App and GitLab (16.11+) webhooks—or a resumable 60-second local poller—collect failed workflow runs and job logs. Logs pass through redaction-v1 before encrypted storage or display, while YAML scanners flag unsafe pull_request_target hazards.",
    invariant: "Secrets are scrubbed before persistence, UI rendering, or model prompts (SEC-017, SEC-031).",
    abstentionPath:
      "Repositories in Monitor mode or flagged for SEC-031 hazards record diagnostics without scheduling autonomous repair.",
    artifacts: ["HMAC / Standard Webhooks check", "redaction-v1 log chunks", "SEC-031 workflow posture"],
  },
  {
    step: "02",
    id: "diagnose",
    shortTitle: "Meta Muse Diagnosis",
    title: "Structured root-cause localization under atomic USD budgets",
    proofGrade: "proof: none",
    proofTone: "neutral",
    summary:
      "Meta Muse Spark (meta/muse-spark-1.3) analyzes redacted logs and allowed repository slices to localize the failure cause and surface explicit uncertainties, with optional consented escalation to Meta Muse Wonder (meta/muse-wonder-1.0) for complex multi-file faults.",
    invariant: "Requires active repository inference consent and row-locked PostgreSQL USD budget reservation (ADR-051).",
    abstentionPath:
      "Flaky, infrastructure, credential, or unpriced-model conditions abstain cleanly rather than guessing a patch.",
    artifacts: ["Structured root-cause report", "Explicit uncertainty notes", "S-17 usage ledger entry"],
  },
  {
    step: "03",
    id: "repro",
    shortTitle: "Sandbox A Repro",
    title: "Zero-credential baseline reproduction at the exact base SHA",
    proofGrade: "proof: baseline_confirmed",
    proofTone: "info",
    summary:
      "An mTLS-enrolled Zone Z3 worker materializes a .git-sanitized archive at base_sha inside an isolated runner profile and executes allowlisted test commands to confirm deterministic red failure (V-01) before any candidate patch is evaluated.",
    invariant: "Sandbox A/B receives zero source-write tokens, zero Meta keys, and no host Docker socket (ADR-016).",
    abstentionPath:
      "If Sandbox A passes or cannot deterministically reproduce (repro_unconfirmed), publication is hard-blocked (ADR-031).",
    artifacts: ["Fidelity report (F1–F3)", "V-01 baseline failure receipt", "Read-only tenant cache check"],
  },
  {
    step: "04",
    id: "verify",
    shortTitle: "Gates V-02 – V-07",
    title: "Deterministic Sandbox B verification & signed EvidenceManifestV1",
    proofGrade: "proof: locally_verified",
    proofTone: "success",
    summary:
      "Bounded candidate diffs run in Sandbox B across six independent checks: target suite green (V-02), broader regression suite (V-03), static lint/typecheck (V-04), path and line-budget compliance (V-05), AST anti-test-weakening guard (V-06), and Ed25519 manifest signing (V-07).",
    invariant: "Only deterministic executor exit codes and AST/policy verifiers can advance proof to locally_verified.",
    abstentionPath:
      "Patches that touch forbidden paths, exceed diff caps, or weaken test assertions are rejected with full audit context.",
    artifacts: ["Gates V-01..V-07 verdict", "SHA-256 patch digest", "Ed25519 EvidenceManifestV1"],
  },
  {
    step: "05",
    id: "approval",
    shortTitle: "Policy & Step-Up",
    title: "Immutable 4-layer repository policy & human step-up authorization",
    proofGrade: "proof: locally_verified",
    proofTone: "success",
    summary:
      "The policy engine evaluates the pinned repository policy revision across Monitor, Approval, and Auto-Repair modes. Sensitive file classes or Approval mode pause at policy_gate for RBAC review and fresh 5-minute TOTP MFA step-up confirmation.",
    invariant: "Telegram and MCP surfaces issue intent links only—privileged confirmation completes in the authenticated web console.",
    abstentionPath:
      "Rejected or expired approvals transition cleanly without mutating remote branches.",
    artifacts: ["Pinned policy revision check", "5-minute TOTP step-up receipt", "Hash-chained audit record"],
  },
  {
    step: "06",
    id: "publish",
    shortTitle: "Draft PR & V-08",
    title: "Idempotent Draft PR/MR publication & exact-SHA remote CI check",
    proofGrade: "proof: remotely_verified",
    proofTone: "success",
    summary:
      "A narrow Zone Z2 publisher saga pushes red2pr/repair/* and opens a Draft PR or Draft MR embedding the verification summary. Remote observer V-08 tracks every configured required provider check against the exact published commit SHA.",
    invariant: "Never auto-merges; upgrades to remotely_verified only when all required checks pass on the exact head SHA (ADR-042).",
    abstentionPath:
      "If a human pushes new commits or a required remote check fails, exact-SHA remote verification stays distinct from local proof.",
    artifacts: ["Draft PR / MR on red2pr/repair/*", "Exact head SHA binding", "V-08 required-set digest"],
  },
];

export interface ShowcaseTab {
  readonly id: string;
  readonly label: string;
  readonly eyebrow: string;
  readonly title: string;
  readonly description: string;
  readonly highlights: readonly string[];
  readonly lightFile: string;
  readonly darkFile: string;
  readonly width: number;
  readonly height: number;
  readonly routeLabel: string;
  readonly statusBadge: string;
  readonly statusTone: "success" | "info" | "neutral";
  readonly alt: string;
}

export const SHOWCASE_TABS: readonly ShowcaseTab[] = [
  {
    id: "overview",
    label: "Overview & Ledger",
    eyebrow: "Workspace Telemetry · UI-S03",
    title: "Track every repair stage with explicit denominators and USD spend.",
    description:
      "See the full 8-stage funnel from Ingested through Remotely Verified alongside local, remote, pending, unknown, and abstained outcomes—backed by an atomic PostgreSQL USD usage ledger.",
    highlights: [
      "8-stage funnel with exact numerator/denominator tables",
      "Settled vs. estimated unsettled USD inference accounting",
      "First-class visibility into abstained and unknown outcomes",
    ],
    lightFile: "hero-overview-light.png",
    darkFile: "hero-overview-dark.png",
    width: 2720,
    height: 2344,
    routeLabel: "/w/acme-platform/overview",
    statusBadge: "8-stage funnel",
    statusTone: "info",
    alt: "Red2PR Workspace Overview screen displaying the 8-stage repair funnel, denominator table, outcome counts, and USD Meta Muse cost ledger",
  },
  {
    id: "repositories",
    label: "Repository Safety",
    eyebrow: "Governance & SEC-031 · UI-S04",
    title: "Onboard in Monitor mode by default and catch workflow hazards early.",
    description:
      "Synchronize GitHub App and GitLab repositories with scoped access grants, inspect SEC-031 workflow hazards before enabling autonomous modes, and preview bulk policy updates safely.",
    highlights: [
      "Per-repository Monitor, Approval, and Auto-Repair operating modes",
      "Automated SEC-031 scanner flags unsafe pull_request_target workflows",
      "Optimistic concurrency checks and dry-run historical policy previews",
    ],
    lightFile: "repositories-light.png",
    darkFile: "repositories-dark.png",
    width: 2720,
    height: 1720,
    routeLabel: "/w/acme-platform/repositories",
    statusBadge: "SEC-031 active",
    statusTone: "neutral",
    alt: "Red2PR Repository Catalog screen showing Approval, Auto-Repair, and Monitor modes plus SEC-031 workflow hazard detection",
  },
  {
    id: "diagnosis",
    label: "Muse Diagnosis",
    eyebrow: "Root-Cause Analysis · UI-S08",
    title: "Pinpoint the regression commit—and surface what still needs review.",
    description:
      "Meta Muse Spark localizes failure causes against sanitized logs and bounded code context while separating phase, local proof grade, and remote publication state.",
    highlights: [
      "Independent badges for proof grade, remote CI status, and session phase",
      "Root-cause localization tied to concrete files, symbols, and commits",
      "Explicit Uncertainties section highlights downstream reviewer checks",
    ],
    lightFile: "repair-diagnosis-light.png",
    darkFile: "repair-diagnosis-dark.png",
    width: 2720,
    height: 1720,
    routeLabel: "/w/acme-platform/repairs/0196f000",
    statusBadge: "locally verified",
    statusTone: "success",
    alt: "Red2PR Repair 0196f000 Cause tab showing Meta Muse Spark localization of a Decimal rounding regression and explicit reviewer uncertainties",
  },
  {
    id: "verification",
    label: "Gates V-01 – V-07",
    eyebrow: "Deterministic Proof · UI-S08",
    title: "Every local verification gate inspected and cryptographically signed.",
    description:
      "Before a repair reaches the policy gate, Red2PR persists evidence items for baseline red reproduction, target and broader test suites, static analysis, path rules, and AST test integrity.",
    highlights: [
      "V-01 baseline failure reproduction through V-06 test-integrity guard",
      "SHA-256 patch digest bound to pinned repository policy revision",
      "V-07 Ed25519-signed EvidenceManifestV1 verified before publication",
    ],
    lightFile: "verification-proof-light.png",
    darkFile: "verification-proof-dark.png",
    width: 2720,
    height: 1720,
    routeLabel: "/w/acme-platform/repairs/0196f000?tab=verification",
    statusBadge: "V-01..V-07 passed",
    statusTone: "success",
    alt: "Red2PR Deterministic Verification tab showing passed gates V-01 through V-07 and SHA-256 patch digest",
  },
  {
    id: "draft-pr",
    label: "Draft PR & V-08",
    eyebrow: "Publication & Remote CI · UI-S10",
    title: "Draft reviews only, verified against the exact published commit SHA.",
    description:
      "Inspect open Draft PRs/MRs on red2pr/repair/* branches, confirm required remote checks passed on the exact head SHA, and trigger audited provider reconciliation.",
    highlights: [
      "Opens Draft PRs/MRs only—autonomous merge is architecturally absent",
      "Binds V-08 remote check verification to the exact 40-char head SHA",
      "Audited manual reconciliation with explicit operator reason logging",
    ],
    lightFile: "draft-pr-workflow-light.png",
    darkFile: "draft-pr-workflow-dark.png",
    width: 2720,
    height: 2056,
    routeLabel: "/w/acme-platform/prs",
    statusBadge: "Remote V-08 passed",
    statusTone: "success",
    alt: "Red2PR Pull Requests screen showing published Draft PRs, exact head SHA binding, and passed Remote V-08 checks",
  },
];

export const SAMPLE_VERIFIED_DIFF = `--- a/src/billing/proration.py
+++ b/src/billing/proration.py
@@ -41,8 +41,8 @@ def quantize_credit_note(unit_delta: Decimal, seats: int):
     subtotal = unit_delta * Decimal(seats)
     # Preserve pre-7c4e91f2a8b0 half-up rounding before tax aggregation
-    return subtotal.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
+    return subtotal.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)`;

export interface CapabilityItem {
  readonly eyebrow: string;
  readonly title: string;
  readonly body: string;
  readonly specs: readonly string[];
}

export const CAPABILITY_ITEMS: readonly CapabilityItem[] = [
  {
    eyebrow: "Meta Muse Integration · U16–U18",
    title: "Dual-model reasoning with strict cost & consent controls",
    body: "Pairs meta/muse-spark-1.3 for fast triage and patch synthesis with optional meta/muse-wonder-1.0 escalation. Enforces per-repository outbound consent, Chain-of-Thought stripping, LiteLLM catalog pricing, and row-locked USD budget caps.",
    specs: ["meta/muse-spark-1.3 & muse-wonder-1.0", "SELECT ... FOR UPDATE USD ledger", "Pre-egress redaction-v1"],
  },
  {
    eyebrow: "Repository Governance · U12",
    title: "Immutable 4-layer policies & dry-run simulator",
    body: "Control branch allowlists, path globs, maximum diff lines, and sensitive lockfile or workflow gates via versioned policies. Test policy changes against historical runs before switching a repository out of Monitor mode.",
    specs: ["Monitor / Approval / Auto-Repair", "Dry-run policy preview", "SEC-031 YAML hazard guard"],
  },
  {
    eyebrow: "Operator Surfaces · U22–U30",
    title: "Astryx web console, CLI, Telegram intents & scoped MCP",
    body: "Operate through a 21-screen React 19 + Meta Astryx Neutral console with live SSE updates, the unified red2pr CLI, signed webhooks, Telegram notifications with web-confirmed intents, and an MCP 2025-11-25 Streamable HTTP adapter.",
    specs: ["21 Astryx Neutral screens + SSE", "red2pr status / doctor / backup", "Read & intent-scoped MCP"],
  },
  {
    eyebrow: "Self-Hosted Security Spine · U01–U09",
    title: "Row-level tenant isolation & tamper-evident audit trails",
    body: "Backed by PostgreSQL 16 with FORCE ROW LEVEL SECURITY across 98 tables, Argon2id + TOTP MFA + PKCE OIDC, AES-256-GCM encrypted artifact storage, SSRF-hardened egress pinning (ADR-037), and SHA-256 hash-chained audit logs.",
    specs: ["PostgreSQL 16 FORCE RLS", "Argon2id + TOTP 5m step-up", "AES-256-GCM + SHA-256 audit chain"],
  },
];

export interface QuickStartCommandTab {
  readonly id: string;
  readonly label: string;
  readonly language: "bash" | "plaintext";
  readonly title: string;
  readonly caption: string;
  readonly code: string;
}

export const QUICKSTART_TABS: readonly QuickStartCommandTab[] = [
  {
    id: "posix",
    label: "Linux / macOS (Bash)",
    language: "bash",
    title: "scripts/quickstart.sh",
    caption:
      "Boots confined PostgreSQL 16 (pgserver) with migrations 0001..0025 + RLS, FastAPI Control Plane, and built Astryx Web UI on http://127.0.0.1:4280.",
    code: `git clone https://github.com/nguywnben/red2pr.git
cd red2pr
./scripts/quickstart.sh`,
  },
  {
    id: "windows",
    label: "Windows (PowerShell)",
    language: "bash",
    title: "scripts\\quickstart.ps1",
    caption:
      "Verified native Windows PowerShell launcher—preserves local state in .local-data/red2pr and prints a one-use 15-minute /setup#bootstrap_token=... owner claim link.",
    code: `git clone https://github.com/nguywnben/red2pr.git
cd red2pr
powershell -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\quickstart.ps1`,
  },
  {
    id: "containers",
    label: "Containers (GHCR)",
    language: "bash",
    title: "GitHub Container Registry · v0.1.0-beta.1",
    caption:
      "Published non-root (10001:10001), read-only-compatible OCI packages linked to nguywnben/red2pr, with SHA-256 digests published in container-images.txt on GitHub Releases.",
    code: `docker pull ghcr.io/nguywnben/red2pr-control:0.1.0-beta.1
docker pull ghcr.io/nguywnben/red2pr-worker:0.1.0-beta.1

# Verify non-root read-only container wiring locally
docker run --rm --user 10001:10001 --read-only \\
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \\
  ghcr.io/nguywnben/red2pr-worker:0.1.0-beta.1 --check-wiring`,
  },
  {
    id: "verify",
    label: "Preflight & CLI Doctor",
    language: "bash",
    title: "Non-destructive preflight & operator health check",
    caption:
      "Run a read-only dependency check, an isolated temporary smoke stack, or inspect live subsystem health with the red2pr CLI.",
    code: `# Preflight wiring or disposable end-to-end smoke test (Linux / macOS)
./scripts/quickstart.sh --check-only
./scripts/quickstart.sh --smoke-test

# With the stack running on http://127.0.0.1:4280
RED2PR_API_URL=http://127.0.0.1:4280 uv run red2pr status
RED2PR_API_URL=http://127.0.0.1:4280 uv run red2pr doctor`,
  },
];
