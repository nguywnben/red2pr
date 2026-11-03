# Security Policy

## Supported Versions

Red2PR is currently in **Early-Access Beta (`v0.1.0-beta.1`)**. Wave 6 (`U31`–`U36`) multi-OS sandbox host certification and `P5` independent security certification for `v1.0.0` are deferred.

| Version | Security Updates | Notes |
|---|---|---|
| `0.1.0-beta.x` (`main`) | Yes | Current pre-release evaluation & hackathon track (`U01`–`U30` implemented). |
| `1.0.0` | Planned | Requires Wave 6 (`R-01`–`R-15`) & `P5` independent audit completion. |

## Reporting a Vulnerability

**Do not open public GitHub issues or pull requests containing exploit details, unredacted logs, credentials, or tenant data.**

Please report suspected security vulnerabilities privately via **[GitHub Private Vulnerability Reporting](https://github.com/nguywnben/red2pr/security/advisories/new)** on this repository.

Include, when possible:
- Affected component (`apps/control-plane`, `apps/worker-supervisor`, `apps/web`, `apps/cli`, `packages/py-contracts`, or `deploy/`).
- Trust boundary impacted (`Z1` Control Plane, `Z2` Secret/Inference/Publisher Brokers, or `Z3` Sandbox Worker).
- Exact commit SHA and minimal reproduction steps using synthetic/non-sensitive fixtures.
- Impact assessment (e.g., cross-tenant RLS bypass, secret redaction bypass, SSRF/egress bypass, approval/step-up bypass, or sandbox escape).

## Core Security Invariants

Red2PR enforces the following non-negotiable architectural invariants (detailed in [docs/14_SECURITY_IDENTITY.md](docs/14_SECURITY_IDENTITY.md) and [docs/26_SECURITY_TEST_MATRIX.md](docs/26_SECURITY_TEST_MATRIX.md)):

1. **Proof Over Prose:** Language models may propose diagnoses and diffs, but cannot self-certify tests, grant permissions, waive policies, or publish branches.
2. **Three-Zone Trust Separation (`Z1` / `Z2` / `Z3`):**
   - Repository source code, CI logs, dependency hooks, and webhook payloads are treated as **untrusted**.
   - `Z3` sandbox workers never receive GitHub/GitLab write tokens, Meta Model API keys, master encryption keys, or host Docker sockets.
   - Architectural import boundaries are statically enforced by `import-linter`.
3. **No Dangerous Autonomy:** Red2PR opens **Draft Pull Requests / Merge Requests** only. Auto-merge, branch-protection bypass, silent test weakening/deletion, and unapproved workflow edits (`SEC-031`) are prohibited.
4. **Pre-Inference Redaction & Consent:** Outbound Meta inference requires per-repository owner consent and runs strictly after secret redaction (`Redactor`) and `ADR-037` HTTPS egress checks.
5. **Tenant Isolation & Tamper-Evident Audit:** Multi-workspace isolation is enforced by PostgreSQL 16 `FORCE ROW LEVEL SECURITY` (`red2pr_app` role), envelope-encrypted artifacts (`AES-256-GCM`), and SHA-256 hash-chained audit logs.

## Beta Deployment Guidance

During the `v0.1.0-beta.x` phase:
- Run local quickstart evaluations on trusted repositories or inside disposable non-production VMs.
- Do not process untrusted third-party repositories without an attested isolated `Z3` worker matching the workspace trust domain (`ADR-034`).
- Never commit `.env` files, `.pem`/`.key` files, API tokens, or `.local-data/` directories.
