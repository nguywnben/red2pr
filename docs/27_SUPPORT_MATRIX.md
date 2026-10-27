# Supported, limited and unsupported execution profiles

**All items are TARGET support, not current verified support. Actual shipped matrix is established through test evidence.**

| Dimension | Target supported in first production scope | Limitations |
|---|---|---|
| Source provider | GitHub.com Actions, GitLab.com CI, selected certified self-managed GitLab | enterprise self-hosted versions require explicit testing |
| Repository visibility | public/private when integration permitted | private source outbound to Meta requires explicit consent |
| Runner platform | Linux x86_64 and certified ARM64 as verified | macOS/Windows CI runner fidelity not guaranteed |
| Python | pinned supported Python + pytest | arbitrary pyenv/Poetry/plugin version must be tested |
| Node.js | pinned Node + Jest/Vitest with lockfile | browser/Playwright-heavy suites may need declared profile |
| CI configuration | standard GitHub/GitLab YAML metadata | actions relying on privileged cloud/physical hardware unsupported |
| Sandbox | signed/tested OCI runtime, dedicated host/VM for untrusted repos | desktop single-host trusted-use only with warning |
| Installer | tested Linux distributions, macOS versions, Windows/WSL2 versions | exact version/hardware list based on QA; Docker installation may require permission/restart |
| Frontend | React 19 + Vite + TypeScript + pinned Astryx version, evergreen browsers tested | desktop first; browser versions certified through release tests |
| Agent backend | Meta Model API Muse Spark by capability check; Wonder optional | model access/limits must be verified per account |
| Event delivery | polling on local, webhooks on public HTTPS server, reconcile | no true realtime local without relay/public ingress |
| External integrations | GitHub/GitLab + in-app/Telegram; email/Slack/Discord/webhook adapters | each additional channel declared supported after contract tests |
| Multi-user | workspace/repo RBAC | SSO/enterprise directory optional based on test |

## Unsupported explicit examples
- macOS/Windows-specific compiled runners, GPUs, privileged Docker-in-Docker, Kubernetes cluster mutation, secret-backed production deployments, hardware-in-the-loop, auto-merge, arbitrary legacy CI systems. These may be future adapters only and must return an intelligible `unsupported` or `needs_human` status.

## Capability declaration mechanism
Installer scans OS prerequisites; provider integration uses live permissions/capability check; CI run maps to exact runner profile. UI displays `supported`, `partial`, `unsupported` with reasons and remediation. Production claims MUST be scoped by actual tests and signed release notes.

## P2 candidate certification rows (ADR-036 PROPOSED)
Every row is **CANDIDATE / NOT RUN**, not CERTIFIED. Rows select a bounded initial QA envelope, not permission to omit Windows/macOS installer or GitLab support. Release manifest must replace version ranges/TBD with exact tested patch versions/digests and dates; unresolved required row blocks support claim.

| Profile ID | Candidate envelope | Topology / execution | Must pass |
|---|---|---|---|
| CERT-LINUX | Ubuntu24.04 LTS x86_64; exact kernel/runtime patch TBD | local trusted-use or server control + separate hostile worker VM | R-05,R-09,R-10,R-13 |
| CERT-WINDOWS | Windows11 x86_64 with supported WSL2/virtualization + Linux runtime; exact OS build/runtime TBD | local control in Linux environment; isolated/remote worker; reboot/admin may be needed | R-05,R-09,R-10 |
| CERT-MACOS | macOS15+ Apple Silicon candidate; exact OS/runtime TBD | local VM-based Linux environment; ARM64 jobs only with certified image/profile; remote x86 worker otherwise | R-05,R-09,R-10 |
| CERT-DISTRIBUTED | Linux control profile, TLS/mTLS workers, PostgreSQL + object storage candidate versions pinned at certification | worker topology only; no implied multi-node HA database | R-05,R-07,R-10,R-13 |
| CERT-PYTHON | Linux x86_64 Python3.12 + pytest exact version/image/lockfiles TBD | no arbitrary secret-backed services or privileged hooks | R-05,R-12 |
| CERT-NODE | Linux x86_64 Node22 at compatible patch + separately pinned Jest/Vitest profiles | Node frontend build minimum per Vite; product backend remains Python | R-05,R-11,R-12 |
| CERT-GITHUB | GitHub.com Actions, App API candidate2026-03-10 | webhook + polling; GHES unclaimed unless separate certificate | R-02 |
| CERT-GITLAB | GitLab.com plus self-managed candidate19.1 signed mode; selected legacy17.4+ row only after explicit compatibility tests | exact server release/edition/token-role recorded; no blanket>= support | R-03 |
| CERT-UI | React19 + Astryx0.7.5 source snapshot candidate; latest stable Chromium/Firefox/WebKit selected on certification day | desktop and mobile viewport; keyboard/screen reader/dark-light | R-11 |
| CERT-META | Spark1.3 public-doc candidate; Wonder1.0 optional capability | actual region/account/limits/terms must be verified with authorized key | R-04,R-12 |
| CERT-NOTIFY | Telegram Bot API10.3 docs; SMTP server,Slack webhook,Discord webhook API versions captured during test; Red2PR webhookv1 | each adapter real consented test destination | R-08 |

Browser/runtime latest release is not automatically certified. Unsupported major upgrades show unsupported/degraded until regression tests; dependency compatibility checked before install. Candidate macOS15+ and GitLab17.4+ are evaluation ranges, not a promise every later version works. Hardware targets are [37](37_NFR_AND_RECOVERY.md); exact minima remain ADR-022 verification tasks.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
