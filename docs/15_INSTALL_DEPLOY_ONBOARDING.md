# One-command install, local/server deployment, first-run setup

## Experience contract
User starts **one command** for Linux/macOS or **one command** for Windows; after automated verified setup, installer prints/open URL (e.g. `http://127.0.0.1:4280`) and one-time bootstrap token. UI wizard configures credentials, integration, repo and worker readiness. The one-command promise means a single entrypoint that can request necessary interaction/admin consent/reboot, **not** unconditionally zero-click on unsupported machines.

## Future command shape (DESIGN, not functional URL)
```bash
curl -fsSL https://<red2pr-official-domain>/install.sh | sh
```
```powershell
irm https://<red2pr-official-domain>/install.ps1 | iex
```
**These are illustrative only.** Provide safer downloadable signed installer + pinned version/checksum option; before deployment avoid encouraging executing unknown remote scripts blindly. Installer must verify publisher signature, digest, TLS, version and supply-chain provenance.

## OS-specific prereqs
| OS/profile | Prerequisites and behavior |
|---|---|
| Linux | architecture/OS detection, rootless Docker/Podman if certified, systemd service profile, permissions, disk/net and port preflight |
| macOS | certified Docker/VM runtime; permission and startup checks; GUI browser open; worker trust limitation |
| Windows | PowerShell, WSL2/virtualization/container runtime prereq, possible elevation/restart, resume-capable installer; browser open |
| Headless Linux server | public HTTPS domain + reverse proxy, firewall, webhook host check; print reachable setup URL |
| Distributed | separate worker provisioning, identity/certificates, worker enrollment and network policy |

Auto-installing Docker Desktop or changing virtualization/kernel settings **requires explicit consent and obeys vendor license**. Installer may guide/manual dependency install and resume; no silent admin policy changes. If prereqs unavailable: clear error/report, no half-configured success.

## Install orchestration contract
1. Preflight supported OS/CPU/disk/memory/network/ports/runtime/time and existing instance; show intended changes and license caveats.
2. Download pinned/signed release manifest, verify binaries/images (digest/signature), select deployment mode and paths.
3. Create restricted system identity/volumes, generate crypto-random bootstrap secret, master key workflow and secure storage. No secrets in command output except one-time token with warning.
4. Provision API, UI, PostgreSQL, queue, artifact store, publisher, workers depending on mode.
5. Apply DB migrations transactionally/with backup and readiness checks; if failure return actionable state and repair/uninstall behavior.
6. Health checks, print local/service URL, bootstrap expiration and command `red2pr doctor`; open browser if interactive desktop.
7. Record deployment manifest, version and system service registration; installer can rerun idempotently without overwriting data.

## Setup Wizard state machine
`UNINITIALIZED -> OWNER_CREATED -> DEPLOYMENT_SET -> MODEL_CONFIGURED_OR_SKIPPED -> SOURCE_INTEGRATED_OR_SKIPPED -> REPO_CONFIGURED -> WORKER_READY_OR_DEGRADED -> READY_FOR_MONITORING -> READY_FOR_REPAIR (only if full checks pass)`.
- Wizard first stage uses expiring bootstrap token and local binding or explicit secure remote restricted setup; prevents takeover if interface accidentally public.
- HTTPS server configuration + cert validation where possible; no plaintext admin credentials over remote HTTP.
- AI model keys via secure UI and a minimal connectivity request with budget notice; metadata from verified provider capabilities.
- GitHub App registration/installation or GitLab project integration and permissions verification, repo selection and policy defaults.
- Telegram setup is optional, bot can use long polling or webhook based on deployment profile.
- Worker security self-test and isolated test repo; `auto_repair` cannot activate unless worker passes.
- Final readiness dashboard highlights skipped or failed components and exact remedial actions.

## Deployment/network constraints
Local browser `localhost` is accessible only on installing machine. Remote server URL needs DNS/reverse proxy/TLS and firewall; public GitHub webhooks cannot target localhost. Local default provider **polling**; server **webhook plus reconciliation**; optional opt-in relay, never secret implicit cloud dependency.

## Installer idempotency/upgrade/uninstall
- Existing DB/volumes preserved by default; show diff and safe reconfigure.
- Update: verify release → backup & preflight → drain queue → schema compatibility → replace images → ready checks → rollback when compatible.
- Uninstall: stop services; separately choose data retention/purge; revoke external connections only with confirmation, clear list of remaining resources.
- `doctor`: fix recommendations, no silent destruction.

## Installer acceptance
Fresh + upgrade + rerun + interrupted + disk-full + insufficient memory + no Docker/WSL + occupied port + expired bootstrap + HTTPS misconfiguration + restore on each certified OS. Release cannot claim one-command support for an untested OS/configuration.

## P2 installer and wizard acceptance
“One command” means one verified entrypoint into guided installation, **not** automatic prerequisite installation without privileges/restart. Existing commands are non-executable product sketches; real distribution URL/publisher/license remain ADR-021 OPEN. Before running downloaded installer, released bootstrap must verify signed release manifest using independently shipped trust root, digest, platform/arch and anti-downgrade policy; checksum from same compromised server alone is insufficient.
Linux checks supported distro/arch, systemd or documented user service, cgroups/resource enforcement, virtualization/isolated runtime, storage/network/ports. Windows checks supported build/arch, WSL2/virtualization and Docker Desktop or approved remote worker profile; missing prerequisites lead needs_admin/needs_restart with explicit instructions/checkpoint. macOS checks arch/supported version and Linux VM-backed runtime; native macOS jobs are not implied. Runtime licensing/operator responsibility disclosed. No container/runtime installer run silently; user may choose remote certified worker instead.
Wizard: (1) bootstrap one-use owner, (2) topology/base URL/TLS, (3) storage/backup/recovery key custody, (4) workspace/admin membership, (5) provider connection+selected repo permissions, (6) inference region/data consent/model capability, (7) isolated worker profile and safe validation, (8) repository mode/policy + downstream CI review, (9) notification destinations/consent/test, (10) readiness checklist. Each phase has input validation, durable checkpoint, back/retry, safe draft redaction, explicit not_configured/blocked/unsupported; skip optional channels records disabled. No secret in URL/clipboard logs; bootstrap exposed only loopback or trusted admin HTTPS channel, expires15min TARGET.
Readiness splits ready_monitor (identity/provider ingestion) and ready_repair (consent,model,budget,worker,profile,policy/proof checks). A failed Meta quota probe cannot be presented as installed repair-ready. Reboot/resume validates saved config digest and reauth, never reuses expired bootstrap. Enrollment/bot/model test incurs external action only after operator confirms scope/cost/recipient.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
