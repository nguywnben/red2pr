# Identity, authorization, secrets and trust-boundary security

## Threat actors/assets
Hostile repo maintainer/PR author; poisoned install script/dependency; forged webhook/Telegram callback; prompt-injection in source/log; compromised worker; malicious low-permission user; stolen browser session; provider token abuse; compromised update artifact; malicious SSRF GitLab self-host URL. Critical assets: source code, CI secrets/logs, provider tokens, Meta key, repair diff, PR publication rights, admin session, DB backups and evidence.

## Auth and RBAC
- Local owner bootstrap once: single-use random token; first-use lock; browser loopback or restricted setup binding; password salted KDF (Argon2id preferred) and secure cookies/CSRF; brute-force limit; TOTP privileged-role requirement proposed ADR-034; passkeys/OIDC remain optional extensions after evaluation.
- Roles `instance_owner`, `workspace_admin`, `maintainer`, `reviewer`, `viewer`, `auditor`, scoped grants per repository. Deny by default and check server-side on every route, artifact URL, background job, Telegram command and webhook-controlled action.
- Privileged operations may require reauthentication; audit on login, role/policy edits, model egress consent, key rotation, publication/approval, backup restore.
- Strict separation `worker`, `publisher`, `provider_reader`, `notification_sender` service identities; never reuse superuser token.

## Secret lifecycle
Store provider installation/private keys, Meta API token, Telegram bot token, SMTP password in OS secret vault or encrypted service secret store; master key separate from DB/backups, secure file permissions, rotation, versioning, revocation and audit. Never write secrets to repo, logs, telemetry, screenshots, artifacts, PR body or untrusted sandbox; scrub runtime stdout and model request. Key loss means documented recovery requirements, not silent reset.

## Data classifications
- `public`: product docs, anonymized aggregate metrics.
- `workspace-internal`: repo names, pipeline/status, user identities.
- `restricted`: source code, private logs, stack traces, patches, artifacts.
- `secret`: API tokens, deployment creds, auth material.
LLM outbound transfer requires workspace/repo consent, redaction and minimization; present data-retention/provider terms without unsupported promises about no training. Users can disable external inference for repo and remain in monitoring-only state.

## Network and ingress
- Enforce TLS on remote UI/webhooks; bind local setup loopback by default; HSTS/secure cookies on HTTPS; CORS deny-by-default, CSRF protection, CSP/XSS output sanitization, SSRF defenses for arbitrary GitLab URLs/outgoing webhooks.
- Allow only verified official provider webhook signatures/tokens; IP allowlist optional and not sole authentication. Origin and installation membership validation mandatory.
- Separate worker VLAN/firewall from control plane: deny metadata/control endpoints; egress allowlist; no cross-tenant mounts.
- All untrusted archive/file paths canonicalized; size bounds, decompression-bomb guard, symlink policy.

## Policy hierarchy
Global instance deny rules > workspace deny rules > repo deny rules > repo allow > safe defaults. Sensitive files/patterns protected; hard denies cannot be overridden by prompt or Telegram. Policy revisions immutable and captured at repair start/publish time; stale revisions require recheck.

## Threat matrix
| Attack | Invariant and mitigation |
|---|---|
| Webhook replay | signature + delivery dedup + logical run attempt |
| Prompt injection | untrusted labeling, safe tools, independent policy |
| Worker escape | dedicated host/VM + runtime controls + no creds |
| Exfil via dependency install | network allowlist, no secrets, air-gapped tests |
| Test suppression | diff/policy checks and baseline verification |
| PR rights escalation | distinct publisher identity, repo grants, no auto-merge |
| Cross-workspace artifact read | authorization on signed URL issuance and storage access |
| Malicious installer/update | signed/pinned releases, checksums, verify provenance |
| Sensitive data in Telegram | minimal payload, escaped formatting, redaction |

## Security operations
- Audit with correlation IDs and privileged action reason; tamper detection where feasible; document audit retention.
- Dependency SBOM and vulnerability scanning, image signing, patch cadence, emergency credential revoke and incident runbook.
- Incident response: pause affected workspace/integration, revoke tokens, isolate workers, preserve sanitized evidence, notify admins, review scope and rotate keys.

## Explicit risk acceptance
Single-host personal installs may run trusted repositories under Docker isolation; they MUST disclose residual host escape risk. Production acceptance for third-party untrusted repos requires separate worker host with tested isolation, not marketing language. No zero-trust/fully secure claims without independent evaluation.

## P2 threat model and identity decisions
Multi-workspace is ACCEPTED ADR-030. MFA policy and break-glass specifics remain PROPOSED ADR-034; prior “optional/MFA-ready” text is not a release decision allowing privileged account bypass. Proposed server sessions: opaque random256-bit cookie; HttpOnly, Secure, SameSite=Lax, same-origin CSRF token + Origin checking for writes; idle30min, absolute12h, step-up5min. Loopback HTTP bootstrap is an explicitly local profile, never remote HTTP. Password hashing Argon2id with parameters benchmarked on certified minimum host; no hardcoded default password. Session rotation on login/privilege change, user-wide grant epoch invalidates tokens/streams; recovery codes hashed single-use, rate-limited, recovery creates audit and notifications. Lost all admin factors requires owner-operated offline recovery procedure with service maintenance/audit, not emailed universal backdoor. No credentials in URL or localStorage.
Workspace roles scoped to repo grants. Instance owner may operate instance/backups but no implicit content read; host administrators can access process/storage and remain a documented trust assumption. Cryptographic isolation from malicious host admin is not claimed. Support export excludes source/secrets by default and requires preview/consent.
Threat coverage and negative tests in [26](26_SECURITY_TEST_MATRIX.md); schemas/signing limits in [36](36_CANONICAL_CONTRACTS.md). Inference, notification, telemetry and provider operations have separate consent purposes, destinations and revocation; agreeing to Meta inference does not authorize publishing private logs to Slack.

Egress policy default denies private/reserved/link-local/metadata and redirects for untrusted URLs. Self-managed GitLab/SMTP/S3 exception is **owner-registered endpoint with exact adapter/host/port/CIDR/CA** under ADR-037; DNS resolution all A/AAAA checked and destination pinned through connection. No arbitrary model/repo-provided URL inherits exception. Never disable TLS verification globally. Secret references resolve only in purpose broker; write/model/notification secrets never enter execution guest. Redaction is tested defense-in-depth, not a guarantee that any arbitrary private source is safe to share.
Supply-chain controls: reviewed source/lockfiles, pinned dependency/image digests, SBOM, signature trust root independent of download checksum, reproducible provenance and vulnerability triage for runtime/build/install paths. Artifact/archives treated as hostile even with valid provider signature. Critical closure and High expiry follow ADR-032; no policy waiver for invariant failure.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
