# Authorization matrix — server-enforced RBAC and resource scoping

## Principal types
Instance owner; Workspace admin; Maintainer; Reviewer; Viewer/Auditor; service identities (ingest, collector, agent, worker, publisher, notification dispatcher). Access to repo is intersection of installation scope, workspace membership, assigned repo grants, policy and provider rights. Explicit deny always wins. All writes require authorization at API and task execution/replay time.

| Action | Owner | WS admin | Maintainer | Reviewer | Viewer | Service identity |
|---|---|---|---|---|---|---|
| View instance/global health | yes | scoped | scoped | scoped | scoped | operational read only |
| Create/remove workspace | yes | no | no | no | no | no |
| Invite/change WS users | yes | yes | no | no | no | no |
| Connect GitHub/GitLab | yes | yes | only if delegated | no | no | integration broker only |
| List repo metadata and runs | all authorized | granted | granted | granted | granted | collector read scoped |
| Set repo automation mode/policy | yes | yes | repo-granted | no | no | no |
| Trigger manual diagnosis | yes | yes | granted | optionally granted | no | orchestrator controlled |
| Approve publishing draft PR/MR | yes | yes | granted | if explicit approval role/grant | no | publisher executes approved intent |
| Cancel/retry repair session | yes | yes | granted | no | no | orchestrator controlled |
| Access sanitized source/evidence | granted | granted | granted | granted | granted according to scope | strict per-job token |
| Reveal stored secret value | never via UI | never | never | never | never | broker does controlled use only |
| Rotate/revoke integration secrets | yes | delegated WS admin | no | no | no | secrets broker with signed intent |
| System upgrade/restore/worker enroll | yes | no | no | no | no | isolated operator identity |
| Export audit/report | yes | scoped | scoped | scoped read | policy-gated | report service with context |
| Link personal Telegram account | own | own | own | own | own | Telegram broker scoped |

`yes` means eligible **only after** resource scope, re-auth/step-up, active session and policy conditions. Assignment of Reviewer approval rights must be explicit, not implied by title. Denied results must not leak existence of other tenant objects. Frontend hides forbidden actions but backend is authoritative.

## Service-to-service credentials
- Ingest can only validate+enqueue incoming event; no code execution or repository write.
- Collector has read scopes and egress through provider API proxy.
- AI agent obtains selected sanitized context and internal typed tools, no direct provider write credential.
- Sandbox receives short-lived one-job scoped token only, never secrets broker/control-plane DB.
- Publisher has just-in-time provider write rights for approved intents, isolated from untrusted code execution.
- Telegram dispatcher has notification-specific token, no implicit approval authority.

## Authentication hardening
Bootstrap one-time token only from local instance protected channel; rotate at completion; MFA/step-up for critical changes; session revocation; non-browser API tokens scoped and hashed at rest; CSRF defenses. Sensitive operations should record `actor`, `scope`, `old_policy_revision`, `new_revision`, `reason`, `correlation_id`, `evidence_id`.

## Negative authorization tests
Direct URL/IDOR, API BOLA, scoped search/autocomplete, artifact downloads and signed URLs, cross-workspace event notifications, approval replay, CSRF, session downgrade, stale authorization when policy changed, Telegram group spoof, worker token lateral movement, restore replay. Any exploitable unauthorized write or private data cross-boundary leakage blocks release.

## P2 multi-workspace clarification
ADR-030 ACCEPTED: multiple workspaces in1.0.0. “Owner yes” on workspace actions means owner **with explicit workspace/repository grant**, except instance-level create/delete/worker/lifecycle operations. Host owner trust limitation is documented in [14](14_SECURITY_IDENTITY.md). Owner cannot read all content through normal API by title alone.
Local invitation lifecycle belongs to IAM-02 P0 under ADR-034 PROPOSED; IAM-03 P1 reserves OIDC/federated invitation/provisioning, with issuer/audience/state/nonce/PKCE validation, no email-domain implicit admin, explicit claim→role mapping, deprovisioning and local emergency recovery. No SSO support until certified. Membership revocation rechecks queued jobs, SSE, exports, signed downloads and notifications at use time.
Approval service records authenticated decision but cannot change verifier result; publisher executes eligible intent and has no ability to grant its own approval. Test/config-sensitive patch proposer cannot self-approve under proposed separation-of-duties policy; small teams need another reviewer or remain blocked, never weaken baseline invariant. API tokens are hashed, scoped, expiring and constrained by issuer's current grants; no token-based MFA/approval shortcut.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
