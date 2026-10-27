# External integration constraints and capability verification

## Vendor contracts are versioned
No SDK/model/API feature is assumed just because README says it exists. Every implementation step records provider docs URL, account tier/permissions, SDK version, test request and failure behaviors in progress log. Synthetic tests cover both supported and denied responses; live integration only with owner-authorized test accounts.

| Dependency | Minimum investigation | Failure/permission behavior |
|---|---|---|
| Meta Model API Muse | exact available model IDs, input/tool/structured output, token limits, costs, throttles, logging/data retention | absent capability -> explicit unavailable; no fake LLM responses |
| GitHub App | registration flow, installation ID scoping, read Actions logs, write branch/PR, workflow-file permissions, webhook signatures | forking, permissions revoked, rate limits, PR duplicate retries |
| GitLab | GitLab.com/self-managed version support, Project/Job/Pipeline hooks, signing token vs legacy secret, MR/commit APIs, auth scopes | verify signed delivery when supported; fallback declared as lower assurance or unsupported |
| Telegram | bot creation/token, `getUpdates` vs webhook, private/group chat restrictions, update IDs, 429 behavior | linking challenge & RBAC web confirmation for mutations |
| SMTP | TLS, sender auth, bounce/error state, unsubscribe/opt-out as appropriate | reject secrets in content; retry no duplicate flood |
| Slack/Discord | incoming webhook/bot support, rate limit, token rotation, permissions | scoped destinations, no private source leaks |
| Generic outgoing webhooks | destination allowlist/SSRF checks, signing, retries, replay protection | signed minimal payload, verified endpoint controls |
| Docker/OCI/runtime | Linux kernel namespaces, rootless, gVisor/VM, CPU/RAM limits, Windows WSL2/macOS runtime | no host execution fallback; unsupported hardware explicit |
| Astryx | React 19 peer deps, neutral theme, official Vite app, CLI `init` impact, component API stability | pinned package; wrapper/visual/contract tests |

## Dependency change review
Any major runtime/SDK/protocol/package change requires ADR impact analysis, a targeted compatibility suite and security assessment. Dependency lockfiles, image digests and release signatures must be recorded. Pinning does not remove the need for security updates.

## Testing rules
CI fixtures may simulate responses deterministically; this does not count as live verification. For shipping an integration, at least one authorized end-to-end test on real provider/test account and known negative cases must pass on the declared version. For installation and sandbox, test fresh OS/VM state, not just developer's workstation.

## Truthful support
Product may fully design relay/distributed/future runtime extensions while release support remains constrained by actual security certification. Do not advertise `supports everything`. List precise platforms and versions. `production-ready` always scoped to published supported configurations.

## P2 verification inventory
[22](22_OFFICIAL_REFERENCES.md) records official source URLs, read date2026-10-27, observed versions and account/runtime limits. Meta public docs accessible; account-only quota/region/terms console still unverified. Astryx source commit inspected without CLI/installation; source props are not rendered behavior. GitLab signed/legacy mode and GitHub API version are explicit compatibility dimensions in [12](12_PROVIDER_INTEGRATIONS.md) and [27](27_SUPPORT_MATRIX.md).
Capability probe inputs: workspace/connection/model/profile, requested capability, expected version, allowed maxcost/timeout, consent record and correlation. Output: available/unavailable/unknown plus sanitized observed facts/time/version, reason and evidence ref. Unsupported or auth failure cannot become “available” by retrying a weaker auth mode. Network probes do not write resources by default; live create-hook/push/message/paid inference require exact operator authorization. No such probes were run during P2.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
