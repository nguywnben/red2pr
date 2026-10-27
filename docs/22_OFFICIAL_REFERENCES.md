# Vendor technical references and verification policy

**Checked reference date: 2026-10-26 (public docs only).** Links serve as references, not as guaranteed exact API contracts; re-check account permissions, API versions and terms before coding and release.

## Meta Model API
- Overview: https://dev.meta.ai/docs/overview
- Models: https://dev.meta.ai/docs/models
- Quickstart: https://dev.meta.ai/docs/quickstart
- Chat completions: https://dev.meta.ai/docs/cookbook/quickstart-chat-completions
- Tool/function calling: https://dev.meta.ai/docs/cookbook/tool-function-calling
- Coding agents: https://dev.meta.ai/docs/coding-agents
- API currently documents base `https://api.meta.ai/v1` and `muse-spark-1.3`; Muse Wonder availability requires account verification.

## Astryx (frontend)
- Getting started: https://astryx.atmeta.com/docs/getting-started (React >=19, theme CSS, CLI, Vite example)
- Vite official example: https://github.com/facebook/astryx/tree/main/apps/example-vite
- CLI integration can write AGENTS.md: review output in a temporary dir and preserve repository rules.

## GitHub
- GitHub App creation/manifest: https://docs.github.com/en/apps/creating-github-apps
- App authentication: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app
- Webhook payloads: https://docs.github.com/en/webhooks/webhook-events-and-payloads
- Webhook validation: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
- Actions API: https://docs.github.com/en/rest/actions
- Pull requests API: https://docs.github.com/en/rest/pulls
- App permission requirements: https://docs.github.com/en/rest/overview/permissions-required-for-github-apps

## GitLab
- Webhooks: https://docs.gitlab.com/user/project/integrations/webhooks/
- REST API: https://docs.gitlab.com/api/rest/
- Jobs API/trace: https://docs.gitlab.com/api/jobs/
- Merge Requests: https://docs.gitlab.com/api/merge_requests/
- Commits: https://docs.gitlab.com/api/commits/

## Telegram
- Bot API (getUpdates/setWebhook, secret_token, formatting, rate errors): https://core.telegram.org/bots/api
- Bot FAQ: https://core.telegram.org/bots/faq

## Runtime / security
- Docker rootless: https://docs.docker.com/engine/security/rootless/
- Docker Desktop setup and licensing: https://docs.docker.com/desktop/
- gVisor: https://gvisor.dev/docs/
- Firecracker: https://firecracker-microvm.github.io/
- OpenTelemetry: https://opentelemetry.io/docs/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/

## Revalidation process
1. Record vendor doc URL, version/date, verified fields/scopes, exact test request/response and account status in ADR/PROGRESS.
2. Do NOT infer GitHub/GitLab webhook event equivalence or API write permissions from general docs.
3. Pricing, model access, OAuth/GitHub installation flows and local runtime support may change. Use capability probes and provider-specific negative tests.
4. Never store user tokens or secrets in documentation or logs; provider requests against real accounts require authorization.


## Verification note on fetched public docs
On 2026-10-26, Astryx getting-started confirms React >=19, `@astryxdesign/core`/`theme-neutral`/`cli`, `npx astryx init` and official Vite example. GitHub App registration documents installation, callback, webhook, permissions. GitLab webhook documentation describes signed payloads with signing tokens for supported recent versions, not blanket compatibility with older self-managed releases. Telegram Bot API supports HTTP bot operations; all account-dependent behavior is subject to tests. Meta documentation may require login; actual model IDs and quotas must be probed via the user's authenticated account.

## P2 research ledger — read 2026-10-27
DOC_VERIFIED = official public text read; SOURCE_VERIFIED = official repository source read at immutable commit. Neither means runtime/account validation. NOT_LIVE_TESTED applies to every row. No paid API, credential access, installer, sandbox or account mutation was used. A page may evolve after this reading; release must recheck. Old “Meta docs may require login” note remains true for account console, but the public pages below were accessible in this audit.

| Ref | Official URL(s) read | Observed version / fact used | Verification limit / required next evidence |
|---|---|---|---|
| REF-META | [Models](https://dev.meta.ai/docs/models), [tool calling](https://dev.meta.ai/docs/cookbook/tool-function-calling), [structured output](https://dev.meta.ai/docs/cookbook/structured-output) | DOC_VERIFIED: Spark1.3, Wonder1.0 listed; Wonder Full not Model API; tool/schema response contracts documented | account/region eligibility, quotas, exact price/usage, retention/terms and response behavior not tested; authenticated console pages not read; no invented quota |
| REF-GH-APP | [Registration](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app), [installation token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) | DOC_VERIFIED: user callback and installation setup distinct; installation token scope/expiry mechanisms | no App created/installed, no granted scopes tested; token format not fixed40characters |
| REF-GH-REST | [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions), [workflow runs](https://docs.github.com/en/rest/actions/workflow-runs), [workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs), [pull requests](https://docs.github.com/en/rest/pulls/pulls) | DOC_VERIFIED:2026-03-10 is documented API version; attempt-specific run/job/log APIs; PR endpoint docs | candidate version only; permissions/rerun/fork/branch protection need real authorized installation; GHES different matrix |
| REF-GH-HOOK | [Webhook validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries), [workflow triggers](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) | DOC_VERIFIED: raw HMAC validation; workflow event semantics require downstream review | no webhook delivered; no assumption draft PR prevents dangerous workflows |
| REF-GL-HOOK | [Webhooks](https://docs.gitlab.com/user/project/integrations/webhooks/) | DOC_VERIFIED: signing headers19.0; flag removed19.1; Idempotency-Key17.4; legacy token mode differs | project/server config and edition untested; version-sensitive auth modes explicitly pinned |
| REF-GL-API | [Jobs](https://docs.gitlab.com/api/jobs/), [MR](https://docs.gitlab.com/api/merge_requests/), [commits](https://docs.gitlab.com/api/commits/) | DOC_VERIFIED: retry jobs enumeration and draft MR surface; deprecated fields vary with version | no project token/role/push/trace/artifact or MR created; full permission proof pending |
| REF-TG | [Bot API](https://core.telegram.org/bots/api) | DOC_VERIFIED: page Bot API10.3 (24Aug2026); getUpdates/setWebhook alternatives, secret_token | no bot token or chat linking tested; official delivery semantics do not imply unlimited update retention |
| REF-REACT | [React19 release](https://react.dev/blog/2024/12/05/react-19) | DOC_VERIFIED: React19 stable release; product major19 chosen by owner | exact patch/peer set not installed or built |
| REF-VITE | [Guide](https://vite.dev/guide/) | DOC_VERIFIED: documented Node20.19+ or22.12+ minimum at reading; templates may require higher | minimum is build-tool requirement, not backend language change; pin tested Vite/Node combination |
| REF-TS | [strict](https://www.typescriptlang.org/tsconfig/strict.html) | DOC_VERIFIED: strict flag family, future upgrades can add checks | exact compiler version/flags need build; no typecheck run |
| REF-ASTRYX | [Getting started](https://astryx.atmeta.com/docs/getting-started), [pinned source](https://github.com/facebook/astryx/tree/2c7ef0e223ffbff3fc9d1264f5cc442fe50317e9) | SOURCE_VERIFIED core0.7.5, React>=19 and StyleX peer; Button/Dialog/Table source props listed in doc29 | source HTTP read only; public exports/CSS path/build/render/CLI write behavior not executed or certified; AGENTS never overwritten |
| REF-DOCKER | [Engine security](https://docs.docker.com/engine/security/), [rootless](https://docs.docker.com/engine/security/rootless/), [Windows install](https://docs.docker.com/desktop/setup/install/windows-install/) | DOC_VERIFIED: rootless uses user namespace and prerequisites; OS install has prerequisites | no runtime here detected on PATH; no Docker/WSL installation/daemon/sandbox launched; licensing/prereqs at customer host still checked |
| REF-GVISOR | [Security model](https://gvisor.dev/docs/architecture_guide/security/) | DOC_VERIFIED architectural security guidance | no runtime benchmark/escape test; not equivalent to certified isolation |
| REF-SLACK | [Incoming webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/), [request signatures](https://docs.slack.dev/authentication/verifying-requests-from-slack/) | DOC_VERIFIED outbound webhook and inbound raw-body HMAC/timestamp verification are separate | no workspace app/message; interactive actions unenabled until web authorization contract tested |
| REF-DISCORD | [Webhooks](https://docs.discord.com/developers/resources/webhook), [rate limits](https://docs.discord.com/developers/topics/rate-limits) | DOC_VERIFIED webhook receipt and rate-limit contracts | no server/webhook created; send/unknown outcome behavior needs real consented destination |
| REF-SMTP | [RFC5321](https://www.rfc-editor.org/info/rfc5321) | DOC_VERIFIED SMTP standard reference; recipient delivery not inferred from relay acceptance | TLS submission server capability/auth/bounce callback not tested; RFC3207 fetch unavailable in this audit, do not claim it read |

### Research gaps and source discipline
Public API docs establish possible capabilities, not this customer's grants, billing tier or vendor legal commitments. Evidence must record host/version/account capability timestamp without exposing credentials. Meta account-only console and quota pages are **UNVERIFIED**, not fabricated. GitHub API-versions old URL fetch failed; canonical about-the-rest-api URL above succeeded. Astryx source was read through official GitHub HTTP when web extraction was insufficient, with no dependency install or CLI execution. CLI docs available is not permission to run init.
For live probes, operator must authorize exact account/repo/channel/cost/scope separately. [35](35_INTEGRATION_DEPENDENCIES.md) lists the capability acceptance work; source facts refresh on version upgrades, then contract fixtures and certified E2E before claims. Legal/data processing terms and precise licensing need official current terms plus owner context, not model assertions.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
