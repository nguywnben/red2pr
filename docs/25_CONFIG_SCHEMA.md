# Configuration & policy reference — proposed schema

## Configuration namespaces
| Namespace | Key/example | Type / behavior |
|---|---|---|
| instance | `deployment_mode=local\|server\|distributed` | immutable except guided migration |
| instance | `public_base_url` | validated URL; loopback local only or HTTPS server |
| instance | `storage_backend=local\|s3-compatible` | sensitive artifact storage scope |
| instance | `backup.retention_days` | bounded and encrypted; owner-only |
| security | `bootstrap.expires_minutes` | single-use, short-lived; no URL secret logs |
| security | `artifact_retention_days` | policy bounds, includes deletion jobs |
| security | `inference_data_policy` | consent/restriction for private source/log outbound |
| runtime | `sandbox_backend` | certified Docker/VM profile; no fallback to host shell |
| runtime | `worker.concurrency`, `cpu`, `memory`, `disk`, `time_limit` | hard quota caps |
| runtime | `egress_policy` | deny/default registry allowlist by phase |
| providers | `github.app_id`, `installation_id`, `webhook_secret_ref` | secret references; never plaintext in config exports |
| providers | `gitlab.base_url`, `secret_ref`, `auth_mode` | URL SSRF validated; GitLab version compatibility |
| ai | `primary_model=muse-spark-1.3` | capabilities verified at setup |
| ai | `escalation_model=muse-wonder-1.0` | optional/availability dependent |
| ai | `max_calls_per_session`, `max_tokens_per_session`, `max_cost_per_session` | bounded hard thresholds |
| integrations | `telegram.bot_token_ref`, `delivery_mode=polling\|webhook` | mutually exclusive modes |
| notifications | `routes`, `quiet_hours`, `min_severity`, `language` | user/workspace scoped |
| repo policy | `mode=monitor\|approval\|auto_repair` | monitor default, versioned |
| repo policy | `branch_allowlist`, `file_denylist`, `sensitive_file_rules` | deny overrides allow |
| repo policy | `max_attempts`, `max_diff_lines` | default conservative; calibrated |
| repo policy | `require_baseline=true` | immutable publication invariant (ADR-031); no provisional publication option |

## Example non-secret schema sketch
```yaml
schema_version: 1
instance:
  deployment_mode: local
  public_base_url: http://127.0.0.1:4280
  telemetry: local-only
ai:
  provider: meta
  primary_model: muse-spark-1.3
  escalation_model: null
  max_calls_per_session: 30  # proposed, must calibrate
repository_defaults:
  mode: monitor
  require_baseline: true
  auto_merge: false
runtime:
  require_isolation_preflight: true
  network_execution: deny
notifications:
  telegram_enabled: false
```

## Validation precedence
Security hard denials are enforced in code: cannot be overridden by env, repository file, LLM or API payload. Policy evaluation: instance baseline → workspace controls → repo controls, deny wins. Secrets only by reference; `GET settings` redacts values and includes verification status. Environment variables supported for bootstrap/secret store injection, not unconstrained policy override.

## Policy changes
Policy update uses expected revision, dry-run effective diff, user re-auth for sensitive changes, audit; active repair captures effective policy revision and re-evaluates before publish. Config exports must redact user IDs where appropriate; key rotation creates new version and safely drains in-flight operations.

## P2 canonical validation and defaults
Legacy provisional_pr_allowed / allow_provisional_pr keys are rejected with CONFIG_RETIRED_KEY even when false; no migration into an opt-in. require_baseline must be true; false fails CONFIG_INVARIANT. auto_merge always false. Canonical ai keys max_calls_per_session, max_tokens_per_session, max_cost_per_session and max_wall_seconds map NFR-06; ambiguous old aliases return explicit migration guidance, not silently ignored.
Namespace paths are canonical: instance.*, security.*, runtime.*, providers.*, ai.*, notifications.*, repository_defaults.*. The earlier YAML `sandbox` namespace is renamed `runtime`; repo policy keys under repository_defaults for default values and per-repo revision for overrides. Defaults/ranges: max_attempts2(1…5),max_diff_lines500(1…2000),calls30(1…100),tokens120000(1…1000000),wall_seconds1800(60…7200),cost USD5(nonnegative decimal with currency); owner may lower workspace caps and all child values must fit. Hard limits must be calibrated before release; zero spend disables model calls. Unknown pricing blocks spend-governed use.
Policy preview returns effective value, source scope/revision and deny reason for each constraint. Config secrets reference encrypted broker entries; API never returns secret values. Export excludes tokens/bootstrap keys and is schema-versioned. Runtime profile/env/egress/key changes invalidate affected running checkpoints and approvals before escalation. Defaults cannot override current stricter policy or accepted invariants.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
