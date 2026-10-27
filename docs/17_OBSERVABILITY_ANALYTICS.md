# Metrics, observability, reports, budgeting

## Telemetry stack proposal
JSON structured logs (`timestamp`, `severity`, `component`, `workspace/repo pseudonymous IDs`, `session_id`, `correlation_id`, `error_code`); OpenTelemetry spans for webhook -> triage -> model -> sandbox -> verifier -> publisher -> remote CI. Prometheus-format metrics and OpenTelemetry exporters optional, built-in UI must not require external managed service. Secret/source-redaction in logs/traces at ingress.

## Reliability SLI/SLO (targets to be calibrated)
- Webhook ingestion success and p95 response time; queue waiting time; worker availability; end-to-end session time; model API error rate.
- Distinguish error budget/availability of **platform** vs inability to reproduce unsupported repo pipeline.
- Alerts for backlog age, failed backups, provider token revocation, worker isolation failure, broken notifications, repeated unauthorized access, disk usage, stalled publishing intent.
- Do not invent numerical SLO guarantees prior to benchmark; set by tested hardware/deployment profile and publish versioned operational targets.

## Repair funnel
`CI failures observed` → `eligible` → `reproduced` → `patch proposed` → `locally verified` → `draft PR created` → `remotely verified` → `human accepted`. Each stage counts unique logical sessions over explicit time windows; display denominator and exclusion reasons. Do not imply success merely because PR exists. Invalid attempt count and multi-iteration metrics shown separately.

## Cost ledger
Per session: Meta input/output tokens, estimated USD/API reported usage, model ID, inference time, sandbox CPU-seconds/memory/storage, notification quotas, retry count. Costs shown as estimates with provider billing delay disclaimer. Budget caps per workspace, repo, session, day; notify at thresholds, stop model requests safely on hard ceiling.

## Security and audit analytics
API authentication failures, denied repair policies, secret-redaction findings, artifact download counts, privileged settings changes, Telegram command attempts and callback outcomes. Audit retained per policy; export signed/verified where supported. No raw private source in dashboards by default.

## Report exports
Workspaces can export CSV/JSON aggregated performance and session evidence manifest within authorization. Sanitization and access checks on analytics query filters; avoid exposing cross-tenant data through aggregation. Repair 'Proof Report' exports environment, commands, log source and verification status; proof manifest references restricted artifacts rather than embedding entire raw CI logs.

## Acceptance
Metrics reconcile with DB event ledger under replays; no duplicate success count; retention honored; `worker.offline` alert fired in controlled test; cost threshold cancels bounded work; UI filters scoped by RBAC; logs redaction canary passed.

## P2 measurable observability
[37](37_NFR_AND_RECOVERY.md) defines NFR-01…16 TARGETS, measurement workload, alarms and failure recovery. Emit metrics for inbox/outbox age, ready/leased/expired jobs, queue lag by workspace class (avoid unbounded raw repo labels), worker saturation, model reserved/settled/unknown cost, gate refusals, publication unknown, remote CI age, notification accepted/unknown/bounced, storage watermark, backup last verified age. Correlation IDs link API→event→job→tool→evidence→publisher→remote observer.
Analytics denominators: eligible failures / all ingested failures; reproduced / eligible executed; local verified / confirmed baselines; published / locally verified eligible; remotely verified / published with completed observation. Show unknown/pending/excluded counts and period/watermark; cost includes failed/abstained/retried sessions. Never call local green a remote success; workspace aggregation only includes current authorized repositories. Trace sampling may reduce benign spans but never remove audit/security transitions.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
