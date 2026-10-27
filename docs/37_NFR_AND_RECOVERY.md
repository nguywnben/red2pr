# Operating targets, recovery and capacity — P2

**All values below are PROPOSED TARGETS under ADR-036, not measurements, guarantees or a contracted SLA.** Release certification requires recorded hardware, software versions, dataset, load generator, raw output and independent reviewer. No benchmark was run during this docs task.

## Reference load and measurement method
Candidate server reference: 8 vCPU,16GiB RAM control/database host, SSD100GiB usable excluding artifacts; two separate worker VMs each4vCPU/8GiB/40GiB. Candidate local:4vCPU/8GiB/40GiB free plus profile dependencies, one repair at a time; monitor-only may need less but no certified minimum yet. Network bandwidth/RTT to provider, artifact storage, fsync/storage durability and worker architecture must be logged. Dataset:10 workspaces,100 repositories,50 concurrent authenticated users,1million audit/events,10k repairs,100GB artifacts. Isolated worker load is capped independently of UI/API load.
Test steady60min at10 API reads/s +2 writes/s,10 webhook events/s with100/s burst60s; two concurrent repair jobs with synthetic timed execution plus real certified benchmark separately. Report p50/p95/p99, errors, saturation and dropped/replayed messages; never exclude failed requests from percentiles. Provider latency/quota reported separately, not hidden inside app performance claim.

| Requirement | TARGET / boundary | Acceptance measurement / release gate |
|---|---|---|
| NFR-01 durability | zero acknowledged inbox/job/approval intent loss after process crash; commit durable before2xx/202; fsync enabled | T-NFR-01: kill API/queue worker at each commit boundary100 iterations; committed ledger equals recovered state; R-07 |
| NFR-02 recovery | worker heartbeat15s, lease60s, orphan detected<=90s; new eligible lease<=120s when capacity exists; no stale write | T-NFR-02: kill worker/Redis, restart, verify fence + exactly one logical effect; R-05,R-07 |
| NFR-03 API/ingress | API reads p95<=500ms,p99<=1500ms; async command acceptance p95<=800ms; webhook durable ack p95<=1s,p99<=3s; app5xx<0.1% | T-NFR-03: reference load; do not wait inference/tests in request; R-13 |
| NFR-04 realtime/reconcile | SSE committed event visible p95<=2s; revoke closes stream/blocks action<=5s; polling default60s + jitter; missed webhook caught<=5min when provider available | T-NFR-04: disconnect/replay/revoke/missed event; provider outage marked excluded with duration; R-02,R-03,R-11,R-13 |
| NFR-05 fairness/rate | per-workspace running repair cap2 by default; no eligible workspace starvation>120s after capacity frees; read120/min/user,mutate30/min/user,login5failed/15min/account+IP TARGET | T-NFR-05: noisy tenant vs quiet tenant, multi-process limiter consistency,429 Retry-After; no indefinite account DoS lockout; R-06,R-07,R-13 |
| NFR-06 spend/time |30 calls,120k total tokens,2 patch attempts,30min session,USD5 estimated ceiling default; backend reserves max potential usage before send | T-NFR-06: parallel reservation,429/timeout/cancel/unknown usage; no cap bypass; price snapshot required; R-04,R-12 |
| NFR-07 retention | raw provider logs7d; redacted evidence/artifacts30d; audit+usage365d; inbox/delivery dedup tombstones90d; SSE replay24h; configurable longer within storage budget | T-NFR-07: expiry across DB/blob/cache/exports, legal hold, delete retry; replay older than retention cannot re-publish; R-06,R-10,R-15 |
| NFR-08 backup | production server RPO<=15min with WAL/archive continuous plus object checkpoint; RTO<=4h for reference dataset; local daily backup RPO<=24h,RTO<=8h | T-NFR-08: timed isolated restore of DB+100GB objects+key refs, manifest verify; no claim PITR if local snapshot only; R-10 |
| NFR-09 availability | server service objective99.5% monthly excluding planned maintenance<=2h/month, dependent on owner infrastructure; single-node failure can exceed target | T-NFR-09:30day operational observation for claim; distinguish dependency vs app downtime; R-13; no HA promise |
| NFR-10 upgrade | preflight detects incompatible schema/worker, writes drained<=5min when no unsafe in-flight effect; binary rollback<=15min only compatible schema | T-NFR-10: interrupted upgrade and old-worker handshake; migration restore timed under NFR-08; R-09,R-10 |
| NFR-11 accessibility/UI | WCAG2.2AA target; all critical actions keyboard+screen reader;320px mobile and200%zoom reflow; diff may scroll with accessible alternative | T-NFR-11: automated+manual critical journeys/dark-light, no critical/serious unresolved violations; R-11 |
| NFR-12 frontend responsiveness | primary overview interactive<=3s p75 on defined4Mbps/150ms mobile emulation; 50kline log/diff opens<=2s after first chunk; no unbounded DOM | T-NFR-12: pinned browser/device trace, bounded paging/virtualization + keyboard tests; R-11,R-13 |
| NFR-13 observability |100% state changes and privileged effects have correlation+audit; no sampled-away security audit; alarms within5min of sustained queue lag/failed backup/worker quarantine | T-NFR-13: synthetic injected incidents, alert route and runbook recovery; logs/traces redact secret canaries; R-06,R-13 |
| NFR-14 artifacts/quotas | default per-log20MiB,download archive100MiB compressed/500MiB expanded/10kfiles; worker output100MiB/job,disk40GiB,pids512; storage soft80% hard90% | T-NFR-14: zip bomb/diskfull/large logs halt safely, report truncated vs unavailable, never partial pass; R-05,R-13 |
| NFR-15 evidence integrity | every published intent linked to valid local manifest + V-01…07; zero false-green/unauthorized publishes in negative suite | T-NFR-15: tampering/wrongSHA/zero-test/skipped-required-check; invariant non-waivable; R-02,R-03,R-05,R-06 |
| NFR-16 notification | healthy channel enqueue→first attempt p95<=30s;8attempts/max24h; revoked recipient suppress<=5s; critical inbox persists independent of external failure | T-NFR-16: outage,timeout,bounce429,role change,quiet hours; receipt ≠ read; R-08 |

## Recovery decisions and data consistency
| Incident | Detection / containment | Recovery proof and operator UI |
|---|---|---|
| PostgreSQL unavailable | reject new mutating acceptance503, stop scheduling/publisher; existing guest bounded | DB reconnect then lease/state reconcile; no in-memory “accepted” jobs; UI degraded |
| Redis lost | DB intents remain; pause dispatch and rebuild queue from authoritative eligible rows | duplicates fenced/deduped; no event-order assumption; queue recovery receipt |
| Worker lost / compromised | expiry or integrity failure; revoke capabilities, quarantine trust domain, stop new jobs | discard untrusted result, preserve forensic redacted refs; fresh worker and new lease; no silent proof reuse |
| Model outage/rate cap | suspend at safe checkpoint; no retries outside budget | explicit resume after capability/consent check; unknown bill accounted |
| Provider revoke/outage | permissions denied / read failures; stop writes, keep unknown outcome intent | reauthorization + object/SHA reconciliation; do not assume timeout means no PR |
| Disk/object storage full | watermark alert, prevent admission, preserve audit space | owner extends/purges by retention; missing artifacts invalidate proof; do not delete evidence merely to get green |
| Notification outage | queue/DLQ alert and in-app visibility | requeue subject to current grant/consent; dedup/unknown warnings retained |
| Signing/master key loss | stop decrypt/sign/publish; expose recovery blocker | separately backed-up wrapped keys + key inventory; if unavailable encrypted backup is not restorable |
| Restore to earlier time | maintenance, disable ingress workers/publisher/outbound dispatcher | rotate instance recovery epoch, re-enroll/fence workers, compare provider state, resume only approved operations |
| Incompatible migration | stop writes, preserve backup/log, mark maintenance_failed | schema-compatible rollback or consistent full restore; don't mix old DB with new blobs |

Backup manifest binds snapshot timestamp/DB LSN, object inventory+digests, schema version, build version, workspace inventory, encrypted key-reference inventory and config hash. Secret wrapping keys stored separately from data backup with tested recovery access. Snapshot/objects need common watermark and deletion hold during backup; WAL alone cannot reconstruct missing artifacts. Verify immutable objects and referential consistency before enabling writes.
Restore starts on isolated destination with no provider/model/notification egress. Dry-run verifies signature, key availability, version/profile compatibility, capacity and target scope. Owner reviews plan digest and confirms; unknown publish/delivery intents reconcile against providers after explicit enablement, never blind replay. Old workers/tokens cannot write into restored epoch. Retention tombstones applied after restore so expired/deleted personal data is not resurrected. RPO/RTO measured from incident to usable authorized operation, including decrypt/reconciliation, not just DB import.
Uninstall defaults preserve data/backups/keys; purge requires explicit scoped confirmation and resolved path ownership guard, no recursive delete of generic user/home/parent folders. Support bundle preview lists exactly included redacted files, expiry and consent; no secrets/source by default.

## Release interpretation
Targets require owner review; unmeasured=NOT RUN, missed=FAIL, unavailable environment=BLOCKED. Target exception for performance needs ADR and public scope, cannot exempt security invariants or silently lower feature priority. R-13 evidence must distinguish load test from long-term99.5% observation; synthetic uptime is not30day operational validation. A release without necessary observation remains preproduction rather than inventing production readiness.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
