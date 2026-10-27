# Product requirements → tests → release gates

P2 design catalogue, 2026-10-27. **46 feature IDs; 41 P0, 4 P1, 1 P2. All tests NOT RUN; no implementation evidence.** Priority preserved from [02](02_FEATURE_CATALOG.md). All P0 mandatory for1.0.0; P1/P2 designs are retained and must pass their listed gates before any support claim, but are not silently relabelled P0. Pending ADRs remain approval prerequisites, not permissions to omit features.

## How to read the matrix
W IDs: [08 workflows](08_EVENTS_STATE_MACHINES.md); UI-S IDs: [34 screens](34_SCREEN_AND_INTERACTION_CONTRACTS.md); A/S IDs: [36 schemas/API](36_CANONICAL_CONTRACTS.md); data constraints: [06](06_DATA_MODEL.md); SEC IDs: [26](26_SECURITY_TEST_MATRIX.md); R IDs: [33](33_RELEASE_EVIDENCE_LEDGER.md).
For **each row** two stable test case IDs are defined: `T-<feature>-P` and `T-<feature>-N`. Positive/negative columns are their exact observable acceptance, not merely proposed test names. Test fixture uses isolated authorized workspace/repo/profile and records input/grants/version plus expected outcome, actual outcome, no-side-effect evidence and audit. Every row additionally requires schema validation, retry/cancel/permission/redaction and UI common states where applicable. P0 acceptance cannot be replaced by mocked UI or LLM narrative.
A family range such as UI-S01…21 or A-01…A-24 means all catalogue entries; slash means all listed entries. SEC-035 shorthand in a compound refers to SEC-035, not a new numeric namespace. DB projection is derived scoped data, not permission to omit authoritative ledger.

| Feature | Priority | Workflow | UI | API/schema family | DB entities | Security | Release | Test case IDs | Positive acceptance | Negative acceptance |
|---|---|---|---|---|---|---|---|---|---|---|
| INS-01 | P0 | W-01/W-08 | UI-S01 | A-01/A-18 | instances,migration_runs | SEC-019/035 | R-09 | `T-INS-01-P`, `T-INS-01-N` | Cài mới/rerun trên ba OS có UI healthy và manifest hợp lệ | Prereq thiếu/restart/chữ ký sai phải dừng có checkpoint, không xóa dữ liệu |
| INS-02 | P0 | W-01 | UI-S01 | A-01/A-06 | instances,consents | SEC-026/038 | R-06/R-09 | `T-INS-02-P`, `T-INS-02-N` | Bootstrap một lần, resume wizard và phân biệt ready_monitor/ready_repair | Token hết hạn/replay hoặc model chưa sẵn sàng không thành ready_repair |
| INS-03 | P0 | W-08 | UI-S20 | A-18/A-24 | backup_records,operation_receipts | SEC-019/035 | R-09/R-10 | `T-INS-03-P`, `T-INS-03-N` | Doctor/status và backup→restore cùng manifest, uninstall giữ data | Restore thiếu key/upgrade sai schema/purge ngoài root bị chặn |
| IAM-01 | P0 | W-01 | UI-S02/UI-S21 | A-02/A-03 | users,sessions,mfa_credentials | SEC-026/038 | R-06 | `T-IAM-01-P`, `T-IAM-01-N` | Login/step-up/recovery và revoke sessions có audit | CSRF/brute force/recovery replay không cấp session |
| IAM-02 | P0 | W-01 | UI-S19 | A-04/A-05 | workspaces,memberships,repo_grants | SEC-010/032/038 | R-06 | `T-IAM-02-P`, `T-IAM-02-N` | Hai workspace có memberships/repo grants độc lập | IDOR/FK/cache/SSE/export chéo tenant và last-admin removal bị từ chối |
| IAM-03 | P1 | W-10 | UI-S02/UI-S19 | A-02/A-05 | users,memberships | SEC-038 | R-06 | `T-IAM-03-P`, `T-IAM-03-N` | Federation capability xác minh issuer/claims và deprovisioning | Issuer/audience sai hoặc email-domain không được tự cấp role |
| SRC-01 | P0 | W-02 | UI-S15 | A-06/A-23 | provider_connections,repositories | SEC-001/011/031 | R-02 | `T-SRC-01-P`, `T-SRC-01-N` | App install xác minh selected repos và permission refresh | Installation query giả/revoke grant không đọc hay publish |
| SRC-02 | P0 | W-02 | UI-S15 | A-06 | provider_connections,capability_snapshots | SEC-003/027 | R-03 | `T-SRC-02-P`, `T-SRC-02-N` | GL.com/self-managed certified tạo draft đúng project/branch | Thiếu signature không downgrade auth; version/token thiếu quyền trả unsupported |
| SRC-03 | P0 | W-03 | UI-S06 | A-22/A-08 | webhook_inbox,outbox_events | SEC-001/002/027 | R-02/R-03/R-07 | `T-SRC-03-P`, `T-SRC-03-N` | Webhook+reconcile một logical session dù duplicate/reorder | Body giả/DB commit lỗi không ACK thành công |
| SRC-04 | P0 | W-03 | UI-S15 | A-06/A-08 | provider_sync_cursors,ci_runs | SEC-002/011 | R-02/R-03 | `T-SRC-04-P`, `T-SRC-04-N` | Polling restart từ cursor, overlap dedup đủ runs | 429/offline vượt history hiển thị gap, không giả đầy đủ |
| SRC-05 | P1 | W-10 | UI-S15 | A-06 | provider_connections,webhook_inbox | SEC-001/002/014 | R-02/R-03/R-06 | `T-SRC-05-P`, `T-SRC-05-N` | Relay opt-in giữ xác thực gốc, tenant scope, reconnection cursor | Relay replay/đổi payload/tenant không tạo session |
| REP-01 | P0 | W-02/W-09 | UI-S04 | A-07 | repositories,repo_grants | SEC-010/032 | R-06/R-11 | `T-REP-01-P`, `T-REP-01-N` | Pagination/filter/tags chỉ repo được cấp, sync partial rõ | Search/count/autocomplete không lộ repo khác |
| REP-02 | P0 | W-04 | UI-S05 | A-07/A-09 | repository_policies,repair_sessions | SEC-022/028 | R-06/R-11 | `T-REP-02-P`, `T-REP-02-N` | Mode/pause versioned, audit và dry-run policy | Monitor không execute; stale update không ghi đè |
| REP-03 | P0 | W-05/W-06 | UI-S05 | A-07 | repository_policies,approval_requests | SEC-007/009/031 | R-06 | `T-REP-03-P`, `T-REP-03-N` | Deny-overrides-allow cho branch/path và sensitive review | Path escape/workflow weakening/protection bypass bị chặn |
| TRI-01 | P0 | W-03/W-04 | UI-S06 | A-08/A-10 | ci_runs,ci_jobs,artifacts | SEC-016/036 | R-02/R-03 | `T-TRI-01-P`, `T-TRI-01-N` | Run/attempt/matrix/log range đúng SHA, missing rõ | Archive bomb/log hết hạn không suy diễn pass |
| TRI-02 | P0 | W-04 | UI-S08 | A-09/A-10 | diagnostics,repair_sessions | SEC-005/024/028 | R-04/R-12 | `T-TRI-02-P`, `T-TRI-02-N` | Classification có cited evidence và abstention lý do | Infra/auth/unsupported/unknown không spawn patch |
| TRI-03 | P0 | W-04 | UI-S08 | A-10 | diagnostics,reproduction_runs | SEC-024/028 | R-12 | `T-TRI-03-P`, `T-TRI-03-N` | History fingerprint+runs bounded phân biệt flaky/unknown | Một lần green không đủ tuyên bố fixed hoặc flaky đã chứng minh |
| AGT-01 | P0 | W-04 | UI-S12 | A-20 | capability_snapshots,provider_connections | SEC-012/023 | R-04 | `T-AGT-01-P`, `T-AGT-01-N` | Consented probe lưu model/capabilities/account thời điểm | Không quota/key/model access không invent ready |
| AGT-02 | P0 | W-04/W-05 | UI-S11 | A-20/A-10 | agent_steps,context_manifests | SEC-005/012/028 | R-04/R-06 | `T-AGT-02-P`, `T-AGT-02-N` | Typed tools chỉ own worktree, bounded valid schema | Prompt injection/extra args/forged tool result không vượt quyền |
| AGT-03 | P0 | W-04/W-05 | UI-S12 | A-20/A-17 | budget_reservations,usage_ledger | SEC-013/033 | R-04/R-12 | `T-AGT-03-P`, `T-AGT-03-N` | Reserve/settle atomic, stop cap/time/cancel | Parallel requests/unknown billing không overspend hay ghi zero |
| AGT-04 | P1 | W-10 | UI-S12 | A-20 | profile_revisions,capability_snapshots | SEC-012/023 | R-04 | `T-AGT-04-P`, `T-AGT-04-N` | Explicit allowed model fallback bảo toàn budget/tool policy | Missing optional model không chuyển vendor hoặc tăng scope ngầm |
| SAN-01 | P0 | W-04/W-05 | UI-S13 | A-13 | workers,sandbox_leases | SEC-006/021/029 | R-05 | `T-SAN-01-P`, `T-SAN-01-N` | Ephemeral job enforce quotas/no keys và cleanup verified | Host socket/control IP/tenant khác/escape attempt bị chặn |
| SAN-02 | P0 | W-04 | UI-S08 | A-10 | reproduction_runs,evidence_manifests | SEC-024/025/030 | R-05/R-12 | `T-SAN-02-P`, `T-SAN-02-N` | Baseline original failure cùng immutable profile đầy đủ fidelity | Unrelated failure/zero-test/timeout không coi reproduced |
| SAN-03 | P0 | W-04/W-05 | UI-S13 | A-13/A-10 | profile_revisions,reproduction_runs | SEC-006/036 | R-05/R-12 | `T-SAN-03-P`, `T-SAN-03-N` | Pytest/Jest/Vitest từng profile lockfile+image chứng minh red→green | Unsupported services/privileged hooks không chạy trên host |
| SAN-04 | P1 | W-10 | UI-S13 | A-13 | workers,profile_revisions | SEC-029/032 | R-05 | `T-SAN-04-P`, `T-SAN-04-N` | Advanced fleet backend capability/certification tách trust domains | Chưa certify không quảng cáo multi-tenant kernel isolation |
| FIX-01 | P0 | W-05 | UI-S08 | A-10 | patch_attempts,verification_runs | SEC-007/008/009/028 | R-06/R-12 | `T-FIX-01-P`, `T-FIX-01-N` | Patch digest/path/size/test semantics được kiểm độc lập | Skip/delete/xfail/harness weakening không được green |
| FIX-02 | P0 | W-05 | UI-S08 | A-10 | verification_runs,evidence_manifests | SEC-025/030 | R-05/R-12 | `T-FIX-02-P`, `T-FIX-02-N` | V-01…07 evidence đầy đủ baseline/patched/regression | Model prose/tampered blob/wrong signer không tạo proof |
| FIX-03 | P0 | W-06 | UI-S09 | A-12 | publication_records,remote_ci_checks | SEC-011/015/016/031 | R-02/R-03 | `T-FIX-03-P`, `T-FIX-03-N` | Một draft tại đúng SHA, remote required-check set đầy đủ | Ambiguous write không duplicate; missing/skipped/wrongSHA không remote verified |
| FIX-04 | P0 | W-04/W-06 | UI-S08 | A-09/A-10 | repair_sessions,diagnostics | SEC-024/028 | R-06/R-12 | `T-FIX-04-P`, `T-FIX-04-N` | Unconfirmed ghi diagnosis+human handoff, không publication | Approval/policy option không thể miễn baseline ADR-031 |
| APP-01 | P0 | W-09 | UI-S07/UI-S08 | A-09/A-10/A-21 | artifacts,repair_sessions,audit_log | SEC-010/032/040 | R-11 | `T-APP-01-P`, `T-APP-01-N` | Timeline/diff/log/evidence đồng bộ snapshot+cursors | Mất SSE/expired artifact không giả pass hoặc leak |
| UI-01 | P0 | W-09 | UI-S01…21 | A-01…A-24 | scoped read DTOs | SEC-026/032/040 | R-11 | `T-UI-01-P`, `T-UI-01-N` | React19/TS strict/Vite/Astryx typed wrappers, keyboard/screenreader đạt | Props sai/unsafe HTML/cross-workspace navigation bị phát hiện |
| UI-02 | P0 | W-09 | UI-S01…21 | A-03/A-16 | user_notification_preferences | SEC-040 | R-11 | `T-UI-02-P`, `T-UI-02-N` | Dark/light/responsive tokens và fallback có ADR+visual evidence | Contrast/focus/upgrade regressions không bị bỏ qua |
| APP-02 | P0 | W-06 | UI-S10 | A-11 | approval_requests,approval_votes | SEC-022/026/031 | R-06/R-11 | `T-APP-02-P`, `T-APP-02-N` | Web step-up approve bound patch/base/policy/expiry | Double click/replay/changed diff/revoked role không publish |
| NOT-01 | P0 | W-07 | UI-S16 | A-16/A-21 | notification_events,user_notification_preferences | SEC-032/034 | R-08 | `T-NOT-01-P`, `T-NOT-01-N` | Durable inbox/read state/filter/quiet hours scoped | Opt-out không xóa security audit; revoked grants không thấy payload |
| NOT-02 | P0 | W-07 | UI-S16/UI-S21 | A-16/A-22 | telegram_links,link_challenges | SEC-004/034/038 | R-08 | `T-NOT-02-P`, `T-NOT-02-N` | One-use link và read commands đúng repo grant, mode polling/webhook tách | Wrong chat/group/spoof/replay không lộ data |
| NOT-03 | P0 | W-07/W-06 | UI-S10/UI-S16 | A-11/A-16 | approval_requests,link_challenges | SEC-004/022/034 | R-06/R-08 | `T-NOT-03-P`, `T-NOT-03-N` | Telegram action chỉ tạo web intent được RBAC step-up xác nhận | Callback/GET/link preview tự nó không mutate |
| NOT-04 | P0 | W-07 | UI-S16 | A-15/A-24 | notification_destinations,notification_deliveries | SEC-014/017/034 | R-08 | `T-NOT-04-P`, `T-NOT-04-N` | SMTP/Slack/Discord/webhook từng adapter receipt/retry/redaction/consent | Delivery timeout giữ unknown; SSRF/replay/revoked recipient không gửi |
| JOB-01 | P0 | W-08 | UI-S14 | A-14 | task_jobs,outbox_events | SEC-002/021 | R-07 | `T-JOB-01-P`, `T-JOB-01-N` | Crash recovery/fair scheduling giữ acknowledged jobs | Mất Redis/lease duplicate không mất job hay effect lặp |
| JOB-02 | P0 | W-08 | UI-S14 | A-09/A-14 | task_jobs,dead_letter_jobs | SEC-015/020/021 | R-07 | `T-JOB-02-P`, `T-JOB-02-N` | Pause/cancel/resume/requeue có fence/checkpoint/receipt | Replay terminal/DLQ không reset budget hay push mù |
| OPS-01 | P0 | W-08/W-09 | UI-S20 | A-18/A-17 | audit_log,operation_receipts | SEC-017/037 | R-13 | `T-OPS-01-P`, `T-OPS-01-N` | Correlation/metrics/alarms+runbook tái hiện incident và recovery | Secret canary trong telemetry/tail tamper không im lặng |
| OPS-02 | P0 | W-08 | UI-S20 | A-18 | backup_records,schema_migrations | SEC-019/020/035 | R-10 | `T-OPS-02-P`, `T-OPS-02-N` | Consistent backup/key recovery/migration/restore timed | Missing blobs/key/incompatible rollback không bật writes |
| OPS-03 | P0 | W-08 | UI-S18 | A-06/A-18/A-19 | consents,api_tokens,artifact_deletion_jobs | SEC-017/033/039 | R-06/R-14/R-15 | `T-OPS-03-P`, `T-OPS-03-N` | Rotate/revoke/retention purge và exception expiry audit được | Secret reveal/egress bypass/waived Critical không qua gate |
| ANL-01 | P0 | W-09 | UI-S17 | A-17 | usage_ledger,reporting projections | SEC-010/032 | R-11/R-13 | `T-ANL-01-P`, `T-ANL-01-N` | Funnel denominator,unknown,cost thất bại và watermark đúng | Filter/tenant aggregate không leak hay đổi local thành remote success |
| ANL-02 | P0 | W-09 | UI-S17/UI-S18 | A-17 | report_exports,audit_log | SEC-032/037/040 | R-06/R-11 | `T-ANL-02-P`, `T-ANL-02-N` | CSV/JSON scoped redacted export hết hạn | Formula injection/expired/revoked export không leak/execute |
| EXT-01 | P0 | W-07/W-09 | UI-S18 | A-19/A-15 | api_tokens,notification_deliveries | SEC-014/022/034 | R-06/R-08 | `T-EXT-01-P`, `T-EXT-01-N` | Scoped expiring API token + signed outgoing events versioned | Issuer revoke/overgrant/replay/SSRF không vượt scope |
| EXT-02 | P2 | W-10 | UI-S15 | A-06 | capability_snapshots,api_tokens | SEC-028/032 | R-06 | `T-EXT-02-P`, `T-EXT-02-N` | Extension negotiate read/status/action capabilities, actions dùng core policy | MCP tool không raw shell/publish bypass và disabled rõ |

## Shared requirements are not orphans
- NFR-01…16 each define T-NFR-01…16 and release mapping in [37](37_NFR_AND_RECOVERY.md).
- S-01…05 apply to all A operations; S-06…18 are used by A catalogue; S-19 by A-21/A-22/NOT/EXT; S-20 by AGT-02; S-21 by SAN-01/JOB; S-22 by FIX-02/OPS. Contract round-trip/unknown fields/unsupported version tests belong to the corresponding T-feature-P/N.
- V-01…07 map FIX-02/FIX-04/FIX-03; V-08 maps FIX-03. SEC-001…040 are mandatory negative corpus for R-06 plus specialized gate mapped in doc26.
- UX-* IDs map UI-S screen rows; FE-* baseline frontend tests map UI-01/UI-02 and R-11. All21 screens included in shared keyboard/theme/empty/error/reconnect assertions, not only17 original summary rows.
- ADR-030 → IAM-02/SEC-032/R-06; ADR-031 → FIX-04/SEC-028/V-01/R-06/R-12; ADR-032 → OPS-03/SEC-039/R-06/R-14.
- OIDC/relay/MCP (P1/P2) remain capability contracts W-10, no invented ready endpoints. Their precise public extension schemas must be separately approved before enabling those extensions; core A references show authorization/configuration boundary, not implemented extension protocol.

## Reverse release mapping and evidence
| Gate | Requirement families that must be represented | Evidence condition |
|---|---|---|
| R-01 | all46 catalogue rows and all P0 trace paths | no missing feature/test/schema/owner mapping; docs validation plus implementation trace later |
| R-02 | SRC-01/03/04,TRI-01,FIX-03 | real authorized GitHub E2E + negative replay/fork/attempt/required checks |
| R-03 | SRC-02/03/04,TRI-01,FIX-03 | real GitLab.com + selected self-managed certified fixtures/version evidence |
| R-04 | AGT-01/02/03; AGT-04 if claimed | real authorized Meta account + structured tools + budgets/cancel; no quota assumptions |
| R-05 | SAN-01/02/03,FIX-02; SAN-04 if claimed | isolation negative tests on each claimed runtime, not host-executed untrusted repo |
| R-06 | IAM,REP,APP-02,FIX-04,OPS-03,EXT-01 and entire SEC corpus | no invariant failures; Critical closed, High valid scoped exceptions only |
| R-07 | SRC-03,JOB-01/02,NFR-01/02/05 | crash/replay/lease/queue recovery with durable proof |
| R-08 | NOT-01/02/03/04,EXT-01 | every channel real consented test, unknown delivery/revocation/signature cases |
| R-09 | INS-01/02/03,NFR-10 | all3 installer OS profiles with prereq/restart paths |
| R-10 | INS-03,OPS-02,NFR-07/08/10 | timed coherent backup/restore, key recovery and incompatible upgrade |
| R-11 | UI-01/02,APP-01/02,REP,ANL,NFR-11/12 | pinned frontend build, all21 screens and accessibility/manual browser evidence |
| R-12 | TRI-02/03,AGT-03,SAN-02/03,FIX-01/02/04 | >=20 benchmark cases with failure/abstention denominators, budgets and immutable proof |
| R-13 | OPS-01,ANL-01,NFR-03/04/05/09/12/13/14 | reference load, alarms/runbooks and availability observation distinguished |
| R-14 | OPS-03,INS-01,security supply chain | signed artifacts, provenance/SBOM, Critical closure/High exception, licensing |
| R-15 | all operational docs,privacy/support declarations,OPS-03 | exact certified matrix, known limitations, consent/retention docs, owner sign-off |

All evidence records include requirement/test IDs, build/source digest, environment+vendor versions, actual result, artifact hashes, runner identity, start/end timestamps, reviewer and expiry/retest trigger. NOT RUN/BLOCKED/FAIL are never PASS; a linked plan is not a result. Owner review of this spec does not authorize real test accounts, notifications, paid API or deployment.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
