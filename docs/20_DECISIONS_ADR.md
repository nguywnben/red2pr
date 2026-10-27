# Architectural Decision Records — baseline 2026-10-26

**Status meaning:** `ACCEPTED` (user explicitly settled direction), `PROPOSED` (tech lead design default to confirm before code), `OPEN` (no decision/needs verification). Future changes append versioned ADR and cross-references, don't silently edit prior behavior.

| ID | Status | Decision | Rationale / consequences |
|---|---|---|---|
| ADR-001 | ACCEPTED | Product = Red2PR, self-hosted automated CI repair with evidence-backed draft PR/MR | differentiate from generic coding agent |
| ADR-002 | ACCEPTED | Production-first full feature **design**, not MVP-only scope | complete functional/UX/API/security plan before code |
| ADR-003 | ACCEPTED | Implement in incremental verified milestones; not defer all tests | prevents systemic rework and false readiness |
| ADR-004 | ACCEPTED | Linux/macOS one-command entrypoint, Windows one-command entrypoint + web wizard | simple operational UX; prerequisites may require interaction |
| ADR-005 | ACCEPTED | User manages multiple repositories and per-repo auto-repair toggles/policies via web | real product UX |
| ADR-006 | ACCEPTED | GitHub Actions & GitLab CI both in target product | provider adapters, support matrix required |
| ADR-007 | ACCEPTED | Telegram + notifications + admin/analytics/integrations in full functional spec | communications are first-class, not merely optional hacks |
| ADR-008 | ACCEPTED | Meta Muse models primary AI engine; coding/diagnosis/reasoning | model API connected outbound; self-host app != offline AI |
| ADR-009 | ACCEPTED | Verification evidence separate from model text, baseline before/after, remote CI independent | reliable claims |
| ADR-010 | ACCEPTED | No auto-merge / no bypass approval | safety, least privilege |
| ADR-011 | ACCEPTED | User approves before any implementation begins; current kit is docs only | no unrequested code/deploy |
| ADR-012 | PROPOSED | Modular monolith control plane (FastAPI) + isolated worker + privileged publisher | simpler to self-host than service sprawl |
| ADR-013 | PROPOSED | PostgreSQL + transactional outbox, Redis transport and S3-compatible or local encrypted artifacts | self-host operations and reliable event delivery; verify actual queue/runtime choice |
| ADR-025 | ACCEPTED | Frontend React 19 + TypeScript + Vite + Astryx Design System; Python/FastAPI control plane/agents | user chose Astryx; static SPA simplifies self-host, no need to rewrite backend in JS |
| ADR-026 | ACCEPTED | Final artifact kit contains only repository documents; Codex operating prompts are external, never embedded in repo ZIP | repo clean, planning prompts can change without touching product files |
| ADR-027 | ACCEPTED | Complete integrated specification and owner-approved master plan before implementation; execute exact chosen plan unit, test continuously | maintain whole-product alignment without end-only test cliff |
| ADR-028 | ACCEPTED | 1.0.0 production claim only after evidence-backed release gates pass; no pressured green reporting | guard user and customers from false readiness |
| ADR-014 | PROPOSED | Local polling default, server HTTPS webhook + reconciliation; opt-in relay later | local NAT and event robustness |
| ADR-015 | PROPOSED | New repo defaults Monitor Only; 3 modes Monitor/Approval/Auto-Repair | safe activation |
| ADR-016 | PROPOSED | Local single-host allowed for trusted repos with risk warning; isolated worker VM mandatory for untrusted code | honest security boundary |
| ADR-017 | PROPOSED | Telegram read-only commands; mutations require secure web confirmation | Telegram identity alone not enough for privileged action |
| ADR-029 | ACCEPTED | Notification channels include in-app, Telegram, email, Slack, Discord and outgoing signed webhook with a common dispatcher | full product suite with consistent event controls; integration credentials remain optional |
| ADR-018 | PROPOSED | Strict support matrix: Linux Python pytest & Node Jest/Vitest, unsupported jobs abstain | release claims must be tested |
| ADR-019 | PROPOSED | Secure release installer with signatures/checksums, updates/backup/restore CLI | supportable self-host operations |
| ADR-020 | PROPOSED | First-party Meta model profiles Spark triage and Wonder optional complex patch, with live account feature checks | cost/capability fit |
| ADR-021 | OPEN | Final public domain, publishing identity, software license and trademark availability | required prior external launch |
| ADR-022 | OPEN | Exact minimum RAM/CPU/WSL/macOS versions, supported GitLab versions and provider API scopes | benchmark + test |
| ADR-023 | OPEN | Multi-org tenancy in one instance vs one-workspace-first support, SSO auth mode | requirements need owner sign-off |
| ADR-024 | OPEN | Cloud relay operated by Red2PR vs self-hosted relay only | privacy, security and operating cost trade-off |

## Change protocol
Any change to an ACCEPTED principle requires explicit owner approval and PR to this document; PROPOSED changes require ADR with trade-off/risks/test impact and owner review for platform-affecting decisions; OPEN entries resolved after official docs/test/environment facts.

## P2 decision records — 2026-10-27

Các dòng ADR-001…029 phía trên được giữ nguyên như lịch sử quyết định. Những record sau ghi rõ phần giải quyết/thay thế; không tự biến đề xuất thành quyết định của owner.

| ID | Status | Decision | Rationale / consequences |
|---|---|---|---|
| ADR-030 | ACCEPTED | 1.0.0 có nhiều workspace mỗi instance | Owner trả lời trực tiếp 2026-10-27. Giải quyết phần tenancy của ADR-023; SSO vẫn OPEN. Mọi tenant entity/query/cache/artifact/event/job bắt buộc scope; R-06 phải kiểm thử chéo workspace. Không đồng nghĩa SaaS công cộng hoặc container chung đủ cách ly code thù địch. |
| ADR-031 | ACCEPTED | Baseline không tái hiện: chỉ diagnosis + human handoff, tuyệt đối không tạo draft PR/MR | Owner trả lời trực tiếp 2026-10-27. Thay thế tùy chọn provisional của docs 11/25; V-01 không có waiver, approval không vượt invariant. Khả năng sửa tự động thấp hơn nhưng không bán kết luận chưa có bằng chứng. |
| ADR-032 | ACCEPTED | Critical phải đóng; High chỉ ngoại lệ có thời hạn, owner và mitigation | Owner trả lời trực tiếp 2026-10-27. Invariant vi phạm (secret, vượt quyền, false-green, rò workspace, escape) luôn chặn release. Ngoại lệ hết hạn tự chặn; đánh giá lại mỗi release. |

### ADR-033 — PROPOSED: canonical modes, contracts and identifiers
Conflict: monitor ở docs 02 cấm sandbox nhưng docs 31 từng cho phép; state/event/config/tool names khác nhau. Đề xuất monitor chỉ ingest/diagnose, chuyển sang approval bằng web để execute; pause là override riêng. Dùng schema/event/tool thống nhất ở [36](36_CANONICAL_CONTRACTS.md), workflow ở [08](08_EVENTS_STATE_MACHINES.md). Lợi ích: testable contract, không có execute ẩn; tác động: canonical names trong draft thay tên cũ, chưa có code/data cần migrate. Alternative: thêm explicit reproduction mode làm UI/policy phức tạp hơn. Owner duyệt trước implementation.

### ADR-034 — PROPOSED: multi-workspace identity and mandatory isolation baseline
Giữ local onboarding/invitations của IAM-02 ở P0; IAM-03 P1 là federation/OIDC provisioning. Đề xuất TOTP + single-use recovery ở P0 cho owner/admin và người publish/approve, step-up 5 phút cho thao tác đặc quyền; passkey và OIDC vẫn P1. Server owner quản trị instance không mặc nhiên đọc repo của mọi workspace; break-glass có grant tạm thời, reason, audit và thông báo.
ADR-030 buộc SAN-01 P0 có worker host/VM tách control plane cho code chưa tin cậy; SAN-04 P1 là fleet hardening/backend nâng cao, không phải hoãn isolation cơ bản. Workspace không có trust claim mặc định; pooled hostile workloads cần ephemeral VM/job hoặc dedicated worker trust domain được chứng minh. Alternative: một shared Docker host rẻ hơn nhưng không đủ boundary cho hostile tenancy. Tác động: vận hành, recovery MFA và capacity cần R-05/R-06; không đổi priority SAN-04.

### ADR-035 — PROPOSED: durable control plane and evidence trust
Cụ thể hóa ADR-012/013: Python/FastAPI modular monolith, PostgreSQL source of truth, transactional inbox/outbox; Redis + Dramatiq chỉ transport, mất Redis không mất accepted jobs. Local encrypted object store cho local; S3-compatible cho distributed. Không buộc Temporal khi chưa chứng minh nhu cầu.
Trusted supervisor ngoài guest ký manifest; control verifier xác thực, append audit hash chain + signed checkpoints và bảo quản checkpoint ngoài writer. Hash đơn lẻ không chứng minh tác giả; chữ ký không chứng minh host bị compromise báo đúng. Alternative Temporal giảm logic orchestration tự viết nhưng tăng operational footprint. Các crash/replay/forgery tests bắt buộc trước quyết định pin runtime.

### ADR-036 — PROPOSED: operating targets and certification envelope
Các số ở [37](37_NFR_AND_RECOVERY.md) là TARGET, chưa measured SLA. Candidate profiles ở [27](27_SUPPORT_MATRIX.md) chỉ thành CERTIFIED sau R-09/R-10/R-13; không hỗ trợ mọi OS/CPU/job. Local single control node không hứa HA; distributed chỉ worker separation, không tự động HA PostgreSQL.
High waiver đề xuất tối đa 30 ngày, security reviewer + release owner ký, tái duyệt khi thay artifact; owner cần duyệt duration, không phải nới ADR-032.

### ADR-037 — PROPOSED: private integration endpoints and outbound consent
Giải quyết private GitLab/S3/SMTP với SSRF: owner đăng ký service endpoint và CIDR/CA riêng qua step-up; egress proxy chỉ cấp đúng adapter, không mở cho URL từ repo/model/artifact. Link-local/metadata/loopback luôn cấm ở fetcher từ xa. Redirect không kế thừa credential. External channel opt-in per destination; inbox security/audit events không bị unsubscribe để xóa dấu vết.
Tác động: private deployment khả thi nhưng thêm registry/audit/network tests; không blanket allow private IP.

### Review order (decisions, not implementation plan)
1. ADR-034 identity/isolation và mức trust giữa workspace.
2. ADR-035/012/013 queue, storage, signing/recovery ownership.
3. ADR-033 canonical contracts; ADR-037 egress/consent policy.
4. ADR-036 operating budgets/retention/support envelope.
5. ADR-021 license/domain/publisher và ADR-024 relay operating model.
Vendor version/capability phải tự xác minh theo [22](22_OFFICIAL_REFERENCES.md), không yêu cầu owner đoán API. No source implementation is authorized by this document update.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
