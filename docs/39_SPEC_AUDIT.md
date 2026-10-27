# P2 specification audit — gap analysis trước/sau

**Ngày:** 2026-10-27 (Asia/Saigon). **Phạm vi:** nghiên cứu tài liệu công khai và sửa Markdown đặc tả; không code sản phẩm, không master plan chi tiết, không cài dependency, không sandbox/API có phí, không cấu hình tài khoản hay gửi thông báo. **Kết luận:** bộ thiết kế đã được mở rộng và đồng bộ để chủ dự án duyệt; chưa thể kết luận sản phẩm đã chạy hoặc production-ready.

## Hiện trạng thực tế và mức chứng minh
Workspace: thư mục dự án `red2pr` trên máy Windows (đường dẫn cá nhân được lược bỏ khi chuẩn bị công khai). Tại thời điểm kiểm toán P2, chưa có metadata Git; `git status --short` báo “not a git repository”. Các kết luận P2 dùng nội dung/hash đầu phiên, không dựa trên Git diff. Việc khởi tạo và xuất bản Git được chủ dự án yêu cầu riêng sau P2; xem [progress](23_PROGRESS.md).
Trước P2:38tài liệu chính thức (AGENTS,README,docs00…35) +34tệp skills/metadata =72tệp. Không có product source/tests/manifests/lockfiles/migrations/CI/Dockerfile. Skill utility shell không phải code sản phẩm và không chạy. Sau P2 thêm4Markdown docs36…39; AGENTS và skills được bảo toàn.
Môi trường: PowerShell7.6.5; tìm thấy Git,Python3.12-path,Node/npm,WSL executable; không tìm Docker trên PATH. Đây là discovery executable, không chứng nhận daemon/WSL distro/virtualization/runtime hoạt động. Không chạy code repo, installer hay worker. Version/hardware sâu và runtime readiness để lại kiểm chứng khi được cấp phép.

| Mức | Có thể kết luận | Không được suy diễn |
|---|---|---|
| DESIGNED | feature/flow/contract/security/test/release requirements có tài liệu, một phần PROPOSED | thiết kế được owner chấp thuận toàn bộ |
| IMPLEMENTED | **0 product modules** | API/tool/schema table là code chạy |
| TESTED | **0 product test suites** | kiểm tra Markdown là test sản phẩm |
| OPERATIONALLY_VALIDATED | **0 deployments / 0 integration validations / 0 release gates pass** | vendor public docs hoặc Astryx source prove runtime |
| DOC/SOURCE_VERIFIED | official pages và Astryx source snapshot đọc, link/ID checks của docs riêng | account Meta quota, provider grants hay component render đã xác minh |

## Bảng chứng minh đọc đủ baseline
Tất cả38file dưới đã đọc đầy đủ trong intake/P2, không chỉ tên file. Cột yêu cầu chỉ trích tóm tắt quyết định trọng tâm; Cxx dẫn gap register sau bảng. Những file dài đọc theo từng nhóm. Skill instructions đọc riêng không tính là product spec.

| File | Vai trò | Yêu cầu chính đã đối chiếu | Conflict/gap |
|---|---|---|---|
| [AGENTS.md](../AGENTS.md) | Operating contract | docs-only, proof, least privilege, exact owner-approved scope, no overwrite | giữ nguyên; không tự cấp quyền code |
| [README.md](../README.md) | Product entry point | production-first full product, chosen stack, approval before code | C01,C16 |
| [00_INDEX.md](00_INDEX.md) | Mục lục/status | ADR precedence, complete product scope | C01 |
| [01_PRODUCT_VISION.md](01_PRODUCT_VISION.md) | Vision/personas | Self-hosted repair with proof; không auto-merge | C04 |
| [02_FEATURE_CATALOG.md](02_FEATURE_CATALOG.md) | 46 feature IDs/priority | 41P0/4P1/1P2, acceptance toàn sản phẩm | C06,C07 |
| [03_PERSONAS_JOURNEYS.md](03_PERSONAS_JOURNEYS.md) | User journeys | Local/team/repair/refusal/Telegram/recovery | C02,C04,C06 |
| [04_UI_UX_SPEC.md](04_UI_UX_SPEC.md) | IA/screens/states | 21routes, access, dark/light, responsive | C13 |
| [05_SYSTEM_ARCHITECTURE.md](05_SYSTEM_ARCHITECTURE.md) | Modules/trust/topology | Python/FastAPI, boundaries, DB/outbox/worker | C01,C07 |
| [06_DATA_MODEL.md](06_DATA_MODEL.md) | Entity relationships | Tenant constraints/indexes, immutable evidence, retention | C10 |
| [07_API_CONTRACTS.md](07_API_CONTRACTS.md) | Public/internal API | Auth/errors/paging/idempotency/typed worker tools | C02,C05,C10 |
| [08_EVENTS_STATE_MACHINES.md](08_EVENTS_STATE_MACHINES.md) | Domain transitions/events | Durable inbox/outbox, lease, publish reconciliation | C04,C05,C08 |
| [09_AI_AGENT_META.md](09_AI_AGENT_META.md) | AI/model/tools | Bounded diagnosis/patch, no model self-certification | C05,C14 |
| [10_SANDBOX_REPRODUCTION.md](10_SANDBOX_REPRODUCTION.md) | Isolation/fidelity | A/B controlled tests, runtime quotas, no secrets | C07,C10 |
| [11_REPAIR_VERIFICATION.md](11_REPAIR_VERIFICATION.md) | Proof/publishing | V-01…08, safe diff, approval, remote CI | C04,C10 |
| [12_PROVIDER_INTEGRATIONS.md](12_PROVIDER_INTEGRATIONS.md) | GitHub/GitLab | Scopes, version, attempts, retry/revocation, PR/MR | C12,C14 |
| [13_NOTIFICATIONS_TELEGRAM.md](13_NOTIFICATIONS_TELEGRAM.md) | Channels/commands | Opt-in external sends, link, web-confirmed dangerous action | C05,C08 |
| [14_SECURITY_IDENTITY.md](14_SECURITY_IDENTITY.md) | Threat/auth/secrets | Least privilege, consent, SSRF, session security | C06,C12 |
| [15_INSTALL_DEPLOY_ONBOARDING.md](15_INSTALL_DEPLOY_ONBOARDING.md) | Installer/wizard | 3OS entrypoints, prereq, TLS, recovery readiness | C15 |
| [16_OPERATIONS_CLI.md](16_OPERATIONS_CLI.md) | Operations/CLI | doctor/update/backup/restore/uninstall safe recovery | C15 |
| [17_OBSERVABILITY_ANALYTICS.md](17_OBSERVABILITY_ANALYTICS.md) | Metrics/SLO | Truthful funnels, budgets, logs/traces/alerts | C15 |
| [18_TESTING_ACCEPTANCE.md](18_TESTING_ACCEPTANCE.md) | Acceptance suites | Positive/negative/e2e + security/UX evidence | C16 |
| [19_DELIVERY_PLAN.md](19_DELIVERY_PLAN.md) | Existing outline D0…D10 | Full scope, continuous testing, owner approval | C11 |
| [20_DECISIONS_ADR.md](20_DECISIONS_ADR.md) | Decision authority | 16accepted original retained; proposals/open separated | C01,C04,C09 |
| [21_OPEN_QUESTIONS.md](21_OPEN_QUESTIONS.md) | Uncertainty/risk | Owner vs verifiable issues, no invented facts | C14,C15 |
| [22_OFFICIAL_REFERENCES.md](22_OFFICIAL_REFERENCES.md) | Vendor sources | Official URLs/read date/version/account caveats | C14 |
| [23_PROGRESS.md](23_PROGRESS.md) | Truthful status | Designed vs implemented/tested/operationally_validated | C16 |
| [24_RELEASE_READINESS.md](24_RELEASE_READINESS.md) | Production policy | All gates, no false-green, security thresholds | C09 |
| [25_CONFIG_SCHEMA.md](25_CONFIG_SCHEMA.md) | Config/policy keys | Precedence, immutable invariant, secrets by reference | C04,C05 |
| [26_SECURITY_TEST_MATRIX.md](26_SECURITY_TEST_MATRIX.md) | Adversarial cases | SEC-001…025 existing and trust boundary attacks | C10,C12,C16 |
| [27_SUPPORT_MATRIX.md](27_SUPPORT_MATRIX.md) | Support envelope | 3OS/cloud selfhost providers/certified runtime claims | C07,C14,C15 |
| [28_BENCHMARK_DEMO.md](28_BENCHMARK_DEMO.md) | Repair evaluation | 20+cases, denominators, abstention not fake demo | C04,C16 |
| [29_FRONTEND_ASTRYX.md](29_FRONTEND_ASTRYX.md) | Frontend/library contract | React19/TS/Vite/Astryx, Python unchanged, AGENTS safe | C01,C13,C14 |
| [30_ACCESS_CONTROL_MATRIX.md](30_ACCESS_CONTROL_MATRIX.md) | Role/action matrix | Repo scope/service authority/step-up/revocation | C02,C06 |
| [31_POLICY_AND_AUTOMATION.md](31_POLICY_AND_AUTOMATION.md) | Policy/approvals | Modes, deny precedence, bounded automation | C03,C04,C05 |
| [32_NOTIFICATION_EVENT_MATRIX.md](32_NOTIFICATION_EVENT_MATRIX.md) | Event/delivery contract | All channels, retry/redaction/link/replay | C05,C08 |
| [33_RELEASE_EVIDENCE_LEDGER.md](33_RELEASE_EVIDENCE_LEDGER.md) | Gate/provenance record | R-01…15 all NOT RUN, evidence/sign-off | C09,C16 |
| [34_SCREEN_AND_INTERACTION_CONTRACTS.md](34_SCREEN_AND_INTERACTION_CONTRACTS.md) | Interactions/UI details | Screen actions/form states/a11y tests | C10,C13 |
| [35_INTEGRATION_DEPENDENCIES.md](35_INTEGRATION_DEPENDENCIES.md) | Capability probe contract | Account/version/permission limits, authorized tests | C14 |

## Gap analysis trước/sau
“Đã sửa” ở đây là **đặc tả**, không phải lỗ hổng phần mềm đã được khắc phục. Nơi quyết định chưa được owner chốt, trạng thái là “đề xuất thống nhất”, không ACCEPTED.

| Gap | Trước: bằng chứng file/mục | Sau: điều chỉnh và tác động | Trạng thái / còn phải làm |
|---|---|---|---|
| C01 | doc05 Accepted language boundary chứa DB recommendation; doc29 React>=19 | React major19/TS/Vite/Astryx + Python/FastAPI giữ nguyên; PostgreSQL/outbox topology ghi PROPOSED ADR-013/035, không đổi accepted rows | chỉnh phân loại; owner duyệt infrastructure |
| C02 | doc07 workspace create Owner/Admin vs doc30 owner-only; journeyB admin creates | A-04 và journey dùng instance owner; workspace admin quản trị scope hiện có; owner không mặc nhiên đọc mọi repo | đã sửa contract; R-06 chưa chạy |
| C03 | doc02 monitor no execution vs doc31 sandbox exception | ADR-033 đề xuất monitor chỉ ingest/diagnose, chuyển mode web có audit; pause là override | PROPOSED, không âm thầm accepted |
| C04 | doc08 (REPRO_*)→PATCHING; doc11 provisional draft; doc25 two keys | ADR-031 owner đã chốt; chỉ confirmed baseline đi patch; unconfirmed terminal diagnosis; bỏ provisional option và từ chối legacy key | ACCEPTED direction, negative proof pending |
| C05 | docs07/09 tool aliases,08/32 event aliases,09 waiting model,25 budget aliases | S-20toolset, S-19event registry, suspension reason và namespace keys canonical; schema/code generation deferred | ADR-033 PROPOSED; no existing data migration |
| C06 | IAM-03 invitesP1 vs team journeyP0; doc14 MFAoptional vs doc30 stepup | ADR-034 đề xuất local invitation IAM-02P0, federationP1; mandatory TOTP/stepup privileged roles, recovery/last-admin contract | owner review required; no priority deleted |
| C07 | SAN-04 P1 “multi-tenant” vs mandatory isolated hostile workers | ADR-030 accepted tenancy; SAN-01P0 baseline isolation, SAN-04 advanced fleet extension; guest keys/control separated | implementation backend PROPOSED; independent R-05 |
| C08 | doc32 “publish only once” vs at-least-once external channels | logical DB uniqueness, sending/accepted/unknown/bounced states; replay and perchannel receipt limits | spec corrected; R-08 needs live consented validation |
| C09 | doc24 Critical/High waiver clause | ADR-032 Critical closed, High expiry/mitigation/owner; invariant non-waivable; SEC-039 | ACCEPTED;30day default PROPOSED |
| C10 | docs06/07 broad tables, no complete fields/FKs/SSE/worker/evidence signing contract | doc36 A-01…24/S-01…22; composite tenant FKs/indexes; supervisor signing/tamper-evident checkpoint and explicit trust limitations | design filled; schemas/code/crypto/runtime not tested |
| C11 | doc19 D7 UI could imply UI/auth deferred | clarify cross-cutting UI/auth/tests in every affected slice, retain original D0…D10 | no detailed master plan created |
| C12 | private GitLab support vs blanket private-IP SSRF denial | ADR-037 exact owner-registered adapter/host/CIDR/CA exception with pinned DNS/egress; never arbitrary URL exemption | PROPOSED;SEC-033 required |
| C13 | UI17 detailed rows vs21routes; mobile readonly vs responsive admin; speculative Astryxprops | all21 screen actions/API/data mapping, full states/a11y; source-verified component props at pinned commit, export/runtime gaps stated | design filled; actualUI/build/browser NOT RUN |
| C14 | vendor general links without version/account distinction | official ledger2026-10-27 with observed models/API version/GL signing and source snapshot; exact-account limitations | DOC/SOURCE_VERIFIED only; real probes pending authorization |
| C15 | SLO/hardware/restore fields vague, one-command could overpromise | doc37 sixteen numeric TARGETS+measurement/recovery; candidate3OS/distributed profiles; prereq/admin/reboot and key+object backup consistency | PROPOSED; no measured SLA/support claim |
| C16 | tests and gates not linked per feature; “complete design” wording too strong | doc38 all46features positive/negative + reverse15gates;40SEC cases; status/progress explicit design awaiting review | doc structural checks only; all product gates NOT RUN |

## Product và architecture review
Red2PR phục vụ maintainer, reviewer, platform/SRE và security của nhóm có nhiều repository/workspace. Giá trị là giảm vòng chẩn đoán/sửa CI với bằng chứng có thể kiểm toán; không phải chatbot trả lời lỗi. Dòng xử lý: authenticated CI→normalized attempts/matrix→diagnosis/abstention→isolated baseline→bounded Meta patch→independent verifier→policy/approval→draft PR/MR→provider-confirmed CI at exact SHA. Không baseline thì dừng, không merge/deploy. Kiến trúc/trust map ở [05](05_SYSTEM_ARCHITECTURE.md).
React19/TypeScript/Vite/Astryx hiển thị dữ liệu qua typed API/SSE; Python/FastAPI giữ orchestration, quyền, budgets, verifier và publisher. Meta inference thường outbound và phải có consent; sandbox không có provider write tokens/Meta key. PostgreSQL/outbox/storage/transport là ADR kỹ thuật còn chờ duyệt. In-app,Telegram,SMTP,Slack,Discord,signed webhooks đều trong P0; không cấu hình một channel không làm mất engine hay giả gửi thành công.
Installers Windows/Linux/macOS đi qua preflight+wizard+checkpoint; server webhook và local polling đều reconcile; distributed có worker separation, không tự hứa HA control plane. Admin responsive và keyboard accessible, truthful proof/remote states. Release chỉ khi mọi P0 và15gate có evidence trên matrix công khai.

## New supporting documents and review outcome
| File | Vì sao cần riêng | Nội dung đã đọc lại/đối chiếu |
|---|---|---|
| [36 Canonical contracts](36_CANONICAL_CONTRACTS.md) | tránh lặp schema và naming drift giữa06/07/08/09 |24API families,22schema families, typed tools,worker,evidence/SSE |
| [37 NFR/recovery](37_NFR_AND_RECOVERY.md) | targets cần workload/measurement/recovery chung |16NFR targets, DB/queue/worker/model/provider/storage recovery |
| [38 Traceability](38_REQUIREMENTS_TRACEABILITY.md) | toàn sản phẩm phải truy vết hai chiều |46feature pairs of acceptance cases,15reverse gates |
| [39 Audit](39_SPEC_AUDIT.md) | bằng chứng đọc và gap trước/sau |38baseline files,16gaps, accepted/proposed/open separation |

## Quyết định còn mở và thứ tự nghiên cứu P2
1. Chốt ADR-034 identity/isolation: privileged MFA, local invitations, independent reviewer/break-glass và trust domain vận hành.
2. Duyệt ADR-035/012/013 control/queue/storage/evidence signing architecture; chọn key custody/recovery operator.
3. Duyệt ADR-033 canonical contracts và ADR-037 private endpoint/consent exception; các conflict đã nêu không bị che bằng code.
4. Duyệt ADR-036 target capacity/retention/RPO-RTO/High waiver duration; sau đó đo trong môi trường được phép trước support claims.
5. ADR-021 license/domain/publisher/market privacy, ADR-024 relay ownership; owner cần cho business context.
Vendor account/model quotas, exactOS/runtime/scopes/CLI effects là **có thể kiểm chứng**, không hỏi owner đoán. License intent/customer region/operating risk là **cần chủ dự án quyết định**. P1 extensions giữ design/capability boundaries; detailed federation/relay/MCP protocol freeze trước khi bật support, không suy diễn từ core API.

## Documentation validation
Kiểm tra cuối đạt exit0:272liên kết nội bộ,55bảng,46feature/92acceptance cases; không lỗi cấu trúc hoặc ID trong các nhóm đã kiểm tra.16ACCEPTED gốc và AGENTS/skills nguyên vẹn. Kết quả hashes/scope và actual commands ở [23](23_PROGRESS.md). Chúng chỉ kiểm tra tài liệu; không chứng minh contract đã được thực thi. Không commit/push vì workspace không có Git metadata và người dùng không yêu cầu. Khi hoàn tất P2, dừng chờ chủ dự án duyệt đặc tả.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
