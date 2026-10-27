# Red2PR — CI Repair with Proof

> **Trạng thái:** BỘ ĐẶC TẢ SẢN PHẨM / CHƯA TRIỂN KHAI. Đây không phải source code hay bằng chứng sản phẩm đạt production readiness.
>
> **Định hướng:** production-first, self-hosted, dành cho cá nhân/nhóm/doanh nghiệp quản lý CI repair với AI Meta Muse. **Frontend:** React 19 + TypeScript + Vite + Meta Astryx Design System. **Backend/agents:** Python + FastAPI; phiên bản chính thức v1.0.0 chỉ được phát hành sau khi release gates có bằng chứng kiểm thử đạt.

Red2PR tiếp nhận thất bại CI từ GitHub Actions/GitLab CI, phân tích nguyên nhân, tái hiện trong sandbox cô lập, đề xuất/apply bản vá, xác minh bằng các bài kiểm thử thật và mở **draft Pull Request / Merge Request** kèm evidence, sau đó theo dõi CI từ xa. Tất cả side effects đều đi qua policy/approval; **không auto-merge**.

## Quy tắc làm việc
- `AGENTS.md` là hướng dẫn an toàn cho coding agents; **không phải prompt gửi chat**.
- `docs/00_INDEX.md` dẫn tới toàn bộ đặc tả; `docs/20_DECISIONS_ADR.md` lưu quyết định có hiệu lực.
- Thiết kế toàn diện trước, triển khai theo vertical slices có test liên tục. Không thay scope mục tiêu bằng bản demo; cũng không được gọi một hệ thống chưa test là production.
- Không chứa API keys, thông tin cá nhân, tài nguyên cloud hoặc mã triển khai trong bộ tài liệu này.
- Tài liệu là **specification/contract**, không phải một mệnh lệnh triển khai tất cả không kiểm thử. UI chỉ sử dụng thành phần Astryx được tài liệu/CLI chính thức xác nhận; backend vẫn là Python.
- Để làm việc với AI coding agent: ingestion → deep review/spec consolidation → frozen integrated implementation plan → execute exact approved unit → independently audited release. Các prompt vận hành nằm **ngoài repository**, không kèm vào ZIP này.

## Trạng thái và phạm vi hỗ trợ
Tất cả tính năng trong `docs/02_FEATURE_CATALOG.md` là **yêu cầu mục tiêu**. Phạm vi phiên bản phát hành đầu, ma trận support và gates xem `docs/24_RELEASE_READINESS.md`, `docs/27_SUPPORT_MATRIX.md`. Các vấn đề chưa chốt cần được chứng thực tại `docs/21_OPEN_QUESTIONS.md`.

## Mục lục
Xem [docs/00_INDEX.md](docs/00_INDEX.md).

## Specification review P2 — 2026-10-27
Current artifact is a **design under owner review**, not working product code. [Specification index](docs/00_INDEX.md), [before/after audit](docs/39_SPEC_AUDIT.md), [46-feature traceability](docs/38_REQUIREMENTS_TRACEABILITY.md) and [decisions](docs/20_DECISIONS_ADR.md) record the production scope, accepted owner choices, proposed contracts and unverified vendor/runtime dependencies. Frontend remains React19 + TypeScript + Vite + Astryx; backend/agents Python/FastAPI. No implementation master plan or product execution is authorized by this documentation update.
