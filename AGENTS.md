# Red2PR — Agent operating contract

## Trạng thái và thứ tự ưu tiên
- Đây là **repository đang ở giai đoạn thiết kế**, không được coi các docs là code đã tồn tại. Kiểm tra actual tree, Git status và môi trường mỗi phiên.
- Chủ repo yêu cầu **chưa triển khai source code** cho đến khi phê duyệt kế hoạch; đọc và cập nhật docs khi được chỉ định. Sự chấp thuận viết code KHÔNG đồng nghĩa cấp phép gọi API thực, push commit, tạo PR/MR, phát tin nhắn, mua compute hay xử lý repo thứ ba.
- Nguồn sự thật: `docs/20_DECISIONS_ADR.md` (decisions) > requirements/architecture specs tương ứng > README. Xung đột phải nêu và đề xuất ADR; không tự lặng lẽ đổi phạm vi.

## Đọc trước khi thực hiện công việc
Đọc `docs/00_INDEX.md`, `docs/01_PRODUCT_VISION.md`, `docs/02_FEATURE_CATALOG.md`, `docs/05_SYSTEM_ARCHITECTURE.md`, `docs/14_SECURITY_IDENTITY.md`, `docs/18_TESTING_ACCEPTANCE.md`, `docs/20_DECISIONS_ADR.md`, `docs/21_OPEN_QUESTIONS.md`, `docs/23_PROGRESS.md`. Mở tài liệu module liên quan theo chỉ mục. Chỉ đề xuất implementation sau khi tổng hợp requirement IDs, API/data contracts, quyền, negative cases, test và migration.

## Nguyên tắc bất khả xâm phạm
1. **Proof over prose:** LLM có thể suy luận/đề xuất, không tự xác nhận test pass, cấp quyền, phê duyệt, hoặc tạo PR. Evidence lấy từ kết quả executor đã kiểm chứng.
2. **Least privilege:** control plane/publisher và sandbox runner tách trust boundary. Repo code, dependency hooks, CI logs và webhook payload đều là untrusted; không đưa write tokens/Meta keys vào sandbox; không share host Docker socket/privileged container.
3. **No dangerous autonomy:** không auto-merge, không bypass branch protections, không production deploy, không tự mở rộng file scope, không tự sửa test để làm xanh CI. Những sửa đổi test/config hợp lệ đòi policy và review bổ sung.
4. **No false completion:** Phân biệt `designed`, `implemented`, `tested`, `operationally_validated`. `locally_verified` khác `remotely_verified`; lỗi không tái hiện ghi `unconfirmed`.
5. **No blind retry:** Idempotency cho webhook, job, patch publication, notification, callback. Mọi side effects có correlation ID và audit.
6. **No secret leakage:** redact trước model, log, artifacts, notifications; hạn chế egress; repo private bắt buộc owner consent cho outbound inference.
7. **No invented capabilities:** kiểm tra API chính thức của Meta/GitHub/GitLab/Telegram trước code; feature availability phụ thuộc tài khoản, phiên bản và permissions.
8. **Self-hosted ≠ offline:** model Meta thường là cloud dependency. Nếu không truy cập được provider, hiển thị paused/degraded, không tuyên bố hỗ trợ offline mặc định.

## Cách phát triển sau khi được duyệt
- Phân rã vertical slices theo `docs/19_DELIVERY_PLAN.md`, nhưng không cắt tính năng production bắt buộc; viết test cùng code cho mỗi milestone, bao gồm unhappy path và security.
- Định nghĩa migrations, contracts, schema validation, observability, audit, explicit errors và rollback từ đầu; không tạo mock-only happy path rồi gọi là production.
- Mỗi milestone ghi `docs/23_PROGRESS.md` với diff summary, lệnh test đã chạy, exit status, known risks, evidence refs. Cập nhật ADR khi có quyết định mới.
- Frontend phải dùng React 19 + TypeScript + Vite + Astryx theo `docs/29_FRONTEND_ASTRYX.md`; backend và AI agent tiếp tục dùng Python. Astryx CLI `init` có thể ghi `AGENTS.md`: **không bao giờ ghi đè hoặc làm mất nội dung file này**; tích hợp tài liệu tạo ra vào vị trí an toàn. Không suy diễn các API component Astryx chưa kiểm chứng.
- Khi có kế hoạch triển khai được owner phê duyệt: thực thi **đúng mã hiệu và phạm vi milestone/task owner nêu**; không tự chia lại plan, không bỏ requirement, không tự thêm feature ngoài scope. Nếu dependency thiếu thì báo blocked + tác động thay vì âm thầm tạo roadmap khác.
- Kết thúc dự án: chạy kiểm thử độc lập và release gates có evidence, lặp lại sửa lỗi trong phạm vi cho phép. Không bắt buộc báo cáo “production-ready” khi thiếu điều kiện; trung thực về blocker là bắt buộc.
- Trước mọi thao tác external hoặc destructive: yêu cầu người dùng phê duyệt cụ thể phạm vi, đích, chi phí và tác động.
- Không sửa file trong repository ngoài phạm vi task. Không chạy source/code không tin cậy trên host điều khiển.
