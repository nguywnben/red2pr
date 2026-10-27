# Tầm nhìn, giá trị, phạm vi

## Tuyên bố sản phẩm
**Red2PR** = self-hosted **autonomous CI failure investigation and evidence-backed repair platform**. Input: run/job CI thất bại từ GitHub/GitLab. Output: phân loại đúng, bằng chứng tái hiện, diff sửa lỗi trong phạm vi cho phép, verification và draft PR/MR minh bạch; tiếp tục theo dõi remote CI.

## Persona / người mua
- Solo developer / maintainer: muốn rút ngắn thời gian CI đỏ, không thuê hạ tầng phức tạp, cài một lệnh.
- Engineering lead / DevOps: quản lý nhiều repo, quy tắc riêng, độ tin cậy và throughput.
- Security / platform admin: kiểm soát dữ liệu, quyền, chi phí, sandbox, worker, audits, lifecycle.
- Reviewer: xem nguyên nhân, proof, patch và quyết định merge ở provider.

## Core jobs-to-be-done
1. Kết nối GitHub/GitLab an toàn; chọn repo, branches, modes.
2. Nhận thất bại; loại bỏ lỗi transient/không thể sửa thay vì cố patch.
3. Lưu bền workflow ngay cả khi restart, retry hoặc đến webhook trùng.
4. Reproduce với đúng SHA và môi trường có kiểm soát, lưu fidelity report.
5. Patch code/config, xác minh red→green và regressions; từ chối test tampering.
6. Tạo draft PR/MR + căn cứ, theo dõi remote validation; người dùng review.
7. Quan sát cost/latency/success, cảnh báo qua Telegram/email, quản trị bằng dashboard/CLI.

## Lợi thế cạnh tranh cần chứng minh
- **Proof package:** baseline failure, patched outcome, artifact hashes, command, image digest, limitations.
- **Correct abstention:** nhận biết credential/outage/infra/flaky/unsupported; không tạo patch bừa.
- **Operationally self-hosted:** wizard, auth, lifecycle, safety, backups, monitoring và support matrix.

## Nguyên tắc UX
- Zero-confusions install: khởi tạo bằng một lệnh **khi điều kiện hệ thống đáp ứng**, sau đó setup browser.
- Safe by default: Monitor Only cho repo mới, draft PR, no merge, budgets hữu hạn.
- Progressive disclosure: trang tổng quan ngắn, evidence chi tiết khi cần.
- Every mutation has actor, time, reason, irreversible-warning, audit ID.

## Không thuộc mục tiêu sản phẩm
- Không thay thế GitHub/GitLab hay CI runner gốc.
- Không tự merge, release hay deploy production.
- Không hứa sửa mọi ngôn ngữ, runner, integration, private secret-backed pipeline.
- Không biến Telegram thành kênh cấp quyền không kiểm soát.
- Không coi LLM hallucination là bằng chứng; không cần camera/voice.

## Đường đua hackathon
Meta Muse đóng vai trò reason/patch; deterministic modules làm policy và test. Hackathon checkpoint quan trọng nhưng không phải tiêu chuẩn kết luận production; giữ benchmark và demo chân thực.

## P2 product contract
1.0.0 serves teams with multiple workspaces per self-hosted instance (ADR-030), with explicit repository grants and isolated execution. “Repair with proof” means diagnosis grounded in immutable CI evidence, confirmed baseline, bounded patch, independent verification, policy-authorized draft PR/MR and separate remote-CI verdict. No baseline reproduction means diagnosis/human handling only (ADR-031). Self-hosted control/data custody does not imply offline Meta inference; owner outbound consent remains mandatory. No reduction to chatbot/demo/MVP or removal of production capabilities is authorized.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
