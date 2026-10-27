# Personas, journeys, use cases

## Roles
- **Instance owner**: system lifecycle, encryption, global security settings, bootstrap.
- **Workspace admin**: invitations, integrations, repo access, billing/usage policies.
- **Maintainer**: repo settings, repair policy, approve patches, cancel jobs.
- **Reviewer**: view, comment and approve gated actions allowed by policy.
- **Viewer/Auditor**: read authorized sessions/evidence/audit; no mutating actions.
- **Service identity**: provider integration, worker, publisher; each minimal independent scopes.

## Journey A — mới cài trên laptop
1. Chạy installer OS; môi trường không hỗ trợ thì gợi ý sửa prereq, không báo thành công giả.
2. Mở loopback web bằng bootstrap token một lần; owner tạo admin.
3. Chọn local polling, cấu hình Meta key qua secure input; hệ thống test bằng yêu cầu nhỏ có giới hạn.
4. Kết nối GitHub App, chọn đúng repos; ban đầu `monitor`.
5. Bật `approval`/`auto_repair` theo repo sau khi xem risk notice và worker readiness.
6. Xem repair timeline, optional Telegram; restart/redelivery không mất trạng thái.

## Journey B — server team
1. Installer Linux server; HTTPS domain + reverse proxy; instance owner creates workspace; MFA policy proposed ADR-034, SSO P1.
2. GitHub/GitLab hook secret signing configured, provider permissions checked.
3. Tách worker host, configure policy, role access, resource quotas, retention, outbound model consent.
4. Những người cần review được mời; họ thấy đúng repo của workspace.
5. Sự kiện CI đến, bot gửi notification theo preferences; PR được tạo sau gate.

## Journey C — lỗi sửa được
1. CI run failed; provider event verified; idempotent session.
2. Evidence collector lấy jobs, stacktrace, relevant diffs (không gửi raw secret).
3. Diagnosis tạo giả thuyết có source references; triage eligible.
4. Baseline test thất bại tại SHA gốc trong sandbox; nếu không tái hiện, kết thúc repro_unconfirmed, chỉ diagnosis/human handoff, không tạo patch hoặc PR/MR (ADR-031).
5. Agent sửa patch trong clone độc lập, attempt tối đa theo policy.
6. Verifier kiểm diff, chạy test mục tiêu + regressions; report fidelity.
7. Publisher tạo draft PR/MR đúng base/ref, không tạo trùng khi API timeout.
8. Remote CI kết thúc: update session, không auto merge; reviewer quyết định.

## Journey D — lỗi không sửa được
- Registry outage, credentials thiếu, disk full, unsupported ARM/macOS job, flaky race, unknown upstream issue => `diagnosed_only`, `needs_human` hoặc `unsupported`. Không được tạo patch giả. Có actionable remediation notes.

## Journey E — điều khiển từ Telegram
- Telegram `/status` xem health, `/repos` xem repo đã có quyền, `/repairs` xem phiên đang chạy.
- `/pause` hoặc `/retry` chỉ khởi tạo web challenge một lần, xác thực session + role + CSRF và ghi audit; command trong group không đủ để approve.
- Bot token rotated: integration degraded, không gián đoạn repair engine.

## Journey F — khôi phục sự cố
- Mất API connection giữa lúc publish: reconcile by branch/PR markers, không tạo hai PR.
- Worker restart: lease hết hạn -> requeue eligible job, inspect prior artifacts; không chạy duplicate side effects.
- Upgrade fail: backup/snapshot, rollback image compatible; restore drills recorded.

## UX acceptance
Mọi hành động destructive có confirmation và summary; keyboard navigation và status dễ nhận biết; empty/loading/degraded/permission denied states. Không hiển thị secrets/raw private logs trong notification mặc định.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
