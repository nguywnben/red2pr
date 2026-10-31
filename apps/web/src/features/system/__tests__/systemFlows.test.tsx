import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { describe, expect, it } from "vitest";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";
import { SystemPage } from "../SystemPage";

function renderSystem(fetchImpl: typeof fetch) {
  return render(<I18nProvider><ThemeProvider defaultMode="light"><ApiClientProvider queryClient={createWorkspaceQueryClient()} clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchImpl, getCsrfToken: () => "csrf-test" }}><SystemPage /></ApiClientProvider></ThemeProvider></I18nProvider>);
}

function systemFetch(options: { maintenanceEnabled?: boolean; maintenanceReason?: string | null; restoreCompatible?: boolean } = {}): { fetch: typeof fetch; calls: Request[] } {
  const calls: Request[] = [];
  const fetchImpl: typeof fetch = async (input) => {
    const request = input instanceof Request ? input : new Request(input);
    calls.push(request);
    const url = new URL(request.url);
    if (url.pathname === "/api/v1/me") return Response.json({ is_instance_owner: true, mfa_enabled: true, step_up_valid_until: null });
    if (url.pathname === "/api/v1/system/status") return Response.json({ state: options.maintenanceEnabled ? "maintenance" : "ready", generated_at: "2026-10-31T00:00:00Z", application_version: "0.1.0", schema_revision: "0022_backups_migrations_ops", database_version: "16.4", recovery_epoch: 1, maintenance_enabled: options.maintenanceEnabled ?? false, maintenance_reason: options.maintenanceReason ?? null, worker_protocols: [], checks: [{ check_id: "database", state: "ok", summary: "PostgreSQL is reachable." }] });
    if (url.pathname === "/api/v1/system/doctor") return Response.json({ generated_at: "2026-10-31T00:00:00Z", overall_state: "healthy", checks: [{ check_id: "database", state: "ok", summary: "Database is reachable." }] });
    if (url.pathname === "/api/v1/system/support-bundles/preview") return Response.json({ manifest_digest: "a".repeat(64), file_ids: ["health_summary", "doctor_report"], redacted_file_count: 2, excluded_secrets: true, excluded_repository_source: true, expires_at: "2026-10-31T00:10:00Z" });
    if (url.pathname === "/api/v1/auth/step-up") return Response.json({ step_up_valid_until: "2099-01-01T00:05:00Z" });
    if (url.pathname === "/api/v1/system/backups" && request.method === "POST") return Response.json({ id: "0196ef00-0000-7000-8000-000000000002", state: "succeeded", created_at: "2026-10-31T00:00:00Z", completed_at: "2026-10-31T00:00:01Z", manifest_digest: "b".repeat(64), size_bytes: 4096, object_count: 2, error_code: null }, { status: 201 });
    if (url.pathname === "/api/v1/system/restore/dry-run" && request.method === "POST") return Response.json({ backup_id: "0196ef00-0000-7000-8000-000000000002", manifest_digest: "b".repeat(64), plan_digest: "c".repeat(64), target_schema_revision: "0022_backups_migrations_ops", compatible: options.restoreCompatible ?? false, requires_maintenance: true, restores_artifacts: true, rotates_recovery_epoch: true, reapplies_retention_tombstones: true, requires_remote_reconciliation: true, blockers: options.restoreCompatible ? [] : ["schema_incompatible"], warnings: [] });
    if (url.pathname === "/api/v1/system/restore" && request.method === "POST") return Response.json({ restore_id: "0196ef00-0000-7000-8000-000000000003", backup_id: "0196ef00-0000-7000-8000-000000000002", state: "succeeded", recovery_epoch: 2, maintenance_enabled: true, requires_external_reconciliation: true, message: "Restore completed." });
    if (url.pathname === "/api/v1/system/support-bundles" && request.method === "POST") return Response.json({ id: "0196ef00-0000-7000-8000-000000000001", manifest_digest: "a".repeat(64), created_at: "2026-10-31T00:00:00Z", expires_at: "2026-10-31T01:00:00Z", file_count: 2, size_bytes: 32, download_url: "/api/v1/system/support-bundles/0196ef00-0000-7000-8000-000000000001" }, { status: 201 });
    return new Response(null, { status: 204 });
  };
  return { fetch: fetchImpl, calls };
}

describe("U26 system operations screen", () => {
  it("renders actual status and allowlisted doctor results without exposing secret values", async () => {
    const { fetch } = systemFetch();
    const view = renderSystem(fetch);
    expect(await screen.findByText(/schema: 0022_backups_migrations_ops/)).toBeTruthy();
    expect(await screen.findByText(/database: ok — Database is reachable/)).toBeTruthy();
    expect(await axe.run(view.container)).toMatchObject({ violations: [] });
  });

  it("previews then step-up gates support export and sends the preview digest", async () => {
    const user = userEvent.setup();
    const { fetch, calls } = systemFetch();
    renderSystem(fetch);
    await user.click(await screen.findByRole("button", { name: "Preview bundle" }));
    expect(await screen.findByText(/Preview digest:/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Create support bundle" }));
    expect(await screen.findByRole("heading", { name: "Confirm privileged step-up (5-minute window)" })).toBeTruthy();
    expect(calls.some((request) => new URL(request.url).pathname === "/api/v1/system/support-bundles" && request.method === "POST")).toBe(false);
    await user.type(screen.getByLabelText("Current password"), "valid-password");
    await user.type(screen.getByLabelText("Current 6-digit authenticator code"), "123456");
    await user.click(screen.getByRole("button", { name: "Verify step-up" }));
    expect(await screen.findByText(/Bundle ready until/)).toBeTruthy();
    const exportCall = calls.find((request) => new URL(request.url).pathname === "/api/v1/system/support-bundles" && request.method === "POST");
    expect(exportCall).toBeDefined();
    expect(await exportCall?.json()).toMatchObject({ manifest_digest: "a".repeat(64), confirm_export: true });
  });

  it("step-up gates backup creation and displays the signed backup receipt", async () => {
    const user = userEvent.setup();
    const { fetch, calls } = systemFetch();
    renderSystem(fetch);
    await user.click(await screen.findByRole("button", { name: "Create signed backup" }));
    expect(await screen.findByRole("heading", { name: "Confirm privileged step-up (5-minute window)" })).toBeTruthy();
    expect(calls.some((request) => new URL(request.url).pathname === "/api/v1/system/backups" && request.method === "POST")).toBe(false);
    await user.type(screen.getByLabelText("Current password"), "valid-password");
    await user.type(screen.getByLabelText("Current 6-digit authenticator code"), "123456");
    await user.click(screen.getByRole("button", { name: "Verify step-up" }));
    expect(await screen.findByText(/Backup 0196ef00-0000-7000-8000-000000000002 verified and stored/)).toBeTruthy();
  });

  it("requires maintenance and fresh step-up before executing the exact restore plan", async () => {
    const user = userEvent.setup();
    const { fetch, calls } = systemFetch({ maintenanceEnabled: true, maintenanceReason: "Owner enabled maintenance.", restoreCompatible: true });
    renderSystem(fetch);
    await user.type(await screen.findByLabelText("Backup ID for restore preflight"), "0196ef00-0000-7000-8000-000000000002");
    await user.click(screen.getByRole("button", { name: "Verify restore preflight" }));
    await user.click(await screen.findByRole("button", { name: "Restore verified backup" }));
    expect(await screen.findByRole("heading", { name: "Confirm privileged step-up (5-minute window)" })).toBeTruthy();
    expect(calls.some((request) => new URL(request.url).pathname === "/api/v1/system/restore" && request.method === "POST")).toBe(false);
    await user.type(screen.getByLabelText("Current password"), "valid-password");
    await user.type(screen.getByLabelText("Current 6-digit authenticator code"), "123456");
    await user.click(screen.getByRole("button", { name: "Verify step-up" }));
    expect(await screen.findByText(/Restore completed at recovery epoch 2/)).toBeTruthy();
    const restoreCall = calls.find((request) => new URL(request.url).pathname === "/api/v1/system/restore" && request.method === "POST");
    expect(restoreCall).toBeDefined();
    expect(await restoreCall?.json()).toMatchObject({ backup_id: "0196ef00-0000-7000-8000-000000000002", manifest_digest: "b".repeat(64), plan_digest: "c".repeat(64) });
  });

  it("requires an explicit reconciliation confirmation before leaving restore maintenance", async () => {
    const { fetch } = systemFetch({ maintenanceEnabled: true, maintenanceReason: "Restore completed; reconcile external effects before resume." });
    const view = renderSystem(fetch);
    const button = await screen.findByRole("button", { name: "Disable maintenance" });
    expect(button.hasAttribute("disabled")).toBe(true);
    expect(screen.getByLabelText(/I have reconciled ambiguous task/)).toBeTruthy();
    expect(await axe.run(view.container)).toMatchObject({ violations: [] });
  });
});
