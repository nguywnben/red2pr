import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  listWorkspaceNotifications: vi.fn(),
  listNotificationDestinations: vi.fn(),
  listNotificationDeliveries: vi.fn(),
  getNotificationPreferences: vi.fn(),
  updateWorkspaceNotificationReadState: vi.fn(),
  patchNotificationPreferences: vi.fn(),
  createNotificationDestination: vi.fn(),
  testNotificationDestination: vi.fn(),
  updateNotificationCredential: vi.fn(),
  rotateWebhookSigningKey: vi.fn(),
  deleteNotificationDestination: vi.fn(),
}));

vi.mock("../../../shared/api", () => ({
  useRed2PrApi: () => api,
  invalidateWorkspaceQueries: vi.fn(async () => undefined),
}));

import { NotificationsPage } from "../NotificationsPage";

const workspace = { id: "ws-1", slug: "acme", name: "Acme", version: 1 } as never;
const me = {
  memberships: [{ workspace_id: "ws-1", role: "admin" }],
} as never;
const notification = {
  id: "notice-1",
  event_id: "event-1",
  event_type: "repair.blocked",
  title: "Repair blocked",
  body: "Verification needs review.",
  severity: "warning",
  deep_link: "/w/acme/repairs/repair-1",
  is_security: false,
  read_at: null,
  created_at: "2026-10-30T12:00:00Z",
};
const page = (items: unknown[]) => ({ data: { items, next_cursor: null, snapshot_at: "2026-10-30T12:00:00Z" }, correlationId: "corr-u21" });

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><MemoryRouter><NotificationsPage workspace={workspace} me={me} /></MemoryRouter></QueryClientProvider>);
}

describe("U21 notifications UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.listWorkspaceNotifications.mockResolvedValue(page([notification]));
    api.listNotificationDestinations.mockResolvedValue(page([]));
    api.listNotificationDeliveries.mockResolvedValue(page([]));
    api.getNotificationPreferences.mockResolvedValue({ data: { workspace_id: "ws-1", event_types: [], min_severity: "info", quiet_hours: null, timezone: "UTC", version: 1 }, correlationId: "corr-u21" });
    api.updateWorkspaceNotificationReadState.mockResolvedValue({ data: { ...notification, read_at: "2026-10-30T12:01:00Z" }, correlationId: "corr-u21" });
    api.patchNotificationPreferences.mockResolvedValue({ data: { workspace_id: "ws-1", event_types: [], min_severity: "warning", quiet_hours: null, timezone: "UTC", version: 2 }, correlationId: "corr-u21" });
    api.createNotificationDestination.mockResolvedValue({ data: {}, correlationId: "corr-u21" });
    api.updateNotificationCredential.mockResolvedValue({ correlationId: "corr-u23" });
    api.rotateWebhookSigningKey.mockResolvedValue({ data: { key_id: "whk-key-1", secret: "S".repeat(43), overlap_hours: 48 }, correlationId: "corr-u23" });
  });

  it("shows a scoped inbox item and marks it read", async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText("Repair blocked")).toBeTruthy();
    await user.click(screen.getByRole("link", { name: "Open related item" }));
    await user.click(screen.getByRole("button", { name: "Mark read" }));
    await waitFor(() => expect(api.updateWorkspaceNotificationReadState).toHaveBeenCalledWith("acme", "notice-1", { read: true }));
    expect(await screen.findByText("Inbox state updated.")).toHaveAttribute("role", "status");
  });

  it("saves quiet-hours preferences and describes credential verification", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Repair blocked");
    await user.click(screen.getByLabelText("Quiet hours"));
    await user.clear(screen.getByLabelText("IANA timezone"));
    await user.type(screen.getByLabelText("IANA timezone"), "Asia/Ho_Chi_Minh");
    await user.click(screen.getByRole("button", { name: "Save preferences" }));
    await waitFor(() => expect(api.patchNotificationPreferences).toHaveBeenCalledWith({
      workspace_id: "ws-1", event_types: [], min_severity: "info", timezone: "Asia/Ho_Chi_Minh", quiet_hours: { start_hhmm: "22:00", end_hhmm: "07:00" },
    }));
    expect(screen.getByText(/credentials stay encrypted and are never returned/i)).toBeTruthy();
  });

  it("creates only a consent-bound destination with an idempotency key", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Repair blocked");
    await user.selectOptions(screen.getByLabelText("Channel"), "webhook");
    await user.type(screen.getByLabelText("Destination address"), "https://hooks.example.invalid/red2pr");
    await user.type(screen.getByLabelText("Active notification consent ID"), "0196ed14-0000-7000-8000-000000000501");
    await user.click(screen.getByRole("button", { name: "Save destination" }));
    await waitFor(() => expect(api.createNotificationDestination).toHaveBeenCalledTimes(1));
    const [ws, body, options] = api.createNotificationDestination.mock.calls[0] as [string, Record<string, unknown>, { idempotencyKey: string }];
    expect(ws).toBe("acme");
    expect(body).toMatchObject({ channel: "webhook", scope: "workspace", address: "https://hooks.example.invalid/red2pr", consent_id: "0196ed14-0000-7000-8000-000000000501", secret_ref: null });
    expect(options.idempotencyKey).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it("stores channel credentials write-only and verifies webhook keys are shown once", async () => {
    const user = userEvent.setup();
    api.listNotificationDestinations.mockResolvedValue(page([{
      id: "destination-webhook",
      workspace_id: "ws-1",
      channel: "webhook",
      scope: "workspace",
      address: "hidden",
      status: "not_configured",
      secret_presence: { configured: false, secret_version: null },
      version: 1,
    }, {
      id: "destination-email",
      workspace_id: "ws-1",
      channel: "email",
      scope: "workspace",
      address: "hidden",
      status: "not_configured",
      secret_presence: { configured: false, secret_version: null },
      version: 1,
    }]));
    renderPage();
    const credentialField = await screen.findByLabelText("Encrypted email credential/configuration");
    fireEvent.change(credentialField, { target: { value: '{"host":"smtp.example.test","port":587,"sender":"alerts@example.test","tls_mode":"starttls"}' } });
    await user.click(screen.getByRole("button", { name: "Save encrypted credential" }));
    await waitFor(() => expect(api.updateNotificationCredential).toHaveBeenCalledWith(
      "acme",
      "destination-email",
      { secret_value: '{"host":"smtp.example.test","port":587,"sender":"alerts@example.test","tls_mode":"starttls"}' },
    ));
    await screen.findByText("webhook · workspace");
    await user.click(screen.getByRole("button", { name: "Rotate signing key" }));
    expect(await screen.findByLabelText("Signing secret")).toHaveValue("S".repeat(43));
    expect(api.rotateWebhookSigningKey).toHaveBeenCalledWith("acme", "destination-webhook");
    await user.click(screen.getByRole("button", { name: "I copied the key" }));
    expect(screen.queryByLabelText("Signing secret")).toBeNull();
  });

  it("has no axe accessibility violations in the ready state", async () => {
    const { container } = renderPage();
    await screen.findByText("Repair blocked");
    const results = await axe.run(container);
    expect(results.violations).toEqual([]);
  });
});
