import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { describe, expect, it } from "vitest";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { RelayConfigCard } from "../RelayConfigCard";

const WORKSPACE_ID = "0196f000-0000-7000-8000-000000000301";
const CONNECTION_ID = "0196f000-0000-7000-8000-000000000401";
const TEST_PRIVATE_KEY = "x".repeat(80);

const workspace = {
  id: WORKSPACE_ID,
  version: 1,
  created_at: "2026-11-01T10:00:00Z",
  updated_at: "2026-11-01T10:00:00Z",
  name: "Relay Workspace",
  slug: "relay-workspace",
  status: "active",
  paused: false,
} as const;

const me = {
  user: { id: "0196f000-0000-7000-8000-000000000101" },
  memberships: [{ workspace_id: WORKSPACE_ID, role: "admin" }],
  mfa_enabled: true,
} as never;

function renderCard(fetchImpl: typeof fetch) {
  return render(
    <I18nProvider>
      <ApiClientProvider
        queryClient={createWorkspaceQueryClient()}
        clientOptions={{ baseUrl: "https://red2pr.invalid", fetch: fetchImpl }}
      >
        <RelayConfigCard workspace={workspace} me={me} />
      </ApiClientProvider>
    </I18nProvider>,
  );
}

describe("U29 customer-operated relay configuration", () => {
  it("saves write-only mTLS/HMAC credentials and keeps relay opt-in", async () => {
    const user = userEvent.setup();
    const requests: Request[] = [];
    renderCard(async (request) => {
      requests.push(request as Request);
      const url = new URL(request instanceof Request ? request.url : String(request));
      if (url.pathname.endsWith("/integrations")) {
        return Response.json({ items: [{
          id: CONNECTION_ID,
          provider: "github",
          display_name: "Customer GitHub",
          status: "ready",
        }] });
      }
      if (url.pathname.endsWith("/relay") && request instanceof Request && request.method === "GET") {
        return Response.json(null);
      }
      if (url.pathname.endsWith("/relay") && request instanceof Request && request.method === "PUT") {
        const body = (await request.clone().json()) as Record<string, unknown>;
        expect(body.enabled).toBe(false);
        expect(body.relay_hmac_secret).toBe("relay-frame-secret-0123456789abcdef");
        expect(String(body.client_private_key_pem)).toHaveLength(80);
        return Response.json({
          id: "0196f000-0000-7000-8000-000000000501",
          version: 1,
          workspace_id: WORKSPACE_ID,
          provider_connection_id: CONNECTION_ID,
          endpoint_registration_id: "0196f000-0000-7000-8000-000000000601",
          consent_id: "0196f000-0000-7000-8000-000000000701",
          enabled: false,
          status: "disabled",
          last_relay_seq: 0,
          last_received_at: null,
          status_detail: null,
        }, { headers: { ETag: '"v1"' } });
      }
      throw new Error(`Unexpected request ${request instanceof Request ? request.method : "?"} ${url.pathname}`);
    });

    await user.type(await screen.findByLabelText("Registered endpoint ID"), "0196f000-0000-7000-8000-000000000601");
    await user.type(screen.getByLabelText("Provider consent ID"), "0196f000-0000-7000-8000-000000000701");
    await user.type(screen.getByLabelText("Relay frame HMAC secret"), "relay-frame-secret-0123456789abcdef");
    await user.type(screen.getByLabelText("Client certificate PEM"), "-----BEGIN CERTIFICATE-----\ncertificate-data-long-enough-for-validation\n-----END CERTIFICATE-----");
    await user.type(screen.getByLabelText("Client private key PEM"), TEST_PRIVATE_KEY);
    expect(screen.getByLabelText("Enable relay (off by default)")).not.toBeChecked();
    await user.click(screen.getByRole("button", { name: "Save relay configuration" }));
    expect(await screen.findByText("Customer relay configuration saved disabled.")).toBeInTheDocument();
    await waitFor(() => expect(requests.some((request) => request.method === "PUT")).toBe(true));
    const save = requests.find((request) => request.method === "PUT");
    expect(save?.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7/);
    expect(window.localStorage.getItem("relay-frame-secret-0123456789abcdef")).toBeNull();
  });

  it("lets an admin disable an existing relay without exposing or resubmitting its credentials", async () => {
    const user = userEvent.setup();
    let putBody: Record<string, unknown> | null = null;
    renderCard(async (request) => {
      const url = new URL(request instanceof Request ? request.url : String(request));
      if (url.pathname.endsWith("/integrations")) {
        return Response.json({ items: [{
          id: CONNECTION_ID,
          provider: "github",
          display_name: "Customer GitHub",
          status: "ready",
        }] });
      }
      if (url.pathname.endsWith("/relay") && request instanceof Request && request.method === "GET") {
        return Response.json({
          id: "0196f000-0000-7000-8000-000000000501",
          version: 3,
          workspace_id: WORKSPACE_ID,
          provider_connection_id: CONNECTION_ID,
          endpoint_registration_id: "0196f000-0000-7000-8000-000000000601",
          consent_id: "0196f000-0000-7000-8000-000000000701",
          enabled: true,
          status: "ready",
          last_relay_seq: 5,
          last_received_at: "2026-11-01T10:05:00Z",
          status_detail: null,
        });
      }
      if (url.pathname.endsWith("/relay") && request instanceof Request && request.method === "PUT") {
        putBody = (await request.clone().json()) as Record<string, unknown>;
        expect(putBody.enabled).toBe(false);
        expect(putBody.relay_hmac_secret).toBeUndefined();
        return Response.json({
          id: "0196f000-0000-7000-8000-000000000501",
          version: 4,
          workspace_id: WORKSPACE_ID,
          provider_connection_id: CONNECTION_ID,
          endpoint_registration_id: "0196f000-0000-7000-8000-000000000601",
          consent_id: "0196f000-0000-7000-8000-000000000701",
          enabled: false,
          status: "disabled",
          last_relay_seq: 5,
          last_received_at: "2026-11-01T10:05:00Z",
          status_detail: null,
        });
      }
      throw new Error(`Unexpected request ${url.pathname}`);
    });

    await user.click(await screen.findByLabelText("Enable relay (off by default)"));
    await user.click(screen.getByRole("button", { name: "Save relay configuration" }));
    expect(await screen.findByText("Customer relay configuration saved disabled.")).toBeInTheDocument();
    await waitFor(() => expect(putBody).not.toBeNull());
  });
});
