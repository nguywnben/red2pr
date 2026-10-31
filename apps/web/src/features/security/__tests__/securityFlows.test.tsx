import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecurityPage } from "../SecurityPage";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";

const WORKSPACE = {
  id: "0196ef00-0000-7000-8000-000000000301",
  version: 1,
  created_at: "2026-10-30T00:00:00Z",
  updated_at: "2026-10-30T00:00:00Z",
  name: "Security test workspace",
  slug: "security-test",
  status: "active",
  paused: false,
} as const;
const token = {
  id: "0196ef00-0000-7000-8000-000000000401",
  version: 1,
  created_at: "2026-10-30T00:00:00Z",
  updated_at: "2026-10-30T00:00:00Z",
  workspace_id: WORKSPACE.id,
  owner_user_id: "0196ef00-0000-7000-8000-000000000501",
  name: "readonly-ci",
  scopes: ["repairs:read"],
  repository_ids: ["repo-1"],
  expires_at: "2027-01-28T00:00:00Z",
  revoked_at: null,
  last_used_at: null,
} as const;
const auditRecord = {
  id: "0196ef00-0000-7000-8000-000000000601",
  version: 1,
  created_at: "2026-10-30T00:00:00Z",
  updated_at: "2026-10-30T00:00:00Z",
  workspace_id: WORKSPACE.id,
  actor: "user",
  action: "iam.api_token.created",
  target: "api_token:0196ef00-0000-7000-8000-000000000401",
  decision: "allow",
  reason_code: "scoped_expiring_token",
  correlation_id: "security-correlation-1",
  prev_hash: "0".repeat(64),
  entry_hash: "a".repeat(64),
} as const;
const releaseException = {
  id: "0196ef00-0000-7000-8000-000000000701",
  finding_ref: "CVE-TEST-1",
  severity: "high",
  artifact_digest: "b".repeat(64),
  owner_user_id: "0196ef00-0000-7000-8000-000000000501",
  security_reviewer_user_id: "0196ef00-0000-7000-8000-000000000502",
  mitigation: "Network ingress is limited while a patched package is validated.",
  created_at: "2026-10-30T00:00:00Z",
  expires_at: "2026-11-13T00:00:00Z",
  revoked_at: null,
} as const;
const keyMetadata = {
  active_kek_version: 1,
  items: [{
    id: "0196ef00-0000-7000-8000-000000000801",
    purpose: "meta_inference",
    active_key_version: 1,
    kek_version: 1,
    configured: true,
    rotated_at: null,
    revoked_at: null,
    created_at: "2026-10-30T00:00:00Z",
    updated_at: "2026-10-30T00:00:00Z",
  }],
} as const;
const modelSecurity = {
  inference_consent_active: true,
  active_inference_consent_id: "0196ef00-0000-7000-8000-000000000901",
} as const;

function renderPage(fetchImpl: typeof fetch) {
  return render(
    <I18nProvider>
      <ThemeProvider defaultMode="light">
        <ApiClientProvider
          queryClient={createWorkspaceQueryClient()}
          clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchImpl, getCsrfToken: () => "csrf-test" }}
        >
          <SecurityPage workspace={WORKSPACE} />
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
}

function securityFetch(options?: { readonly auditError?: boolean }): { fetch: typeof fetch; calls: Request[] } {
  const calls: Request[] = [];
  const fetchImpl: typeof fetch = async (input) => {
    const request = input instanceof Request ? input : new Request(input);
    calls.push(request);
    const url = new URL(request.url);
    if (url.pathname === "/api/v1/me" && request.method === "GET") {
      return Response.json({ is_instance_owner: true, mfa_enabled: true, step_up_valid_until: null });
    }
    if (url.pathname.endsWith("/security/secrets") && request.method === "GET") {
      return Response.json(keyMetadata);
    }
    if (url.pathname === "/api/v1/auth/step-up" && request.method === "POST") {
      return Response.json({ step_up_valid_until: "2099-01-01T00:05:00Z" });
    }
    if (url.pathname.endsWith("/security/secrets/rotate") && request.method === "POST") {
      return Response.json({ active_kek_version: 2, rotated_count: 1, completed_at: "2026-10-30T00:00:00Z" });
    }
    if (url.pathname.endsWith("/api-tokens") && request.method === "GET") {
      return Response.json({ items: [token], next_cursor: null, snapshot_at: "2026-10-30T00:00:00Z" });
    }
    if (url.pathname.endsWith("/repositories")) {
      return Response.json({ items: [{ id: "repo-1", name: "org/private", version: 1, created_at: "2026-10-30T00:00:00Z", updated_at: "2026-10-30T00:00:00Z" }], next_cursor: null, snapshot_at: "2026-10-30T00:00:00Z" });
    }
    if (url.pathname.endsWith("/release-exceptions") && request.method === "GET") {
      return Response.json({ items: [releaseException] });
    }
    if (url.pathname.endsWith("/release-exceptions") && request.method === "POST") {
      return Response.json(releaseException, { status: 201 });
    }
    if (url.pathname.endsWith("/models") && request.method === "GET") {
      return Response.json(modelSecurity);
    }
    if (url.pathname.endsWith("/members")) {
      return Response.json({ items: [{ id: "m1", workspace_id: WORKSPACE.id, user_id: "0196ef00-0000-7000-8000-000000000502", role: "admin", repository_grants: ["repo-1"], version: 1, created_at: "2026-10-30T00:00:00Z", updated_at: "2026-10-30T00:00:00Z" }], next_cursor: null, snapshot_at: "2026-10-30T00:00:00Z" });
    }
    if (url.pathname.endsWith("/audit")) {
      return options?.auditError
        ? Response.json({ status: 503, code: "audit_verification_unavailable", detail: "Unavailable" }, { status: 503 })
        : Response.json({ items: [auditRecord], next_cursor: null, snapshot_at: "2026-10-30T00:00:00Z" });
    }
    if (url.pathname.endsWith("/api-tokens") && request.method === "POST") {
      return Response.json({ token: "r2p_secret_once", metadata: token }, { status: 201 });
    }
    return new Response(null, { status: 204 });
  };
  return { fetch: fetchImpl, calls };
}

describe("U25 security screen", () => {
  beforeEach(() => {
    const NativeRequest = globalThis.Request;
    vi.stubGlobal("Request", class extends NativeRequest {
      constructor(input: RequestInfo | URL, init?: RequestInit) {
        const { signal: _signal, ...safeInit } = init ?? {};
        super(input, safeInit);
      }
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("shows verified audit events, masked token metadata, retention and accessible search", async () => {
    const { fetch } = securityFetch();
    const { container } = renderPage(fetch);
    expect(await screen.findByText("iam.api_token.created")).toBeTruthy();
    expect(await screen.findByText("readonly-ci")).toBeTruthy();
    expect(await screen.findByText(/admin; 1 repository grants/)).toBeTruthy();
    expect(await screen.findByText(/Outbound inference consent: active/)).toBeTruthy();
    expect(screen.queryByText("r2p_secret_once")).toBeNull();
    expect(screen.getByText(/Raw provider logs: 7 days/)).toBeTruthy();
    expect((await axe.run(container)).violations).toEqual([]);
  });

  it("filters audit search by correlation id and displays the verified-chain failure state", async () => {
    const user = userEvent.setup();
    const { fetch, calls } = securityFetch({ auditError: true });
    renderPage(fetch);
    await screen.findByRole("heading", { name: "Security and audit" });
    await user.type(screen.getByLabelText("Correlation ID"), "cid-123");
    await user.click(screen.getByRole("button", { name: "Search audit" }));
    expect(await screen.findByText(/signed checkpoint could not be verified/)).toBeTruthy();
    expect(calls.some((call) => new URL(call.url).searchParams.get("correlation_id") === "cid-123")).toBe(true);
  });

  it("shows digest-bound exceptions and requires a distinct admin reviewer", async () => {
    const user = userEvent.setup();
    const { fetch, calls } = securityFetch();
    renderPage(fetch);
    expect(await screen.findByText("CVE-TEST-1 · High")).toBeTruthy();
    await user.type(screen.getByLabelText("Finding reference"), "CVE-TEST-2");
    await user.type(screen.getByLabelText("Artifact SHA-256 digest"), "c".repeat(64));
    await user.selectOptions(await screen.findByLabelText("Independent security reviewer"), "0196ef00-0000-7000-8000-000000000502");
    await user.type(screen.getByLabelText("Mitigation"), "Ingress is restricted while the dependency update is prepared.");
    await user.click(screen.getByRole("button", { name: "Record 14-day High exception" }));
    expect(calls.some((call) => new URL(call.url).pathname.endsWith("/release-exceptions") && call.method === "POST")).toBe(true);
  });

  it("shows metadata only and runs master key rotation through fresh MFA step-up", async () => {
    const user = userEvent.setup();
    const { fetch, calls } = securityFetch();
    renderPage(fetch);
    expect(await screen.findByText(/Active master key version: 1/)).toBeTruthy();
    expect(await screen.findByText(/meta_inference: configured; KEK v1/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Re-encrypt all secrets with active master key" }));
    const dialog = await screen.findByRole("dialog", { name: /Confirm privileged step-up/i });
    await user.type(within(dialog).getByLabelText(/Current password/i), "OwnerPass!123456");
    await user.type(within(dialog).getByLabelText(/Authenticator code/i), "123456");
    await user.click(within(dialog).getByRole("button", { name: /Verify step-up/i }));
    expect(await screen.findByText(/Re-encrypted 1 secret entries with KEK v2/)).toBeTruthy();
    expect(calls.some((call) => new URL(call.url).pathname.endsWith("/security/secrets/rotate") && call.method === "POST")).toBe(true);
    expect(calls.some((call) => new URL(call.url).pathname === "/api/v1/auth/step-up" && call.method === "POST")).toBe(true);
  });

  it("issues a scoped token and only then reveals its raw value once", async () => {
    const user = userEvent.setup();
    const { fetch } = securityFetch();
    renderPage(fetch);
    await user.type(await screen.findByLabelText("Token name"), "automation-read");
    await screen.findByRole("option", { name: "org/private" });
    await user.selectOptions(screen.getByLabelText("Repository access"), "repo-1");
    await user.click(screen.getByRole("button", { name: "Issue scoped token" }));
    expect(await screen.findByText("r2p_secret_once")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Hide token" }));
    expect(screen.queryByText("r2p_secret_once")).toBeNull();
  });
});
