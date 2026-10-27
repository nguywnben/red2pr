import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter, useLocation } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../../app/App";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { THEME_STORAGE_KEY, ThemeProvider } from "../../../shared/theme";

const ADMIN_USER_ID = "0196ed09-0000-7000-8000-000000000101";
const SESSION_ID = "0196ed09-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ed09-0000-7000-8000-000000000301";
const MEM_ID = "0196ed09-0000-7000-8000-000000000401";
const CONN_ID = "0196ed09-0000-7000-8000-000000000501";
const SNAP_ID = "0196ed09-0000-7000-8000-000000000601";
const REPO_PAYMENTS_ID = "0196ed09-0000-7000-8000-000000000701";
const REPO_DOCS_ID = "0196ed09-0000-7000-8000-000000000702";
const NOW_ISO = "2026-10-27T14:00:00Z";
const EXPIRES_ISO = "2026-10-28T02:00:00Z";
const STATE_EXPIRES_ISO = "2026-10-27T14:10:00Z";
const VALID_STATE_NONCE = "st_u09_single_use_callback_nonce_0123456789abcdef";

function jsonResponse(
  body: unknown,
  init: {
    status?: number;
    correlationId?: string;
    contentType?: string;
    extraHeaders?: Record<string, string>;
  } = {},
): Response {
  const status = init.status ?? 200;
  const headers = new Headers({
    "Content-Type": init.contentType ?? "application/json",
    "X-Correlation-Id": init.correlationId ?? "corr-u09-web-01",
    ...(init.extraHeaders ?? {}),
  });
  return new Response(body === null ? null : JSON.stringify(body), { status, headers });
}

function problemResponse(params: {
  status: number;
  code: string;
  title: string;
  detail: string;
  correlationId?: string;
}): Response {
  const cid = params.correlationId ?? "corr-u09-err-01";
  return jsonResponse(
    {
      type: `https://red2pr.local/problems/${params.code}`,
      title: params.title,
      status: params.status,
      code: params.code,
      detail: params.detail,
      correlation_id: cid,
      errors: null,
    },
    {
      status: params.status,
      correlationId: cid,
      contentType: "application/problem+json",
    },
  );
}

function sseIdleConnectedResponse(): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(": connected\n\n"));
    },
  });
  return new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache",
    },
  });
}

function LocationProbe(): React.JSX.Element {
  const location = useLocation();
  return <div data-testid="router-location">{`${location.pathname}${location.search}`}</div>;
}

function renderIntegrationsApp(opts: {
  initialEntry?: string;
  fetchImpl: typeof fetch;
  themeMode?: "light" | "dark";
}) {
  const queryClient = createWorkspaceQueryClient();
  const rendered = render(
    <I18nProvider>
      <ThemeProvider defaultMode={opts.themeMode ?? "light"}>
        <ApiClientProvider
          queryClient={queryClient}
          clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: opts.fetchImpl }}
        >
          <MemoryRouter initialEntries={[opts.initialEntry ?? "/w/acme/integrations"]}>
            <LocationProbe />
            <AppRoutes />
          </MemoryRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
  return { ...rendered, queryClient };
}

function assertZeroWebStorageSecrets(secretCanaries: readonly string[] = []): void {
  for (let i = 0; i < window.localStorage.length; i += 1) {
    const key = window.localStorage.key(i);
    expect(key).toBe(THEME_STORAGE_KEY);
    const val = key ? (window.localStorage.getItem(key) ?? "") : "";
    for (const canary of secretCanaries) {
      expect(val).not.toContain(canary);
    }
  }
  expect(window.sessionStorage.length).toBe(0);
}

function buildWorkspace(): Record<string, unknown> {
  return {
    id: WS_ACME_ID,
    version: 1,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    name: "Acme Platform",
    slug: "acme",
    status: "active",
    paused: false,
  };
}

function buildMePayload(role: "admin" | "maintainer" | "viewer"): Record<string, unknown> {
  return {
    user: {
      id: ADMIN_USER_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      display_name: "Integrations Operator",
      email: "integrations@red2pr.local",
      status: "active",
    },
    session: {
      id: SESSION_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      user_id: ADMIN_USER_ID,
      expires_at: EXPIRES_ISO,
      auth_strength: "mfa",
      step_up_at: NOW_ISO,
      grant_epoch: 1,
    },
    is_instance_owner: false,
    mfa_enabled: true,
    mfa_required_for_privileged: true,
    step_up_valid_until: EXPIRES_ISO,
    recovery_codes_remaining: 10,
    workspaces: [
      {
        id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        name: "Acme Platform",
        slug: "acme",
        status: "active",
        paused: false,
      },
    ],
    memberships: [
      {
        id: MEM_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        user_id: ADMIN_USER_ID,
        role,
        repository_grants: [REPO_PAYMENTS_ID],
      },
    ],
    telegram_link: { status: "not_configured" },
    csrf_token: "csrf-u09-token",
  };
}

function buildConnection(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: CONN_ID,
    workspace_id: WS_ACME_ID,
    version: 1,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    provider: "github",
    display_name: "Acme Production GitHub App",
    base_url: "https://api.github.com",
    auth_mode: "github_app",
    app_id: "340122",
    client_id: "Iv1.acme01",
    app_slug: "red2pr-acme",
    installation_id: null,
    account_login: null,
    account_type: null,
    status: "degraded",
    status_detail: "Credentials sealed; await GitHub App installation confirmation.",
    api_version: "2026-03-10",
    capabilities: {
      ci_read: "unknown",
      log_download: "unknown",
      artifact_download: "unknown",
      branch_write: "unknown",
      draft_review_create: "unknown",
      checks_write: "unknown",
      webhook_hmac: "available",
    },
    granted_permissions: {},
    missing_permissions: [],
    grant_review_required: false,
    secret_presence: {
      configured: true,
      secret_version: 1,
      updated_at: NOW_ISO,
    },
    webhook_secret_presence: {
      configured: true,
      secret_version: 1,
      updated_at: NOW_ISO,
    },
    checked_at: NOW_ISO,
    last_synced_at: null,
    revoked_at: null,
    ...overrides,
  };
}

function buildDiscoveredRepositories(): Record<string, unknown>[] {
  return [
    {
      id: REPO_PAYMENTS_ID,
      workspace_id: WS_ACME_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      provider_connection_id: CONN_ID,
      provider: "github",
      external_id: "501001",
      name: "acme-corp/payments-api",
      default_branch: "main",
      visibility: "private",
      mode: "monitor",
      paused: false,
      active: true,
      archived: false,
      is_fork: false,
      policy_revision: 1,
      tags: [],
      workflow_hazard_status: "clean",
      workflow_hazards: [],
      auto_repair_blocked: false,
      last_synced_at: NOW_ISO,
    },
    {
      id: REPO_DOCS_ID,
      workspace_id: WS_ACME_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      provider_connection_id: CONN_ID,
      provider: "github",
      external_id: "501002",
      name: "acme-corp/docs-site",
      default_branch: "main",
      visibility: "public",
      mode: "monitor",
      paused: false,
      active: true,
      archived: false,
      is_fork: false,
      policy_revision: 1,
      tags: [],
      workflow_hazard_status: "flagged",
      workflow_hazards: [
        {
          code: "pull_request_target",
          severity: "high",
          workflow_path: ".github/workflows/pr_target_deploy.yml",
          detail:
            "Hazardous pull_request_target checkout of untrusted PR head SHA detected; auto_repair blocked.",
        },
      ],
      auto_repair_blocked: true,
      last_synced_at: NOW_ISO,
    },
  ];
}

describe("U09 GitHub App Integrations UI, Callback State & Hazard Flows (UI-S15 / SRC-01)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("seals write-only RSA PEM & webhook secrets on create, wipes inputs, and redirects /connections alias", async () => {
    const user = userEvent.setup();
    const pemCanary = "-----BEGIN PRIVATE KEY-----\nSECRET_CANARY_U09_PEM\n-----END PRIVATE KEY-----";
    const whCanary = "whsec_canary_u09_never_persist_in_storage";
    let connections: Record<string, unknown>[] = [];
    const captured: {
      createBody: Record<string, unknown> | null;
      headers: Headers | null;
    } = { createBody: null, headers: null };

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const method = req.method.toUpperCase();

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("admin"));
      }
      if (url.pathname === "/api/v1/workspaces/acme" && method === "GET") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/integrations" && method === "GET") {
        return jsonResponse({ items: connections, next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === "/api/v1/workspaces/acme/integrations" && method === "POST") {
        captured.headers = new Headers(req.headers);
        captured.createBody = (await req.clone().json()) as Record<string, unknown>;
        const created = buildConnection();
        connections = [created];
        return jsonResponse(created, {
          status: 201,
          extraHeaders: { ETag: '"v1"' },
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${CONN_ID}` && method === "GET") {
        return jsonResponse(
          {
            connection: connections[0],
            latest_snapshot: null,
            repositories: [],
          },
          { extraHeaders: { ETag: '"v1"' } },
        );
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
    });

    // Navigate via legacy `/w/acme/connections` alias to verify canonical `/w/acme/integrations` redirect
    const { container } = renderIntegrationsApp({
      initialEntry: "/w/acme/connections",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    await waitFor(() => {
      expect(screen.getByTestId("router-location")).toHaveTextContent("/w/acme/integrations");
    });

    expect(await screen.findByText("No GitHub App connections configured")).toBeInTheDocument();

    const addButtons = screen.getAllByRole("button", { name: "Add GitHub App connection" });
    await user.click(addButtons[0]!);

    const form = await screen.findByTestId("github-create-connection-form");
    await user.type(within(form).getByLabelText("Connection display name"), "Acme Production GitHub App");
    await user.type(within(form).getByLabelText("GitHub App ID (required)"), "340122");
    await user.type(within(form).getByLabelText("Client ID (optional)"), "Iv1.acme01");
    const pemInput = within(form).getByLabelText(
      "RSA private key PEM (write-only · sealed in Z2 SecretBroker)",
    );
    const whInput = within(form).getByLabelText("Webhook HMAC secret (optional · write-only)");
    await user.type(pemInput, pemCanary);
    await user.type(whInput, whCanary);

    await user.click(within(form).getByRole("button", { name: "Seal credentials & create connection" }));

    await waitFor(() => {
      expect(captured.createBody).not.toBeNull();
    });
    expect(captured.createBody?.private_key_pem).toBe(pemCanary);
    expect(captured.createBody?.webhook_secret).toBe(whCanary);
    expect(captured.headers?.get("X-CSRF-Token")).toBe("csrf-u09-token");
    expect(captured.headers?.get("Idempotency-Key")).toBeTruthy();

    // Detail card renders secret presence (never raw secrets!) and zero secrets exist in DOM or Web Storage
    const detail = await screen.findByTestId("github-connection-detail");
    expect(within(detail).getAllByText("Configured (v1)").length).toBeGreaterThanOrEqual(2);
    expect(container.textContent).not.toContain("SECRET_CANARY_U09_PEM");
    expect(container.textContent).not.toContain(whCanary);
    assertZeroWebStorageSecrets(["SECRET_CANARY_U09_PEM", whCanary]);
  });

  it("executes A-23 single-use state minting, read-only callback redirect, and installation confirmation with SEC-031 hazards", async () => {
    const user = userEvent.setup();
    let isConfirmed = false;
    let confirmCalls = 0;

    const unboundConn = buildConnection();
    const boundConn = buildConnection({
      version: 2,
      installation_id: "99001",
      account_login: "acme-corp",
      account_type: "Organization",
      status: "degraded",
      status_detail: "Missing recommended permission: pull_requests:write.",
      capabilities: {
        ci_read: "available",
        log_download: "available",
        artifact_download: "available",
        branch_write: "available",
        draft_review_create: "unavailable",
        checks_write: "available",
        webhook_hmac: "available",
      },
      granted_permissions: {
        actions: "read",
        checks: "write",
        contents: "write",
        metadata: "read",
      },
      missing_permissions: ["pull_requests:write"],
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const method = req.method.toUpperCase();

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("admin"));
      }
      if (url.pathname === "/api/v1/workspaces/acme" && method === "GET") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/integrations/github/callback" && method === "GET") {
        // Read-only validation on GET — never mutates connection!
        expect(isConfirmed).toBe(false);
        return jsonResponse({
          workspace_id: WS_ACME_ID,
          workspace_slug: "acme",
          connection_id: CONN_ID,
          installation_id: url.searchParams.get("installation_id") ?? "99001",
          setup_action: url.searchParams.get("setup_action") ?? "install",
          state_valid: true,
          confirmation_required: true,
          expires_at: STATE_EXPIRES_ISO,
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme/integrations" && method === "GET") {
        return jsonResponse({
          items: [isConfirmed ? boundConn : unboundConn],
          next_cursor: null,
          snapshot_at: NOW_ISO,
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${CONN_ID}` && method === "GET") {
        return jsonResponse(
          {
            connection: isConfirmed ? boundConn : unboundConn,
            latest_snapshot: null,
            repositories: isConfirmed ? buildDiscoveredRepositories() : [],
          },
          { extraHeaders: { ETag: isConfirmed ? '"v2"' : '"v1"' } },
        );
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/integrations/${CONN_ID}/installations/state` &&
        method === "POST"
      ) {
        return jsonResponse(
          {
            connection_id: CONN_ID,
            state: VALID_STATE_NONCE,
            expires_at: STATE_EXPIRES_ISO,
            install_url: `https://github.com/apps/red2pr-acme/installations/new?state=${VALID_STATE_NONCE}`,
          },
          { status: 201 },
        );
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/integrations/${CONN_ID}/installations/confirm` &&
        method === "POST"
      ) {
        confirmCalls += 1;
        const body = (await req.clone().json()) as Record<string, unknown>;
        expect(body.installation_id).toBe("99001");
        expect(body.state).toBe(VALID_STATE_NONCE);
        isConfirmed = true;
        return jsonResponse({
          connection: boundConn,
          snapshot: {
            id: SNAP_ID,
            workspace_id: WS_ACME_ID,
            provider_connection_id: CONN_ID,
            provider: "github",
            status: "degraded",
            api_version: "2026-03-10",
            capabilities: boundConn.capabilities,
            granted_permissions: boundConn.granted_permissions,
            missing_permissions: boundConn.missing_permissions,
            detail: "Missing pull_requests:write.",
            checked_at: NOW_ISO,
          },
          repositories: buildDiscoveredRepositories(),
          partial_sync: false,
          grant_review_required: false,
        });
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
    });

    // Enter via `/integrations/github/callback?state=...&installation_id=99001&setup_action=install`
    renderIntegrationsApp({
      initialEntry: `/integrations/github/callback?state=${VALID_STATE_NONCE}&installation_id=99001&setup_action=install`,
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    // Global callback route redirects to `/w/acme/integrations?...` without mutating state (`confirmCalls === 0`)
    await waitFor(() => {
      expect(screen.getByTestId("router-location")).toHaveTextContent(
        `/w/acme/integrations?state=${VALID_STATE_NONCE}&installation_id=99001&setup_action=install`,
      );
    });
    expect(await screen.findByTestId("github-callback-verified-banner")).toBeInTheDocument();
    expect(confirmCalls).toBe(0);

    // Also verify explicit `Mint 10m install state` button renders the single-use nonce + sanitized link
    await user.click(screen.getByRole("button", { name: "Mint 10m install state" }));
    const mintedBox = await screen.findByTestId("github-minted-state-box");
    expect(within(mintedBox).getByText(VALID_STATE_NONCE)).toBeInTheDocument();

    // Now click `Confirm & bind installation` -> executes POST confirm, clears query params, shows repos + hazards
    await user.click(screen.getByRole("button", { name: "Confirm & bind installation" }));

    await waitFor(() => {
      expect(confirmCalls).toBe(1);
      expect(screen.getByTestId("router-location")).toHaveTextContent("/w/acme/integrations");
    });

    expect(await screen.findByText("acme-corp/payments-api")).toBeInTheDocument();
    expect(screen.getByText("Clean Workflows")).toBeInTheDocument();
    expect(screen.getByText("acme-corp/docs-site")).toBeInTheDocument();
    expect(screen.getByText("Hazard Flagged · Auto-Repair Blocked")).toBeInTheDocument();
    expect(screen.getByText("pull_request_target")).toBeInTheDocument();
    expect(screen.getByText(".github/workflows/pr_target_deploy.yml")).toBeInTheDocument();
    expect(screen.getByTestId("github-missing-permissions")).toHaveTextContent(
      "Missing permissions: pull_requests:write",
    );
  });

  it("rejects forged callbacks missing state on both /integrations/github/callback and /w/:ws/integrations (T-SRC-01-N)", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const method = req.method.toUpperCase();

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("admin"));
      }
      if (url.pathname === "/api/v1/workspaces/acme" && method === "GET") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/integrations/github/callback" && method === "GET") {
        return problemResponse({
          status: 400,
          code: "missing_or_invalid_install_state",
          title: "Invalid Installation State",
          detail: "GitHub callback requires a valid single-use state nonce.",
          correlationId: "corr-forged-cb-99",
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme/integrations" && method === "GET") {
        return jsonResponse({ items: [buildConnection()], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${CONN_ID}` && method === "GET") {
        return jsonResponse({
          connection: buildConnection(),
          latest_snapshot: null,
          repositories: [],
        });
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
    });

    const firstRender = renderIntegrationsApp({
      initialEntry: "/integrations/github/callback?installation_id=99001",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const routeErr = await screen.findByTestId("github-callback-route-error");
    expect(routeErr).toHaveTextContent("GitHub callback requires a valid single-use state nonce.");
    expect(routeErr).toHaveTextContent("corr-forged-cb-99");
    firstRender.unmount();

    renderIntegrationsApp({
      initialEntry: "/w/acme/integrations?installation_id=99001",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const inlineErr = await screen.findByTestId("github-callback-error-banner");
    expect(inlineErr).toHaveTextContent("GitHub callback requires a valid single-use state nonce.");
    expect(inlineErr).toHaveTextContent("corr-forged-cb-99");
  });

  it("handles 412 optimistic concurrency conflict, typed-confirmation disconnect (SEC-011), and W-02 reconnect warning", async () => {
    const user = userEvent.setup();
    let currentConn = buildConnection({
      version: 2,
      installation_id: "99001",
      status: "ready",
      grant_review_required: true,
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const method = req.method.toUpperCase();

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("admin"));
      }
      if (url.pathname === "/api/v1/workspaces/acme" && method === "GET") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/integrations" && method === "GET") {
        return jsonResponse({ items: [currentConn], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${CONN_ID}` && method === "GET") {
        return jsonResponse(
          {
            connection: currentConn,
            latest_snapshot: null,
            repositories: buildDiscoveredRepositories(),
          },
          { extraHeaders: { ETag: `"v${String(currentConn.version)}"` } },
        );
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${CONN_ID}` && method === "PATCH") {
        // Simulate concurrent edit advancing version to 3
        currentConn = buildConnection({
          ...currentConn,
          version: 3,
          display_name: "Acme Updated GH App",
        });
        return problemResponse({
          status: 412,
          code: "precondition_failed",
          title: "Precondition Failed",
          detail: "If-Match precondition failed against authoritative connection v3.",
          correlationId: "corr-conflict-412",
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${CONN_ID}` && method === "DELETE") {
        currentConn = buildConnection({
          ...currentConn,
          version: 4,
          status: "revoked",
          grant_review_required: true,
          secret_presence: { configured: false, secret_version: null, updated_at: NOW_ISO },
        });
        return jsonResponse(
          {
            operation_id: "0196ed09-0000-7000-8000-000000000801",
            status: "succeeded",
            resource_id: CONN_ID,
            correlation_id: "corr-revoke-01",
            completed_at: NOW_ISO,
          },
          { status: 202 },
        );
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
    });

    renderIntegrationsApp({
      initialEntry: "/w/acme/integrations",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    // W-02 reconnect banner shown initially because `grant_review_required === true` on `ready` connection
    const reconnectBanner = await screen.findByTestId("github-reconnect-review-banner");
    expect(reconnectBanner).toHaveTextContent("Reconnected after revocation (W-02)");

    // Trigger 412 optimistic version conflict via Rotate / edit
    await user.click(screen.getByRole("button", { name: "Rotate / edit" }));
    const saveBtn = await screen.findByRole("button", { name: "Save & rotate" });
    await user.click(saveBtn);

    const conflictBanner = await screen.findByTestId("github-version-conflict-banner");
    expect(conflictBanner).toHaveTextContent("precondition_failed");
    await user.click(
      within(conflictBanner).getByRole("button", { name: "Reload authoritative connection" }),
    );
    await waitFor(() => {
      expect(screen.queryByTestId("github-version-conflict-banner")).not.toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Acme Updated GH App" })).toBeInTheDocument();
    });

    // Destructive disconnect requires exact typed display_name confirmation (`SEC-011`)
    await user.click(screen.getByRole("button", { name: "Disconnect & revoke" }));
    const confirmRevokeBtn = await screen.findByRole("button", {
      name: "Confirm disconnect & revoke",
    });
    expect(confirmRevokeBtn).toBeDisabled();

    const confirmInput = screen.getByLabelText(/to confirm revocation/i);
    await user.type(confirmInput, "Wrong Name");
    expect(confirmRevokeBtn).toBeDisabled();

    await user.clear(confirmInput);
    await user.type(confirmInput, "Acme Updated GH App");
    expect(confirmRevokeBtn).not.toBeDisabled();

    await user.click(confirmRevokeBtn);

    await waitFor(() => {
      expect(screen.getByTestId("connection-status-badge")).toHaveTextContent(
        "Revoked — Suspended",
      );
    });
    expect(screen.getByTestId("github-reconnect-review-banner")).toHaveTextContent(
      "Connection revoked (SEC-011)",
    );
  });

  it("enforces viewer read-only RBAC, renders GitLab U10 notice tab, and passes WCAG 2.2 AA axe-core in light & dark themes", async () => {
    const user = userEvent.setup();
    const readyConn = buildConnection({
      version: 2,
      installation_id: "99001",
      status: "ready",
      account_login: "acme-corp",
    });
    const grantedReposOnly = [buildDiscoveredRepositories()[0]!];

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const method = req.method.toUpperCase();

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("viewer"));
      }
      if (url.pathname === "/api/v1/workspaces/acme" && method === "GET") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/integrations" && method === "GET") {
        if (url.searchParams.get("provider") === "gitlab") {
          return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
        }
        return jsonResponse({ items: [readyConn], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${CONN_ID}` && method === "GET") {
        return jsonResponse({
          connection: readyConn,
          latest_snapshot: null,
          repositories: grantedReposOnly,
        });
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
    });

    const lightView = renderIntegrationsApp({
      initialEntry: "/w/acme/integrations",
      fetchImpl: fetchMock as unknown as typeof fetch,
      themeMode: "light",
    });

    expect(await screen.findByTestId("github-readonly-rbac-banner")).toBeInTheDocument();
    expect(await screen.findByText("acme-corp/payments-api")).toBeInTheDocument();
    expect(screen.queryByText("acme-corp/docs-site")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Add GitHub App connection" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Mint 10m install state" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Disconnect & revoke" })).not.toBeInTheDocument();

    const lightAxe = await axe.run(lightView.container);
    expect(lightAxe.violations).toEqual([]);

    // Switch to GitLab (SRC-02) tab -> renders live GitLabIntegrationPanel cleanly (U10)
    await user.click(screen.getByRole("button", { name: /GitLab \(SRC-02\)/i }));
    expect(await screen.findByTestId("gitlab-integration-panel")).toBeInTheDocument();
    expect(await screen.findByTestId("gitlab-readonly-rbac-banner")).toBeInTheDocument();

    const gitlabTabAxe = await axe.run(lightView.container);
    expect(gitlabTabAxe.violations).toEqual([]);
    lightView.unmount();

    // Verify dark mode WCAG 2.2 AA contrast & semantics
    const darkView = renderIntegrationsApp({
      initialEntry: "/w/acme/integrations",
      fetchImpl: fetchMock as unknown as typeof fetch,
      themeMode: "dark",
    });
    expect(await screen.findByTestId("github-readonly-rbac-banner")).toBeInTheDocument();
    expect(await screen.findByText("acme-corp/payments-api")).toBeInTheDocument();
    const darkAxe = await axe.run(darkView.container);
    expect(darkAxe.violations).toEqual([]);
    assertZeroWebStorageSecrets();
  });
});
