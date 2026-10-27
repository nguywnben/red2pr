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

const ADMIN_USER_ID = "0196ed10-0000-7000-8000-000000000101";
const SESSION_ID = "0196ed10-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ed10-0000-7000-8000-000000000301";
const MEM_ID = "0196ed10-0000-7000-8000-000000000401";
const GL_CONN_ID = "0196ed10-0000-7000-8000-000000000501";
const GL_SNAP_ID = "0196ed10-0000-7000-8000-000000000601";
const PROJ_BILLING_ID = "0196ed10-0000-7000-8000-000000000701";
const PROJ_DEPLOY_ID = "0196ed10-0000-7000-8000-000000000702";
const NOW_ISO = "2026-10-27T15:00:00Z";
const EXPIRES_ISO = "2026-10-28T03:00:00Z";

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
    "X-Correlation-Id": init.correlationId ?? "corr-u10-web-01",
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
  const cid = params.correlationId ?? "corr-u10-err-01";
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
      display_name: "GitLab Operator",
      email: "gitlab-ops@red2pr.local",
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
    memberships: [
      {
        id: MEM_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        workspace_id: WS_ACME_ID,
        workspace_slug: "acme",
        workspace_name: "Acme Platform",
        user_id: ADMIN_USER_ID,
        role,
        grant_epoch: 1,
      },
    ],
  };
}

function buildGitLabConnection(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    id: GL_CONN_ID,
    version: 1,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    workspace_id: WS_ACME_ID,
    provider: "gitlab",
    base_url: "https://gitlab.com",
    display_name: "Acme GitLab Cloud",
    app_id: null,
    installation_id: null,
    account_login: "red2pr-gitlab-bot",
    auth_mode: "gitlab_signed_v19",
    status: "ready",
    status_detail: "GitLab 19.1.2-ee capability probe succeeded with full bot write scopes.",
    vendor_version: "19.1.2-ee",
    api_version: "v4",
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
    capabilities: {
      repo_discovery: "available",
      ci_log_read: "available",
      draft_review_create: "available",
      branch_write: "available",
      webhook_hmac: "available",
      webhook_admin: "available",
      polling_fallback: "available",
      idempotency_key_v17_4: "available",
    },
    granted_permissions: {
      scopes: "api,write_repository",
      edition: "ee",
    },
    missing_permissions: [],
    grant_review_required: false,
    discovered_repo_count: 0,
    flagged_hazard_repo_count: 0,
    checked_at: NOW_ISO,
    last_synced_at: null,
    ...overrides,
  };
}

function buildDiscoveredProjects(): Record<string, unknown>[] {
  return [
    {
      id: PROJ_BILLING_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      workspace_id: WS_ACME_ID,
      connection_id: GL_CONN_ID,
      provider: "gitlab",
      external_id: "50101",
      name: "acme-group/billing-engine",
      default_branch: "main",
      visibility: "private",
      is_fork: false,
      archived: false,
      mode: "monitor",
      paused: false,
      workflow_hazard_status: "clean",
      workflow_hazards: [],
    },
    {
      id: PROJ_DEPLOY_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      workspace_id: WS_ACME_ID,
      connection_id: GL_CONN_ID,
      provider: "gitlab",
      external_id: "50102",
      name: "acme-group/deploy-infra\u202E<img src=x onerror=alert(1)>",
      default_branch: "main",
      visibility: "internal",
      is_fork: false,
      archived: false,
      mode: "monitor",
      paused: false,
      workflow_hazard_status: "flagged",
      workflow_hazards: [
        {
          code: "gitlab_mr_production_deploy",
          severity: "high",
          workflow_path: ".gitlab-ci.yml",
          trigger: "merge_request_event+environment:production",
          detail:
            "Job 'deploy_prod' targets production environment without when: manual; autonomous MR repair is blocked (SEC-031).",
          auto_repair_blocked: true,
        },
      ],
    },
  ];
}

describe("U10 GitLab Integrations Panel (UI-S15, SRC-02, SEC-003/011/027/031, W-02)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("completes admin GitLab onboarding: write-only token/whsec sealing, v19 capability probe, project sync, and .gitlab-ci.yml hazard rendering with XSS sanitization", async () => {
    const user = userEvent.setup();
    const secretTokenCanary = "glpat-u10SecretBotToken9876543210";
    const signingKeyCanary = "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    let connections: Record<string, unknown>[] = [];
    let repositories: Record<string, unknown>[] = [];
    let latestSnapshot: Record<string, unknown> | null = null;
    let createRequestBody: Record<string, unknown> | null = null;

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
        const provider = url.searchParams.get("provider");
        if (provider === "github") {
          return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
        }
        return jsonResponse({ items: connections, next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === "/api/v1/workspaces/acme/integrations" && method === "POST") {
        expect(req.headers.get("Idempotency-Key")).toBeTruthy();
        createRequestBody = (await req.json()) as Record<string, unknown>;
        const created = buildGitLabConnection({
          status: "checking",
          vendor_version: null,
          account_login: null,
          checked_at: null,
          status_detail: "GitLab credentials sealed in Z2 vault; run Probe capabilities.",
        });
        connections = [created];
        return jsonResponse(created, {
          status: 201,
          extraHeaders: { ETag: '"v1"' },
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${GL_CONN_ID}` && method === "GET") {
        const active = connections[0]!;
        return jsonResponse(
          {
            connection: active,
            latest_snapshot: latestSnapshot,
            repositories,
          },
          { extraHeaders: { ETag: `"v${String(active.version)}"` } },
        );
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/integrations/${GL_CONN_ID}/probes` &&
        method === "POST"
      ) {
        expect(req.headers.get("Idempotency-Key")).toBeTruthy();
        const probed = buildGitLabConnection({ version: 2, status: "ready" });
        latestSnapshot = {
          id: GL_SNAP_ID,
          connection_id: GL_CONN_ID,
          status: "ready",
          vendor_version: "19.1.2-ee",
          api_version: "v4",
          capabilities: probed.capabilities,
          granted_permissions: probed.granted_permissions,
          missing_permissions: [],
          detail: "Negotiated GitLab 19.1.2-ee with Standard Webhooks v19 HMAC and Idempotency-Key support.",
          checked_at: NOW_ISO,
        };
        connections = [probed];
        return jsonResponse({ connection: probed, snapshot: latestSnapshot });
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/integrations/${GL_CONN_ID}/sync` &&
        method === "POST"
      ) {
        expect(req.headers.get("Idempotency-Key")).toBeTruthy();
        repositories = buildDiscoveredProjects();
        const synced = buildGitLabConnection({
          version: 3,
          status: "ready",
          discovered_repo_count: 2,
          flagged_hazard_repo_count: 1,
          last_synced_at: NOW_ISO,
        });
        connections = [synced];
        return jsonResponse({
          connection: synced,
          discovered_count: 2,
          flagged_hazard_count: 1,
          partial_sync: false,
          repositories,
          synced_at: NOW_ISO,
        });
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
    });

    renderIntegrationsApp({
      initialEntry: "/w/acme/integrations",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    // Switch to GitLab (SRC-02) tab
    const glTab = await screen.findByRole("button", { name: /GitLab \(SRC-02\)/i });
    await user.click(glTab);

    expect(await screen.findByText("No GitLab connection configured")).toBeInTheDocument();

    // Open registration modal
    await user.click(screen.getByTestId("open-create-gitlab-btn"));
    const dialog = await screen.findByRole("dialog");

    const nameInput = within(dialog).getByLabelText("Connection display name");
    const tokenInput = within(dialog).getByLabelText(
      /Project or Group Access Token \(Write-Only\)/i,
    ) as HTMLInputElement;
    const whsecInput = within(dialog).getByLabelText(
      /Webhook Signing Key \(Write-Only/i,
    ) as HTMLInputElement;

    await user.type(nameInput, "Acme GitLab Cloud");
    await user.type(tokenInput, secretTokenCanary);
    await user.type(whsecInput, signingKeyCanary);

    await user.click(within(dialog).getByRole("button", { name: /Seal credentials & create/i }));

    // Verify payload sent write-only fields and never echoed them into DOM or Web Storage
    await waitFor(() => {
      expect(createRequestBody).toMatchObject({
        provider: "gitlab",
        base_url: "https://gitlab.com",
        auth_mode: "gitlab_signed_v19",
        display_name: "Acme GitLab Cloud",
        access_token: secretTokenCanary,
        webhook_secret: signingKeyCanary,
      });
    });

    expect(await screen.findByTestId("gitlab-pinned-auth-pill")).toHaveTextContent(
      "Pinned: Signed v19 HMAC",
    );
    expect(screen.getByTestId("gitlab-token-presence")).toHaveTextContent("Configured · key v1");
    expect(screen.getByTestId("gitlab-webhook-presence")).toHaveTextContent("Configured · key v1");
    expect(document.body.textContent ?? "").not.toContain(secretTokenCanary);
    expect(document.body.textContent ?? "").not.toContain(signingKeyCanary);
    assertZeroWebStorageSecrets([secretTokenCanary, signingKeyCanary]);

    // Run capability probe
    await user.click(screen.getByTestId("probe-gitlab-btn"));
    await waitFor(() => {
      expect(screen.getByTestId("gitlab-connection-status-pill")).toHaveTextContent("Ready");
    });
    expect(screen.getByText("19.1.2-ee")).toBeInTheDocument();
    expect(screen.getByText("idempotency_key_v17_4: Available")).toBeInTheDocument();

    // Sync projects & inspect .gitlab-ci.yml deployment hazard (SEC-031)
    await user.click(screen.getByTestId("sync-gitlab-btn"));
    expect(await screen.findByText("acme-group/billing-engine")).toBeInTheDocument();
    expect(screen.getByTestId("gitlab-hazard-summary-pill")).toHaveTextContent("1 hazard-flagged");
    expect(screen.getByText("Hazard Flagged · Auto-Repair Blocked")).toBeInTheDocument();
    expect(
      screen.getByText(/Job 'deploy_prod' targets production environment/i),
    ).toBeInTheDocument();

    // Verify bidi control characters in untrusted project name were stripped and no injected <img> exists
    expect(document.body.textContent ?? "").not.toContain("\u202E");
    expect(document.querySelectorAll("img[src='x']")).toHaveLength(0);
    assertZeroWebStorageSecrets([secretTokenCanary, signingKeyCanary]);
  });

  it("surfaces unsupported <19.0 signed auth without downgrade (SEC-027), read_api polling fallback, If-Match 412 conflict, W-02 reconnect review, and typed-name Disconnect & revoke", async () => {
    const user = userEvent.setup();

    let activeConn = buildGitLabConnection({
      version: 2,
      status: "unsupported",
      vendor_version: "16.11.5-ce",
      status_detail:
        "Pinned gitlab_signed_v19 requires GitLab >= 19.0; negotiated server 16.11.5-ce does not support Standard Webhooks signing.",
      capabilities: {
        repo_discovery: "available",
        ci_log_read: "available",
        draft_review_create: "unavailable",
        branch_write: "unavailable",
        webhook_hmac: "unavailable",
        webhook_admin: "unavailable",
        polling_fallback: "available",
        idempotency_key_v17_4: "unavailable",
      },
      missing_permissions: ["api_or_write_repository", "gitlab_19_0_signed_webhooks"],
    });

    let patchAttempts = 0;

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
        if (url.searchParams.get("provider") === "github") {
          return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
        }
        return jsonResponse({ items: [activeConn], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${GL_CONN_ID}` && method === "GET") {
        return jsonResponse(
          {
            connection: activeConn,
            latest_snapshot: null,
            repositories: [],
          },
          { extraHeaders: { ETag: `"v${String(activeConn.version)}"` } },
        );
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/integrations/${GL_CONN_ID}` &&
        method === "PATCH"
      ) {
        patchAttempts += 1;
        expect(req.headers.get("If-Match")).toBe('"v2"');
        const body = (await req.json()) as Record<string, unknown>;
        // Pinned auth_mode is never sent as a downgrade by UI
        expect(body.auth_mode).toBeUndefined();

        if (patchAttempts === 1) {
          return problemResponse({
            status: 412,
            code: "precondition_failed",
            title: "ETag mismatch",
            detail: "Connection version changed concurrently; reload latest ETag.",
          });
        }
        activeConn = buildGitLabConnection({
          version: 3,
          status: "ready",
          vendor_version: "19.1.2-ee",
          grant_review_required: true,
          status_detail:
            "Rotated token after prior revocation; all projects remain in Monitor until reviewed (W-02).",
        });
        return jsonResponse(activeConn, { extraHeaders: { ETag: '"v3"' } });
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/integrations/${GL_CONN_ID}` &&
        method === "DELETE"
      ) {
        activeConn = buildGitLabConnection({
          version: 4,
          status: "revoked",
          grant_review_required: true,
          secret_presence: { configured: false, secret_version: 2, updated_at: NOW_ISO },
          webhook_secret_presence: { configured: false, secret_version: 2, updated_at: NOW_ISO },
        });
        return jsonResponse(
          {
            operation_id: "0196ed10-0000-7000-8000-000000000801",
            state: "succeeded",
            resource_id: GL_CONN_ID,
            correlation_id: "corr-u10-revoke",
            completed_at: NOW_ISO,
          },
          { status: 200 },
        );
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
    });

    renderIntegrationsApp({
      initialEntry: "/w/acme/integrations",
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    await user.click(await screen.findByRole("button", { name: /GitLab \(SRC-02\)/i }));

    // Verify unsupported banner, disabled Sync button, and read_api polling fallback notice
    expect(await screen.findByTestId("gitlab-unsupported-auth-banner")).toBeInTheDocument();
    expect(screen.getByTestId("gitlab-polling-fallback-notice")).toBeInTheDocument();
    expect(screen.getByTestId("gitlab-missing-permissions-banner")).toHaveTextContent(
      "gitlab_19_0_signed_webhooks",
    );
    expect(screen.getByTestId("sync-gitlab-btn")).toBeDisabled();

    // Attempt rotate -> 412 version conflict banner
    await user.click(screen.getByTestId("rotate-gitlab-btn"));
    const rotateDialog = await screen.findByRole("dialog");
    await user.type(
      within(rotateDialog).getByLabelText(/New Project\/Group Access Token/i),
      "glpat-rotatedTokenValue123456",
    );
    await user.click(within(rotateDialog).getByRole("button", { name: /Save & rotate/i }));

    expect(await screen.findByTestId("gitlab-version-conflict-banner")).toBeInTheDocument();

    // Retry save -> succeeds and displays W-02 grant review banner
    await user.click(within(rotateDialog).getByRole("button", { name: /Save & rotate/i }));
    expect(await screen.findByTestId("gitlab-grant-review-banner")).toBeInTheDocument();

    // Typed-name Disconnect & revoke (SEC-011)
    await user.click(screen.getByTestId("open-revoke-gitlab-btn"));
    const revokeDialog = await screen.findByRole("dialog");
    const confirmBtn = within(revokeDialog).getByTestId("confirm-revoke-gitlab-btn");
    expect(confirmBtn).toBeDisabled();

    await user.type(
      within(revokeDialog).getByLabelText("Confirm connection name"),
      "Acme GitLab Cloud",
    );
    expect(confirmBtn).toBeEnabled();
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(screen.getByTestId("gitlab-connection-status-pill")).toHaveTextContent(
        "Revoked — Suspended",
      );
    });
  });

  it("enforces viewer read-only RBAC and passes WCAG 2.2 AA axe-core in both light and dark themes", async () => {
    const user = userEvent.setup();
    const readyConn = buildGitLabConnection({
      auth_mode: "gitlab_legacy_token",
      discovered_repo_count: 1,
    });
    const grantedProjectsOnly = [buildDiscoveredProjects()[0]!];

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
        if (url.searchParams.get("provider") === "github") {
          return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
        }
        return jsonResponse({ items: [readyConn], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === `/api/v1/workspaces/acme/integrations/${GL_CONN_ID}` && method === "GET") {
        return jsonResponse({
          connection: readyConn,
          latest_snapshot: null,
          repositories: grantedProjectsOnly,
        });
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
    });

    for (const themeMode of ["light", "dark"] as const) {
      const view = renderIntegrationsApp({
        initialEntry: "/w/acme/integrations",
        fetchImpl: fetchMock as unknown as typeof fetch,
        themeMode,
      });

      await user.click(await screen.findByRole("button", { name: /GitLab \(SRC-02\)/i }));
      expect(await screen.findByTestId("gitlab-readonly-rbac-banner")).toBeInTheDocument();
      expect(await screen.findByText("acme-group/billing-engine")).toBeInTheDocument();
      expect(screen.getByTestId("gitlab-pinned-auth-pill")).toHaveTextContent(
        "Pinned: Legacy X-Gitlab-Token (TLS)",
      );

      // Viewer must not see admin mutation controls
      expect(screen.queryByTestId("open-create-gitlab-btn")).not.toBeInTheDocument();
      expect(screen.queryByTestId("probe-gitlab-btn")).not.toBeInTheDocument();
      expect(screen.queryByTestId("sync-gitlab-btn")).not.toBeInTheDocument();
      expect(screen.queryByTestId("rotate-gitlab-btn")).not.toBeInTheDocument();
      expect(screen.queryByTestId("open-revoke-gitlab-btn")).not.toBeInTheDocument();

      const axeRes = await axe.run(view.container);
      expect(axeRes.violations).toEqual([]);
      view.unmount();
    }
  });
});
