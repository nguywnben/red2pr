import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { AppRoutes } from "../../../app/App";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";

const ADMIN_USER_ID = "0196ee10-0000-7000-8000-000000000101";
const SESSION_ID = "0196ee10-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ee10-0000-7000-8000-000000000301";
const MEM_ID = "0196ee10-0000-7000-8000-000000000401";
const GH_CONN_ID = "0196ee10-0000-7000-8000-000000000501";
const GL_CONN_ID = "0196ee10-0000-7000-8000-000000000502";
const REPO_PAYMENTS_ID = "0196ee10-0000-7000-8000-000000000601";
const REPO_BILLING_ID = "0196ee10-0000-7000-8000-000000000602";
const CURSOR_GAP_ID = "0196ee10-0000-7000-8000-000000000701";
const CURSOR_RL_ID = "0196ee10-0000-7000-8000-000000000702";
const OP_ID = "0196ee10-0000-7000-8000-000000000801";
const NOW_ISO = "2026-10-27T16:00:00Z";
const EXPIRES_ISO = "2026-10-28T04:00:00Z";

function jsonResponse(
  body: unknown,
  init: {
    status?: number;
    correlationId?: string;
    extraHeaders?: Record<string, string>;
  } = {},
): Response {
  const status = init.status ?? 200;
  const headers = new Headers({
    "Content-Type": "application/json",
    "X-Correlation-Id": init.correlationId ?? "corr-u11-web-01",
    ...(init.extraHeaders ?? {}),
  });
  return new Response(body === null ? null : JSON.stringify(body), { status, headers });
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

function renderIntegrationsApp(opts: {
  initialEntry?: string;
  fetchImpl: typeof fetch;
  themeMode?: "light" | "dark";
}) {
  const queryClient = createWorkspaceQueryClient();
  return render(
    <I18nProvider>
      <ThemeProvider defaultMode={opts.themeMode ?? "light"}>
        <ApiClientProvider
          queryClient={queryClient}
          clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: opts.fetchImpl }}
        >
          <MemoryRouter initialEntries={[opts.initialEntry ?? "/w/acme/integrations"]}>
            <AppRoutes />
          </MemoryRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
}

function buildMePayload(role: "admin" | "viewer"): Record<string, unknown> {
  return {
    user: {
      id: ADMIN_USER_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      display_name: "Polling Operator",
      email: "polling-ops@red2pr.local",
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
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        user_id: ADMIN_USER_ID,
        role,
        repository_grants: [REPO_PAYMENTS_ID, REPO_BILLING_ID],
      },
    ],
    csrf_token: "csrf-u11-test-token",
    telegram_link: { linked: false, telegram_username: null, linked_at: null },
  };
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

function buildGitHubConnection(): Record<string, unknown> {
  return {
    id: GH_CONN_ID,
    workspace_id: WS_ACME_ID,
    version: 2,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    provider: "github",
    base_url: "https://api.github.com",
    auth_mode: "github_app",
    display_name: "Acme GitHub Prod",
    app_id: "340122",
    installation_id: "99001",
    account_login: "acme-platform",
    secret_presence: { configured: true, secret_version: 1 },
    webhook_secret_presence: { configured: true, secret_version: 1 },
    status: "ready",
    capabilities: {
      app_jwt_auth: "available",
      repo_discovery: "available",
      webhook_hmac: "available",
      polling_fallback: "available",
    },
    api_version: "2026-03-10",
    repository_count: 2,
    flagged_hazard_repo_count: 0,
    grant_review_required: false,
    status_detail: "GitHub App verified.",
  };
}

function buildGitLabConnection(): Record<string, unknown> {
  return {
    id: GL_CONN_ID,
    workspace_id: WS_ACME_ID,
    version: 2,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    provider: "gitlab",
    base_url: "https://gitlab.com",
    auth_mode: "gitlab_signed_v19",
    display_name: "Acme GitLab Cloud",
    account_login: "acme-group",
    secret_presence: { configured: true, secret_version: 1 },
    webhook_secret_presence: { configured: true, secret_version: 1 },
    status: "ready",
    capabilities: {
      repo_discovery: "available",
      webhook_hmac: "available",
      polling_fallback: "available",
    },
    vendor_version: "19.1.2-ee",
    api_version: "v4",
    repository_count: 1,
    flagged_hazard_repo_count: 0,
    grant_review_required: false,
    status_detail: "GitLab connection ready.",
  };
}

describe("U11 UI-S15 Webhook Ingress, 429 Backoff, History-Gap & Reconcile Flows", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("surfaces offline >TTL history-gap & 429 rate-limit banners, acknowledges gap via S-05 reconcile, and passes axe", async () => {
    const user = userEvent.setup();
    let gapAcknowledged = false;
    const seenReconcileCalls: Array<{
      csrf: string | null;
      idemKey: string | null;
      body: Record<string, unknown>;
    }> = [];

    const repos = [
      {
        id: REPO_PAYMENTS_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        external_id: "700101",
        connection_id: GH_CONN_ID,
        name: "acme-platform/payments-service",
        default_branch: "main",
        visibility: "private",
        mode: "monitor",
        paused: false,
        policy_revision: 1,
        tags: [],
        archived: false,
        is_fork: false,
        workflow_hazard_status: "clean",
        workflow_hazards: [],
        auto_repair_blocked: false,
      },
      {
        id: REPO_BILLING_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        external_id: "700102",
        connection_id: GH_CONN_ID,
        name: "acme-platform/billing-worker",
        default_branch: "main",
        visibility: "private",
        mode: "monitor",
        paused: false,
        policy_revision: 1,
        tags: [],
        archived: false,
        is_fork: false,
        workflow_hazard_status: "clean",
        workflow_hazards: [],
        auto_repair_blocked: false,
      },
    ];

    const buildCursors = () => [
      {
        id: CURSOR_GAP_ID,
        workspace_id: WS_ACME_ID,
        version: gapAcknowledged ? 3 : 2,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        connection_id: GH_CONN_ID,
        repository_id: REPO_PAYMENTS_ID,
        provider: "github",
        etag: 'W/"runs-etag-1"',
        high_water_mark_at: NOW_ISO,
        last_seen_run_id: "5001",
        last_stable_page: 1,
        overlap_seconds: 300,
        poll_interval_seconds: 60,
        last_polled_at: NOW_ISO,
        last_success_at: NOW_ISO,
        next_poll_after: "2026-10-27T16:01:05Z",
        consecutive_failures: 0,
        last_status: gapAcknowledged ? "ok" : "gap_detected",
        history_gap_detected: !gapAcknowledged,
        history_gap_since: gapAcknowledged ? null : "2026-07-15T00:00:00Z",
        history_gap_until: gapAcknowledged ? null : NOW_ISO,
        history_gap_detail: gapAcknowledged
          ? null
          : "Offline duration (104d) exceeded provider run history retention (90d); missed runs in gap window cannot be recovered.",
      },
      {
        id: CURSOR_RL_ID,
        workspace_id: WS_ACME_ID,
        version: 2,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        connection_id: GH_CONN_ID,
        repository_id: REPO_BILLING_ID,
        provider: "github",
        etag: null,
        high_water_mark_at: null,
        last_seen_run_id: null,
        last_stable_page: 1,
        overlap_seconds: 300,
        poll_interval_seconds: 60,
        last_polled_at: NOW_ISO,
        last_success_at: null,
        next_poll_after: "2026-10-27T16:15:00Z",
        rate_limit_remaining: 0,
        rate_limit_reset_at: "2026-10-27T16:15:00Z",
        consecutive_failures: 1,
        last_status: "rate_limited",
        last_error_code: "provider_rate_limited",
        last_error_detail: "GitHub API rate limit exceeded (Retry-After 900s).",
        history_gap_detected: false,
      },
    ];

    const fetchImpl: typeof fetch = async (input) => {
      const req = input instanceof Request ? input : new Request(String(input));
      const url = new URL(req.url);

      if (url.pathname.endsWith("/events/stream")) {
        return sseIdleConnectedResponse();
      }
      if (req.method === "GET" && url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("admin"));
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces") {
        return jsonResponse({ items: [buildWorkspace()], next_cursor: null });
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme/integrations") {
        const prov = url.searchParams.get("provider");
        if (prov === "gitlab") {
          return jsonResponse({ items: [buildGitLabConnection()], next_cursor: null });
        }
        return jsonResponse({ items: [buildGitHubConnection()], next_cursor: null });
      }
      if (
        req.method === "GET" &&
        url.pathname === `/api/v1/workspaces/acme/integrations/${GH_CONN_ID}`
      ) {
        return jsonResponse(
          {
            connection: buildGitHubConnection(),
            latest_snapshot: null,
            repositories: repos,
            sync_cursors: buildCursors(),
          },
          { extraHeaders: { ETag: '"v2"' } },
        );
      }
      if (
        req.method === "GET" &&
        url.pathname === `/api/v1/workspaces/acme/integrations/${GL_CONN_ID}`
      ) {
        return jsonResponse(
          {
            connection: buildGitLabConnection(),
            latest_snapshot: null,
            repositories: [],
            sync_cursors: [],
          },
          { extraHeaders: { ETag: '"v2"' } },
        );
      }
      if (
        req.method === "POST" &&
        url.pathname === `/api/v1/workspaces/acme/integrations/${GH_CONN_ID}/reconcile`
      ) {
        const body = (await req.json()) as Record<string, unknown>;
        seenReconcileCalls.push({
          csrf: req.headers.get("X-CSRF-Token"),
          idemKey: req.headers.get("Idempotency-Key"),
          body,
        });
        if (body["acknowledge_history_gap"] === true) {
          gapAcknowledged = true;
        }
        const cursors = buildCursors();
        return jsonResponse({
          receipt: {
            operation_id: OP_ID,
            resource_id: GH_CONN_ID,
            state: "succeeded",
            correlation_id: "corr-u11-reconcile-01",
            status_url: `/api/v1/operations/${OP_ID}`,
            result_id: GH_CONN_ID,
          },
          connection_id: GH_CONN_ID,
          polled_repository_count: 1,
          rate_limited_count: 1,
          history_gap_count: gapAcknowledged ? 0 : 1,
          triggers_created_count: 1,
          pending_inbox_reconciled_count: 1,
          complete_recovery: false,
          sync_cursors: cursors,
        });
      }
      throw new Error(`Unhandled ${req.method} ${url.pathname}`);
    };

    const { container } = renderIntegrationsApp({ fetchImpl, themeMode: "dark" });

    // Wait for polling reconcile card & both warning banners to appear
    const gapBanner = await screen.findByTestId("polling-history-gap-banner", {}, { timeout: 5000 });
    expect(gapBanner).toHaveTextContent(/Incomplete history recovery/i);
    expect(gapBanner).toHaveTextContent(/missed runs in gap window cannot be recovered/i);

    const rateLimitBanner = await screen.findByTestId("polling-rate-limit-banner");
    expect(rateLimitBanner).toHaveTextContent(/429 Retry-After/i);
    expect(rateLimitBanner).toHaveTextContent(/billing-worker/i);

    expect(screen.getByTestId("webhook-ingress-endpoint")).toHaveTextContent(
      `/api/v1/hooks/github/${GH_CONN_ID}`,
    );

    // WCAG 2.2 AA axe audit with both banners rendered
    const axeResults = await axe.run(container);
    expect(axeResults.violations).toEqual([]);

    // Click Acknowledge gap & resync -> sends S-05 Idempotency-Key + CSRF + acknowledge_history_gap=true
    const ackBtn = screen.getByTestId("acknowledge-history-gap-btn");
    await user.click(ackBtn);

    await waitFor(() => {
      expect(seenReconcileCalls).toHaveLength(1);
    });
    expect(seenReconcileCalls[0]?.csrf).toBe("csrf-u11-test-token");
    expect(seenReconcileCalls[0]?.idemKey).toMatch(/^[0-9a-f-]{36}$/i);
    expect(seenReconcileCalls[0]?.body["acknowledge_history_gap"]).toBe(true);
    expect(seenReconcileCalls[0]?.body["force_poll"]).toBe(true);

    // Gap banner clears after acknowledgment, while active 429 rate-limit banner remains honest (`complete_recovery=false`)
    await waitFor(() => {
      expect(screen.queryByTestId("polling-history-gap-banner")).toBeNull();
    });
    expect(screen.getByTestId("polling-rate-limit-banner")).toBeInTheDocument();
    expect(screen.getByTestId("github-feedback-banner")).toHaveTextContent(
      /incomplete recovery \(1 rate-limited cursor\(s\)\)/i,
    );

    // Switch to GitLab tab and verify GitLab webhook ingress endpoint & polling card render cleanly
    const glTab = screen.getByRole("button", { name: /GitLab/i });
    await user.click(glTab);
    expect(
      await screen.findByTestId("polling-reconcile-card-gitlab", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(screen.getByTestId("webhook-ingress-endpoint")).toHaveTextContent(
      `/api/v1/hooks/gitlab/${GL_CONN_ID}`,
    );
  });

  it("hides mutating reconcile & gap-acknowledge buttons for read-only viewer role", async () => {
    const fetchImpl: typeof fetch = async (input) => {
      const req = input instanceof Request ? input : new Request(String(input));
      const url = new URL(req.url);
      if (url.pathname.endsWith("/events/stream")) {
        return sseIdleConnectedResponse();
      }
      if (req.method === "GET" && url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("viewer"));
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces") {
        return jsonResponse({ items: [buildWorkspace()], next_cursor: null });
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme/integrations") {
        return jsonResponse({ items: [buildGitHubConnection()], next_cursor: null });
      }
      if (
        req.method === "GET" &&
        url.pathname === `/api/v1/workspaces/acme/integrations/${GH_CONN_ID}`
      ) {
        return jsonResponse({
          connection: buildGitHubConnection(),
          latest_snapshot: null,
          repositories: [],
          sync_cursors: [
            {
              id: CURSOR_GAP_ID,
              workspace_id: WS_ACME_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              connection_id: GH_CONN_ID,
              repository_id: REPO_PAYMENTS_ID,
              provider: "github",
              last_stable_page: 1,
              overlap_seconds: 300,
              poll_interval_seconds: 60,
              consecutive_failures: 0,
              last_status: "gap_detected",
              history_gap_detected: true,
              history_gap_detail: "Offline gap beyond TTL.",
            },
          ],
        });
      }
      throw new Error(`Unhandled ${req.method} ${url.pathname}`);
    };

    renderIntegrationsApp({ fetchImpl, themeMode: "light" });
    expect(
      await screen.findByTestId("polling-history-gap-banner", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("reconcile-connection-runs-btn")).toBeNull();
    expect(screen.queryByTestId("acknowledge-history-gap-btn")).toBeNull();
  });
});
