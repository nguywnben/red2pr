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

const OWNER_USER_ID = "0196ed07-0000-7000-8000-000000000101";
const SESSION_ID = "0196ed07-0000-7000-8000-000000000201";
const WS_CORE_ID = "0196ed07-0000-7000-8000-000000000301";
const CONSENT_INF_ID = "0196ed07-0000-7000-8000-000000000401";
const ENDPOINT_GL_ID = "0196ed07-0000-7000-8000-000000000501";
const NOW_ISO = "2026-10-27T12:00:00Z";
const EXPIRES_ISO = "2026-10-28T00:00:00Z";

const ORDERED_PHASES = [
  "owner_claim",
  "topology_tls",
  "storage_keys",
  "workspace_admin",
  "provider_connect",
  "model_consent",
  "worker_readiness",
  "repo_policy",
  "notifications",
  "readiness_review",
] as const;

const OPTIONAL_PHASES = new Set([
  "provider_connect",
  "model_consent",
  "worker_readiness",
  "notifications",
]);

function jsonResponse(
  body: unknown,
  init: {
    status?: number;
    correlationId?: string;
    contentType?: string;
  } = {},
): Response {
  const status = init.status ?? 200;
  const headers = new Headers({
    "Content-Type": init.contentType ?? "application/json",
    "X-Correlation-Id": init.correlationId ?? "corr-u07-web-01",
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
  const cid = params.correlationId ?? "corr-u07-err-01";
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

function LocationProbe(): React.JSX.Element {
  const location = useLocation();
  return <div data-testid="router-location">{`${location.pathname}${location.search}`}</div>;
}

function renderSetupApp(opts: {
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
          <MemoryRouter initialEntries={[opts.initialEntry ?? "/setup"]}>
            <LocationProbe />
            <AppRoutes />
          </MemoryRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
  return { ...rendered, queryClient };
}

function assertZeroWebStorageSecrets(): void {
  for (let i = 0; i < window.localStorage.length; i += 1) {
    const key = window.localStorage.key(i);
    expect(key).toBe(THEME_STORAGE_KEY);
    const val = key ? window.localStorage.getItem(key) : null;
    expect(["light", "dark", "system"]).toContain(val);
  }
  expect(window.sessionStorage.length).toBe(0);
}

function buildMePayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    user: {
      id: OWNER_USER_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      display_name: "Alice Owner",
      email: "alice.owner@red2pr.local",
      status: "active",
    },
    session: {
      id: SESSION_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      user_id: OWNER_USER_ID,
      expires_at: EXPIRES_ISO,
      mfa_verified_at: null,
      client_ip: "127.0.0.1",
      user_agent: "Vitest",
    },
    csrf_token: "csrf-u07-tok",
    is_instance_owner: true,
    mfa_enabled: false,
    step_up_valid_until: null,
    workspaces: [
      {
        id: WS_CORE_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        name: "Core Engineering",
        slug: "core-eng",
        owner_user_id: OWNER_USER_ID,
        status: "active",
        paused: false,
      },
    ],
    memberships: [],
    repo_grants: {},
    active_break_glass_workspace_ids: [],
    telegram_link: null,
    ...overrides,
  };
}

function buildSetupState(params: {
  phase: (typeof ORDERED_PHASES)[number];
  checkpoint: string;
  ownerClaimed: boolean;
  readyMonitor?: boolean;
  readyRepair?: boolean;
  completedAt?: string | null;
  stepStatuses?: Partial<Record<(typeof ORDERED_PHASES)[number], string>>;
  drafts?: Partial<Record<(typeof ORDERED_PHASES)[number], Record<string, unknown>>>;
}): Record<string, unknown> {
  const readyMonitor = params.readyMonitor ?? false;
  const readyRepair = params.readyRepair ?? false;
  const readiness = readyRepair ? "ready_repair" : readyMonitor ? "ready_monitor" : "not_ready";

  return {
    phase: params.phase,
    checkpoint: params.checkpoint,
    readiness,
    owner_claimed: params.ownerClaimed,
    ready_monitor: readyMonitor,
    ready_repair: readyRepair,
    completed_at: params.completedAt ?? null,
    default_workspace_id: params.ownerClaimed ? WS_CORE_ID : null,
    default_workspace_slug: params.ownerClaimed ? "core-eng" : null,
    prerequisites: [
      {
        id: "monitor_baseline",
        status: readyMonitor ? "passed" : "not_configured",
        remediation: readyMonitor
          ? "Webhook/API monitoring prerequisites verified."
          : "Complete topology, storage, workspace, and Git provider phases.",
      },
      {
        id: "inference_consent",
        status: readyRepair ? "passed" : "not_configured",
        remediation: readyRepair
          ? "Active outbound inference consent granted."
          : "Grant explicit purpose='inference' outbound consent.",
      },
    ],
    steps: ORDERED_PHASES.map((p, idx) => ({
      phase: p,
      order: idx + 1,
      optional: OPTIONAL_PHASES.has(p),
      status:
        params.stepStatuses?.[p] ??
        (p === "owner_claim" && params.ownerClaimed ? "completed" : "pending"),
      probe_status:
        params.stepStatuses?.[p] === "completed" ||
        (p === "owner_claim" && params.ownerClaimed)
          ? "passed"
          : "not_configured",
      probe_detail: `Status for ${p}`,
      blocking_reasons: [],
      redacted_draft: params.drafts?.[p] ?? {},
      updated_at: NOW_ISO,
    })),
  };
}

describe("U07 Setup Wizard, Consent Ledger & Private Endpoint Registry UI (UX-SETUP-001, UX-01)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    document.cookie = "red2pr_csrf=csrf-u07-tok; path=/";
  });

  it("claims owner from Phase 1, resumes at server checkpoint, skips optional phases as Not Configured, and distinguishes Monitor Ready from Repair Blocked (UX-SETUP-001, UX-01)", async () => {
    const user = userEvent.setup();
    let claimed = false;
    let phase: (typeof ORDERED_PHASES)[number] = "owner_claim";
    let checkpoint = "ckpt-001";
    let readyMonitor = false;
    const stepStatuses: Partial<Record<(typeof ORDERED_PHASES)[number], string>> = {};

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();

      if (url.endsWith("/api/v1/auth/csrf")) {
        return jsonResponse({ csrf_token: "csrf-u07-tok" });
      }
      if (url.endsWith("/api/v1/auth/me")) {
        if (!claimed) {
          return problemResponse({
            status: 401,
            code: "unauthenticated",
            title: "Unauthenticated",
            detail: "Sign in required.",
          });
        }
        return jsonResponse(buildMePayload());
      }
      if (url.endsWith("/api/v1/setup") && method === "GET") {
        return jsonResponse(
          buildSetupState({
            phase,
            checkpoint,
            ownerClaimed: claimed,
            readyMonitor,
            readyRepair: false,
            stepStatuses,
          }),
        );
      }
      if (url.endsWith("/api/v1/setup/claim") && method === "POST") {
        claimed = true;
        phase = "model_consent"; // Simulate resuming directly at Phase 6!
        checkpoint = "ckpt-006";
        stepStatuses.owner_claim = "completed";
        stepStatuses.topology_tls = "completed";
        stepStatuses.storage_keys = "completed";
        stepStatuses.workspace_admin = "completed";
        stepStatuses.provider_connect = "completed";
        readyMonitor = true;
        return jsonResponse(
          {
            user: buildMePayload().user,
            session: buildMePayload().session,
            csrf_token: "csrf-u07-tok",
          },
          { status: 201 },
        );
      }
      if (url.includes("/api/v1/setup/steps/") && method === "POST") {
        const targetPhase = url.split("/api/v1/setup/steps/")[1] as (typeof ORDERED_PHASES)[number];
        const rawBody =
          typeof init?.body === "string"
            ? (JSON.parse(init.body) as Record<string, unknown>)
            : input instanceof Request
              ? ((await input.clone().json()) as Record<string, unknown>)
              : {};
        if (rawBody.action === "skip") {
          stepStatuses[targetPhase] = "not_configured";
          phase = "worker_readiness";
          checkpoint = "ckpt-007";
        }
        return jsonResponse(
          buildSetupState({
            phase,
            checkpoint,
            ownerClaimed: true,
            readyMonitor,
            readyRepair: false,
            stepStatuses,
          }),
        );
      }
      if (url.includes("/api/v1/setup/consents")) {
        return jsonResponse({ items: [], next_cursor: null, has_more: false, snapshot_at: NOW_ISO });
      }
      if (url.includes("/api/v1/setup/endpoints")) {
        return jsonResponse({ items: [], next_cursor: null, has_more: false, snapshot_at: NOW_ISO });
      }
      return problemResponse({
        status: 404,
        code: "not_found",
        title: "Not found",
        detail: `Unhandled ${method} ${url}`,
      });
    });

    const { container, unmount } = renderSetupApp({
      fetchImpl: fetchMock as unknown as typeof fetch,
      themeMode: "light",
    });

    // Phase 1 renders bootstrap claim form
    const phase1Section = await screen.findByTestId("setup-phase-owner_claim");
    expect(screen.getByTestId("badge-ready-monitor")).toHaveTextContent(/Monitor Not Ready/i);
    expect(screen.getByTestId("badge-ready-repair")).toHaveTextContent(/Repair Blocked/i);

    // Accessibility check in light theme (`0` WCAG 2.2 AA violations)
    const axeLight = await axe.run(container);
    expect(axeLight.violations).toEqual([]);

    await user.type(
      within(phase1Section).getByLabelText(/One-time bootstrap token/i),
      "boot_secret_123456",
    );
    await user.type(
      within(phase1Section).getByLabelText(/Owner password/i),
      "OwnerSup3rStr0ng!Pass#27",
    );
    await user.click(
      within(phase1Section).getByRole("button", { name: /Claim owner & sign in/i }),
    );

    // Wizard resumes at Phase 6 (`model_consent`), showing Monitor Ready & Repair Blocked
    await screen.findByTestId("setup-phase-model_consent");
    expect(screen.getByTestId("badge-ready-monitor")).toHaveTextContent(/Monitor Ready/i);
    expect(screen.getByTestId("badge-ready-repair")).toHaveTextContent(/Repair Blocked/i);

    // Skip optional Phase 6 -> Step 6 shows honest "Not Configured" (never green/Completed!)
    await user.click(screen.getByRole("button", { name: /Skip for now/i }));
    await screen.findByTestId("setup-phase-worker_readiness");
    expect(screen.getByTestId("setup-step-item-model_consent")).toHaveTextContent(
      /Not Configured/i,
    );

    assertZeroWebStorageSecrets();
    unmount();
  });

  it("grants and revokes explicit inference consent, handles 409 checkpoint_conflict recovery, and gates private endpoint registration behind StepUpDialog in dark theme (SEC-018, ADR-037)", async () => {
    const user = userEvent.setup();
    let stepUpUntil: string | null = null;
    let readyRepair = false;
    let checkpoint = "ckpt-010";
    let forceConflictOnce = true;

    const consents: Array<Record<string, unknown>> = [];
    const endpoints: Array<Record<string, unknown>> = [];

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();

      if (url.endsWith("/api/v1/auth/csrf")) {
        return jsonResponse({ csrf_token: "csrf-u07-tok" });
      }
      if (url.endsWith("/api/v1/auth/me")) {
        return jsonResponse(buildMePayload({ step_up_valid_until: stepUpUntil }));
      }
      if (url.endsWith("/api/v1/auth/step-up") && method === "POST") {
        stepUpUntil = new Date(Date.now() + 5 * 60_000).toISOString();
        return jsonResponse({
          session_id: SESSION_ID,
          step_up_valid_until: stepUpUntil,
        });
      }
      if (url.endsWith("/api/v1/setup") && method === "GET") {
        return jsonResponse(
          buildSetupState({
            phase: "readiness_review",
            checkpoint,
            ownerClaimed: true,
            readyMonitor: true,
            readyRepair,
          }),
        );
      }
      if (url.endsWith("/api/v1/setup/steps/readiness_review") && method === "POST") {
        if (forceConflictOnce) {
          forceConflictOnce = false;
          checkpoint = "ckpt-011-fresh";
          return problemResponse({
            status: 409,
            code: "checkpoint_conflict",
            title: "Checkpoint conflict",
            detail: "Expected setup checkpoint is stale.",
          });
        }
        checkpoint = "ckpt-012-done";
        return jsonResponse(
          buildSetupState({
            phase: "readiness_review",
            checkpoint,
            ownerClaimed: true,
            readyMonitor: true,
            readyRepair,
            completedAt: NOW_ISO,
          }),
        );
      }
      if (url.includes("/api/v1/setup/consents") && method === "GET") {
        return jsonResponse({
          items: consents,
          next_cursor: null,
          has_more: false,
          snapshot_at: NOW_ISO,
        });
      }
      if (url.endsWith("/api/v1/setup/consents") && method === "POST") {
        const created = {
          id: CONSENT_INF_ID,
          version: 1,
          created_at: NOW_ISO,
          updated_at: NOW_ISO,
          purpose: "inference",
          scope: "instance",
          workspace_id: null,
          repository_id: null,
          destination: "https://api.llama.com",
          data_classes: ["public", "workspace_internal"],
          status: "active",
          granted_by_user_id: OWNER_USER_ID,
          granted_at: NOW_ISO,
          revoked_by_user_id: null,
          revoked_at: null,
          revocation_reason: null,
        };
        consents.splice(0, consents.length, created);
        readyRepair = true;
        return jsonResponse(created, { status: 201 });
      }
      if (url.endsWith(`/api/v1/setup/consents/${CONSENT_INF_ID}`) && method === "DELETE") {
        consents.splice(0, consents.length);
        readyRepair = false;
        return jsonResponse({
          id: CONSENT_INF_ID,
          version: 2,
          created_at: NOW_ISO,
          updated_at: NOW_ISO,
          purpose: "inference",
          scope: "instance",
          workspace_id: null,
          repository_id: null,
          destination: "https://api.llama.com",
          data_classes: ["public", "workspace_internal"],
          status: "revoked",
          granted_by_user_id: OWNER_USER_ID,
          granted_at: NOW_ISO,
          revoked_by_user_id: OWNER_USER_ID,
          revoked_at: NOW_ISO,
          revocation_reason: "Revoked in setup wizard",
        });
      }
      if (url.includes("/api/v1/setup/endpoints") && method === "GET") {
        return jsonResponse({
          items: endpoints,
          next_cursor: null,
          has_more: false,
          snapshot_at: NOW_ISO,
        });
      }
      if (url.endsWith("/api/v1/setup/endpoints") && method === "POST") {
        if (!stepUpUntil) {
          return problemResponse({
            status: 403,
            code: "step_up_required",
            title: "Step-up required",
            detail: "Fresh 5-minute step-up verification required.",
          });
        }
        const ep = {
          id: ENDPOINT_GL_ID,
          version: 1,
          created_at: NOW_ISO,
          updated_at: NOW_ISO,
          adapter: "gitlab",
          scheme: "https",
          host: "gitlab.corp.internal",
          port: 8443,
          cidrs: ["10.24.0.0/16"],
          ca_ref: "ref:corp-ca",
          description: "Corp GitLab",
          status: "active",
          registered_by_user_id: OWNER_USER_ID,
          revoked_by_user_id: null,
          revoked_at: null,
        };
        endpoints.splice(0, endpoints.length, ep);
        return jsonResponse(ep, { status: 201 });
      }
      return problemResponse({
        status: 404,
        code: "not_found",
        title: "Not found",
        detail: `Unhandled ${method} ${url}`,
      });
    });

    const { container, unmount } = renderSetupApp({
      fetchImpl: fetchMock as unknown as typeof fetch,
      themeMode: "dark",
    });

    await screen.findByTestId("setup-phase-readiness_review");
    await screen.findByTestId("setup-endpoints-panel");
    await waitFor(() => {
      expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(4);
    });

    // 1) Dark-mode WCAG 2.2 AA check (`0` violations)
    const axeDark = await axe.run(container);
    expect(axeDark.violations).toEqual([]);

    // 2) Grant explicit `inference` consent -> Repair Ready turns active; revoking drops it back!
    const consentsPanel = screen.getByTestId("setup-consents-panel");
    const grantBtn = within(consentsPanel).getByRole("button", {
      name: /Grant outbound consent/i,
    });
    expect(grantBtn).toBeDisabled();
    await user.click(
      within(consentsPanel).getByLabelText(
        /I explicitly authorize redacted outbound transmission/i,
      ),
    );
    expect(grantBtn).toBeEnabled();
    await user.click(grantBtn);

    await waitFor(() => {
      expect(screen.getByTestId("badge-ready-repair")).toHaveTextContent(/Repair Ready/i);
    });
    expect(screen.getByTestId("consent-row-inference")).toBeInTheDocument();

    await user.click(within(consentsPanel).getByRole("button", { name: /Revoke consent/i }));
    await waitFor(() => {
      expect(screen.getByTestId("badge-ready-repair")).toHaveTextContent(/Repair Blocked/i);
    });

    // 3) Trigger 409 checkpoint_conflict -> recovery banner reloads latest checkpoint & succeeds
    await user.click(screen.getByRole("button", { name: /Complete setup review/i }));
    const conflictBanner = await screen.findByTestId("setup-checkpoint-conflict-banner");
    await user.click(
      within(conflictBanner).getByRole("button", { name: /Reload latest checkpoint/i }),
    );
    await waitFor(() => {
      expect(screen.queryByTestId("setup-checkpoint-conflict-banner")).not.toBeInTheDocument();
    });
    await user.click(screen.getByRole("button", { name: /Complete setup review/i }));
    await screen.findByRole("button", { name: /Open initial workspace/i });

    // 4) Registering private endpoint opens StepUpDialog when step-up is missing, then completes!
    const endpointsPanel = screen.getByTestId("setup-endpoints-panel");
    await user.type(within(endpointsPanel).getByLabelText(/Hostname/i), "gitlab.corp.internal");
    await user.clear(within(endpointsPanel).getByLabelText(/^Port$/i));
    await user.type(within(endpointsPanel).getByLabelText(/^Port$/i), "8443");
    await user.type(
      within(endpointsPanel).getByLabelText(/Custom CA bundle reference/i),
      "ref:corp-ca",
    );
    await user.click(
      within(endpointsPanel).getByRole("button", { name: /Register private endpoint/i }),
    );

    // StepUpDialog opens
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(/Current password/i), "OwnerSup3rStr0ng!Pass#27");
    await user.click(within(dialog).getByRole("button", { name: /Verify step-up/i }));

    const epRow = await screen.findByTestId("endpoint-row-gitlab.corp.internal");
    expect(epRow).toHaveTextContent("https://gitlab.corp.internal:8443");
    expect(epRow).toHaveTextContent("10.24.0.0/16");

    assertZeroWebStorageSecrets();
    unmount();
  });
});
