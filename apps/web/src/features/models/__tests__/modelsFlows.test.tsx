import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../../app/App";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { THEME_STORAGE_KEY, ThemeProvider } from "../../../shared/theme";

const OWNER_USER_ID = "0196ed16-0000-7000-8000-000000000101";
const SESSION_ID = "0196ed16-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ed16-0000-7000-8000-000000000301";
const MEM_ID = "0196ed16-0000-7000-8000-000000000401";
const REPO_ID = "0196ed16-0000-7000-8000-000000000501";
const CONSENT_ID = "0196ed16-0000-7000-8000-000000000601";
const BUDGET_ID = "0196ed16-0000-7000-8000-000000000701";
const SNAP_SPARK_ID = "0196ed16-0000-7000-8000-000000000801";
const SNAP_WONDER_ID = "0196ed16-0000-7000-8000-000000000802";
const USAGE_SETTLED_ID = "0196ed16-0000-7000-8000-000000000901";
const USAGE_UNKNOWN_ID = "0196ed16-0000-7000-8000-000000000902";
const OP_ID = "0196ed16-0000-7000-8000-000000000999";
const NOW_ISO = "2026-10-28T12:00:00Z";
const EXPIRES_ISO = "2026-10-29T12:00:00Z";

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
    "X-Correlation-Id": init.correlationId ?? "corr-u16-web-01",
    ...(init.extraHeaders ?? {}),
  });
  return new Response(body === null ? null : JSON.stringify(body), { status, headers });
}

function problemResponse(params: {
  status: number;
  code: string;
  title: string;
  detail: string;
}): Response {
  return jsonResponse(
    {
      type: `https://red2pr.local/problems/${params.code}`,
      title: params.title,
      status: params.status,
      code: params.code,
      detail: params.detail,
      correlation_id: "corr-u16-err-01",
      errors: null,
    },
    {
      status: params.status,
      correlationId: "corr-u16-err-01",
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

function renderModelsApp(opts: {
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
          <MemoryRouter initialEntries={["/w/acme/models"]}>
            <AppRoutes />
          </MemoryRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
  return { ...rendered, queryClient };
}

function assertZeroWebStorageSecrets(secretCanary?: string): void {
  for (let i = 0; i < window.localStorage.length; i += 1) {
    const key = window.localStorage.key(i);
    expect(key).toBe(THEME_STORAGE_KEY);
    if (secretCanary && key) {
      expect(window.localStorage.getItem(key)).not.toContain(secretCanary);
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

function buildMePayload(role: "admin" | "viewer"): Record<string, unknown> {
  return {
    user: {
      id: OWNER_USER_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      display_name: role === "admin" ? "Workspace Admin" : "Workspace Viewer",
      email: "admin@red2pr.local",
      status: "active",
    },
    session: {
      id: SESSION_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      user_id: OWNER_USER_ID,
      expires_at: EXPIRES_ISO,
      auth_strength: "password",
      step_up_at: NOW_ISO,
      grant_epoch: 1,
    },
    is_instance_owner: role === "admin",
    mfa_enabled: false,
    mfa_required_for_privileged: false,
    step_up_valid_until: EXPIRES_ISO,
    recovery_codes_remaining: 0,
    workspaces: [buildWorkspace()],
    memberships: [
      {
        id: MEM_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        user_id: OWNER_USER_ID,
        role,
        repository_grants: [REPO_ID],
      },
    ],
    telegram_link: { status: "not_configured" },
    csrf_token: "csrf-u16-token",
  };
}

function buildModelsState(overrides: {
  version?: number;
  keyConfigured?: boolean;
  consentActive?: boolean;
  sparkStatus?: "not_probed" | "available";
  wonderStatus?: "not_probed" | "unavailable" | "available";
  pricingConfigured?: boolean;
  suspensionReason?: "model_unavailable" | null;
  statusDetail?: string | null;
  retryAfter?: number | null;
  withUsage?: boolean;
} = {}): Record<string, unknown> {
  const version = overrides.version ?? 1;
  const keyConfigured = overrides.keyConfigured ?? false;
  const consentActive = overrides.consentActive ?? false;
  const sparkStatus = overrides.sparkStatus ?? "not_probed";
  const wonderStatus = overrides.wonderStatus ?? "not_probed";
  const pricingConfigured = overrides.pricingConfigured ?? false;
  const consents = consentActive
    ? [
        {
          id: CONSENT_ID,
          version: 1,
          created_at: NOW_ISO,
          updated_at: NOW_ISO,
          purpose: "inference",
          scope: "workspace",
          workspace_id: WS_ACME_ID,
          repository_id: null,
          destination: "https://api.meta.ai/v1",
          data_classes: ["public", "workspace_internal"],
          granted_by: OWNER_USER_ID,
          granted_at: NOW_ISO,
          policy_version: 1,
          status: "active",
          revoked_by: null,
          revoked_at: null,
          revoke_reason: null,
        },
      ]
    : [];

  return {
    workspace_id: WS_ACME_ID,
    version,
    updated_at: NOW_ISO,
    endpoint_base_url: "https://api.meta.ai/v1",
    endpoint_registration_id: null,
    api_key_presence: {
      configured: keyConfigured,
      secret_version: keyConfigured ? 1 : null,
      updated_at: keyConfigured ? NOW_ISO : null,
    },
    active_inference_consent_id: consentActive ? CONSENT_ID : null,
    inference_consent_active: consentActive,
    available_inference_consents: consents,
    suspension_reason: overrides.suspensionReason ?? null,
    status_detail: overrides.statusDetail ?? null,
    retry_after_seconds: overrides.retryAfter ?? null,
    ready_for_repair_inference:
      keyConfigured &&
      consentActive &&
      pricingConfigured &&
      sparkStatus === "available" &&
      (overrides.suspensionReason ?? null) === null,
    models: [
      {
        model_id: "muse-spark-1.3",
        display_name: "Meta Muse Spark 1.3",
        vendor: "meta",
        tier_role: "primary",
        enabled: true,
        status: sparkStatus,
        pricing: pricingConfigured
          ? {
              pricing_revision: "meta-2026-10",
              input_per_1m_tokens: { amount: "1.500000", currency: "USD" },
              output_per_1m_tokens: { amount: "6.000000", currency: "USD" },
              configured: true,
            }
          : {
              pricing_revision: "unconfigured",
              input_per_1m_tokens: { amount: "0.000000", currency: "USD" },
              output_per_1m_tokens: { amount: "0.000000", currency: "USD" },
              configured: false,
            },
        latest_snapshot:
          sparkStatus === "available"
            ? {
                id: SNAP_SPARK_ID,
                workspace_id: WS_ACME_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                model_id: "muse-spark-1.3",
                tier_role: "primary",
                status: "available",
                capabilities: {
                  tool_calls: "available",
                  structured_output: "available",
                  streaming: "available",
                  context_window_tokens: 131072,
                  max_output_tokens: 16384,
                  rate_limit_rpm: 60,
                  rate_limit_tpm: 120000,
                },
                provider_request_id: "req-meta-spark-01",
                consent_id: CONSENT_ID,
                probed_at: NOW_ISO,
                status_detail: "Capability probe succeeded.",
                suspension_reason: null,
                retry_after_seconds: null,
              }
            : null,
      },
      {
        model_id: "muse-wonder-1.0",
        display_name: "Meta Muse Wonder 1.0",
        vendor: "meta",
        tier_role: "escalation",
        enabled: false,
        status: wonderStatus,
        pricing: pricingConfigured
          ? {
              pricing_revision: "meta-2026-10",
              input_per_1m_tokens: { amount: "5.000000", currency: "USD" },
              output_per_1m_tokens: { amount: "20.000000", currency: "USD" },
              configured: true,
            }
          : {
              pricing_revision: "unconfigured",
              input_per_1m_tokens: { amount: "0.000000", currency: "USD" },
              output_per_1m_tokens: { amount: "0.000000", currency: "USD" },
              configured: false,
            },
        latest_snapshot:
          wonderStatus === "unavailable"
            ? {
                id: SNAP_WONDER_ID,
                workspace_id: WS_ACME_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                model_id: "muse-wonder-1.0",
                tier_role: "escalation",
                status: "unavailable",
                capabilities: {
                  tool_calls: "unavailable",
                  structured_output: "unavailable",
                  streaming: "unavailable",
                  context_window_tokens: null,
                  max_output_tokens: null,
                  rate_limit_rpm: null,
                  rate_limit_tpm: null,
                },
                provider_request_id: "req-meta-wonder-403",
                consent_id: CONSENT_ID,
                probed_at: NOW_ISO,
                status_detail: "Account tier does not grant muse-wonder-1.0 access.",
                suspension_reason: null,
                retry_after_seconds: null,
              }
            : null,
      },
    ],
    budget_policy: {
      max_calls_per_session: 30,
      max_tokens_per_session: 120000,
      max_patch_attempts: 2,
      max_wall_seconds: 1800,
      max_cost_per_session: { amount: "5.000000", currency: "USD" },
      daily_workspace_cap: { amount: "25.000000", currency: "USD" },
      alert_threshold_percent: 80,
    },
    escalation_policy: {
      escalation_enabled: false,
      escalation_model_id: "muse-wonder-1.0",
      escalate_after_failed_attempts: 1,
      require_probed_availability: true,
      allow_non_meta_fallback: false,
    },
    workspace_budget: {
      id: BUDGET_ID,
      workspace_id: WS_ACME_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      scope_kind: "workspace_daily",
      scope_key: "daily:2026-10-28",
      currency: "USD",
      cost_cap: { amount: "25.000000", currency: "USD" },
      reserved_cost: { amount: "0.000000", currency: "USD" },
      settled_cost: { amount: "0.001200", currency: "USD" },
      unknown_cost: { amount: "0.120000", currency: "USD" },
      remaining_cost: { amount: "24.878800", currency: "USD" },
      token_cap: 0,
      reserved_tokens: 0,
      settled_tokens: 48,
      unknown_tokens: 512,
      call_cap: 0,
      reserved_calls: 0,
      settled_calls: 1,
      unknown_calls: 1,
      max_patch_attempts: 0,
      patch_attempts_used: 0,
      max_wall_seconds: 86400,
      window_started_at: "2026-10-28T00:00:00Z",
      window_ends_at: "2026-10-29T00:00:00Z",
      cancelled_at: null,
    },
    recent_usage: overrides.withUsage
      ? [
          {
            id: USAGE_SETTLED_ID,
            workspace_id: WS_ACME_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            reservation_id: "0196ed16-0000-7000-8000-000000000951",
            provider_request_id: "req-meta-spark-01",
            model_id: "muse-spark-1.3",
            input_tokens: 32,
            output_tokens: 16,
            estimated_cost: { amount: "0.005000", currency: "USD" },
            settled_cost: { amount: "0.001200", currency: "USD" },
            currency: "USD",
            pricing_revision: "meta-2026-10",
            status: "settled",
          },
          {
            id: USAGE_UNKNOWN_ID,
            workspace_id: WS_ACME_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            reservation_id: "0196ed16-0000-7000-8000-000000000952",
            provider_request_id: null,
            model_id: "muse-spark-1.3",
            input_tokens: null,
            output_tokens: null,
            estimated_cost: { amount: "0.120000", currency: "USD" },
            settled_cost: null,
            currency: "USD",
            pricing_revision: "meta-2026-10",
            status: "unknown",
          },
        ]
      : [],
  };
}

describe("U16 Models & Budgets Screen (UI-S12, AGT-01, AGT-03, SEC-012, SEC-018, SEC-023, SEC-040)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("rotates write-only Meta API key via step-up retry without storing secrets, grants consent, and executes a consented paid capability probe", async () => {
    const user = userEvent.setup();
    const secretCanary = "meta-secret-canary-key-9988776655";
    let currentState = buildModelsState();
    let stepUpVerified = false;
    const seenConfigIdempotencyKeys: string[] = [];

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const method = req.method.toUpperCase();

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("admin"));
      }
      if (url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/models" && method === "GET") {
        return jsonResponse(currentState, {
          extraHeaders: { ETag: `"v${String(currentState.version)}"` },
        });
      }
      if (url.pathname === "/api/v1/auth/step-up" && method === "POST") {
        stepUpVerified = true;
        return jsonResponse({
          step_up_valid_until: EXPIRES_ISO,
          auth_strength: "password",
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme/models/config" && method === "PATCH") {
        const idemKey = req.headers.get("Idempotency-Key") ?? "";
        seenConfigIdempotencyKeys.push(idemKey);
        const body = JSON.parse(await req.text()) as Record<string, unknown>;
        if ("api_key" in body && !stepUpVerified) {
          return problemResponse({
            status: 403,
            code: "step_up_required",
            title: "Step-up required",
            detail: "Fresh 5-minute step-up verification is required to rotate Meta API keys.",
          });
        }
        currentState = buildModelsState({
          version: Number(currentState.version) + 1,
          keyConfigured: true,
          consentActive: Boolean(currentState.inference_consent_active),
          pricingConfigured: Boolean(body.pricing_updates) || true,
          sparkStatus: "not_probed",
          wonderStatus: "not_probed",
        });
        return jsonResponse(
          {
            receipt: {
              operation_id: OP_ID,
              idempotency_key: idemKey,
              status: "completed",
              replayed: false,
            },
            models_state: currentState,
          },
          { extraHeaders: { ETag: `"v${String(currentState.version)}"` } },
        );
      }
      if (url.pathname === "/api/v1/workspaces/acme/models/consents" && method === "POST") {
        currentState = buildModelsState({
          version: Number(currentState.version) + 1,
          keyConfigured: true,
          consentActive: true,
          pricingConfigured: true,
          sparkStatus: "not_probed",
          wonderStatus: "unavailable",
        });
        return jsonResponse(
          (currentState.available_inference_consents as unknown[])[0],
          { status: 201 },
        );
      }
      if (url.pathname === "/api/v1/workspaces/acme/model-probes" && method === "POST") {
        const body = JSON.parse(await req.text()) as {
          model_id: string;
          max_cost: { amount: string; currency: string };
          consent_id: string;
        };
        expect(body.model_id).toBe("muse-spark-1.3");
        expect(body.max_cost).toEqual({ amount: "0.050000", currency: "USD" });
        expect(body.consent_id).toBe(CONSENT_ID);
        currentState = buildModelsState({
          version: Number(currentState.version) + 1,
          keyConfigured: true,
          consentActive: true,
          pricingConfigured: true,
          sparkStatus: "available",
          wonderStatus: "unavailable",
          withUsage: true,
        });
        const models = currentState.models as Record<string, unknown>[];
        const recentUsage = currentState.recent_usage as Record<string, unknown>[];
        return jsonResponse({
          receipt: {
            operation_id: OP_ID,
            idempotency_key: req.headers.get("Idempotency-Key"),
            status: "completed",
            replayed: false,
          },
          snapshot: models[0]?.latest_snapshot,
          usage_record: recentUsage[0],
        });
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}`);
    });

    const { container } = renderModelsApp({ fetchImpl: fetchMock as unknown as typeof fetch });

    await screen.findByTestId("models-page");
    expect(screen.getByTestId("meta-key-presence-badge")).toHaveTextContent("Not Configured");
    expect(screen.getByTestId("models-readiness-badge")).toHaveTextContent(
      "Repair Inference Blocked",
    );
    expect(screen.getByRole("button", { name: "Probe muse-spark-1.3" })).toBeDisabled();

    // Enter write-only Meta API key; submit triggers 403 step_up_required and clears input immediately
    const keyInput = screen.getByLabelText(/Write-only Meta API key/i) as HTMLInputElement;
    await user.type(keyInput, secretCanary);
    await user.click(screen.getByRole("button", { name: "Save / Rotate API Key" }));

    expect(keyInput.value).toBe("");
    expect(container.textContent).not.toContain(secretCanary);
    assertZeroWebStorageSecrets(secretCanary);

    // Complete 5-minute step-up dialog -> retries with identical Idempotency-Key
    const stepUpDialog = await screen.findByRole("dialog", {
      name: /Confirm privileged step-up/i,
    });
    await user.type(within(stepUpDialog).getByLabelText(/Current password/i), "OwnerPass!123456");
    await user.click(within(stepUpDialog).getByRole("button", { name: /Verify step-up/i }));

    await waitFor(() => {
      expect(screen.getByTestId("meta-key-presence-badge")).toHaveTextContent("Configured (v1)");
    });
    expect(seenConfigIdempotencyKeys.length).toBe(2);
    expect(seenConfigIdempotencyKeys[0]).toBe(seenConfigIdempotencyKeys[1]);

    // Grant workspace inference consent
    await user.click(screen.getByRole("button", { name: "Grant workspace inference consent" }));
    await waitFor(() => {
      expect(screen.getByTestId("inference-consent-badge")).toHaveTextContent("Consent Active");
    });

    // Open paid capability probe confirmation modal for muse-spark-1.3
    const probeSparkBtn = screen.getByRole("button", { name: "Probe muse-spark-1.3" });
    expect(probeSparkBtn).toBeEnabled();
    await user.click(probeSparkBtn);

    const probeDialog = await screen.findByRole("dialog", {
      name: /Confirm paid capability probe \(muse-spark-1.3\)/i,
    });
    expect(
      within(probeDialog).getByLabelText(/Explicit max_cost ceiling/i),
    ).toHaveValue("0.050000");
    await user.click(
      within(probeDialog).getByRole("button", { name: "Confirm paid capability probe" }),
    );

    await waitFor(() => {
      expect(screen.getByTestId("models-readiness-badge")).toHaveTextContent(
        "Repair Inference Ready",
      );
    });
    expect(screen.getByText(/tools:available · schema:available · ctx:131072/i)).toBeInTheDocument();

    // muse-wonder-1.0 is unavailable on this account -> escalation toggle remains disabled
    const escalationCheckbox = screen.getByLabelText(
      /Enable optional escalation to muse-wonder-1.0/i,
    );
    expect(escalationCheckbox).toBeDisabled();
    assertZeroWebStorageSecrets(secretCanary);
  });

  it("renders suspension/cooldown banner truthfully, keeps unknown usage distinct from $0.00, handles 412 conflict reload, enforces viewer read-only RBAC, and passes axe in light & dark themes", async () => {
    const user = userEvent.setup();
    let role: "admin" | "viewer" = "admin";
    let returnStaleOnce = true;
    const suspendedState = buildModelsState({
      version: 3,
      keyConfigured: true,
      consentActive: true,
      pricingConfigured: true,
      sparkStatus: "available",
      wonderStatus: "unavailable",
      suspensionReason: "model_unavailable",
      statusDetail: "Upstream 429 rate limit \u202E\u001b[31mcooldown active",
      retryAfter: 42,
      withUsage: true,
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const method = req.method.toUpperCase();

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload(role));
      }
      if (url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/models" && method === "GET") {
        return jsonResponse(suspendedState, { extraHeaders: { ETag: '"v3"' } });
      }
      if (url.pathname === "/api/v1/workspaces/acme/models/config" && method === "PATCH") {
        if (returnStaleOnce) {
          returnStaleOnce = false;
          return problemResponse({
            status: 412,
            code: "version_precondition_failed",
            title: "Precondition Failed",
            detail: "If-Match precondition failed.",
          });
        }
        return jsonResponse({
          receipt: {
            operation_id: OP_ID,
            idempotency_key: req.headers.get("Idempotency-Key"),
            status: "completed",
            replayed: false,
          },
          models_state: suspendedState,
        });
      }
      throw new Error(`Unexpected request: ${method} ${url.pathname}`);
    });

    const lightRender = renderModelsApp({
      fetchImpl: fetchMock as unknown as typeof fetch,
      themeMode: "light",
    });

    const suspensionBanner = await screen.findByTestId("models-suspension-banner");
    expect(suspensionBanner).toHaveTextContent("model_unavailable");
    expect(suspensionBanner).toHaveTextContent("Retry cooldown: 42s.");
    // SEC-040: bidi U+202E and ANSI ESC sequences stripped
    expect(suspensionBanner.textContent).not.toContain("\u202E");
    expect(suspensionBanner.textContent).not.toContain("\u001b");

    // Unknown usage row must NEVER coerce settled_cost or tokens to 0 / $0.00
    expect(screen.getByText("Unconfirmed (hold USD 0.120000)")).toBeInTheDocument();
    expect(screen.getByText("Unconfirmed (—)")).toBeInTheDocument();

    // Trigger 412 stale conflict and reload
    await user.click(screen.getByRole("button", { name: "Save pricing & budget policy" }));
    const staleBanner = await screen.findByTestId("models-stale-conflict-banner");
    await user.click(within(staleBanner).getByRole("button", { name: "Reload latest state" }));
    await waitFor(() => {
      expect(screen.queryByTestId("models-stale-conflict-banner")).toBeNull();
    });

    const lightAxe = await axe.run(lightRender.container);
    expect(lightAxe.violations).toEqual([]);
    lightRender.unmount();

    // Viewer role read-only RBAC + dark mode WCAG 2.2 AA check
    role = "viewer";
    const darkRender = renderModelsApp({
      fetchImpl: fetchMock as unknown as typeof fetch,
      themeMode: "dark",
    });
    await screen.findByTestId("models-readonly-banner");
    expect(screen.getByRole("button", { name: "Save pricing & budget policy" })).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Grant workspace inference consent" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Probe muse-spark-1.3" })).toBeDisabled();

    const darkAxe = await axe.run(darkRender.container);
    expect(darkAxe.violations).toEqual([]);
  });
});
