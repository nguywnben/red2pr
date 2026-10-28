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

const OWNER_USER_ID = "0196ed17-0000-7000-8000-000000000101";
const SESSION_ID = "0196ed17-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ed17-0000-7000-8000-000000000301";
const MEM_ID = "0196ed17-0000-7000-8000-000000000401";
const REPO_ID = "0196ed17-0000-7000-8000-000000000501";
const DIAG_PROFILE_ID = "0196ed17-0000-7000-8000-000000000601";
const PATCH_PROFILE_ID = "0196ed17-0000-7000-8000-000000000602";
const REPAIR_ID = "0196ed17-0000-7000-8000-000000000701";
const STEP_OK_ID = "0196ed17-0000-7000-8000-000000000801";
const STEP_DENIED_ID = "0196ed17-0000-7000-8000-000000000802";
const OP_ID = "0196ed17-0000-7000-8000-000000000999";
const NOW_ISO = "2026-10-28T15:00:00Z";
const EXPIRES_ISO = "2026-10-29T15:00:00Z";
const DIGEST_A = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
    "X-Correlation-Id": init.correlationId ?? "corr-u17-web-01",
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
      correlation_id: "corr-u17-err-01",
      errors: null,
    },
    {
      status: params.status,
      correlationId: "corr-u17-err-01",
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

function renderAgentsApp(opts: {
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
          <MemoryRouter initialEntries={["/w/acme/agents"]}>
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
    csrf_token: "csrf-u17-token",
  };
}

function buildProfilesState(overrides: {
  diagVersion?: number;
  diagReasoning?: "low" | "medium" | "high";
  diagMaxSteps?: number;
  ready?: boolean;
  suspensionReason?: string | null;
} = {}): Record<string, unknown> {
  const diagTools = [
    "read_file",
    "search_repo",
    "read_log_excerpt",
    "read_commit_diff",
    "request_reproduction",
    "get_execution_result",
  ];
  const patchTools = [...diagTools, "apply_patch", "run_targeted_test"];

  return {
    workspace_id: WS_ACME_ID,
    ready_for_repair_inference: overrides.ready ?? true,
    suspension_reason: overrides.suspensionReason ?? null,
    prohibited_capabilities: [
      "publish",
      "merge",
      "approve",
      "rotate_secret",
      "edit_policy",
      "send_network_request",
      "run_host_shell",
    ],
    profiles: [
      {
        id: DIAG_PROFILE_ID,
        workspace_id: WS_ACME_ID,
        version: overrides.diagVersion ?? 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        role_key: "triage_diagnosis",
        display_name: "Triage & Diagnosis Agent",
        description: "Evidence-cited triage, unsupported abstention, and Sandbox A repro plan.",
        model_id: "muse-spark-1.3",
        escalation_model_id: null,
        reasoning_effort: overrides.diagReasoning ?? "medium",
        allowed_tools: diagTools,
        immutable_role_tool_ceiling: diagTools,
        max_steps: overrides.diagMaxSteps ?? 6,
        max_tool_calls_per_step: 4,
        max_schema_repair_retries: 2,
        arbitrary_prompt_override_allowed: false,
        enabled: true,
        updated_by_user_id: null,
      },
      {
        id: PATCH_PROFILE_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        role_key: "bounded_patch",
        display_name: "Bounded Patch Agent",
        description: "ADR-031 baseline-gated minimal unified diff candidate generation.",
        model_id: "muse-spark-1.3",
        escalation_model_id: null,
        reasoning_effort: "medium",
        allowed_tools: patchTools,
        immutable_role_tool_ceiling: patchTools,
        max_steps: 8,
        max_tool_calls_per_step: 4,
        max_schema_repair_retries: 2,
        arbitrary_prompt_override_allowed: false,
        enabled: true,
        updated_by_user_id: null,
      },
    ],
    tool_matrix: [
      {
        name: "read_file",
        category: "s20_allowed",
        description: "Read bounded pinned file slice.",
        permitted_for_diagnosis: true,
        permitted_for_patch: true,
        immutable_reason: "Allowlisted S-20 read tool.",
      },
      {
        name: "apply_patch",
        category: "s20_allowed",
        description: "Validate and stage unified diff inside isolated patch session.",
        permitted_for_diagnosis: false,
        permitted_for_patch: true,
        immutable_reason: "Permitted only for bounded_patch after ADR-031 baseline confirmation.",
      },
      {
        name: "publish",
        category: "prohibited",
        description: "Create or update remote PRs/MRs.",
        permitted_for_diagnosis: false,
        permitted_for_patch: false,
        immutable_reason: "Forbidden by SEC-028; enforced exclusively by Z2 publisher.",
      },
      {
        name: "run_host_shell",
        category: "prohibited",
        description: "Execute arbitrary host shell commands.",
        permitted_for_diagnosis: false,
        permitted_for_patch: false,
        immutable_reason: "Forbidden by SEC-028; execution occurs only via certified Z3 profiles.",
      },
    ],
    recent_steps: [
      {
        id: STEP_OK_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        repository_id: REPO_ID,
        repair_id: REPAIR_ID,
        agent_role: "diagnosis",
        attempt_number: 1,
        step_number: 1,
        step_kind: "tool_call",
        status: "ok",
        tool_call_id: "0196ed17-0000-7000-8000-000000000811",
        tool_name: "read_file",
        args_redacted_digest: DIGEST_A,
        result_redacted_digest: DIGEST_A,
        context_digest: DIGEST_A,
        deny_reason_code: null,
        deny_explanation: null,
        model_id: "muse-spark-1.3",
        provider_request_id: "req_diag_01",
        usage_record_id: null,
      },
      {
        id: STEP_DENIED_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        repository_id: REPO_ID,
        repair_id: REPAIR_ID,
        agent_role: "diagnosis",
        attempt_number: 1,
        step_number: 2,
        step_kind: "policy_denial",
        status: "denied",
        tool_call_id: "0196ed17-0000-7000-8000-000000000812",
        tool_name: "publish",
        args_redacted_digest: DIGEST_A,
        result_redacted_digest: null,
        context_digest: DIGEST_A,
        deny_reason_code: "tool_not_permitted",
        deny_explanation: "\u001b[31m\u202eDenied prohibited capability publish in broker\u001b[0m",
        model_id: "muse-spark-1.3",
        provider_request_id: "req_diag_02",
        usage_record_id: null,
      },
    ],
  };
}

describe("UI-S11 Workspace Agents & Tool Governance flows (U17)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("renders bounded agent profiles, enforces diagnosis tool ceiling, saves with If-Match + Idempotency-Key, sanitizes SEC-040 text, and passes axe-core in light mode", async () => {
    const user = userEvent.setup();
    let currentState = buildProfilesState();
    const seenPatches: Array<{
      ifMatch: string | null;
      idempotencyKey: string | null;
      csrf: string | null;
      body: Record<string, unknown>;
    }> = [];

    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (req.method === "GET" && url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("admin"));
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme/agent-profiles") {
        return jsonResponse(currentState);
      }
      if (
        req.method === "PATCH" &&
        url.pathname === `/api/v1/workspaces/acme/agent-profiles/${DIAG_PROFILE_ID}`
      ) {
        const body = (await req.json()) as Record<string, unknown>;
        seenPatches.push({
          ifMatch: req.headers.get("If-Match"),
          idempotencyKey: req.headers.get("Idempotency-Key"),
          csrf: req.headers.get("X-CSRF-Token"),
          body,
        });
        currentState = buildProfilesState({
          diagVersion: 2,
          diagReasoning: (body.reasoning_effort as "high") ?? "high",
          diagMaxSteps: Number(body.max_steps ?? 8),
        });
        const updatedProfile = (currentState.profiles as Array<Record<string, unknown>>)[0];
        return jsonResponse(
          {
            receipt: {
              operation_id: OP_ID,
              resource_id: DIAG_PROFILE_ID,
              state: "succeeded",
              correlation_id: "corr-u17-save-01",
              status_url: `/api/v1/operations/${OP_ID}`,
              result_id: DIAG_PROFILE_ID,
            },
            profile: updatedProfile,
            profiles_state: currentState,
          },
          { extraHeaders: { ETag: '"v2"' } },
        );
      }
      throw new Error(`Unhandled ${req.method} ${url.pathname}`);
    }) as unknown as typeof fetch;

    const { container } = renderAgentsApp({ fetchImpl, themeMode: "light" });

    expect(
      await screen.findByRole("heading", { name: /Agents & Tool Governance/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/arbitrary_prompt_override_allowed: false/i)).toBeInTheDocument();
    expect(screen.getByText("Ready for Repair Inference")).toBeInTheDocument();

    // Diagnosis ceiling excludes apply_patch & run_targeted_test, while Patch card includes them
    const diagCard = screen.getByTestId("agent-profile-card-triage_diagnosis");
    const patchCard = screen.getByTestId("agent-profile-card-bounded_patch");
    expect(within(diagCard).queryByLabelText("apply_patch")).not.toBeInTheDocument();
    expect(within(diagCard).queryByLabelText("run_targeted_test")).not.toBeInTheDocument();
    expect(within(patchCard).getByLabelText("apply_patch")).toBeChecked();
    expect(within(patchCard).getByLabelText("run_targeted_test")).toBeChecked();

    // Prohibited capabilities & SEC-040 sanitization in Recent Steps table
    expect(screen.getAllByText("Permanently Prohibited").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/Denied prohibited capability publish in broker/i)).toBeInTheDocument();
    expect(container.textContent).not.toContain("\u001b");
    expect(container.textContent).not.toContain("\u202e");

    // Admin updates diagnosis reasoning effort & max steps
    await user.selectOptions(
      within(diagCard).getByLabelText(/Reasoning effort \(triage_diagnosis\)/i),
      "high",
    );
    const maxStepsInput = within(diagCard).getByLabelText(/Max steps \(triage_diagnosis, 1-16\)/i);
    await user.clear(maxStepsInput);
    await user.type(maxStepsInput, "8");
    await user.click(within(diagCard).getByRole("button", { name: /Save Triage & Diagnosis Agent/i }));

    await waitFor(() => {
      expect(seenPatches).toHaveLength(1);
    });
    expect(seenPatches[0]?.ifMatch).toBe('"v1"');
    expect(seenPatches[0]?.idempotencyKey).toMatch(/^[0-9a-f-]{36}$/);
    expect(seenPatches[0]?.csrf).toBe("csrf-u17-token");
    expect(seenPatches[0]?.body.reasoning_effort).toBe("high");
    expect(seenPatches[0]?.body.max_steps).toBe(8);

    expect(await screen.findByTestId("agents-notice-banner")).toHaveTextContent(/updated to v2/i);
    assertZeroWebStorageSecrets();

    const axeResults = await axe.run(container);
    expect(axeResults.violations).toEqual([]);
  });

  it("surfaces 412 stale If-Match reload banner for admins and enforces viewer read-only RBAC + dark-mode axe-core parity", async () => {
    const user = userEvent.setup();
    let role: "admin" | "viewer" = "admin";
    let diagVersion = 1;

    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (req.method === "GET" && url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload(role));
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (req.method === "GET" && url.pathname === "/api/v1/workspaces/acme/agent-profiles") {
        return jsonResponse(
          buildProfilesState({
            diagVersion,
            ready: false,
            suspensionReason: "model_unavailable",
          }),
        );
      }
      if (
        req.method === "PATCH" &&
        url.pathname === `/api/v1/workspaces/acme/agent-profiles/${DIAG_PROFILE_ID}`
      ) {
        diagVersion = 3;
        return problemResponse({
          status: 412,
          code: "version_precondition_failed",
          title: "Precondition Failed",
          detail: "If-Match precondition failed against version 3.",
        });
      }
      throw new Error(`Unhandled ${req.method} ${url.pathname}`);
    }) as unknown as typeof fetch;

    const firstRender = renderAgentsApp({ fetchImpl, themeMode: "dark" });
    const diagCard = await screen.findByTestId("agent-profile-card-triage_diagnosis");
    expect(screen.getByText(/Paused \(model_unavailable\)/i)).toBeInTheDocument();

    await user.click(
      within(diagCard).getByRole("button", { name: /Save Triage & Diagnosis Agent/i }),
    );
    const conflictBanner = await screen.findByTestId("agents-stale-conflict-banner");
    expect(conflictBanner).toHaveTextContent(/HTTP 412/i);

    await user.click(within(conflictBanner).getByRole("button", { name: /Reload latest profiles/i }));
    await waitFor(() => {
      expect(screen.queryByTestId("agents-stale-conflict-banner")).not.toBeInTheDocument();
    });
    expect(within(diagCard).getByText(/v3/i)).toBeInTheDocument();

    firstRender.unmount();

    // Now render as viewer and verify read-only RBAC + dark-mode WCAG 2.2 AA
    role = "viewer";
    const viewerRender = renderAgentsApp({ fetchImpl, themeMode: "dark" });
    expect(await screen.findByTestId("agents-readonly-banner")).toHaveTextContent(/Read-only mode/i);
    const viewerDiagCard = screen.getByTestId("agent-profile-card-triage_diagnosis");
    expect(
      within(viewerDiagCard).getByLabelText(/Reasoning effort \(triage_diagnosis\)/i),
    ).toBeDisabled();
    expect(
      within(viewerDiagCard).queryByRole("button", { name: /Save Triage & Diagnosis Agent/i }),
    ).not.toBeInTheDocument();

    const axeDark = await axe.run(viewerRender.container);
    expect(axeDark.violations).toEqual([]);
  });
});
