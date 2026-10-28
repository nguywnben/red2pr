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

const OWNER_USER_ID = "0196ed14-0000-7000-8000-000000000101";
const SESSION_ID = "0196ed14-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ed14-0000-7000-8000-000000000301";
const MEM_ID = "0196ed14-0000-7000-8000-000000000401";
const REPO_ID = "0196ed14-0000-7000-8000-000000000501";
const WORKER_VM_ID = "0196ed14-0000-7000-8000-000000000601";
const WORKER_TL_ID = "0196ed14-0000-7000-8000-000000000602";
const LEASE_ID = "0196ed14-0000-7000-8000-000000000701";
const JOB_ID = "0196ed14-0000-7000-8000-000000000702";
const ENROLL_ID = "0196ed14-0000-7000-8000-000000000801";
const OP_ACTION_ID = "0196ed14-0000-7000-8000-000000000901";
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
    "X-Correlation-Id": init.correlationId ?? "corr-u14-web-01",
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
  const cid = params.correlationId ?? "corr-u14-err-01";
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

function renderWorkersApp(opts: {
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
          <MemoryRouter initialEntries={[opts.initialEntry ?? "/w/acme/workers"]}>
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

function buildMePayload(opts: {
  isInstanceOwner: boolean;
  role?: "admin" | "maintainer" | "viewer";
}): Record<string, unknown> {
  return {
    user: {
      id: OWNER_USER_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      display_name: opts.isInstanceOwner ? "Instance Owner" : "Workspace Member",
      email: "owner@red2pr.local",
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
    is_instance_owner: opts.isInstanceOwner,
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
        role: opts.role ?? "admin",
        repository_grants: [REPO_ID],
      },
    ],
    telegram_link: { status: "not_configured" },
    csrf_token: "csrf-u14-token",
  };
}

function buildReadinessPayload(opts: { trustedLocalWarning?: boolean } = {}): Record<string, unknown> {
  return {
    workspace_id: WS_ACME_ID,
    ready: true,
    eligible_online_workers: 2,
    available_profiles: ["python-3.12-node-22"],
    vm_isolation_available: true,
    trusted_local_warning: opts.trustedLocalWarning ?? true,
    degraded_reason: null,
    snapshot_at: NOW_ISO,
    active_workspace_leases: [
      {
        id: LEASE_ID,
        job_id: JOB_ID,
        repository_id: REPO_ID,
        repair_id: "0196ed14-0000-7000-8000-000000000999",
        profile_id: "python-3.12-node-22",
        lease_epoch: 2,
        status: "running",
        issued_at: NOW_ISO,
        lease_expires_at: "2026-10-28T12:01:00Z",
      },
    ],
  };
}

function buildFleetPayload(): Record<string, unknown> {
  return {
    items: [
      {
        id: WORKER_VM_ID,
        version: 3,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        trust_domain: "worker-supervisor",
        profile_ids: ["python-3.12-node-22"],
        capabilities: {
          network_none: true,
          seccomp: true,
          no_new_privileges: true,
          rootless: true,
        },
        heartbeat_at: NOW_ISO,
        status: "online",
        host_id: "vm-node-01.internal",
        isolation_mode: "vm_isolated",
        runtime_name: "firecracker\u202E\u001b[31m-clean",
        cpu_limit: 4,
        memory_limit_bytes: 8589934592,
        disk_limit_bytes: 21474836480,
        pids_limit: 512,
        signer_key_id: "ed25519-vm-01",
        mtls_cert_fingerprint_sha256: "a".repeat(64),
        mtls_cert_expires_at: EXPIRES_ISO,
        quarantine_reason: null,
        drain_reason: null,
        active_leases: 1,
        host_escape_warning: false,
      },
      {
        id: WORKER_TL_ID,
        version: 2,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        trust_domain: "worker-supervisor",
        profile_ids: ["python-3.12-node-22"],
        capabilities: { network_none: true, seccomp: true },
        heartbeat_at: NOW_ISO,
        status: "quarantined",
        host_id: "docker-local-01",
        isolation_mode: "oci_trusted_local",
        runtime_name: "docker",
        cpu_limit: 2,
        memory_limit_bytes: 4294967296,
        disk_limit_bytes: 10737418240,
        pids_limit: 256,
        signer_key_id: "ed25519-tl-01",
        mtls_cert_fingerprint_sha256: "b".repeat(64),
        mtls_cert_expires_at: EXPIRES_ISO,
        quarantine_reason: "conflicting_duplicate_result\u202E",
        drain_reason: null,
        active_leases: 0,
        host_escape_warning: true,
      },
    ],
    next_cursor: null,
    snapshot_at: NOW_ISO,
    summary: {
      total_count: 2,
      online_count: 1,
      draining_count: 0,
      quarantined_count: 1,
      offline_count: 0,
      vm_isolated_count: 1,
      trusted_local_warning_count: 1,
      active_leases_count: 1,
    },
  };
}

describe("UI-S13 Workers & Sandbox Fleet flows (U14)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("renders workspace readiness & leases for non-owner members without calling /api/v1/system/workers*", async () => {
    const calledUrls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const req = input instanceof Request ? input : new Request(input);
      const parsed = new URL(req.url);
      calledUrls.push(parsed.pathname);
      if (parsed.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload({ isInstanceOwner: false, role: "viewer" }));
      }
      if (parsed.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (parsed.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (parsed.pathname === "/api/v1/workspaces/acme/workers/readiness") {
        return jsonResponse(buildReadinessPayload({ trustedLocalWarning: true }));
      }
      return problemResponse({
        status: 404,
        code: "not_found",
        title: "Not Found",
        detail: `Unexpected URL ${parsed.pathname}`,
      });
    });

    const { container } = renderWorkersApp({ fetchImpl: fetchMock as typeof fetch });

    expect(await screen.findByTestId("workers-page")).toBeInTheDocument();
    expect(screen.getByTestId("workers-owner-boundary-notice")).toBeInTheDocument();
    expect(screen.getByTestId("workers-trusted-local-warning")).toBeInTheDocument();
    expect(screen.queryByTestId("workers-enroll-open")).not.toBeInTheDocument();
    expect(screen.getByText(JOB_ID)).toBeInTheDocument();

    // Non-owner MUST NOT request /api/v1/system/workers* (ADR-034):
    expect(calledUrls.some((u) => u.includes("/api/v1/system/workers"))).toBe(false);
    assertZeroWebStorageSecrets();

    const axeResults = await axe.run(container);
    expect(axeResults.violations).toEqual([]);
  }, 30000);

  it("supports instance-owner enrollment (ADR-016 + step-up retry), self-test, drain/412 conflict, SEC-040 sanitization & WCAG AA", async () => {
    const user = userEvent.setup({ delay: null });
    let stepUpDone = false;
    let actionAttempts = 0;
    const capturedActionHeaders: Record<string, string>[] = [];

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const req = input instanceof Request ? input : new Request(input, init);
      const parsed = new URL(req.url);
      const method = (init?.method ?? req.method ?? "GET").toUpperCase();

      if (parsed.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload({ isInstanceOwner: true, role: "admin" }));
      }
      if (parsed.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (parsed.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (parsed.pathname === "/api/v1/workspaces/acme/workers/readiness") {
        return jsonResponse(buildReadinessPayload());
      }
      if (parsed.pathname === "/api/v1/system/workers" && method === "GET") {
        return jsonResponse(buildFleetPayload());
      }
      if (parsed.pathname === "/api/v1/auth/step-up" && method === "POST") {
        stepUpDone = true;
        return jsonResponse({
          step_up_valid_until: EXPIRES_ISO,
          csrf_token: "csrf-u14-stepped-up",
        });
      }
      if (parsed.pathname === "/api/v1/system/workers/enrollments" && method === "POST") {
        if (!stepUpDone) {
          return problemResponse({
            status: 403,
            code: "step_up_required",
            title: "Step-up required",
            detail: "Fresh 5-minute step-up verification is required.",
          });
        }
        return jsonResponse(
          {
            enrollment_id: ENROLL_ID,
            enrollment_token: "r2pw_enroll_OneTimeTokenSecretValue1234567890",
            trust_domain: "worker-supervisor",
            profile_ids: ["python-3.12-node-22"],
            isolation_mode: "oci_trusted_local",
            expires_at: EXPIRES_ISO,
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIBWjCCAUCgAwIBAgIU\n-----END CERTIFICATE-----\n",
          },
          { status: 201 },
        );
      }
      if (parsed.pathname === `/api/v1/system/workers/${WORKER_VM_ID}/self-test` && method === "POST") {
        return jsonResponse({
          worker_id: WORKER_VM_ID,
          passed: true,
          isolation_mode: "vm_isolated",
          checked_at: NOW_ISO,
          detail: "All mTLS, external Ed25519 signer, and sandbox isolation checks passed.",
          checks: [
            {
              check_id: "mtls_certificate_active",
              passed: true,
              detail: "TLS 1.3 SPIFFE cert active",
            },
            {
              check_id: "external_ed25519_signer_active",
              passed: true,
              detail: "key_id=ed25519-vm-01 (ADR-035)",
            },
          ],
        });
      }
      if (parsed.pathname === `/api/v1/system/workers/${WORKER_VM_ID}/actions` && method === "POST") {
        actionAttempts += 1;
        const hdrs = new Headers(init?.headers ?? req.headers);
        capturedActionHeaders.push({
          idem: hdrs.get("Idempotency-Key") ?? "",
          ifMatch: hdrs.get("If-Match") ?? "",
        });
        if (actionAttempts === 1) {
          return problemResponse({
            status: 412,
            code: "version_precondition_failed",
            title: "Precondition Failed",
            detail: "Worker version changed concurrently.",
          });
        }
        return jsonResponse(
          {
            operation_id: OP_ACTION_ID,
            resource_id: WORKER_VM_ID,
            state: "succeeded",
            correlation_id: "corr-u14-act-01",
            status_url: `/api/v1/operations/${OP_ACTION_ID}`,
            result_id: WORKER_VM_ID,
            problem: null,
          },
          { status: 202 },
        );
      }
      return problemResponse({
        status: 404,
        code: "not_found",
        title: "Not Found",
        detail: `Unhandled ${method} ${parsed.pathname}`,
      });
    });

    const { container } = renderWorkersApp({
      fetchImpl: fetchMock as typeof fetch,
      themeMode: "dark",
    });

    expect(await screen.findByTestId("workers-page")).toBeInTheDocument();
    expect(
      screen.getByText(`spiffe://worker-supervisor/ns/sandbox/worker/${WORKER_VM_ID}`),
    ).toBeInTheDocument();

    // SEC-040: Bidi override U+202E and ANSI escape \u001b[31m MUST be stripped from rendered DOM!
    expect(container.textContent).not.toContain("\u202E");
    expect(container.textContent).not.toContain("\u001b");

    // 1) Self-test modal:
    const selfTestBtns = screen.getAllByRole("button", { name: "Self-test" });
    await user.click(selfTestBtns[0]!);
    const stDialog = await screen.findByTestId("workers-selftest-dialog");
    expect(await within(stDialog).findByText("All Self-Test Checks Passed")).toBeInTheDocument();
    await user.click(within(stDialog).getAllByRole("button", { name: "Close" })[0]!);

    // 2) Enrollment modal: ADR-016 checkbox disables submit until checked + step-up retry:
    await user.click(screen.getByTestId("workers-enroll-open"));
    const enrollDialog = await screen.findByTestId("workers-enroll-dialog");
    const backendSelect = within(enrollDialog).getByLabelText("Sandbox Isolation Backend");
    await user.selectOptions(backendSelect, "oci_trusted_local");

    const mintBtn = within(enrollDialog).getByRole("button", { name: "Mint enrollment token" });
    expect(mintBtn).toBeDisabled();

    const ackCheckbox = within(enrollDialog).getByRole("checkbox");
    await user.click(ackCheckbox);
    expect(mintBtn).toBeEnabled();

    // Triggers 403 step_up_required -> opens StepUpDialog -> verifies password -> retries & shows token!
    await user.click(mintBtn);
    const pwdInput = await screen.findByLabelText(/password/i);
    await user.type(pwdInput, "OwnerSup3rStr0ng!Pass#14");
    const verifyBtns = screen.getAllByRole("button", { name: /verify|confirm/i });
    await user.click(verifyBtns[verifyBtns.length - 1]!);

    const tokenBox = await screen.findByTestId("workers-enrolled-token-box");
    expect(within(tokenBox).getByText(/r2pw_enroll_OneTimeTokenSecretValue/)).toBeInTheDocument();
    assertZeroWebStorageSecrets();
    await user.click(within(enrollDialog).getAllByRole("button", { name: "Close" })[0]!);

    // 3) Drain action modal -> first attempt hits 412 stale conflict banner -> Reload fleet -> retry succeeds!
    await user.click(screen.getByRole("button", { name: "Drain" }));
    const actDialog = await screen.findByTestId("workers-action-dialog");
    await user.type(within(actDialog).getByLabelText("Audit Reason"), "Scheduled kernel upgrade");
    await user.click(within(actDialog).getByRole("button", { name: "Confirm drain" }));

    expect(await screen.findByTestId("workers-stale-conflict-banner")).toBeInTheDocument();
    expect(capturedActionHeaders[0]?.ifMatch).toBe('"v3"');
    expect((capturedActionHeaders[0]?.idem ?? "").length).toBeGreaterThanOrEqual(36);

    await user.click(within(actDialog).getByRole("button", { name: "Reload fleet" }));
    await waitFor(() => {
      expect(screen.queryByTestId("workers-action-dialog")).not.toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "Drain" }));
    const actDialog2 = await screen.findByTestId("workers-action-dialog");
    await user.type(within(actDialog2).getByLabelText("Audit Reason"), "Retry after fleet reload");
    await user.click(within(actDialog2).getByRole("button", { name: "Confirm drain" }));
    await waitFor(() => {
      expect(screen.queryByTestId("workers-action-dialog")).not.toBeInTheDocument();
    });

    const axeDark = await axe.run(container);
    expect(axeDark.violations).toEqual([]);
  }, 30000);
});
