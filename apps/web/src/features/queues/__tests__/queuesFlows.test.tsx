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
import { generateClientUuidV7 } from "../QueuesPage";

const ADMIN_USER_ID = "0196ed08-0000-7000-8000-000000000101";
const SESSION_ID = "0196ed08-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ed08-0000-7000-8000-000000000301";
const MEM_ID = "0196ed08-0000-7000-8000-000000000401";
const REPO_ID = "0196ed08-0000-7000-8000-000000000501";
const WORKER_1_ID = "0196ed08-0000-7000-8000-000000000601";
const WORKER_2_ID = "0196ed08-0000-7000-8000-000000000602";
const JOB_RUNNING_ID = "0196ed08-0000-7000-8000-000000000701";
const JOB_DLQ_ID = "0196ed08-0000-7000-8000-000000000702";
const JOB_AMBIGUOUS_ID = "0196ed08-0000-7000-8000-000000000703";
const JOB_PAGE2_ID = "0196ed08-0000-7000-8000-000000000704";
const OP_CANCEL_ID = "0196ed08-0000-7000-8000-000000000801";
const OP_REQUEUE_ID = "0196ed08-0000-7000-8000-000000000802";
const OP_RECONCILE_ID = "0196ed08-0000-7000-8000-000000000803";
const NOW_ISO = "2026-10-27T13:00:00Z";
const EXPIRES_ISO = "2026-10-28T01:00:00Z";

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
    "X-Correlation-Id": init.correlationId ?? "corr-u08-web-01",
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
  const cid = params.correlationId ?? "corr-u08-err-01";
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

function renderQueuesApp(opts: {
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
          <MemoryRouter initialEntries={[opts.initialEntry ?? "/w/acme/queues"]}>
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

function buildWorkspace(paused = false): Record<string, unknown> {
  return {
    id: WS_ACME_ID,
    version: 1,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    name: "Acme Platform",
    slug: "acme",
    status: "active",
    paused,
  };
}

function buildMePayload(role: "admin" | "maintainer" | "viewer", paused = false): Record<string, unknown> {
  return {
    user: {
      id: ADMIN_USER_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      display_name: "Queue Operator",
      email: "operator@red2pr.local",
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
    workspaces: [buildWorkspace(paused)],
    memberships: [
      {
        id: MEM_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        user_id: ADMIN_USER_ID,
        role,
        repository_grants: [REPO_ID],
      },
    ],
    telegram_link: { status: "not_configured" },
    csrf_token: "csrf-u08-token",
  };
}

function buildSampleJobs(opts: { ambiguousReconciled?: boolean } = {}): Record<string, unknown>[] {
  const reconciled = opts.ambiguousReconciled ?? false;
  return [
    {
      id: JOB_RUNNING_ID,
      workspace_id: WS_ACME_ID,
      repository_id: REPO_ID,
      repair_id: "0196ed08-0000-7000-8000-000000000901",
      version: 2,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      kind: "repair.reproduce",
      resource_id: "0196ed08-0000-7000-8000-000000000901",
      state: "running",
      lease_epoch: 2,
      attempt: 2,
      max_attempts: 3,
      priority: 100,
      not_before: NOW_ISO,
      deadline: EXPIRES_ISO,
      logical_effect_key: "eff:reproduce:901",
      budget_key: "budget:session:901",
      correlation_id: "corr-job-run-01",
      leased_by_worker_id: WORKER_2_ID,
      heartbeat_at: NOW_ISO,
      lease_expires_at: "2026-10-27T13:01:00Z",
      recoverable: true,
      reconcile_required: false,
    },
    {
      id: JOB_DLQ_ID,
      workspace_id: WS_ACME_ID,
      repository_id: REPO_ID,
      repair_id: "0196ed08-0000-7000-8000-000000000902",
      version: 4,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      kind: "repair.verify",
      resource_id: "0196ed08-0000-7000-8000-000000000902",
      state: "dead_letter",
      lease_epoch: 3,
      attempt: 3,
      max_attempts: 3,
      priority: 50,
      not_before: NOW_ISO,
      deadline: EXPIRES_ISO,
      logical_effect_key: "eff:verify:preserve-77",
      budget_key: "budget:preserve-77",
      correlation_id: "corr-job-dlq-77",
      last_error_code: "runner_transient_io",
      last_error_detail: "Exhausted max_attempts=3.",
      recoverable: true,
      reconcile_required: false,
    },
    {
      id: JOB_AMBIGUOUS_ID,
      workspace_id: WS_ACME_ID,
      repository_id: REPO_ID,
      repair_id: "0196ed08-0000-7000-8000-000000000903",
      version: reconciled ? 6 : 5,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      kind: "publish.draft_pr",
      resource_id: "0196ed08-0000-7000-8000-000000000903",
      state: "dead_letter",
      lease_epoch: 1,
      attempt: 1,
      max_attempts: 2,
      priority: 10,
      not_before: NOW_ISO,
      deadline: EXPIRES_ISO,
      logical_effect_key: "eff:draft_pr:amb-88",
      budget_key: "budget:amb-88",
      correlation_id: "corr-job-amb-88",
      last_error_code: "provider_timeout_post_write",
      last_error_detail: "Timeout after POST /pulls.",
      recoverable: true,
      reconcile_required: !reconciled,
    },
  ];
}

describe("UI-S14 /w/:ws/queues Durable Task Queue & DLQ Screen (U08)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("generates valid RFC 9562 UUIDv7 idempotency keys", () => {
    const key = generateClientUuidV7(1_761_570_000_000);
    expect(key).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it(
    "renders fairness cap summary, filters & signed cursor pagination, and inspects attempt + DLQ history",
    async () => {
      const user = userEvent.setup({ delay: null });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const req = input instanceof Request ? input : new Request(input);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("admin"));
      }
      if (url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace(false));
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/task-jobs") {
        const cursor = url.searchParams.get("cursor");
        const stateParam = url.searchParams.get("state");
        const allItems = buildSampleJobs();
        const filtered = stateParam
          ? allItems.filter((item) => item.state === stateParam)
          : cursor === "cur_page_2"
            ? [
                {
                  ...allItems[0],
                  id: JOB_PAGE2_ID,
                  kind: "webhook.ingest",
                  correlation_id: "corr-page-2",
                },
              ]
            : allItems;
        return jsonResponse({
          items: filtered,
          next_cursor: cursor || stateParam ? null : "cur_page_2",
          snapshot_at: NOW_ISO,
          summary: {
            max_running_repairs: 2,
            active_running_repairs: 2,
            queued_count: 14,
            leased_count: 1,
            running_count: 1,
            cancel_requested_count: 0,
            dead_letter_count: 2,
            workspace_paused: false,
            backpressure_active: true,
            transport_status: "healthy",
            transport_detail: null,
          },
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/task-jobs/${JOB_DLQ_ID}`) {
        return jsonResponse(
          {
            ...buildSampleJobs()[1],
            attempts_history: [
              {
                id: "0196ed08-0000-7000-8000-000000000952",
                job_id: JOB_DLQ_ID,
                attempt_number: 2,
                lease_epoch: 2,
                worker_id: WORKER_2_ID,
                state: "failed",
                started_at: NOW_ISO,
                heartbeat_at: NOW_ISO,
                lease_expires_at: EXPIRES_ISO,
                ended_at: NOW_ISO,
                error_code: "runner_transient_io",
                error_detail: "Exhausted max_attempts=3.",
              },
              {
                id: "0196ed08-0000-7000-8000-000000000951",
                job_id: JOB_DLQ_ID,
                attempt_number: 1,
                lease_epoch: 1,
                worker_id: WORKER_1_ID,
                state: "orphaned",
                started_at: NOW_ISO,
                heartbeat_at: NOW_ISO,
                lease_expires_at: EXPIRES_ISO,
                ended_at: NOW_ISO,
                error_code: "lease_expired",
                error_detail: "Worker missed 15s heartbeat past 60s TTL.",
              },
            ],
            dead_letter_entry: {
              id: "0196ed08-0000-7000-8000-000000000961",
              workspace_id: WS_ACME_ID,
              repository_id: REPO_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              original_job_id: JOB_DLQ_ID,
              kind: "repair.verify",
              resource_id: "0196ed08-0000-7000-8000-000000000902",
              logical_effect_key: "eff:verify:preserve-77",
              budget_key: "budget:preserve-77",
              error_code: "runner_transient_io",
              error_detail: "Exhausted max_attempts=3.",
              attempts: 3,
              recoverable: true,
              reconcile_required: false,
              status: "open",
            },
          },
          { extraHeaders: { ETag: '"v4"' } },
        );
      }
      return problemResponse({
        status: 404,
        code: "not_found",
        title: "Not found",
        detail: `Unhandled URL ${url.pathname}`,
      });
    });

    const { container } = renderQueuesApp({ fetchImpl: fetchMock as typeof fetch });

    expect(
      await screen.findByRole("heading", { name: "Durable Task Queue & Leases" }),
    ).toBeInTheDocument();

    expect(screen.getByTestId("queues-cap-metric")).toHaveTextContent("2 / 2");
    expect(screen.getByTestId("queues-backpressure-banner")).toBeInTheDocument();
    expect(screen.getByText("corr-job-run-01")).toBeInTheDocument();
    expect(screen.getByText("corr-job-dlq-77")).toBeInTheDocument();

    // WCAG 2.2 AA check (light theme)
    const axeLight = await axe.run(container);
    expect(axeLight.violations).toEqual([]);

    // Cursor pagination: Next page -> Previous page
    await user.click(screen.getByRole("button", { name: "Next page" }));
    expect(await screen.findByText("corr-page-2")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Previous page" }));
    expect(await screen.findByText("corr-job-dlq-77")).toBeInTheDocument();

    // Filter by state = dead_letter
    await user.selectOptions(screen.getByLabelText("Filter by state"), "dead_letter");
    await waitFor(() => {
      expect(screen.queryByText("corr-job-run-01")).not.toBeInTheDocument();
    });
    expect(screen.getByText("corr-job-dlq-77")).toBeInTheDocument();

    // Open Inspect dialog on JOB_DLQ_ID and verify attempt history + DLQ ledger
    const inspectButtons = screen.getAllByRole("button", { name: "Inspect" });
    await user.click(inspectButtons[0]!);

    const dialog = await screen.findByTestId("queue-inspect-dialog");
    expect(await within(dialog).findByText("eff:verify:preserve-77")).toBeInTheDocument();
    expect(within(dialog).getByText("budget:preserve-77")).toBeInTheDocument();
    expect(within(dialog).getByTestId("queue-inspect-dlq-box")).toHaveTextContent(
      "Dead-Letter Entry (open)",
    );
    expect(
      within(dialog).getByText(/Attempt #1 · Lease Epoch 1 \(orphaned\)/),
    ).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Close detail" }));
    assertZeroWebStorageSecrets();
  }, 25_000);

  it(
    "enforces W-08 reconcile before requeue, previews preserved effect & budget keys, cancels with A-24 receipt refresh, and surfaces 409 conflicts",
    async () => {
      const user = userEvent.setup({ delay: null });
    let ambiguousReconciled = false;
    let cancelPolled = false;
    const recordedActions: Array<{
      jobId: string;
      idempotencyKey: string | null;
      ifMatch: string | null;
      body: Record<string, unknown>;
    }> = [];

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const req = input instanceof Request ? input : new Request(input);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("maintainer"));
      }
      if (url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace(false));
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/task-jobs") {
        return jsonResponse({
          items: buildSampleJobs({ ambiguousReconciled }),
          next_cursor: null,
          snapshot_at: NOW_ISO,
          summary: {
            max_running_repairs: 2,
            active_running_repairs: 1,
            queued_count: 0,
            leased_count: 0,
            running_count: 1,
            cancel_requested_count: 0,
            dead_letter_count: 2,
            workspace_paused: false,
            backpressure_active: false,
            transport_status: "healthy",
            transport_detail: null,
          },
        });
      }
      if (url.pathname.endsWith("/actions") && req.method === "POST") {
        const segments = url.pathname.split("/");
        const jobId = segments[segments.length - 2] ?? "";
        const body = (await req.json()) as Record<string, unknown>;
        recordedActions.push({
          jobId,
          idempotencyKey: req.headers.get("Idempotency-Key"),
          ifMatch: req.headers.get("If-Match"),
          body,
        });

        if (body.reason === "trigger-conflict") {
          return problemResponse({
            status: 409,
            code: "stale_version",
            title: "Version conflict",
            detail: "Task job version changed concurrently.",
            correlationId: "corr-conflict-409",
          });
        }

        if (body.action === "cancel") {
          return jsonResponse(
            {
              operation_id: OP_CANCEL_ID,
              resource_id: jobId,
              state: "running",
              correlation_id: "corr-cancel-202",
              status_url: `/api/v1/operations/${OP_CANCEL_ID}`,
            },
            { status: 202 },
          );
        }
        if (body.action === "reconcile") {
          ambiguousReconciled = true;
          return jsonResponse(
            {
              operation_id: OP_RECONCILE_ID,
              resource_id: jobId,
              state: "succeeded",
              correlation_id: "corr-reconcile-202",
              status_url: `/api/v1/operations/${OP_RECONCILE_ID}`,
              result_id: jobId,
            },
            { status: 202 },
          );
        }
        return jsonResponse(
          {
            operation_id: OP_REQUEUE_ID,
            resource_id: jobId,
            state: "succeeded",
            correlation_id: "corr-requeue-202",
            status_url: `/api/v1/operations/${OP_REQUEUE_ID}`,
            result_id: jobId,
          },
          { status: 202 },
        );
      }
      if (url.pathname === `/api/v1/operations/${OP_CANCEL_ID}`) {
        cancelPolled = true;
        return jsonResponse({
          operation_id: OP_CANCEL_ID,
          resource_id: JOB_RUNNING_ID,
          state: "succeeded",
          correlation_id: "corr-cancel-202",
          status_url: `/api/v1/operations/${OP_CANCEL_ID}`,
          result_id: JOB_RUNNING_ID,
        });
      }
      return problemResponse({
        status: 404,
        code: "not_found",
        title: "Not found",
        detail: url.pathname,
      });
    });

    renderQueuesApp({ fetchImpl: fetchMock as typeof fetch });
    expect(await screen.findByText("corr-job-amb-88")).toBeInTheDocument();

    // 1. Ambiguous job (JOB_AMBIGUOUS_ID) has disabled Requeue button until reconciled!
    const requeueButtonsBefore = screen.getAllByRole("button", { name: "Requeue" });
    expect(requeueButtonsBefore).toHaveLength(2);
    expect(requeueButtonsBefore[0]).not.toBeDisabled(); // JOB_DLQ_ID
    expect(requeueButtonsBefore[1]).toBeDisabled(); // JOB_AMBIGUOUS_ID (reconcile_required=true)

    // 2. Scoped DLQ Requeue Preview on JOB_DLQ_ID shows preserved logical_effect_key & budget_key
    await user.click(requeueButtonsBefore[0]!);
    const requeueDialog = await screen.findByTestId("queue-requeue-dialog");
    const scopeBox = within(requeueDialog).getByTestId("queue-requeue-scope-preview");
    expect(scopeBox).toHaveTextContent("eff:verify:preserve-77");
    expect(scopeBox).toHaveTextContent("budget:preserve-77");
    expect(scopeBox).toHaveTextContent("v4");

    // Trigger 409 conflict first and verify correlation ID surfaces inside dialog
    const reasonField = within(requeueDialog).getByLabelText("Audited operator reason");
    await user.type(reasonField, "trigger-conflict");
    await user.click(within(requeueDialog).getByRole("button", { name: "Confirm scoped requeue" }));
    expect(await within(requeueDialog).findByText(/corr-conflict-409/)).toBeInTheDocument();

    // Submit valid scoped requeue
    await user.clear(reasonField);
    await user.type(reasonField, "Transient runner outage mitigated.");
    await user.click(within(requeueDialog).getByRole("button", { name: "Confirm scoped requeue" }));
    await waitFor(() => {
      expect(screen.queryByTestId("queue-requeue-dialog")).not.toBeInTheDocument();
    });

    // 3. Reconcile JOB_AMBIGUOUS_ID as confirmed_absent -> unlocks its Requeue button!
    const reconcileButtons = screen.getAllByRole("button", { name: "Reconcile" });
    await user.click(reconcileButtons[1]!);
    const reconcileDialog = await screen.findByTestId("queue-reconcile-dialog");
    await user.selectOptions(
      within(reconcileDialog).getByLabelText("Verified upstream outcome"),
      "confirmed_absent",
    );
    await user.type(
      within(reconcileDialog).getByLabelText("Audited operator reason"),
      "Verified GitHub pulls API: no draft PR created.",
    );
    await user.click(
      within(reconcileDialog).getByRole("button", { name: "Submit reconciliation" }),
    );
    await waitFor(() => {
      expect(screen.queryByTestId("queue-reconcile-dialog")).not.toBeInTheDocument();
    });

    await waitFor(() => {
      const updatedRequeueBtns = screen.getAllByRole("button", { name: "Requeue" });
      expect(updatedRequeueBtns[1]).not.toBeDisabled();
    });

    // 4. Cancel running job and refresh A-24 operation receipt status (running -> succeeded)
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    const cancelDialog = await screen.findByTestId("queue-cancel-dialog");
    await user.type(
      within(cancelDialog).getByLabelText("Audited operator reason"),
      "Stop superseded repair run.",
    );
    await user.click(within(cancelDialog).getByRole("button", { name: "Confirm cancel" }));

    const receiptBanner = await screen.findByTestId("queues-latest-receipt");
    expect(receiptBanner).toHaveTextContent("Operation Receipt (running)");
    await user.click(within(receiptBanner).getByRole("button", { name: "Refresh receipt status" }));
    await waitFor(() => {
      expect(cancelPolled).toBe(true);
      expect(screen.getByTestId("queues-latest-receipt")).toHaveTextContent(
        "Operation Receipt (succeeded)",
      );
    });

    // Verify every action carried a valid RFC 9562 UUIDv7 Idempotency-Key and If-Match
    expect(recordedActions.length).toBe(4);
    for (const call of recordedActions) {
      expect(call.idempotencyKey).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
      expect(call.ifMatch).toMatch(/^"v\d+"$/);
    }
  }, 25_000);

  it(
    "renders degraded Redis banner, paused workspace banner, read-only viewer role gating, and passes dark-mode WCAG 2.2 AA",
    async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const req = input instanceof Request ? input : new Request(input);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("viewer", true));
      }
      if (url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace(true));
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/task-jobs") {
        return jsonResponse({
          items: buildSampleJobs(),
          next_cursor: null,
          snapshot_at: NOW_ISO,
          summary: {
            max_running_repairs: 2,
            active_running_repairs: 0,
            queued_count: 5,
            leased_count: 0,
            running_count: 1,
            cancel_requested_count: 0,
            dead_letter_count: 2,
            workspace_paused: true,
            backpressure_active: true,
            transport_status: "degraded",
            transport_detail: "Connection refused on redis://127.0.0.1:6379.",
          },
        });
      }
      return problemResponse({
        status: 404,
        code: "not_found",
        title: "Not found",
        detail: url.pathname,
      });
    });

    const { container } = renderQueuesApp({
      fetchImpl: fetchMock as typeof fetch,
      themeMode: "dark",
    });

    expect(await screen.findByTestId("queues-degraded-transport-banner")).toHaveTextContent(
      "Connection refused on redis://127.0.0.1:6379.",
    );
    expect(screen.getByTestId("queues-workspace-paused-banner")).toBeInTheDocument();
    expect(screen.getByTestId("queues-readonly-role-badge")).toHaveTextContent(
      "Read-only (viewer)",
    );

    // Viewer role sees Inspect buttons, NEVER Cancel / Requeue / Reconcile operator controls
    expect(screen.getAllByRole("button", { name: "Inspect" }).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Requeue" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reconcile" })).not.toBeInTheDocument();

    const axeDark = await axe.run(container);
    expect(axeDark.violations).toEqual([]);
  }, 25_000);
});
