import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { AppRoutes } from "../../../app/App";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";

const ADMIN_USER_ID = "0196ef00-0000-7000-8000-000000000101";
const SESSION_ID = "0196ef00-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ef00-0000-7000-8000-000000000301";
const MEM_ID = "0196ef00-0000-7000-8000-000000000401";
const GH_CONN_ID = "0196ef00-0000-7000-8000-000000000501";
const REPO_PAYMENTS_ID = "0196ef00-0000-7000-8000-000000000601";
const RUN_ATTEMPT_1_ID = "0196ef00-0000-7000-8000-000000000701";
const RUN_ATTEMPT_2_ID = "0196ef00-0000-7000-8000-000000000702";
const JOB_MATRIX_FAIL_ID = "0196ef00-0000-7000-8000-000000000801";
const JOB_EXPIRED_LOG_ID = "0196ef00-0000-7000-8000-000000000802";
const ART_JUNIT_ID = "0196ef00-0000-7000-8000-000000000901";
const ART_EXPIRED_ID = "0196ef00-0000-7000-8000-000000000902";
const FP_UNPROVEN_ID = "0196ef00-0000-7000-8000-000000001001";
const NOW_ISO = "2026-10-28T11:00:00Z";
const EXPIRES_ISO = "2026-10-28T23:00:00Z";

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
    "X-Correlation-Id": init.correlationId ?? "corr-u13-web-01",
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

function renderPipelinesApp(opts: {
  initialEntry: string;
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
          <MemoryRouter initialEntries={[opts.initialEntry]}>
            <AppRoutes />
          </MemoryRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
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

function buildMePayload(): Record<string, unknown> {
  const ws = buildWorkspace();
  return {
    user: {
      id: ADMIN_USER_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      display_name: "Pipeline Triage Operator",
      email: "triage@red2pr.local",
      status: "active",
      grant_epoch: 1,
      is_instance_owner: true,
    },
    session: {
      id: SESSION_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      user_id: ADMIN_USER_ID,
      expires_at: EXPIRES_ISO,
      last_seen_at: NOW_ISO,
      ip_prefix: "127.0.0.0/8",
      user_agent_hash: "a".repeat(64),
      mfa_verified_at: NOW_ISO,
    },
    workspaces: [ws],
    memberships: [
      {
        id: MEM_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        user_id: ADMIN_USER_ID,
        role: "admin",
        repository_grants: [],
      },
    ],
    mfa_enrolled: true,
    csrf_token: "csrf-u13-web",
  };
}

function buildRunFixtures() {
  const run1 = {
    id: RUN_ATTEMPT_1_ID,
    workspace_id: WS_ACME_ID,
    repository_id: REPO_PAYMENTS_ID,
    version: 1,
    created_at: "2026-10-28T10:50:00Z",
    updated_at: "2026-10-28T10:52:00Z",
    external_id: "990042",
    attempt_key: "attempt:1",
    attempt_number: 1,
    provider: "github",
    repository_name: "acme/payments-service",
    head_sha: "deadbeef".repeat(5),
    head_sha_verified: true,
    ref: "refs/heads/main",
    event_type: "push",
    status: "completed",
    conclusion: "failure",
    jobs_complete: true,
    ingestion_state: "incomplete",
    incomplete_reason: "One matrix job log expired upstream (HTTP 410).",
    failed_job_count: 2,
    total_job_count: 2,
    artifact_count: 2,
    flaky_classification: "single_pass_unproven",
    child_pipeline_ids: ["child-pipe-88"],
  };
  const run2 = {
    ...run1,
    id: RUN_ATTEMPT_2_ID,
    attempt_key: "attempt:2",
    attempt_number: 2,
    conclusion: "success",
    ingestion_state: "ingested",
    incomplete_reason: null,
    head_sha_verified: false,
    flaky_classification: "flaky",
  };
  return { run1, run2 };
}

describe("U13 Pipelines Screen UI-S06 (TRI-01, TRI-03, A-08, A-10, SEC-016, SEC-040)", () => {
  it("renders runs, switches attempts, handles 410 log_expired, downloads S-14 artifacts, and passes WCAG 2.2 AA", async () => {
    const user = userEvent.setup();
    const { run1, run2 } = buildRunFixtures();

    const fetchMock: typeof fetch = async (input) => {
      const req = input instanceof Request ? input : new Request(String(input));
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload());
      }
      if (url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/repositories") {
        return jsonResponse({
          items: [
            {
              id: REPO_PAYMENTS_ID,
              workspace_id: WS_ACME_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              external_id: "7001",
              connection_id: GH_CONN_ID,
              name: "acme/payments-service",
              default_branch: "main",
              visibility: "private",
              mode: "monitor",
              paused: false,
              policy_revision: 1,
              tags: ["tier-1"],
              archived: false,
              is_fork: false,
            },
          ],
          next_cursor: null,
          snapshot_at: NOW_ISO,
          facets: { tags: ["tier-1"], organizations: ["acme"], partial_sync_connection_ids: [] },
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme/runs") {
        const flakyOnly = url.searchParams.get("flaky_only") === "true";
        return jsonResponse({
          items: flakyOnly ? [run2] : [run1, run2],
          next_cursor: null,
          snapshot_at: NOW_ISO,
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/runs/${RUN_ATTEMPT_1_ID}`) {
        return jsonResponse({
          run: run1,
          sibling_attempts: [run1, run2],
          jobs: [
            {
              id: JOB_MATRIX_FAIL_ID,
              workspace_id: WS_ACME_ID,
              repository_id: REPO_PAYMENTS_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              run_id: RUN_ATTEMPT_1_ID,
              external_id: "501",
              name: "pytest (py312, linux)",
              status: "completed",
              conclusion: "failure",
              matrix_dimensions: { python: "3.12", os: "linux" },
              retry_of_id: "499",
              is_child_pipeline_job: true,
              log_status: "available",
              log_size_bytes: 512,
              log_truncated: true,
              flaky_classification: "single_pass_unproven",
            },
            {
              id: JOB_EXPIRED_LOG_ID,
              workspace_id: WS_ACME_ID,
              repository_id: REPO_PAYMENTS_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              run_id: RUN_ATTEMPT_1_ID,
              external_id: "502",
              name: "integration-e2e (expired)",
              status: "completed",
              conclusion: "failure",
              matrix_dimensions: { suite: "e2e" },
              log_status: "available",
              log_size_bytes: 0,
              log_truncated: false,
              flaky_classification: "unknown",
            },
          ],
          artifacts: [
            {
              id: ART_JUNIT_ID,
              workspace_id: WS_ACME_ID,
              repository_id: REPO_PAYMENTS_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              kind: "junit_xml",
              name: "junit-report.zip",
              run_id: RUN_ATTEMPT_1_ID,
              mime: "application/zip",
              size_bytes: 4,
              digest: "c".repeat(64),
              redaction_version: 1,
              access_class: "workspace_internal",
              retention_until: EXPIRES_ISO,
              available: true,
            },
            {
              id: ART_EXPIRED_ID,
              workspace_id: WS_ACME_ID,
              repository_id: REPO_PAYMENTS_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              kind: "coverage",
              name: "expired-cov.zip",
              run_id: RUN_ATTEMPT_1_ID,
              mime: "application/zip",
              size_bytes: 16,
              digest: "d".repeat(64),
              redaction_version: 1,
              access_class: "restricted",
              retention_until: "2026-10-01T00:00:00Z",
              available: false,
              purge_reason: "retention_expired",
            },
          ],
          fingerprints: [
            {
              id: FP_UNPROVEN_ID,
              workspace_id: WS_ACME_ID,
              repository_id: REPO_PAYMENTS_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              fingerprint_hash: "e".repeat(64),
              signature_label: "FAILED tests/test_ledger.py::test_settle - AssertionError",
              test_identifier: "tests/test_ledger.py::test_settle",
              error_kind: "AssertionError",
              classification: "single_pass_unproven",
              confidence_reason:
                "Observed 1 failure and 1 same-SHA green rerun; >=2 failures required for flaky.",
              failure_count: 1,
              pass_on_same_sha_count: 1,
              distinct_sha_count: 1,
              first_seen_at: NOW_ISO,
              last_seen_at: NOW_ISO,
              recent_observations: [],
            },
          ],
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/runs/${RUN_ATTEMPT_2_ID}`) {
        return jsonResponse({
          run: run2,
          sibling_attempts: [run1, run2],
          jobs: [],
          artifacts: [],
          fingerprints: [],
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/jobs/${JOB_MATRIX_FAIL_ID}/log`) {
        return jsonResponse({
          job_id: JOB_MATRIX_FAIL_ID,
          run_id: RUN_ATTEMPT_1_ID,
          log_status: "available",
          content:
            "\u001b[31mFAILED tests/test_ledger.py::test_settle\u001b[0m\n\u202eBIDI_SPOOF_TOKEN=[REDACTED]\nAssertionError: expected 200 got 500",
          start_offset: 0,
          next_offset: 98,
          returned_bytes: 98,
          total_bytes: 98,
          has_more: false,
          truncated: true,
          log_complete: false,
          redaction_version: 1,
          incomplete_marker: "upstream_log_truncated_at_cap",
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/jobs/${JOB_EXPIRED_LOG_ID}/log`) {
        return jsonResponse(
          {
            type: "https://red2pr.local/problems/log_expired",
            title: "Gone",
            status: 410,
            code: "log_expired",
            detail: "Upstream CI job log has expired and cannot be retrieved.",
            correlation_id: "corr-u13-410-log",
          },
          { status: 410, contentType: "application/problem+json" },
        );
      }
      if (url.pathname === `/api/v1/workspaces/acme/artifacts/${ART_JUNIT_ID}/download`) {
        return new Response(new Uint8Array([0x50, 0x4b, 0x03, 0x04]), {
          status: 200,
          headers: {
            "Content-Type": "application/zip",
            "Content-Disposition": 'attachment; filename="junit-report.zip"',
            "X-Correlation-Id": "corr-u13-dl-ok",
          },
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/artifacts/${ART_EXPIRED_ID}/download`) {
        return jsonResponse(
          {
            type: "https://red2pr.local/problems/artifact_expired",
            title: "Gone",
            status: 410,
            code: "artifact_expired",
            detail: "Artifact retention window has expired.",
            correlation_id: "corr-u13-dl-410",
          },
          { status: 410, contentType: "application/problem+json" },
        );
      }
      return jsonResponse({ detail: `Unhandled ${url.pathname}` }, { status: 404 });
    };

    const { container, unmount } = renderPipelinesApp({
      initialEntry: "/w/acme/failures",
      fetchImpl: fetchMock,
      themeMode: "light",
    });

    // Redirects /w/acme/failures -> /w/acme/pipelines and loads runs + attempt:1 detail
    expect(await screen.findByRole("heading", { name: "CI Runs, Logs & Artifacts" })).toBeTruthy();
    expect(await screen.findByText(/Single green rerun after 1 failure is unproven/i)).toBeTruthy();
    expect(screen.getByText(/Matrix: python=3.12, os=linux/i)).toBeTruthy();
    expect(screen.getByText(/child-pipe-88/i)).toBeTruthy();

    // ANSI & bidi sequences stripped in SafeLogViewer (SEC-040) + truncated notice shown
    expect(await screen.findByText(/Truncated log/i)).toBeTruthy();
    expect(
      (await screen.findAllByText(/FAILED tests\/test_ledger\.py::test_settle/)).length,
    ).toBeGreaterThanOrEqual(2);
    expect(container.textContent?.includes("\u202e")).toBe(false);
    expect(container.textContent?.includes("\u001b")).toBe(false);

    // WCAG 2.2 AA axe-core audit in light theme
    const lightAxe = await axe.run(container);
    expect(lightAxe.violations).toEqual([]);

    // Switch to expired-log matrix job -> surfaces HTTP 410 log_expired StateView (never passing)
    await user.click(screen.getByRole("button", { name: /integration-e2e \(expired\)/i }));
    expect(await screen.findByText(/CI job log expired \(HTTP 410\)/i)).toBeTruthy();

    // Download valid artifact -> shows verified download status + live-region announcement
    await user.click(screen.getByRole("button", { name: "Download junit-report.zip" }));
    expect(
      (await screen.findAllByText(/Downloaded verified artifact junit-report\.zip/i)).length,
    ).toBeGreaterThanOrEqual(1);

    // Attempt expired artifact download -> surfaces 410 artifact_expired alert cleanly
    await user.click(screen.getByRole("button", { name: "Download expired-cov.zip" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/artifact_expired/i);

    // Switch sibling attempt:2 -> surfaces SEC-016 SHA mismatch danger alert
    const attemptGroup = screen.getByRole("group", { name: "Rerun attempt selector" });
    await user.click(within(attemptGroup).getByRole("button", { name: /attempt:2/i }));
    expect(await screen.findByText(/SEC-016 Stale\/mismatched SHA blocked/i)).toBeTruthy();

    unmount();

    // Dark theme WCAG 2.2 AA audit
    const darkRender = renderPipelinesApp({
      initialEntry: "/w/acme/pipelines",
      fetchImpl: fetchMock,
      themeMode: "dark",
    });
    expect(
      await darkRender.findByRole("heading", { name: "CI Runs, Logs & Artifacts" }),
    ).toBeTruthy();
    expect(await darkRender.findByText(/Truncated log/i)).toBeTruthy();
    const darkAxe = await axe.run(darkRender.container);
    expect(darkAxe.violations).toEqual([]);
    darkRender.unmount();
  }, 20000);

  it("virtualizes a 50,000-line CI job log smoothly without rendering 50k DOM nodes (UI-S06)", async () => {
    const { run1 } = buildRunFixtures();
    const fiftyThousandLines = Array.from(
      { length: 50_000 },
      (_, idx) => `2026-10-28T11:00:00Z [step] line ${String(idx + 1)} status=ok`,
    ).join("\n");

    const fetchMock: typeof fetch = async (input) => {
      const req = input instanceof Request ? input : new Request(String(input));
      const url = new URL(req.url);
      if (url.pathname === "/api/v1/me") return jsonResponse(buildMePayload());
      if (url.pathname === "/api/v1/workspaces/acme") return jsonResponse(buildWorkspace());
      if (url.pathname === "/api/v1/workspaces/acme/events") return sseIdleConnectedResponse();
      if (url.pathname === "/api/v1/workspaces/acme/repositories") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO, facets: {} });
      }
      if (url.pathname === "/api/v1/workspaces/acme/runs") {
        return jsonResponse({ items: [run1], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === `/api/v1/workspaces/acme/runs/${RUN_ATTEMPT_1_ID}`) {
        return jsonResponse({
          run: run1,
          sibling_attempts: [run1],
          jobs: [
            {
              id: JOB_MATRIX_FAIL_ID,
              workspace_id: WS_ACME_ID,
              repository_id: REPO_PAYMENTS_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              run_id: RUN_ATTEMPT_1_ID,
              external_id: "501",
              name: "massive-50k-job",
              status: "completed",
              conclusion: "failure",
              log_status: "available",
              log_size_bytes: fiftyThousandLines.length,
              log_truncated: false,
              flaky_classification: "persistent_failure",
            },
          ],
          artifacts: [],
          fingerprints: [],
        });
      }
      if (url.pathname === `/api/v1/workspaces/acme/jobs/${JOB_MATRIX_FAIL_ID}/log`) {
        return jsonResponse({
          job_id: JOB_MATRIX_FAIL_ID,
          run_id: RUN_ATTEMPT_1_ID,
          log_status: "available",
          content: fiftyThousandLines,
          start_offset: 0,
          next_offset: fiftyThousandLines.length,
          returned_bytes: 65536,
          total_bytes: fiftyThousandLines.length,
          has_more: true,
          truncated: false,
          log_complete: true,
          redaction_version: 1,
        });
      }
      return jsonResponse({ detail: "Not found" }, { status: 404 });
    };

    const { container, unmount } = renderPipelinesApp({
      initialEntry: "/w/acme/pipelines",
      fetchImpl: fetchMock,
    });

    await waitFor(() => {
      expect(screen.getByText(/Showing lines .* of 50000/i)).toBeTruthy();
    });

    // Virtualizer renders only visible viewport + overscan rows (< 60), never 50,000 DOM rows!
    expect(screen.getByText(/line 1 status=ok/)).toBeTruthy();
    expect(screen.queryByText(/line 49999 status=ok/)).toBeNull();
    const renderedLogRows = container.querySelectorAll("[data-log-line]");
    expect(renderedLogRows.length).toBeGreaterThan(0);
    expect(renderedLogRows.length).toBeLessThan(60);

    unmount();
  }, 20000);
});
