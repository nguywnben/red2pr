import type { ReportExportReceipt, WorkspaceAnalyticsResponse } from "@red2pr/ts-client";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AnalyticsPage } from "../AnalyticsPage";
import { OverviewPage } from "../../overview/OverviewPage";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";

const WORKSPACE = {
  id: "0196ef00-0000-7000-8000-000000000301",
  version: 1,
  created_at: "2026-10-30T00:00:00Z",
  updated_at: "2026-10-30T00:00:00Z",
  name: "U24 workspace",
  slug: "u24",
  status: "active",
  paused: false,
} as const;

const ME = {} as never;
const NativeRequest = globalThis.Request;
const NativeURL = globalThis.URL;
const ANALYTICS: WorkspaceAnalyticsResponse = {
  workspace_id: WORKSPACE.id,
  range_start: "2026-10-01T00:00:00Z",
  range_end: "2026-10-30T23:59:59Z",
  repository_count: 2,
  funnel: [
    { key: "ingested", value: 5, numerator: null, denominator: null },
    { key: "eligible", value: 4, numerator: 4, denominator: 5 },
    { key: "executed", value: 3, numerator: 3, denominator: 4 },
    { key: "reproduced", value: 2, numerator: 2, denominator: 3 },
    { key: "locally_verified", value: 1, numerator: 1, denominator: 2 },
    { key: "publication_eligible", value: 1, numerator: 1, denominator: 1 },
    { key: "published_observed", value: 1, numerator: 1, denominator: 1 },
    { key: "remotely_verified", value: 0, numerator: 0, denominator: 1 },
  ],
  local_success_count: 1,
  remote_success_count: 0,
  unknown_count: 2,
  pending_count: 1,
  abstained_count: 1,
  costs: [
    {
      currency: "USD",
      settled: "1.250000",
      estimated_unsettled: "0.500000",
      total: "1.750000",
      unknown_rows: 1,
      usage_rows: 4,
    },
  ],
  watermark: "2026-10-30T10:00:00Z",
};

function renderAnalytics(fetchImpl: typeof fetch) {
  const queryClient = createWorkspaceQueryClient();
  return { ...render(
    <I18nProvider>
      <ThemeProvider defaultMode="light">
        <ApiClientProvider
          queryClient={queryClient}
          clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchImpl, getCsrfToken: () => "csrf-test" }}
        >
          <AnalyticsPage workspace={WORKSPACE} me={ME} />
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  ), queryClient };
}

function renderOverview(fetchImpl: typeof fetch) {
  return render(
    <I18nProvider>
      <ThemeProvider defaultMode="light">
        <ApiClientProvider
          queryClient={createWorkspaceQueryClient()}
          clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchImpl, getCsrfToken: () => "csrf-test" }}
        >
          <MemoryRouter>
            <OverviewPage workspace={WORKSPACE} me={ME} />
          </MemoryRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
}

function testFetch(): { fetch: typeof fetch; calls: Request[] } {
  const calls: Request[] = [];
  const fetch: typeof globalThis.fetch = async (input) => {
    const request = input instanceof Request ? input : new Request(input);
    calls.push(request);
    const url = new URL(request.url);
    if (url.pathname.endsWith("/analytics")) {
      return Response.json(ANALYTICS, { headers: { "X-Correlation-Id": "u24-corr" } });
    }
    if (url.pathname.endsWith("/exports") && request.method === "POST") {
      const receipt: ReportExportReceipt = {
        export_id: "0196ef00-0000-7000-8000-000000004201",
        kind: "funnel",
        format: "csv",
        digest: "a".repeat(64),
        size_bytes: 12,
        expires_at: "2026-10-31T10:00:00Z",
        download_path: "/api/v1/workspaces/u24/exports/0196ef00-0000-7000-8000-000000004201/download",
        reused: false,
      };
      return Response.json(receipt, { status: 201, headers: { "X-Correlation-Id": "u24-export" } });
    }
    if (url.pathname.endsWith("/download")) {
      return new Response('"stage","value"\r\n"ingested","5"\r\n', {
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="report.csv"',
        },
      });
    }
    return Response.json({ detail: "unexpected request" }, { status: 404 });
  };
  return { fetch, calls };
}

describe("U24 analytics UI", () => {
  beforeEach(() => {
    // Vitest combines Node's Request with jsdom's AbortSignal. The browser uses a single realm.
    vi.stubGlobal("Request", class extends NativeRequest {
      constructor(input: RequestInfo | URL, init?: RequestInit) {
        const { signal: _crossRealmSignal, ...safeInit } = init ?? {};
        super(input, safeInit);
      }
    });
    vi.stubGlobal("URL", Object.assign(class extends NativeURL {}, { createObjectURL: vi.fn(() => "blob:u24-export") }));
  });
  afterEach(() => vi.unstubAllGlobals());

  it("renders the authorized workspace overview and analytics link accessibly", async () => {
    const { fetch } = testFetch();
    const { container } = renderOverview(fetch);
    expect(await screen.findByRole("heading", { name: "Workspace overview" })).toBeTruthy();
    expect(await screen.findByText(/2 currently authorized repositories/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open analytics and exports" }).getAttribute("href")).toBe("/w/u24/analytics");
    expect((await axe.run(container)).violations).toEqual([]);
  });

  it("renders the denominator table and cost totals, exports with idempotency, and is accessible", async () => {
    const user = userEvent.setup();
    const { fetch, calls } = testFetch();
    const { container } = renderAnalytics(fetch);

    expect(await screen.findByRole("table", { name: "Repair funnel values and denominators" })).toBeTruthy();
    expect(screen.getByText("1.750000")).toBeTruthy();
    expect(screen.getByText("Local success").parentElement?.textContent).toContain("1");
    expect(screen.getByText("Remote success").parentElement?.textContent).toContain("0");
    expect((await axe.run(container)).violations).toEqual([]);

    await user.click(screen.getByRole("button", { name: "Create and download export" }));
    expect(await screen.findByRole("link", { name: "Download report.csv" })).toBeTruthy();
    const post = calls.find((request) => request.method === "POST");
    expect(calls.some((request) => new URL(request.url).pathname.endsWith("/download"))).toBe(true);
    expect(post?.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
    expect(post?.headers.get("X-CSRF-Token")).toBeTruthy();
  });

  it("marks an inverted date range and disables export", async () => {
    const { fetch } = testFetch();
    renderAnalytics(fetch);
    await screen.findByRole("table", { name: "Repair funnel values and denominators" });
    const dates = screen.getAllByLabelText(/date \(UTC\)/i);
    fireEvent.change(dates[0]!, { target: { value: "2026-10-30" } });
    fireEvent.change(dates[1]!, { target: { value: "2026-10-01" } });
    expect(screen.getByRole("alert").textContent).toContain("end date must be on or after");
    expect(screen.getByRole("button", { name: "Create and download export" })).toBeDisabled();
  });
});
