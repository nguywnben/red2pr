import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it } from "vitest";
import type { MeResponse, Workspace } from "@red2pr/ts-client";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";
import { RepairDetailPage } from "../RepairDetailPage";

const NOW = "2026-10-29T09:00:00Z";
const WS_ID = "0196f000-0000-7000-8000-000000000301";
const REPAIR_ID = "0196f000-0000-7000-8000-000000000201";
const RUN_ID = "0196f000-0000-7000-8000-000000000101";
const JOB_ID = "0196f000-0000-7000-8000-000000000701";
const workspace = { id: WS_ID, slug: "acme", name: "Acme", status: "active", paused: false, version: 1, created_at: NOW, updated_at: NOW } as Workspace;
const me = { mfa_enabled: false, memberships: [{ workspace_id: WS_ID, role: "viewer" }] } as unknown as MeResponse;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr-u19-detail" } });
}

describe("U19 repair evidence viewer", () => {
  it("shows all seven evidence tabs, persisted Sandbox A/B data and redacted CI log chunks", async () => {
    const user = userEvent.setup();
    const requestedPaths: string[] = [];
    const repair = { id: REPAIR_ID, workspace_id: WS_ID, repository_id: "0196f000-0000-7000-8000-000000000601", run_id: RUN_ID, state: "policy_gate", proof_grade: "locally_verified", remote_status: "not_published", policy_revision: 3, base_sha: "b".repeat(40), target_ref: "refs/heads/main", parent_id: null, suspension: null, budget_id: "0196f000-0000-7000-8000-000000000801", version: 1, created_at: NOW, updated_at: NOW };
    const fetchImpl: typeof fetch = async (input) => {
      const request = input instanceof Request ? input : null;
      const url = new URL(request?.url ?? String(input));
      requestedPaths.push(`${request?.method ?? "GET"} ${url.pathname}`);
      if (url.pathname === `/api/v1/workspaces/acme/repairs/${REPAIR_ID}`) return json(repair);
      if (url.pathname.endsWith("/diagnosis")) return json({ items: [{ id: "diag-1", class: "code_regression", decision: "continue", summary: "A deterministic test failed", uncertainties: ["A fixture may be incomplete"] }], next_cursor: null, snapshot_at: NOW });
      if (url.pathname.endsWith("/patches")) return json({ items: [{ id: "patch-1", attempt: 1, base_sha: "b".repeat(40), patch_digest: "a".repeat(64), changed_paths: ["src/calc.py"], diff_artifact_id: null }], next_cursor: null, snapshot_at: NOW });
      if (url.pathname.endsWith("/verification")) return json({ items: [{ id: "verify-1", status: "verified", proof_grade: "locally_verified", patch_digest: "a".repeat(64), gates: [{ id: "V-01", outcome: "passed" }] }], reproductions: [{ id: "repro-1", phase: "baseline_a", status: "repro_confirmed", base_sha: "b".repeat(40), patch_digest: null, fidelity_grade: "F1_TARGETED", executed_tests_count: 10, passed_tests_count: 9, failed_tests_count: 1, skipped_tests_count: 0, exit_code: 1, failure_reason_code: null }], next_cursor: null, snapshot_at: NOW });
      if (url.pathname.endsWith("/timeline")) return json({ items: [{ id: "event-1", at: NOW, source: "audit", type: "repair.session.created", reason_code: "manual" }], next_cursor: null, snapshot_at: NOW });
      if (url.pathname === `/api/v1/workspaces/acme/runs/${RUN_ID}/jobs`) return json({ run_id: RUN_ID, items: [{ id: JOB_ID, workspace_id: WS_ID, repository_id: "0196f000-0000-7000-8000-000000000601", run_id: RUN_ID, external_id: "job-external-1", name: "pytest", status: "completed", conclusion: "failure", created_at: NOW, updated_at: NOW, version: 1, flaky_classification: "unknown", is_child_pipeline_job: false, log_size_bytes: 22, log_status: "available", log_truncated: false }] });
      if (url.pathname === `/api/v1/workspaces/acme/jobs/${JOB_ID}/log`) return json({ job_id: JOB_ID, run_id: RUN_ID, log_status: "available", content: "[redacted] test output", start_offset: 0, next_offset: 22, returned_bytes: 22, total_bytes: 22, has_more: false, truncated: false, log_complete: true, redaction_version: "redaction-v1", incomplete_marker: null });
      return json({ detail: `Unexpected request ${url.pathname}` }, 404);
    };
    const queryClient = createWorkspaceQueryClient();
    const view = render(<I18nProvider><ThemeProvider defaultMode="light"><ApiClientProvider queryClient={queryClient} clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchImpl }}><MemoryRouter initialEntries={[`/w/acme/repairs/${REPAIR_ID}`]}><Routes><Route path="/w/:ws/repairs/:repairId" element={<RepairDetailPage workspace={workspace} me={me} />} /></Routes></MemoryRouter></ApiClientProvider></ThemeProvider></I18nProvider>);

    expect((await screen.findAllByRole("tab")).length).toBe(7);
    expect(screen.getByTestId("repair-detail-page").getAttribute("data-run-id")).toBe(RUN_ID);
    await user.click(screen.getByRole("tab", { name: "Repro" }));
    expect(await screen.findByText(/baseline_a · repro_confirmed/)).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "Verification" }));
    expect(await screen.findByText(/V-01: passed/)).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "Logs" }));
    await waitFor(() => expect(requestedPaths, requestedPaths.join(" | ")).toContain(`GET /api/v1/workspaces/acme/runs/${RUN_ID}/jobs`));
    expect(await screen.findByRole("combobox", { name: "CI job" })).toBeTruthy();
    await user.selectOptions(screen.getByRole("combobox", { name: "CI job" }), JOB_ID);
    await waitFor(() => expect(requestedPaths, `${requestedPaths.join(" | ")} PANEL=${screen.getByRole("tabpanel").textContent}`).toContain(`GET /api/v1/workspaces/acme/jobs/${JOB_ID}/log`));
    expect(await screen.findByText("[redacted] test output")).toBeTruthy();
    expect(screen.getByText(/redaction redaction-v1/)).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "Audit" }));
    expect(await screen.findByText(/repair.session.created/)).toBeTruthy();
    const accessibility = await axe.run(view.container);
    expect(accessibility.violations).toEqual([]);
  });
});
