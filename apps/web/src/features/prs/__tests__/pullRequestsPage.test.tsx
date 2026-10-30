import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import type { MeResponse, Workspace } from "@red2pr/ts-client";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";
import { PullRequestsPage } from "../PullRequestsPage";

const NOW = "2026-10-30T09:00:00Z";
const WS_ID = "0196f000-0000-7000-8000-000000000301";
const PUBLICATION_ID = "0196f000-0000-7000-8000-000000000801";
const REPAIR_ID = "0196f000-0000-7000-8000-000000000201";
const REPO_ID = "0196f000-0000-7000-8000-000000000601";
const workspace = { id: WS_ID, slug: "acme", name: "Acme", status: "active", paused: false, version: 1, created_at: NOW, updated_at: NOW } as Workspace;
const me = { memberships: [{ workspace_id: WS_ID, role: "reviewer" }] } as unknown as MeResponse;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr-u20-prs" } });
}

describe("U20 draft publications screen", () => {
  it("shows exact-head remote evidence and allows a CSRF-protected reconciliation request", async () => {
    const user = userEvent.setup();
    const calls: { method: string; path: string; idempotency: string | null; body: unknown }[] = [];
    const publication = { id: PUBLICATION_ID, version: 1, workspace_id: WS_ID, repository_id: REPO_ID, repair_id: REPAIR_ID, intent_id: "0196f000-0000-7000-8000-000000000901", branch: "red2pr/repair/abcd", expected_commit_sha: "a".repeat(40), provider_object_id: "pr-123", url: "https://github.com/acme/project/pull/123", status: "published", created_at: NOW, updated_at: NOW };
    const remote_check = { id: "0196f000-0000-7000-8000-000000000902", version: 1, workspace_id: WS_ID, repository_id: REPO_ID, publication_id: PUBLICATION_ID, head_sha: "a".repeat(40), expected_check_set_digest: "b".repeat(64), required_check_names: ["tests", "lint", "security"], observations: [{ check_name: "tests", external_id: "check-1", head_sha: "a".repeat(40), status: "completed", conclusion: "success", observed_at: NOW }, { check_name: "lint", external_id: "check-2", head_sha: "c".repeat(40), status: "completed", conclusion: "success", observed_at: NOW }], outcome: "pending", created_at: NOW, updated_at: NOW };
    const fetchImpl: typeof fetch = async (input, init) => {
      const request = input instanceof Request ? input : null;
      const url = new URL(request?.url ?? String(input));
      const method = init?.method ?? request?.method ?? "GET";
      const body = request && method === "POST" ? await request.json() : null;
      calls.push({ method, path: url.pathname, idempotency: request?.headers.get("Idempotency-Key") ?? null, body });
      if (url.pathname.endsWith("/publications") && method === "GET") return json({ items: [publication], next_cursor: null, snapshot_at: NOW });
      if (url.pathname.endsWith(`/publications/${PUBLICATION_ID}`) && method === "GET") return json({ publication, remote_check });
      if (url.pathname.endsWith(`/publications/${PUBLICATION_ID}/reconciliations`) && method === "POST") return json({ publication, remote_check });
      return json({ detail: `Unexpected request ${url.pathname}` }, 404);
    };
    const view = render(<I18nProvider><ThemeProvider defaultMode="light"><ApiClientProvider queryClient={createWorkspaceQueryClient()} clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchImpl }}><MemoryRouter><PullRequestsPage workspace={workspace} me={me} /></MemoryRouter></ApiClientProvider></ThemeProvider></I18nProvider>);

    await user.click(await screen.findByRole("button", { name: /published/ }));
    const requiredChecks = await screen.findByRole("list", { name: "Required remote checks" });
    expect(within(requiredChecks).getByText("tests")).toBeTruthy();
    expect(requiredChecks.textContent).toContain("passed on exact SHA");
    expect(requiredChecks.textContent).toContain("wrong SHA");
    expect(requiredChecks.textContent).toContain("missing");
    expect(screen.getByText("a".repeat(40))).toBeTruthy();
    await user.type(screen.getByLabelText("Refresh reason"), "Check exact pushed SHA");
    await user.click(screen.getByRole("button", { name: "Reconcile remote CI" }));
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true));
    const request = calls.find((call) => call.method === "POST");
    expect(request?.idempotency).toBeTruthy();
    expect(request?.body).toEqual({ reason: "Check exact pushed SHA" });
    expect(await axe.run(view.container)).toMatchObject({ violations: [] });
  });
});
