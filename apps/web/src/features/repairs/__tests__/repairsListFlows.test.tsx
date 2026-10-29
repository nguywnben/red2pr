import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it } from "vitest";
import type { MeResponse, Workspace } from "@red2pr/ts-client";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";
import { RepairsListPage } from "../RepairsListPage";

const NOW = "2026-10-29T09:00:00Z";
const RUN_ID = "0196f000-0000-7000-8000-000000000101";
const REPAIR_ID = "0196f000-0000-7000-8000-000000000201";
const WS_ID = "0196f000-0000-7000-8000-000000000301";

const workspace = { id: WS_ID, slug: "acme", name: "Acme", status: "active", paused: false, version: 1, created_at: NOW, updated_at: NOW } as Workspace;
const me = { mfa_enabled: true, memberships: [{ workspace_id: WS_ID, role: "maintainer" }] } as unknown as MeResponse;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr-u19-test" } });
}

describe("U19 repairs list UX", () => {
  it("starts an idempotent repair from a failed CI run and is keyboard accessible", async () => {
    const user = userEvent.setup();
    let createdBody: unknown;
    let idempotencyKey: string | null = null;
    const fetchImpl: typeof fetch = async (input, init) => {
      const request = input instanceof Request ? input : null;
      const url = new URL(request?.url ?? String(input));
      const method = init?.method ?? request?.method ?? "GET";
      if (url.pathname === "/api/v1/workspaces/acme/runs") {
        return json({ items: [{ id: RUN_ID, head_sha: "a".repeat(40), conclusion: "failure" }], next_cursor: null, snapshot_at: NOW });
      }
      if (url.pathname === "/api/v1/workspaces/acme/repairs" && method === "GET") {
        return json({ items: [], next_cursor: null, snapshot_at: NOW });
      }
      if (url.pathname === "/api/v1/workspaces/acme/repairs" && method === "POST") {
        createdBody = JSON.parse(request ? await request.clone().text() : String(init?.body));
        idempotencyKey = new Headers(init?.headers ?? request?.headers).get("Idempotency-Key");
        return json({ operation_id: "0196f000-0000-7000-8000-000000000401", resource_id: REPAIR_ID, state: "accepted", correlation_id: "corr-u19-test", status_url: `/api/v1/workspaces/acme/repairs/${REPAIR_ID}` }, 202);
      }
      return json({ detail: `Unexpected request ${url.pathname}` }, 404);
    };
    const queryClient = createWorkspaceQueryClient();
    const view = render(<I18nProvider><ThemeProvider defaultMode="light"><ApiClientProvider queryClient={queryClient} clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchImpl }}><MemoryRouter initialEntries={["/w/acme/repairs"]}><Routes><Route path="/w/acme/repairs" element={<RepairsListPage workspace={workspace} me={me} />} /><Route path="/w/acme/repairs/:repairId" element={<p>Repair detail opened</p>} /></Routes></MemoryRouter></ApiClientProvider></ThemeProvider></I18nProvider>);

    await screen.findByRole("option", { name: /Run 0196f000/ });
    await user.selectOptions(screen.getByLabelText("Failed CI run"), RUN_ID);
    await user.selectOptions(screen.getByLabelText("Repair mode"), "approval");
    await user.type(screen.getByLabelText("Reason"), "Investigate failing CI check");
    await user.click(screen.getByRole("button", { name: "Start repair" }));
    await screen.findByText("Repair detail opened");
    expect(createdBody).toEqual({ run_id: RUN_ID, mode: "approval", reason: "Investigate failing CI check" });
    expect(idempotencyKey).toMatch(/^[0-9a-f-]{36}$/i);
    const accessibility = await axe.run(view.container);
    expect(accessibility.violations).toEqual([]);
  });
});
