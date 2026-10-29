import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import type { MeResponse, Workspace } from "@red2pr/ts-client";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";
import { ApprovalsInboxPage } from "../ApprovalsInboxPage";

const NOW = "2026-10-29T09:00:00Z";
const WS_ID = "0196f000-0000-7000-8000-000000000301";
const APPROVAL_ID = "0196f000-0000-7000-8000-000000000501";
const REPAIR_ID = "0196f000-0000-7000-8000-000000000201";
const REPO_ID = "0196f000-0000-7000-8000-000000000601";
const workspace = { id: WS_ID, slug: "acme", name: "Acme", status: "active", paused: false, version: 1, created_at: NOW, updated_at: NOW } as Workspace;
const me = { mfa_enabled: true, memberships: [{ workspace_id: WS_ID, role: "reviewer" }] } as unknown as MeResponse;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr-u19-approval" } });
}

describe("U19 approval inbox", () => {
  it("shows the full patch binding and requires a recent step-up before recording a vote", async () => {
    const user = userEvent.setup();
    const decisionCalls: { readonly idempotencyKey: string | null; readonly body: unknown }[] = [];
    let decisionCount = 0;
    let decided = false;
    const approval = { id: APPROVAL_ID, workspace_id: WS_ID, repository_id: REPO_ID, repair_id: REPAIR_ID, intent_type: "publish_draft_pr", patch_digest: "a".repeat(64), base_sha: "b".repeat(40), target_ref: "refs/heads/main", policy_revision: 3, expires_at: "2026-10-30T09:00:00Z", status: "pending", decision_actor: null, version: 1, created_at: NOW, updated_at: NOW };
    const fetchImpl: typeof fetch = async (input, init) => {
      const request = input instanceof Request ? input : null;
      const url = new URL(request?.url ?? String(input));
      const method = init?.method ?? request?.method ?? "GET";
      if (url.pathname === "/api/v1/workspaces/acme/approvals" && method === "GET") {
        return json({ items: decided ? [] : [{ approval, requested_by: "0196f000-0000-7000-8000-000000000701", risk_level: "review", scope_description: "Review verified patch attempt 1", sensitive_change: false, decision: null, reason: null }], next_cursor: null, snapshot_at: NOW });
      }
      if (url.pathname.endsWith(`/approvals/${APPROVAL_ID}/decisions`) && method === "POST") {
        const body = request ? await request.json() : null;
        decisionCalls.push({ idempotencyKey: request?.headers.get("Idempotency-Key") ?? null, body });
        decisionCount += 1;
        if (decisionCount === 1) return json({ type: "about:blank", title: "Forbidden", status: 403, code: "step_up_required", detail: "Recent MFA required", correlation_id: "corr-u19-approval" }, 403);
        decided = true;
        return json({ ...approval, status: "approved", decision_actor: "0196f000-0000-7000-8000-000000000701", version: 2, updated_at: NOW });
      }
      if (url.pathname === "/api/v1/auth/step-up" && method === "POST") return json({ csrf_token: "csrf-after-step-up", session: { id: "session-u19", user_id: "0196f000-0000-7000-8000-000000000701", auth_strength: "mfa", step_up_at: NOW, created_at: NOW, updated_at: NOW, expires_at: "2026-10-30T09:00:00Z", grant_epoch: 1, version: 2 }, step_up_expires_at: "2026-10-29T09:05:00Z" });
      return json({ detail: `Unexpected request ${url.pathname}` }, 404);
    };
    const queryClient = createWorkspaceQueryClient();
    const view = render(<I18nProvider><ThemeProvider defaultMode="light"><ApiClientProvider queryClient={queryClient} clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchImpl }}><MemoryRouter><ApprovalsInboxPage workspace={workspace} me={me} /></MemoryRouter></ApiClientProvider></ThemeProvider></I18nProvider>);

    expect(await screen.findByText("Review verified patch attempt 1")).toBeTruthy();
    expect(screen.getByText("b".repeat(40))).toBeTruthy();
    expect(screen.getByText("a".repeat(64))).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Approve" }));
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByRole("heading", { name: /Confirm privileged step-up/ })).toBeTruthy();
    const accessibility = await axe.run(view.container);
    expect(accessibility.violations).toEqual([]);
    await user.type(screen.getByLabelText("Current password"), "correct-horse-battery-staple");
    await user.type(screen.getByLabelText("Current 6-digit authenticator code"), "123456");
    await user.click(screen.getByRole("button", { name: "Verify step-up" }));
    await waitFor(() => expect(decisionCount).toBe(2));
    expect(decisionCalls[0]?.idempotencyKey).toBeTruthy();
    expect(decisionCalls[1]?.idempotencyKey).toBe(decisionCalls[0]?.idempotencyKey);
    expect(decisionCalls[1]?.body).toEqual({ decision: "approve", reason: null, expected_patch_digest: "a".repeat(64), expected_policy_revision: 3 });
  });
});
