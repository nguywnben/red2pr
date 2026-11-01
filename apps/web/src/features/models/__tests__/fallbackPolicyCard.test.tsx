import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { describe, expect, it } from "vitest";
import type { ConsentRecord } from "@red2pr/ts-client";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { FallbackPolicyCard } from "../FallbackPolicyCard";

const WORKSPACE_ID = "0196f100-0000-7000-8000-000000000301";
const REPOSITORY_ID = "0196f100-0000-7000-8000-000000000401";
const CONSENT_ID = "0196f100-0000-7000-8000-000000000501";
const PRIMARY_PROFILE_ID = "0196f100-0000-7000-8000-000000000801";
const SECONDARY_PROFILE_ID = "0196f100-0000-7000-8000-000000000802";

const workspace = {
  id: WORKSPACE_ID,
  version: 1,
  created_at: "2026-11-01T10:00:00Z",
  updated_at: "2026-11-01T10:00:00Z",
  name: "Fallback Workspace",
  slug: "fallback-workspace",
  status: "active",
  paused: false,
} as const;

const me = {
  user: { id: "0196f100-0000-7000-8000-000000000101" },
  memberships: [{ workspace_id: WORKSPACE_ID, role: "admin" }],
  mfa_enabled: true,
} as never;

const repo = {
  id: REPOSITORY_ID,
  name: "billing-api",
  organization: "acme",
  connection_id: "0196f100-0000-7000-8000-000000000601",
  external_id: "repo-27",
  default_branch: "main",
  active: true,
  archived: false,
  auto_repair_blocked: false,
  grant_review_required: false,
  is_fork: false,
  mode: "monitor",
  paused: false,
  policy_revision: 1,
  visibility: "private",
  created_at: "2026-11-01T10:00:00Z",
  updated_at: "2026-11-01T10:00:00Z",
} as const;

const consent: ConsentRecord = {
  id: CONSENT_ID,
  version: 1,
  created_at: "2026-11-01T10:00:00Z",
  updated_at: "2026-11-01T10:00:00Z",
  purpose: "inference",
  scope: "repository",
  workspace_id: WORKSPACE_ID,
  repository_id: REPOSITORY_ID,
  destination: "https://api.meta.ai/v1",
  data_classes: ["restricted"],
  granted_by_user_id: "0196f100-0000-7000-8000-000000000101",
  policy_revision: 1,
  status: "active",
  revoked_at: null,
  revoke_reason: null,
} as const;

function renderCard(fetchImpl: typeof fetch, consents: readonly (typeof consent)[]) {
  return render(
    <I18nProvider>
      <ApiClientProvider
        queryClient={createWorkspaceQueryClient()}
        clientOptions={{ baseUrl: "https://red2pr.invalid", fetch: fetchImpl }}
      >
        <FallbackPolicyCard workspace={workspace} me={me} consents={consents} isAdmin />
      </ApiClientProvider>
    </I18nProvider>,
  );
}

describe("U29 repository model fallback policy", () => {
  it("requires repository consent and submits a disabled same-vendor policy by default", async () => {
    const user = userEvent.setup();
    const requests: Request[] = [];
    renderCard(async (request) => {
      requests.push(request as Request);
      const url = new URL(request instanceof Request ? request.url : String(request));
      if (url.pathname.endsWith("/repositories")) {
        return Response.json({ items: [repo] });
      }
      if (url.pathname.endsWith("/agent-profiles")) {
        return Response.json({
          profiles: [
            { id: PRIMARY_PROFILE_ID, display_name: "Triage", model_id: "muse-spark-1.3", enabled: true },
            { id: SECONDARY_PROFILE_ID, display_name: "Patch", model_id: "muse-wonder-1.0", enabled: true },
          ],
        });
      }
      if (url.pathname.endsWith("/model-fallback") && request instanceof Request && request.method === "GET") {
        return Response.json(null);
      }
      if (url.pathname.endsWith("/model-fallback") && request instanceof Request && request.method === "PUT") {
        const body = (await request.clone().json()) as Record<string, unknown>;
        expect(body.enabled).toBe(false);
        expect(body.primary_model_profile_id).toBe(PRIMARY_PROFILE_ID);
        expect(body.secondary_model_profile_id).toBe(SECONDARY_PROFILE_ID);
        expect(body.consent_id).toBe(CONSENT_ID);
        return Response.json({
          id: "0196f100-0000-7000-8000-000000000701",
          version: 1,
          workspace_id: WORKSPACE_ID,
          repository_id: REPOSITORY_ID,
          primary_model_profile_id: PRIMARY_PROFILE_ID,
          secondary_model_profile_id: SECONDARY_PROFILE_ID,
          consent_id: CONSENT_ID,
          enabled: false,
          last_fallback_at: null,
          last_fallback_reason: null,
        });
      }
      throw new Error(`Unexpected request ${request instanceof Request ? request.method : "?"} ${url.pathname}`);
    }, [consent]);

    await screen.findByRole("option", { name: "acme/billing-api" });
    expect(screen.getByLabelText("Enable fallback (off by default)")).not.toBeChecked();
    await user.click(screen.getByRole("button", { name: "Save repository fallback policy" }));
    expect(await screen.findByText("Fallback policy saved disabled.")).toBeInTheDocument();
    await waitFor(() => expect(requests.some((request) => request.method === "PUT")).toBe(true));
    expect(requests.find((request) => request.method === "PUT")?.headers.get("Idempotency-Key")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7/,
    );
  });

  it("keeps save unavailable without active consent for the selected repository", async () => {
    renderCard(async (request) => {
      const url = new URL(request instanceof Request ? request.url : String(request));
      if (url.pathname.endsWith("/repositories")) {
        return Response.json({ items: [repo] });
      }
      if (url.pathname.endsWith("/agent-profiles")) {
        return Response.json({
          profiles: [
            { id: PRIMARY_PROFILE_ID, display_name: "Triage", model_id: "muse-spark-1.3", enabled: true },
            { id: SECONDARY_PROFILE_ID, display_name: "Patch", model_id: "muse-wonder-1.0", enabled: true },
          ],
        });
      }
      if (url.pathname.endsWith("/model-fallback")) {
        return Response.json(null);
      }
      throw new Error(`Unexpected request ${url.pathname}`);
    }, []);

    await screen.findByRole("option", { name: "acme/billing-api" });
    expect(screen.getByRole("button", { name: "Save repository fallback policy" })).toBeDisabled();
    expect(screen.getByRole("option", { name: "No eligible consent" })).toBeInTheDocument();
  });
});
