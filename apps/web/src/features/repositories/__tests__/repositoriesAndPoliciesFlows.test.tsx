import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { AppRoutes } from "../../../app/App";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";

const ADMIN_USER_ID = "0196ee20-0000-7000-8000-000000000101";
const SESSION_ID = "0196ee20-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ee20-0000-7000-8000-000000000301";
const MEM_ID = "0196ee20-0000-7000-8000-000000000401";
const GH_CONN_ID = "0196ee20-0000-7000-8000-000000000501";
const REPO_PAYMENTS_ID = "0196ee20-0000-7000-8000-000000000601";
const REPO_SEARCH_ID = "0196ee20-0000-7000-8000-000000000602";
const TRIGGER_ID = "0196ee20-0000-7000-8000-000000000701";
const JOB_ID = "0196ee20-0000-7000-8000-000000000801";
const POL_REV_1_ID = "0196ee20-0000-7000-8000-000000000901";
const POL_REV_2_ID = "0196ee20-0000-7000-8000-000000000902";
const POL_REV_3_ID = "0196ee20-0000-7000-8000-000000000903";
const NOW_ISO = "2026-10-28T10:00:00Z";
const EXPIRES_ISO = "2026-10-28T22:00:00Z";

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
    "X-Correlation-Id": init.correlationId ?? "corr-u12-web-01",
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

function renderRepositoriesApp(opts: {
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

function buildMePayload(role: "admin" | "maintainer" | "viewer"): Record<string, unknown> {
  const ws = buildWorkspace();
  return {
    user: {
      id: ADMIN_USER_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      display_name: "Repo Governance Operator",
      email: "repo-ops@red2pr.local",
      status: "active",
    },
    session: {
      id: SESSION_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      user_id: ADMIN_USER_ID,
      expires_at: EXPIRES_ISO,
      auth_strength: "password",
      step_up_at: null,
      grant_epoch: 1,
    },
    mfa_enabled: false,
    mfa_required_for_privileged: false,
    step_up_valid_until: null,
    is_instance_owner: false,
    workspaces: [ws],
    memberships: [
      {
        id: MEM_ID,
        workspace_id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        user_id: ADMIN_USER_ID,
        role,
        repository_grants: [REPO_PAYMENTS_ID, REPO_SEARCH_ID],
      },
    ],
    csrf_token: "csrf-u12-test-token",
    telegram_link: { linked: false, telegram_username: null, linked_at: null },
  };
}

function buildPolicyDto(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    branch_allowlist: ["main", "release/*"],
    branch_denylist: ["release/frozen"],
    file_allowlist: ["src/**"],
    file_denylist: ["src/generated/**"],
    sensitive_rules: ["src/billing/**"],
    required_check_names: ["build", "unit-tests"],
    allow_test_edits: false,
    allow_config_edits: false,
    max_attempts: 3,
    max_diff_lines: 400,
    max_calls_per_session: 40,
    max_tokens_per_session: 200000,
    max_wall_seconds: 1800,
    max_cost_per_session: { amount: "2.50", currency: "USD" },
    require_baseline: true,
    inference_consent_id: null,
    runtime_profile_id: "python-3.12-isolated",
    ...overrides,
  };
}

function buildEffectivePolicyDto(mode: "monitor" | "approval" | "auto_repair"): Record<string, unknown> {
  return {
    mode,
    effective_mode: mode,
    paused: false,
    effective_paused: false,
    allow_sandbox_execution: mode !== "monitor",
    allow_auto_publication: mode === "auto_repair",
    require_baseline: true,
    auto_merge: false,
    branch_allowlist: ["main", "release/*"],
    branch_denylist: ["release/frozen"],
    file_allowlist: ["src/**"],
    file_denylist: ["src/generated/**"],
    hard_denied_paths: [".env", ".git/**", "**/*.pem"],
    sensitive_rules: ["src/billing/**"],
    protected_paths: [".github/workflows/**", ".gitlab-ci.yml", "uv.lock"],
    allow_test_edits: false,
    allow_config_edits: false,
    max_attempts: 3,
    max_diff_lines: 400,
    max_calls_per_session: 40,
    max_tokens_per_session: 200000,
    max_wall_seconds: 1800,
    max_cost_per_session: { amount: "2.50", currency: "USD" },
    inference_consent_id: null,
    runtime_profile_id: "python-3.12-isolated",
    field_sources: {
      mode: "repository",
      require_baseline: "hard_invariant",
      auto_merge: "hard_invariant",
      max_attempts: "repository",
      max_diff_lines: "repository",
      paused: "repository",
      runtime_profile_id: "repository",
    },
  };
}

function buildReadinessGates(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    worker_isolation_ready: true,
    inference_consent_ready: true,
    workflow_hazard_blocked: false,
    grant_review_required: false,
    instance_paused: false,
    workspace_paused: false,
    blocking_reasons: [],
    ...overrides,
  };
}

function buildRepoDto(opts: {
  id: string;
  name: string;
  org: string;
  mode?: "monitor" | "approval" | "auto_repair";
  paused?: boolean;
  tags?: string[];
  grantReviewRequired?: boolean;
  hazardStatus?: "clean" | "flagged";
  version?: number;
  policyRevision?: number;
}): Record<string, unknown> {
  return {
    id: opts.id,
    workspace_id: WS_ACME_ID,
    version: opts.version ?? 1,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    connection_id: GH_CONN_ID,
    provider: "github",
    external_id: opts.id.slice(-6),
    name: opts.name,
    organization: opts.org,
    default_branch: "main",
    visibility: "private",
    mode: opts.mode ?? "monitor",
    paused: opts.paused ?? false,
    policy_revision: opts.policyRevision ?? 1,
    tags: opts.tags ?? ["tier-1"],
    archived: false,
    is_fork: false,
    workflow_hazard_status: opts.hazardStatus ?? "clean",
    workflow_hazards:
      opts.hazardStatus === "flagged"
        ? [
            {
              code: "pull_request_target_untrusted_checkout",
              severity: "critical",
              workflow_path: ".github/workflows/pr-target.yml",
              detail: "Untrusted PR checkout in pull_request_target.",
            },
          ]
        : [],
    auto_repair_blocked: opts.hazardStatus === "flagged",
    active: true,
    grant_review_required: opts.grantReviewRequired ?? false,
    sync_status: "ok",
    last_synced_at: NOW_ISO,
    last_ci_conclusion: "failure",
    last_ci_at: NOW_ISO,
  };
}

describe("U12 UI-S04 & UI-S05 Repository Catalog, Detail 7-Tab & Policy Dry-Run Simulator", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("renders UI-S04 catalog with scoped UX-02 facets, SEC-040 sanitization, org grouping, bulk preview + step-up retry, and passes axe", async () => {
    const user = userEvent.setup();
    let stepUpDone = false;
    let bulkApplied = false;
    const bulkUpdateCalls: Array<Record<string, unknown>> = [];

    const fetchImpl: typeof fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const method = req.method.toUpperCase();

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("maintainer"));
      }
      if (url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/repositories" && method === "GET") {
        const items = [
          buildRepoDto({
            id: REPO_PAYMENTS_ID,
            name: "acme/payments-\u202eservice\u001b[31m",
            org: "acme",
            mode: bulkApplied ? "approval" : "monitor",
            tags: bulkApplied ? ["tier-1", "critical"] : ["tier-1"],
            version: bulkApplied ? 2 : 1,
          }),
          buildRepoDto({
            id: REPO_SEARCH_ID,
            name: "beta-labs/search-indexer",
            org: "beta-labs",
            mode: bulkApplied ? "approval" : "monitor",
            tags: ["search"],
            version: bulkApplied ? 2 : 1,
          }),
        ];
        return jsonResponse({
          items,
          next_cursor: null,
          snapshot_at: NOW_ISO,
          facets: {
            tags: bulkApplied ? ["critical", "search", "tier-1"] : ["search", "tier-1"],
            organizations: ["acme", "beta-labs"],
            mode_counts: { [bulkApplied ? "approval" : "monitor"]: 2 },
            paused_count: 0,
            hazard_flagged_count: 0,
            partial_sync_connection_ids: [GH_CONN_ID],
          },
        });
      }
      if (
        url.pathname === "/api/v1/workspaces/acme/repositories/policy-previews" &&
        method === "POST"
      ) {
        return jsonResponse({
          can_apply_all: true,
          requires_step_up: true,
          items: [
            {
              repository_id: REPO_PAYMENTS_ID,
              repository_name: "acme/payments-service",
              current_version: 1,
              current_mode: "monitor",
              target_mode: "approval",
              current_paused: false,
              target_paused: false,
              can_apply: true,
              requires_step_up: true,
              active_job_count: 1,
              denials: [],
            },
          ],
        });
      }
      if (
        url.pathname === "/api/v1/workspaces/acme/repositories/bulk-update" &&
        method === "POST"
      ) {
        const rawText = await req.clone().text();
        const parsed = JSON.parse(rawText || "{}") as Record<string, unknown>;
        bulkUpdateCalls.push(parsed);
        if (!stepUpDone) {
          return jsonResponse(
            {
              type: "https://red2pr.local/problems/step_up_required",
              title: "Step-up required",
              status: 403,
              code: "step_up_required",
              detail: "Fresh 5-minute step-up verification is required.",
              correlation_id: "corr-u12-stepup",
            },
            { status: 403, contentType: "application/problem+json" },
          );
        }
        bulkApplied = true;
        return jsonResponse({
          updated_repositories: [
            buildRepoDto({
              id: REPO_PAYMENTS_ID,
              name: "acme/payments-service",
              org: "acme",
              mode: "approval",
              tags: ["tier-1", "critical"],
              version: 2,
            }),
          ],
        });
      }
      if (url.pathname === "/api/v1/auth/step-up" && method === "POST") {
        stepUpDone = true;
        return jsonResponse({
          step_up_valid_until: "2026-10-28T10:05:00Z",
          auth_strength: "password",
        });
      }
      return jsonResponse({ detail: `Unhandled ${method} ${url.pathname}` }, { status: 404 });
    };

    const { container } = renderRepositoriesApp({
      initialEntry: "/w/acme/repositories",
      fetchImpl,
      themeMode: "light",
    });

    await screen.findByTestId("repositories-page");
    expect(screen.getByTestId("repositories-partial-sync-banner")).toBeInTheDocument();

    // SEC-040: bidi U+202E replaced with [BIDI-STRIPPED] and ESC [31m stripped from rendered text
    const cleanRepoLink = await screen.findByRole("link", {
      name: "acme/payments-[BIDI-STRIPPED]service",
    });
    expect(cleanRepoLink.textContent).not.toContain("\u202e");
    expect(cleanRepoLink.textContent).not.toContain("\u001b");
    expect(cleanRepoLink.textContent).not.toContain("[31m");

    // UX-02 scoped tag facet select contains only granted tags
    const tagSelect = screen.getByLabelText(/Scoped tag/i) as HTMLSelectElement;
    const optionValues = Array.from(tagSelect.options).map((o) => o.value);
    expect(optionValues).toEqual(["", "search", "tier-1"]);

    // Toggle organization grouping
    const groupCheckbox = screen.getByLabelText(/Group by organization/i);
    await user.click(groupCheckbox);
    expect(await screen.findByTestId("repositories-org-groups")).toBeInTheDocument();
    await user.click(groupCheckbox);

    // Select repository and open Bulk Policy & Tag Update dialog
    const selectCheckbox = screen.getByLabelText(
      "Select repository acme/payments-[BIDI-STRIPPED]service",
    );
    await user.click(selectCheckbox);
    await user.click(screen.getByRole("button", { name: /Preview bulk policy change \(1\)/i }));

    const dialog = await screen.findByRole("dialog", {
      name: /Bulk Repository Mode, Pause & Tag Preview/i,
    });
    const applyBtn = within(dialog).getByRole("button", { name: /Apply bulk update/i });
    expect(applyBtn).toBeDisabled();

    await user.selectOptions(within(dialog).getByLabelText(/Target Mode/i), "approval");
    await user.type(within(dialog).getByLabelText(/Add Tags/i), "critical");
    await user.click(within(dialog).getByRole("button", { name: /Run bulk preview/i }));

    await screen.findByTestId("bulk-preview-results");
    expect(applyBtn).toBeEnabled();

    // First apply hits 403 step_up_required -> opens StepUpDialog -> retries automatically
    await user.click(applyBtn);
    const pwdInput = await screen.findByLabelText(/Current password/i);
    await user.type(pwdInput, "MaintSup3rStr0ng!Pass#32");
    await user.click(screen.getByRole("button", { name: /Verify step-up/i }));

    await waitFor(() => {
      expect(bulkUpdateCalls.length).toBe(2);
    });
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);

    const axeResults = await axe.run(container);
    expect(axeResults.violations).toEqual([]);
  }, 25_000);

  it("enforces viewer read-only RBAC on UI-S04 catalog without bulk or mutation controls", async () => {
    const fetchImpl: typeof fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("viewer"));
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
            buildRepoDto({
              id: REPO_PAYMENTS_ID,
              name: "acme/payments-service",
              org: "acme",
            }),
          ],
          next_cursor: null,
          snapshot_at: NOW_ISO,
          facets: {
            tags: ["tier-1"],
            organizations: ["acme"],
            mode_counts: { monitor: 1 },
            paused_count: 0,
            hazard_flagged_count: 0,
            partial_sync_connection_ids: [],
          },
        });
      }
      return jsonResponse({}, { status: 404 });
    };

    renderRepositoriesApp({
      initialEntry: "/w/acme/repositories",
      fetchImpl,
    });

    await screen.findByRole("link", { name: "acme/payments-service" });
    expect(screen.queryByRole("button", { name: /Bulk update/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Select all on page/i })).not.toBeInTheDocument();
  });

  it("navigates all 7 WAI-ARIA tabs via keyboard, runs zero-mutation PolicyEditor dry-run, handles 412 stale reload, and passes axe in dark theme", async () => {
    const user = userEvent.setup();
    let policyRevision = 1;
    let firstSaveStaleTriggered = false;
    let w02Held = true;
    const seenMethods: string[] = [];

    const fetchImpl: typeof fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const method = req.method.toUpperCase();
      seenMethods.push(`${method} ${url.pathname}`);

      if (url.pathname === "/api/v1/me") {
        return jsonResponse(buildMePayload("admin"));
      }
      if (url.pathname === "/api/v1/workspaces/acme") {
        return jsonResponse(buildWorkspace());
      }
      if (url.pathname === "/api/v1/workspaces/acme/events") {
        return sseIdleConnectedResponse();
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/repositories/${REPO_PAYMENTS_ID}` &&
        method === "GET"
      ) {
        return jsonResponse(
          {
            repository: buildRepoDto({
              id: REPO_PAYMENTS_ID,
              name: "acme/payments-service",
              org: "acme",
              mode: policyRevision >= 3 ? "approval" : "monitor",
              grantReviewRequired: w02Held,
              version: w02Held ? 1 : 2,
              policyRevision,
            }),
            connection_status: "ready",
            current_policy_revision: policyRevision,
            policy: buildPolicyDto(),
            effective_policy: buildEffectivePolicyDto(
              policyRevision >= 3 ? "approval" : "monitor",
            ),
            readiness_gates: buildReadinessGates({
              grant_review_required: w02Held,
              blocking_reasons: w02Held
                ? ["W-02 review required before leaving monitor mode."]
                : [],
            }),
            sync_cursor: null,
            recent_runs: [
              {
                id: TRIGGER_ID,
                provider: "github",
                provider_run_id: "8801",
                attempt_key: "8801:1",
                head_sha: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f68801",
                ref: "refs/heads/main",
                event_type: "push",
                status: "completed",
                conclusion: "failure",
                is_rerun: false,
                untrusted_fork: false,
                first_source: "webhook",
                job_id: JOB_ID,
                triggered_at: NOW_ISO,
              },
            ],
            active_jobs: [
              {
                job_id: JOB_ID,
                kind: "sandbox.reproduce",
                state: "leased",
                pinned_policy_revision: 1,
                impact_summary: "Leased job stays pinned to policy revision v1.",
              },
            ],
            access_grants: [
              {
                user_id: ADMIN_USER_ID,
                email: "repo-ops@red2pr.local",
                display_name: "Repo Governance Operator",
                role: "admin",
                grant_origin: "workspace_admin",
              },
            ],
            recent_history: [
              {
                id: "0196ee20-0000-7000-8000-000000000999",
                occurred_at: NOW_ISO,
                actor_id: ADMIN_USER_ID,
                action: "repository.policy.updated",
                decision: "allow",
                reason_code: "policy_saved",
                summary: "Initial repository policy snapshot.",
                policy_revision: 1,
              },
            ],
          },
          { extraHeaders: { ETag: `"v${w02Held ? 1 : 2}"` } },
        );
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/repositories/${REPO_PAYMENTS_ID}` &&
        method === "PATCH"
      ) {
        w02Held = false;
        return jsonResponse(
          buildRepoDto({
            id: REPO_PAYMENTS_ID,
            name: "acme/payments-service",
            org: "acme",
            grantReviewRequired: false,
            version: 2,
            policyRevision,
          }),
          { extraHeaders: { ETag: '"v2"' } },
        );
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/repositories/${REPO_PAYMENTS_ID}/policy` &&
        method === "GET"
      ) {
        return jsonResponse(
          {
            repository_id: REPO_PAYMENTS_ID,
            workspace_id: WS_ACME_ID,
            current_revision: policyRevision,
            mode: policyRevision >= 3 ? "approval" : "monitor",
            paused: false,
            policy: buildPolicyDto(),
            effective_policy: buildEffectivePolicyDto(
              policyRevision >= 3 ? "approval" : "monitor",
            ),
            readiness_gates: buildReadinessGates(),
            revisions: [
              {
                id: policyRevision === 1 ? POL_REV_1_ID : policyRevision === 2 ? POL_REV_2_ID : POL_REV_3_ID,
                workspace_id: WS_ACME_ID,
                repository_id: REPO_PAYMENTS_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                revision: policyRevision,
                mode: policyRevision >= 3 ? "approval" : "monitor",
                paused: false,
                policy: buildPolicyDto(),
                change_reason: `Snapshot v${String(policyRevision)}`,
                created_by_user_id: ADMIN_USER_ID,
              },
            ],
          },
          { extraHeaders: { ETag: `"v${String(policyRevision)}"` } },
        );
      }
      if (
        url.pathname ===
          `/api/v1/workspaces/acme/repositories/${REPO_PAYMENTS_ID}/policy/previews` &&
        method === "POST"
      ) {
        return jsonResponse({
          repository_id: REPO_PAYMENTS_ID,
          current_revision: policyRevision,
          next_revision: policyRevision + 1,
          can_apply: true,
          requires_step_up: false,
          readiness_gates: buildReadinessGates(),
          effective_policy: buildEffectivePolicyDto("approval"),
          changed_rules: [
            {
              field: "mode",
              before: "monitor",
              after: "approval",
              impact: "Mode changes from monitor to approval.",
              requires_step_up: false,
            },
          ],
          denials: [],
          branch_evaluations: [
            {
              branch: "main",
              canonical_branch: "main",
              verdict: "requires_approval",
              matched_rule: "main",
              source_layer: "repository",
              reason: "Approval required under approval mode.",
            },
          ],
          path_evaluations: [
            {
              raw_path: ".github/workflows/ci.yml",
              canonical_path: ".github/workflows/ci.yml",
              verdict: "requires_approval",
              category: "protected_sensitive",
              matched_rule: ".github/workflows/**",
              source_layer: "hard_invariant",
              reason: "Protected workflow file requires human approval (SEC-009).",
            },
            {
              raw_path: ".env",
              canonical_path: ".env",
              verdict: "deny",
              category: "hard_denied",
              matched_rule: ".env",
              source_layer: "hard_invariant",
              reason: "Hard-denied secret path (SEC-007).",
            },
          ],
          historical_run_simulations: [
            {
              trigger_id: TRIGGER_ID,
              provider_run_id: "8801",
              attempt_key: "8801:1",
              ref: "refs/heads/main",
              head_sha: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f68801",
              conclusion: "failure",
              triggered_at: NOW_ISO,
              disposition: "eligible_approval_gated",
              reason: "Eligible for sandbox reproduction with mandatory human approval.",
            },
          ],
          affected_in_flight: [
            {
              job_id: JOB_ID,
              kind: "sandbox.reproduce",
              state: "leased",
              pinned_policy_revision: 1,
              impact_summary: "Active job remains pinned to v1.",
            },
          ],
          diff_lines_verdict: "allow",
          diff_lines_reason: "45 lines within max_diff_lines (400).",
        });
      }
      if (
        url.pathname === `/api/v1/workspaces/acme/repositories/${REPO_PAYMENTS_ID}/policy` &&
        method === "PATCH"
      ) {
        if (!firstSaveStaleTriggered) {
          firstSaveStaleTriggered = true;
          policyRevision = 2;
          return jsonResponse(
            {
              type: "https://red2pr.local/problems/precondition_failed",
              title: "Precondition failed",
              status: 412,
              code: "precondition_failed",
              detail: "Policy revision changed concurrently.",
              correlation_id: "corr-u12-412",
            },
            { status: 412, contentType: "application/problem+json" },
          );
        }
        policyRevision = 3;
        return jsonResponse(
          {
            repository_id: REPO_PAYMENTS_ID,
            workspace_id: WS_ACME_ID,
            current_revision: 3,
            mode: "approval",
            paused: false,
            policy: buildPolicyDto(),
            effective_policy: buildEffectivePolicyDto("approval"),
            readiness_gates: buildReadinessGates(),
            revisions: [
              {
                id: POL_REV_3_ID,
                workspace_id: WS_ACME_ID,
                repository_id: REPO_PAYMENTS_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                revision: 3,
                mode: "approval",
                paused: false,
                policy: buildPolicyDto(),
                change_reason: "Enable approval mode.",
                created_by_user_id: ADMIN_USER_ID,
              },
            ],
          },
          { extraHeaders: { ETag: '"v3"' } },
        );
      }
      return jsonResponse({}, { status: 404 });
    };

    const { container } = renderRepositoriesApp({
      initialEntry: `/w/acme/repositories/${REPO_PAYMENTS_ID}`,
      fetchImpl,
      themeMode: "dark",
    });

    await screen.findByTestId("repository-detail-page");
    expect(screen.getByTestId("repo-w02-review-alert")).toBeInTheDocument();

    // Admin acknowledges W-02 review hold
    await user.click(
      screen.getByRole("button", { name: /Acknowledge W-02 reconnect grant review/i }),
    );
    await waitFor(() => {
      expect(screen.queryByTestId("repo-w02-review-alert")).not.toBeInTheDocument();
    });

    // WAI-ARIA 7-tab keyboard navigation: Overview -> ArrowRight (Runs) -> End (History) -> Home (Overview)
    const tablist = screen.getByTestId("repository-detail-tablist");
    const overviewTab = within(tablist).getByRole("tab", { name: "Overview" });
    overviewTab.focus();
    await user.keyboard("{ArrowRight}");
    expect(within(tablist).getByRole("tab", { name: "Runs" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await user.keyboard("{End}");
    expect(within(tablist).getByRole("tab", { name: "History" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await user.keyboard("{Home}");
    expect(overviewTab).toHaveAttribute("aria-selected", "true");

    // Switch to Policies tab
    await user.click(within(tablist).getByRole("tab", { name: "Policies" }));
    await screen.findByTestId("policy-editor");
    expect(screen.getByLabelText(/Required remote CI check names/i)).toHaveValue(
      "build\nunit-tests",
    );

    // Run dry-run simulation and prove ZERO PATCH /policy calls occurred during simulation!
    const patchCallsBeforeSim = seenMethods.filter((m) => m.endsWith("/policy") && m.startsWith("PATCH"));
    expect(patchCallsBeforeSim).toEqual([]);

    await user.selectOptions(screen.getByLabelText(/Operating Mode/i), "approval");
    await user.click(screen.getByRole("button", { name: /Run dry-run policy simulation/i }));
    await screen.findByTestId("policy-preview-results");

    expect(
      seenMethods.filter((m) => m.endsWith("/policy") && m.startsWith("PATCH")),
    ).toEqual([]);
    expect(screen.getByText(/eligible_approval_gated/i)).toBeInTheDocument();

    // First save hits 412 concurrent update -> shows stale banner -> reload v2 -> save v3
    await user.click(screen.getByRole("button", { name: /Save new policy revision/i }));
    const staleBanner = await screen.findByTestId("policy-stale-conflict-banner");
    await user.click(within(staleBanner).getByRole("button", { name: /Reload latest policy/i }));

    await waitFor(() => {
      expect(screen.getByTestId("policy-current-revision")).toHaveTextContent("Revision v2");
    });

    await user.selectOptions(screen.getByLabelText(/Operating Mode/i), "approval");
    await user.click(screen.getByRole("button", { name: /Save new policy revision/i }));
    await screen.findByTestId("policy-save-success-banner");
    expect(screen.getByTestId("policy-current-revision")).toHaveTextContent("Revision v3");

    const axeDarkResults = await axe.run(container);
    expect(axeDarkResults.violations).toEqual([]);
  }, 25_000);
});
