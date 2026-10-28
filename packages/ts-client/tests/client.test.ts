import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createRed2PrClient,
  Red2PrApiError,
  type FidelityGrade,
  type Membership,
  type ModelUsageRecord,
  type Problem,
  type ReproductionRunRecord,
  type RepositoryPolicy,
  type RunnerProfileManifest,
  type SetupState,
  type WorkspaceModelsResponse,
} from "../src/index.js";

describe("@red2pr/ts-client generated OpenAPI v1 contracts", () => {
  it("fetches /api/v1/system/health with correlation propagation", async () => {
    let capturedAccept: string | null = null;
    let capturedCorrelation: string | null = null;

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      fetch: async (request: Request) => {
        capturedAccept = request.headers.get("Accept");
        capturedCorrelation = request.headers.get("X-Correlation-Id");
        return new Response(
          JSON.stringify({
            status: "ok",
            service: "red2pr-control-plane",
            api_version: "v1",
            timestamp: "2026-10-27T06:00:00Z",
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "X-Correlation-Id": capturedCorrelation ?? "generated",
            },
          },
        );
      },
    });

    const result = await client.getSystemHealth({ correlationId: "corr-ts-01" });
    assert.equal(capturedAccept, "application/json, application/problem+json");
    assert.equal(capturedCorrelation, "corr-ts-01");
    assert.equal(result.data.status, "ok");
    assert.equal(result.data.api_version, "v1");
    assert.equal(result.correlationId, "corr-ts-01");
  });

  it("raises Red2PrApiError with Retry-After on 429 Problem+JSON responses", async () => {
    const problemPayload: Problem = {
      type: "https://red2pr.local/problems/rate_limited",
      title: "Too many requests",
      status: 429,
      code: "rate_limited",
      detail: "Rate limit exceeded",
      correlation_id: "corr-429",
      errors: null,
    };

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      fetch: async () =>
        new Response(JSON.stringify(problemPayload), {
          status: 429,
          headers: {
            "Content-Type": "application/problem+json",
            "Retry-After": "15",
            "X-Correlation-Id": "corr-429",
          },
        }),
    });

    await assert.rejects(
      async () => client.getSystemHealth(),
      (err: unknown) => {
        assert.ok(err instanceof Red2PrApiError);
        assert.equal(err.status, 429);
        assert.equal(err.problem.code, "rate_limited");
        assert.equal(err.retryAfterSeconds, 15);
        return true;
      },
    );
  });

  it("preserves ADR-038 and ADR-031 compile-time enum invariants", () => {
    const auditorRole: Membership["role"] = "auditor";
    const finalWizardPhase: SetupState["phase"] = "readiness_review";
    const baselineRequired: RepositoryPolicy["require_baseline"] = true;

    assert.equal(auditorRole, "auditor");
    assert.equal(finalWizardPhase, "readiness_review");
    assert.equal(baselineRequired, true);
  });

  it("synchronizes heap-only CSRF tokens across auth mutations and wipes on logout", async () => {
    const seenHeaders: Array<{ path: string; csrf: string | null }> = [];
    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        seenHeaders.push({
          path: url.pathname,
          csrf: request.headers.get("X-CSRF-Token"),
        });
        if (url.pathname === "/api/v1/auth/csrf") {
          return new Response(
            JSON.stringify({
              csrf_token: "anon.csrf-test-token-01",
              bootstrap_claim_required: false,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (url.pathname === "/api/v1/auth/logout") {
          return new Response(null, { status: 204 });
        }
        throw new Error(`Unexpected path ${url.pathname}`);
      },
    });

    await client.getAuthCsrf();
    await client.logout();
    await client.logout();
    assert.deepEqual(seenHeaders, [
      { path: "/api/v1/auth/csrf", csrf: null },
      { path: "/api/v1/auth/logout", csrf: "anon.csrf-test-token-01" },
      { path: "/api/v1/auth/logout", csrf: null },
    ]);
  });

  it("propagates If-Match, Idempotency-Key, and ETag across U06 workspace & member routes", async () => {
    let seenIfMatch: string | null = null;
    let seenIdemKey: string | null = null;

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      getCsrfToken: () => "sess-csrf-01",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        if (request.method === "PATCH" && url.pathname === "/api/v1/workspaces/acme") {
          seenIfMatch = request.headers.get("If-Match");
          return new Response(
            JSON.stringify({
              id: "0196ed00-0000-7000-8000-000000000101",
              version: 2,
              created_at: "2026-10-27T08:00:00Z",
              updated_at: "2026-10-27T08:01:00Z",
              name: "Acme Core",
              slug: "acme",
              status: "active",
              paused: true,
            }),
            {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                ETag: '"v2"',
                "X-Correlation-Id": "corr-ws-patch",
              },
            },
          );
        }
        if (request.method === "DELETE" && url.pathname === "/api/v1/workspaces/acme") {
          seenIdemKey = request.headers.get("Idempotency-Key");
          return new Response(
            JSON.stringify({
              operation_id: "0196ed00-0000-7000-8000-000000000102",
              state: "succeeded",
              resource_id: "0196ed00-0000-7000-8000-000000000101",
              idempotency_key: "idem-ws-del-01",
              status_url: "/api/v1/operations/0196ed00-0000-7000-8000-000000000101",
              correlation_id: "corr-ws-del",
              replayed: false,
            }),
            {
              status: 202,
              headers: {
                "Content-Type": "application/json",
                "X-Correlation-Id": "corr-ws-del",
              },
            },
          );
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const patched = await client.updateWorkspace(
      "acme",
      { paused: true },
      { ifMatch: '"v1"' },
    );
    assert.equal(seenIfMatch, '"v1"');
    assert.equal(patched.etag, '"v2"');
    assert.equal(patched.data.paused, true);

    const receipt = await client.deleteWorkspace(
      "acme",
      { confirm_name: "Acme Core" },
      { idempotencyKey: "idem-ws-del-01" },
    );
    assert.equal(seenIdemKey, "idem-ws-del-01");
    assert.equal(receipt.data.state, "succeeded");
  });

  it("serializes U07 10-phase setup checkpoint, consent, and private endpoint contracts", async () => {
    const seenRequests: Array<{ method: string; path: string; idemKey: string | null }> = [];
    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      getCsrfToken: () => "csrf-u07-client",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        seenRequests.push({
          method: request.method,
          path: url.pathname,
          idemKey: request.headers.get("Idempotency-Key"),
        });
        if (request.method === "POST" && url.pathname === "/api/v1/setup/steps/model_consent") {
          const body = (await request.json()) as Record<string, unknown>;
          assert.equal(body.expected_checkpoint, "ckpt-v5");
          assert.equal(body.action, "skip");
          return new Response(
            JSON.stringify({
              phase: "worker_readiness",
              checkpoint: "ckpt-v6",
              readiness: "ready_monitor",
              owner_claimed: true,
              ready_monitor: true,
              ready_repair: false,
              completed_at: null,
              default_workspace_id: "0196ed00-0000-7000-8000-000000000201",
              default_workspace_slug: "core-eng",
              prerequisites: [],
              steps: [],
            }),
            { status: 200, headers: { "Content-Type": "application/json", ETag: '"ckpt-v6"' } },
          );
        }
        if (request.method === "POST" && url.pathname === "/api/v1/setup/consents") {
          return new Response(
            JSON.stringify({
              id: "0196ed00-0000-7000-8000-000000000202",
              version: 1,
              created_at: "2026-10-27T08:00:00Z",
              updated_at: "2026-10-27T08:00:00Z",
              purpose: "inference",
              scope: "instance",
              workspace_id: null,
              repository_id: null,
              destination: "https://api.llama.com",
              data_classes: ["public", "workspace_internal"],
              status: "active",
              granted_by_user_id: "0196ed00-0000-7000-8000-000000000001",
              granted_at: "2026-10-27T08:00:00Z",
              revoked_by_user_id: null,
              revoked_at: null,
              revocation_reason: null,
              policy_version: 1,
            }),
            { status: 201, headers: { "Content-Type": "application/json" } },
          );
        }
        if (request.method === "POST" && url.pathname === "/api/v1/setup/endpoints") {
          return new Response(
            JSON.stringify({
              id: "0196ed00-0000-7000-8000-000000000203",
              version: 1,
              created_at: "2026-10-27T08:00:00Z",
              updated_at: "2026-10-27T08:00:00Z",
              adapter: "gitlab",
              scheme: "https",
              host: "gitlab.corp.internal",
              port: 8443,
              cidrs: ["10.24.0.0/16"],
              ca_ref: "ref:corp-ca",
              description: "Corp GitLab",
              status: "active",
              registered_by_user_id: "0196ed00-0000-7000-8000-000000000001",
              revoked_by_user_id: null,
              revoked_at: null,
            }),
            { status: 201, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const stepRes = await client.submitSetupStep(
      "model_consent",
      { expected_checkpoint: "ckpt-v5", action: "skip" },
      { idempotencyKey: "idem-step-06" },
    );
    assert.equal(stepRes.data.phase, "worker_readiness");
    assert.equal(stepRes.data.ready_monitor, true);
    assert.equal(stepRes.data.ready_repair, false);

    const consentRes = await client.grantSetupConsent({
      purpose: "inference",
      scope: "instance",
      destination: "https://api.llama.com",
      data_classes: ["public", "workspace_internal"],
      policy_notice_acknowledged: true,
    });
    assert.equal(consentRes.data.purpose, "inference");

    const epRes = await client.registerPrivateEndpoint({
      adapter: "gitlab",
      scheme: "https",
      host: "gitlab.corp.internal",
      port: 8443,
      cidrs: ["10.24.0.0/16"],
      ca_ref: "ref:corp-ca",
    });
    assert.equal(epRes.data.host, "gitlab.corp.internal");
    assert.equal(seenRequests[0]?.idemKey, "idem-step-06");
  });

  it("handles U08 task-jobs listing, detail ETag, idempotent actions, and operation receipts", async () => {
    const seenHeaders: Array<{ url: string; idemKey: string | null; ifMatch: string | null }> = [];
    const jobId = "019a2400-0000-7000-8000-000000000101";
    const opId = "019a2400-0000-7000-8000-000000000202";

    const client = createRed2PrClient({
      baseUrl: "https://red2pr.example.test",
      getCsrfToken: () => "csrf-queue-token",
      fetch: async (input) => {
        const req = input instanceof Request ? input : new Request(input);
        const url = new URL(req.url);
        seenHeaders.push({
          url: `${req.method} ${url.pathname}${url.search}`,
          idemKey: req.headers.get("Idempotency-Key"),
          ifMatch: req.headers.get("If-Match"),
        });

        if (req.method === "GET" && url.pathname === "/api/v1/workspaces/core/task-jobs") {
          return new Response(
            JSON.stringify({
              items: [
                {
                  id: jobId,
                  workspace_id: "019a2400-0000-7000-8000-000000000001",
                  version: 2,
                  created_at: "2026-10-27T06:00:00Z",
                  updated_at: "2026-10-27T06:01:00Z",
                  kind: "repair.reproduce",
                  resource_id: "019a2400-0000-7000-8000-000000000050",
                  state: "dead_letter",
                  lease_epoch: 3,
                  attempt: 3,
                  not_before: "2026-10-27T06:00:00Z",
                  deadline: "2026-10-27T06:30:00Z",
                  logical_effect_key: "repair.reproduce:run-1",
                  budget_key: "budget:session-1",
                  correlation_id: "corr-queue-01",
                  recoverable: true,
                  reconcile_required: false,
                },
              ],
              next_cursor: null,
              snapshot_at: "2026-10-27T06:02:00Z",
              summary: {
                max_running_repairs: 2,
                active_running_repairs: 1,
                queued_count: 3,
                leased_count: 0,
                running_count: 1,
                cancel_requested_count: 0,
                dead_letter_count: 1,
                workspace_paused: false,
                backpressure_active: false,
                transport_status: "healthy",
                transport_detail: null,
              },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }

        if (req.method === "GET" && url.pathname.endsWith(`/task-jobs/${jobId}`)) {
          return new Response(
            JSON.stringify({
              id: jobId,
              workspace_id: "019a2400-0000-7000-8000-000000000001",
              version: 2,
              created_at: "2026-10-27T06:00:00Z",
              updated_at: "2026-10-27T06:01:00Z",
              kind: "repair.reproduce",
              resource_id: "019a2400-0000-7000-8000-000000000050",
              state: "dead_letter",
              lease_epoch: 3,
              attempt: 3,
              not_before: "2026-10-27T06:00:00Z",
              deadline: "2026-10-27T06:30:00Z",
              attempts_history: [],
              dead_letter_entry: null,
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json", ETag: '"v2"' },
            },
          );
        }

        if (req.method === "POST" && url.pathname.endsWith(`/task-jobs/${jobId}/actions`)) {
          return new Response(
            JSON.stringify({
              operation_id: opId,
              resource_id: jobId,
              state: "succeeded",
              correlation_id: "corr-action-01",
              status_url: `/api/v1/operations/${opId}`,
              result_id: jobId,
            }),
            { status: 202, headers: { "Content-Type": "application/json" } },
          );
        }

        return new Response(
          JSON.stringify({
            operation_id: opId,
            resource_id: jobId,
            state: "succeeded",
            correlation_id: "corr-action-01",
            status_url: `/api/v1/operations/${opId}`,
            result_id: jobId,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      },
    });

    const page = await client.listTaskJobs("core", { state: "dead_letter", limit: 25 });
    assert.equal(page.data.items.length, 1);
    assert.equal(page.data.summary?.dead_letter_count, 1);

    const detail = await client.getTaskJob("core", jobId);
    assert.equal(detail.etag, '"v2"');

    const receipt = await client.performTaskJobAction(
      "core",
      jobId,
      { action: "requeue", reason: "Transient worker node reboot", expected_version: 2 },
      { idempotencyKey: "019a2400-0000-7000-8000-000000000999", ifMatch: '"v2"' },
    );
    assert.equal(receipt.data.operation_id, opId);
    assert.equal(seenHeaders[2]?.idemKey, "019a2400-0000-7000-8000-000000000999");
    assert.equal(seenHeaders[2]?.ifMatch, '"v2"');

    const polled = await client.getOperationReceipt(opId);
    assert.equal(polled.data.state, "succeeded");
  });

  it("serializes U09 A-06 & A-23 GitHub App integration, callback state, and hazard contracts", async () => {
    const connId = "019a2500-0000-7000-8000-000000000101";
    const wsId = "019a2500-0000-7000-8000-000000000001";
    const opId = "019a2500-0000-7000-8000-000000000202";
    const seenCalls: Array<{
      method: string;
      path: string;
      idemKey: string | null;
      csrf: string | null;
    }> = [];

    const sampleConn = {
      id: connId,
      workspace_id: wsId,
      version: 2,
      created_at: "2026-10-27T10:00:00Z",
      updated_at: "2026-10-27T10:01:00Z",
      provider: "github",
      base_url: "https://api.github.com",
      auth_mode: "github_app",
      secret_presence: { configured: true, secret_version: 1 },
      webhook_secret_presence: { configured: true, secret_version: 1 },
      status: "ready",
      capabilities: { app_jwt_auth: "available", repo_discovery: "available" },
      checked_at: "2026-10-27T10:01:00Z",
      vendor_version: "github.com",
      api_version: "2026-03-10",
      display_name: "Acme GitHub App",
      app_id: "340122",
      client_id: "Iv1.acme",
      installation_id: "99001",
      account_login: "acme-corp",
      granted_permissions: { metadata: "read", contents: "read", actions: "read" },
      missing_permissions: ["pull_requests:write"],
      repository_count: 1,
      flagged_hazard_repo_count: 1,
      grant_review_required: false,
      status_detail: "Ready.",
      last_synced_at: "2026-10-27T10:01:00Z",
    };

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      getCsrfToken: () => "csrf-u09-token",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        seenCalls.push({
          method: request.method,
          path: url.pathname,
          idemKey: request.headers.get("Idempotency-Key"),
          csrf: request.headers.get("X-CSRF-Token"),
        });

        if (request.method === "POST" && url.pathname === "/api/v1/workspaces/acme/integrations") {
          return new Response(JSON.stringify({ ...sampleConn, version: 1, status: "not_configured" }), {
            status: 201,
            headers: { "Content-Type": "application/json", ETag: '"v1"' },
          });
        }
        if (
          request.method === "POST" &&
          url.pathname === `/api/v1/workspaces/acme/integrations/${connId}/installations/state`
        ) {
          return new Response(
            JSON.stringify({
              connection_id: connId,
              workspace_id: wsId,
              state: "st_single_use_nonce_1234567890",
              expires_at: "2026-10-27T10:10:00Z",
              install_url: "https://github.com/settings/apps?state=st_single_use_nonce_1234567890",
            }),
            { status: 201, headers: { "Content-Type": "application/json" } },
          );
        }
        if (request.method === "GET" && url.pathname === "/api/v1/integrations/github/callback") {
          assert.equal(url.searchParams.get("state"), "st_single_use_nonce_1234567890");
          assert.equal(url.searchParams.get("installation_id"), "99001");
          return new Response(
            JSON.stringify({
              state_valid: true,
              workspace_id: wsId,
              workspace_slug: "acme",
              connection_id: connId,
              installation_id: "99001",
              setup_action: "install",
              expires_at: "2026-10-27T10:10:00Z",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (
          request.method === "POST" &&
          url.pathname === `/api/v1/workspaces/acme/integrations/${connId}/installations/confirm`
        ) {
          return new Response(
            JSON.stringify({
              receipt: {
                operation_id: opId,
                resource_id: connId,
                state: "succeeded",
                correlation_id: "corr-u09-confirm",
                status_url: `/api/v1/operations/${opId}`,
                result_id: connId,
              },
              connection: sampleConn,
              snapshot: {
                id: "019a2500-0000-7000-8000-000000000303",
                workspace_id: wsId,
                version: 1,
                created_at: "2026-10-27T10:01:00Z",
                updated_at: "2026-10-27T10:01:00Z",
                connection_id: connId,
                provider: "github",
                status: "ready",
                capabilities: { app_jwt_auth: "available", repo_discovery: "available" },
                granted_permissions: { metadata: "read", contents: "read", actions: "read" },
                missing_permissions: ["pull_requests:write"],
                vendor_version: "github.com",
                api_version: "2026-03-10",
                checked_at: "2026-10-27T10:01:00Z",
                detail: "Verified.",
              },
              repositories: [
                {
                  id: "019a2500-0000-7000-8000-000000000404",
                  workspace_id: wsId,
                  version: 1,
                  created_at: "2026-10-27T10:01:00Z",
                  updated_at: "2026-10-27T10:01:00Z",
                  external_id: "501002",
                  connection_id: connId,
                  name: "acme-corp/docs-site",
                  default_branch: "main",
                  visibility: "public",
                  mode: "monitor",
                  paused: false,
                  policy_revision: 1,
                  tags: [],
                  archived: false,
                  is_fork: false,
                  workflow_hazard_status: "flagged",
                  workflow_hazards: [
                    {
                      code: "pull_request_target",
                      severity: "high",
                      workflow_path: ".github/workflows/pr-target.yml",
                      detail: "Workflow triggers on pull_request_target.",
                    },
                  ],
                  auto_repair_blocked: true,
                },
              ],
              partial_sync: false,
              grant_review_required: false,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const created = await client.createConnection(
      "acme",
      {
        provider: "github",
        base_url: "https://api.github.com",
        auth_mode: "github_app",
        display_name: "Acme GitHub App",
        app_id: "340122",
        private_key_pem: "-----BEGIN PRIVATE KEY-----\nREDACTED_IN_TRANSIT\n-----END PRIVATE KEY-----",
      },
      { idempotencyKey: "019a2500-0000-7000-8000-000000000801" },
    );
    assert.equal(created.etag, '"v1"');
    assert.equal(created.data.secret_presence.configured, true);

    const minted = await client.mintGitHubInstallState(
      "acme",
      connId,
      { expected_origin: "http://127.0.0.1:4280" },
      { idempotencyKey: "019a2500-0000-7000-8000-000000000802" },
    );
    assert.equal(minted.data.state, "st_single_use_nonce_1234567890");

    const cb = await client.handleGitHubCallback({
      state: minted.data.state,
      installation_id: "99001",
      setup_action: "install",
    });
    assert.equal(cb.data.state_valid, true);
    assert.equal(cb.data.workspace_slug, "acme");

    const confirmed = await client.confirmGitHubInstallation(
      "acme",
      connId,
      {
        installation_id: "99001",
        state: minted.data.state,
      },
      { idempotencyKey: "019a2500-0000-7000-8000-000000000803" },
    );
    assert.equal(confirmed.data.connection.status, "ready");
    assert.equal(confirmed.data.repositories?.[0]?.auto_repair_blocked, true);
    assert.equal(seenCalls[2]?.csrf, null); // GET callback does not send mutation CSRF
    assert.equal(seenCalls[3]?.csrf, "csrf-u09-token");
  });

  it("serializes U10 GitLab pinned auth_mode, write-only access_token, and probe/sync contracts", async () => {
    const connId = "019a2600-0000-7000-8000-000000000901";
    let capturedBody: Record<string, unknown> | null = null;
    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      getCsrfToken: () => "csrf-u10-token",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        if (request.method === "POST" && url.pathname === "/api/v1/workspaces/acme/integrations") {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return new Response(
            JSON.stringify({
              id: connId,
              workspace_id: "019a2600-0000-7000-8000-000000000101",
              version: 1,
              created_at: "2026-10-27T10:00:00Z",
              updated_at: "2026-10-27T10:00:00Z",
              provider: "gitlab",
              base_url: "https://gitlab.com",
              auth_mode: "gitlab_signed_v19",
              display_name: "GitLab Cloud Prod",
              secret_presence: { configured: true, secret_version: 1 },
              webhook_secret_presence: { configured: true, secret_version: 1 },
              status: "not_configured",
              capabilities: {
                repo_discovery: "unknown",
                webhook_hmac: "available",
                idempotency_key_v17_4: "unknown",
              },
              api_version: "v4",
            }),
            { status: 201, headers: { "Content-Type": "application/json", ETag: '"v1"' } },
          );
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const created = await client.createConnection(
      "acme",
      {
        provider: "gitlab",
        base_url: "https://gitlab.com",
        auth_mode: "gitlab_signed_v19",
        display_name: "GitLab Cloud Prod",
        access_token: "glpat-write-only-token-example",
        webhook_secret: "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
      },
      { idempotencyKey: "019a2600-0000-7000-8000-000000000902" },
    );
    assert.equal(capturedBody?.["auth_mode"], "gitlab_signed_v19");
    assert.equal(capturedBody?.["access_token"], "glpat-write-only-token-example");
    assert.equal(created.data.provider, "gitlab");
    assert.equal(created.data.auth_mode, "gitlab_signed_v19");
    assert.equal(created.data.api_version, "v4");
  });

  it("serializes U11 sync_cursors and reconcileConnectionRuns with honest complete_recovery=false", async () => {
    const connId = "019a2700-0000-7000-8000-000000000101";
    const wsId = "019a2700-0000-7000-8000-000000000001";
    const repoId = "019a2700-0000-7000-8000-000000000201";
    const opId = "019a2700-0000-7000-8000-000000000301";
    let capturedReconcileBody: Record<string, unknown> | null = null;
    let capturedIdemKey: string | null = null;
    let capturedCsrf: string | null = null;

    const sampleCursor = {
      id: "019a2700-0000-7000-8000-000000000401",
      workspace_id: wsId,
      version: 2,
      created_at: "2026-10-27T15:00:00Z",
      updated_at: "2026-10-27T15:05:00Z",
      connection_id: connId,
      repository_id: repoId,
      provider: "github",
      etag: 'W/"etag-5001"',
      high_water_mark_at: "2026-10-27T15:00:00Z",
      last_seen_run_id: "5001",
      last_stable_page: 1,
      overlap_seconds: 300,
      poll_interval_seconds: 60,
      last_polled_at: "2026-10-27T15:05:00Z",
      last_success_at: "2026-10-27T15:05:00Z",
      next_poll_after: "2026-10-27T15:06:05Z",
      consecutive_failures: 0,
      last_status: "gap_detected",
      history_gap_detected: true,
      history_gap_since: "2026-07-01T00:00:00Z",
      history_gap_until: "2026-10-27T15:00:00Z",
      history_gap_detail: "Offline duration exceeded provider retention.",
    };

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      getCsrfToken: () => "csrf-u11-token",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        if (
          request.method === "POST" &&
          url.pathname === `/api/v1/workspaces/acme/integrations/${connId}/reconcile`
        ) {
          capturedIdemKey = request.headers.get("Idempotency-Key");
          capturedCsrf = request.headers.get("X-CSRF-Token");
          capturedReconcileBody = (await request.json()) as Record<string, unknown>;
          return new Response(
            JSON.stringify({
              receipt: {
                operation_id: opId,
                resource_id: connId,
                state: "succeeded",
                correlation_id: "corr-u11-reconcile",
                status_url: `/api/v1/operations/${opId}`,
                result_id: connId,
              },
              connection_id: connId,
              polled_repository_count: 1,
              rate_limited_count: 0,
              history_gap_count: 1,
              triggers_created_count: 1,
              pending_inbox_reconciled_count: 0,
              complete_recovery: false,
              sync_cursors: [sampleCursor],
            }),
            {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "X-Correlation-Id": "corr-u11-reconcile",
              },
            },
          );
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const reconciled = await client.reconcileConnectionRuns(
      "acme",
      connId,
      { acknowledge_history_gap: true, force_poll: true },
      { idempotencyKey: "019a2700-0000-7000-8000-000000000999" },
    );
    assert.equal(capturedIdemKey, "019a2700-0000-7000-8000-000000000999");
    assert.equal(capturedCsrf, "csrf-u11-token");
    assert.equal(capturedReconcileBody?.["acknowledge_history_gap"], true);
    assert.equal(capturedReconcileBody?.["force_poll"], true);
    assert.equal(reconciled.data.complete_recovery, false);
    assert.equal(reconciled.data.sync_cursors?.[0]?.history_gap_detected, true);
  });

  it("serializes U12 A-07 repository catalog, versioned policy, ETag/If-Match, and dry-run previews", async () => {
    const repoId = "019a2800-0000-7000-8000-000000000101";
    const connId = "019a2800-0000-7000-8000-000000000202";
    const wsId = "019a2800-0000-7000-8000-000000000001";
    const seenHeaders: Array<{ path: string; method: string; ifMatch: string | null; csrf: string | null }> = [];

    const sampleRepo = {
      id: repoId,
      workspace_id: wsId,
      version: 2,
      created_at: "2026-10-28T01:00:00Z",
      updated_at: "2026-10-28T01:05:00Z",
      external_id: "70001",
      connection_id: connId,
      provider: "github",
      organization: "acme-corp",
      name: "acme-corp/service-api",
      default_branch: "main",
      visibility: "private",
      mode: "approval",
      paused: false,
      active: true,
      grant_review_required: false,
      policy_revision: 2,
      tags: ["tier-1", "python"],
      archived: false,
      is_fork: false,
      workflow_hazard_status: "clean",
      workflow_hazards: [],
      auto_repair_blocked: false,
      sync_status: "idle",
      last_synced_at: "2026-10-28T01:05:00Z",
      last_ci_conclusion: "failure",
      last_ci_at: "2026-10-28T01:04:00Z",
    };

    const samplePolicy = {
      branch_allowlist: ["main", "release/*"],
      branch_denylist: ["production/*"],
      file_allowlist: ["src/**"],
      file_denylist: ["vendor/**"],
      sensitive_rules: ["auth/**"],
      allow_test_edits: false,
      allow_config_edits: false,
      max_attempts: 3,
      max_diff_lines: 300,
      max_calls_per_session: 15,
      max_tokens_per_session: 80000,
      max_wall_seconds: 600,
      max_cost_per_session: { amount: "2.50", currency: "USD" },
      require_baseline: true as const,
      inference_consent_id: null,
      runtime_profile_id: "py312-linux",
    };

    const samplePolicyState = {
      repository_id: repoId,
      workspace_id: wsId,
      current_revision: 2,
      mode: "approval",
      paused: false,
      policy: samplePolicy,
      effective_policy: {
        mode: "approval",
        effective_mode: "approval",
        paused: false,
        effective_paused: false,
        allow_sandbox_execution: true,
        allow_auto_publication: false,
        require_baseline: true as const,
        auto_merge: false as const,
        branch_allowlist: ["main", "release/*"],
        branch_denylist: ["production/*"],
        file_allowlist: ["src/**"],
        file_denylist: ["vendor/**"],
        hard_denied_paths: [".env", ".git/**"],
        sensitive_rules: ["auth/**"],
        protected_paths: [".github/workflows/**", "uv.lock"],
        allow_test_edits: false,
        allow_config_edits: false,
        max_attempts: 3,
        max_diff_lines: 300,
        max_calls_per_session: 15,
        max_tokens_per_session: 80000,
        max_wall_seconds: 600,
        max_cost_per_session: { amount: "2.50", currency: "USD" },
        inference_consent_id: null,
        runtime_profile_id: "py312-linux",
        field_sources: { mode: "repository", max_attempts: "repository" },
      },
      readiness_gates: {
        auto_repair_eligible: true,
        worker_isolation_ready: true,
        inference_consent_ready: true,
        workflow_hazard_blocked: false,
        grant_review_required: false,
        instance_paused: false,
        workspace_paused: false,
        blocking_reasons: [],
      },
      revisions: [],
    };

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      getCsrfToken: () => "csrf-u12-token",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        seenHeaders.push({
          path: url.pathname,
          method: request.method,
          ifMatch: request.headers.get("If-Match"),
          csrf: request.headers.get("X-CSRF-Token"),
        });

        if (request.method === "GET" && url.pathname === "/api/v1/workspaces/acme/repositories") {
          assert.equal(url.searchParams.get("mode"), "approval");
          assert.equal(url.searchParams.get("tag"), "tier-1");
          return new Response(
            JSON.stringify({
              items: [sampleRepo],
              next_cursor: null,
              snapshot_at: "2026-10-28T01:06:00Z",
              facets: {
                tags: ["python", "tier-1"],
                organizations: ["acme-corp"],
                by_provider: { github: 1 },
                by_mode: { approval: 1 },
                paused_count: 0,
                hazard_flagged_count: 0,
                grant_review_required_count: 0,
                partial_sync_connection_ids: [],
              },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (
          request.method === "PATCH" &&
          url.pathname === `/api/v1/workspaces/acme/repositories/${repoId}/policy`
        ) {
          return new Response(JSON.stringify({ ...samplePolicyState, current_revision: 3 }), {
            status: 200,
            headers: { "Content-Type": "application/json", ETag: '"v3"' },
          });
        }
        if (
          request.method === "POST" &&
          url.pathname === `/api/v1/workspaces/acme/repositories/${repoId}/policy/previews`
        ) {
          return new Response(
            JSON.stringify({
              repository_id: repoId,
              current_revision: 2,
              next_revision: 3,
              can_apply: true,
              requires_step_up: false,
              effective_policy: samplePolicyState.effective_policy,
              readiness_gates: samplePolicyState.readiness_gates,
              changed_rules: [],
              denials: [],
              branch_evaluations: [
                {
                  branch: "main",
                  canonical_branch: "main",
                  verdict: "requires_approval",
                  matched_rule: "main",
                  source_layer: "repository",
                  reason: "Approval mode requires human review.",
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
                  reason: "Protected workflow file requires human approval.",
                },
              ],
              diff_lines_verdict: "allow",
              diff_lines_reason: "40 <= 300",
              historical_run_simulations: [],
              affected_in_flight: [],
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const catalog = await client.listRepositories("acme", { mode: "approval", tag: "tier-1" });
    assert.equal(catalog.data.items.length, 1);
    assert.deepEqual(catalog.data.facets?.tags, ["python", "tier-1"]);

    const updatedPolicy = await client.updateRepositoryPolicy(
      "acme",
      repoId,
      { expected_revision: 2, mode: "approval", paused: false, policy: samplePolicy },
      { ifMatch: '"v2"' },
    );
    assert.equal(updatedPolicy.etag, '"v3"');
    assert.equal(seenHeaders[1]?.ifMatch, '"v2"');
    assert.equal(seenHeaders[1]?.csrf, "csrf-u12-token");

    const preview = await client.previewRepositoryPolicy("acme", repoId, {
      mode: "approval",
      paused: false,
      policy: samplePolicy,
      sample_branches: ["main"],
      sample_paths: [".github/workflows/ci.yml"],
      sample_diff_lines: 40,
    });
    assert.equal(preview.data.can_apply, true);
    assert.equal(preview.data.path_evaluations?.[0]?.verdict, "requires_approval");
  });

  it("serializes U13 A-08 runs/jobs/logs and A-10 binary artifact downloads with 410 errors", async () => {
    const wsId = "019a2500-0000-7000-8000-000000001301";
    const repoId = "019a2500-0000-7000-8000-000000001302";
    const runId = "019a2500-0000-7000-8000-000000001303";
    const jobId = "019a2500-0000-7000-8000-000000001304";
    const expiredJobId = "019a2500-0000-7000-8000-000000001305";
    const artifactId = "019a2500-0000-7000-8000-000000001306";

    const sampleRun = {
      id: runId,
      workspace_id: wsId,
      repository_id: repoId,
      version: 1,
      created_at: "2026-10-28T04:00:00Z",
      updated_at: "2026-10-28T04:01:00Z",
      external_id: "9801001",
      attempt_key: "attempt:2",
      attempt_number: 2,
      provider: "github" as const,
      repository_name: "acme/core-service",
      head_sha: "a".repeat(40),
      head_sha_verified: true,
      ref: "refs/heads/main",
      event_type: "push",
      status: "completed" as const,
      conclusion: "failure" as const,
      jobs_complete: true,
      ingestion_state: "ingested" as const,
      flaky_classification: "single_pass_unproven" as const,
      flaky_job_count: 0,
      failed_job_count: 1,
      artifact_count: 1,
      child_pipeline_ids: [],
    };

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      fetch: async (request) => {
        const url = new URL(request.url);
        if (request.method === "GET" && url.pathname === "/api/v1/workspaces/acme/runs") {
          return new Response(
            JSON.stringify({
              items: [sampleRun],
              next_cursor: null,
              snapshot_at: "2026-10-28T04:02:00Z",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (
          request.method === "GET" &&
          url.pathname === `/api/v1/workspaces/acme/runs/${runId}`
        ) {
          return new Response(
            JSON.stringify({
              run: sampleRun,
              sibling_attempts: [sampleRun],
              jobs: [
                {
                  id: jobId,
                  workspace_id: wsId,
                  repository_id: repoId,
                  version: 1,
                  created_at: "2026-10-28T04:00:10Z",
                  updated_at: "2026-10-28T04:00:55Z",
                  run_id: runId,
                  external_id: "7701",
                  name: "pytest (py312, linux)",
                  status: "completed",
                  conclusion: "failure",
                  matrix_dimensions: { python: "py312", os: "linux" },
                  log_status: "available",
                  log_size_bytes: 128,
                  log_truncated: false,
                  flaky_classification: "single_pass_unproven",
                },
              ],
              artifacts: [
                {
                  id: artifactId,
                  workspace_id: wsId,
                  repository_id: repoId,
                  version: 1,
                  created_at: "2026-10-28T04:00:58Z",
                  updated_at: "2026-10-28T04:00:58Z",
                  kind: "junit_xml",
                  name: "junit-results.zip",
                  run_id: runId,
                  mime: "application/zip",
                  size_bytes: 4,
                  digest: "b".repeat(64),
                  redaction_version: 1,
                  access_class: "workspace_internal",
                  retention_until: "2026-11-27T04:00:58Z",
                  available: true,
                },
              ],
              fingerprints: [],
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (
          request.method === "GET" &&
          url.pathname === `/api/v1/workspaces/acme/jobs/${expiredJobId}/log`
        ) {
          return new Response(
            JSON.stringify({
              type: "https://red2pr.local/problems/log_expired",
              title: "Gone",
              status: 410,
              code: "log_expired",
              detail: "Upstream CI job log has expired.",
              correlation_id: "corr-u13-410",
            }),
            { status: 410, headers: { "Content-Type": "application/problem+json" } },
          );
        }
        if (
          request.method === "GET" &&
          url.pathname === `/api/v1/workspaces/acme/artifacts/${artifactId}/download`
        ) {
          return new Response(new Uint8Array([0x50, 0x4b, 0x03, 0x04]), {
            status: 200,
            headers: {
              "Content-Type": "application/zip",
              "Content-Disposition": 'attachment; filename="junit-results.zip"',
              "X-Correlation-Id": "corr-u13-dl",
            },
          });
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const runs = await client.listRuns("acme", { repository_id: repoId });
    assert.equal(runs.data.items.length, 1);
    assert.equal(runs.data.items[0]?.flaky_classification, "single_pass_unproven");

    const detail = await client.getRun("acme", runId);
    assert.equal(detail.data.jobs?.[0]?.matrix_dimensions?.python, "py312");
    assert.equal("storage_ref" in (detail.data.artifacts?.[0] ?? {}), false);

    await assert.rejects(
      () => client.getJobLog("acme", expiredJobId),
      (err: unknown) =>
        err instanceof Red2PrApiError && err.status === 410 && err.problem.code === "log_expired",
    );

    const downloaded = await client.downloadArtifact("acme", artifactId);
    assert.equal(downloaded.data.filename, "junit-results.zip");
    assert.equal(downloaded.data.bytes.byteLength, 4);
  });

  it("serializes U14 A-13 isolated worker fleet, enrollment, actions, self-test & UI-S13 readiness", async () => {
    const workerId = "019a2900-0000-7000-8000-000000000101";
    const enrollId = "019a2900-0000-7000-8000-000000000202";
    const opId = "019a2900-0000-7000-8000-000000000303";
    const wsId = "019a2900-0000-7000-8000-000000000001";
    const seenHeaders: Array<{ idemKey: string | null; ifMatch: string | null; csrf: string | null }> =
      [];

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      getCsrfToken: () => "csrf-u14-token",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        seenHeaders.push({
          idemKey: request.headers.get("Idempotency-Key"),
          ifMatch: request.headers.get("If-Match"),
          csrf: request.headers.get("X-CSRF-Token"),
        });

        if (request.method === "GET" && url.pathname === "/api/v1/system/workers") {
          assert.equal(url.searchParams.get("status"), "online");
          return new Response(
            JSON.stringify({
              items: [
                {
                  id: workerId,
                  version: 1,
                  created_at: "2026-10-28T06:00:00Z",
                  updated_at: "2026-10-28T06:00:00Z",
                  trust_domain: "red2pr.internal",
                  profile_ids: ["python-3.12-node-22"],
                  status: "online",
                  isolation_mode: "vm_isolated",
                  runtime_name: "firecracker-rootless",
                  heartbeat_at: "2026-10-28T06:00:10Z",
                  cpu_limit: 4,
                  memory_limit_bytes: 8589934592,
                  disk_limit_bytes: 42949672960,
                  pids_limit: 512,
                  signer_key_id: "ed25519-worker-01",
                  mtls_cert_fingerprint_sha256: "a".repeat(64),
                  mtls_cert_expires_at: "2026-10-29T06:00:00Z",
                  active_leases: 0,
                  host_escape_warning: false,
                },
              ],
              next_cursor: null,
              snapshot_at: "2026-10-28T06:00:12Z",
              summary: {
                total_count: 1,
                online_count: 1,
                draining_count: 0,
                quarantined_count: 0,
                offline_count: 0,
                vm_isolated_count: 1,
                trusted_local_warning_count: 0,
                active_leases_count: 0,
              },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (request.method === "POST" && url.pathname === "/api/v1/system/workers/enrollments") {
          return new Response(
            JSON.stringify({
              enrollment_id: enrollId,
              enrollment_token: "r2p_wenr_onetime_token_value_123456",
              expires_at: "2026-10-28T06:15:00Z",
              ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
              trust_domain: "red2pr.internal",
              isolation_mode: "vm_isolated",
              profile_ids: ["python-3.12-node-22"],
              host_escape_warning: false,
            }),
            { status: 201, headers: { "Content-Type": "application/json" } },
          );
        }
        if (
          request.method === "POST" &&
          url.pathname === `/api/v1/system/workers/${workerId}/actions`
        ) {
          return new Response(
            JSON.stringify({
              operation_id: opId,
              resource_id: workerId,
              state: "succeeded",
              correlation_id: "corr-u14-act",
              status_url: `/api/v1/operations/${opId}`,
              result_id: workerId,
            }),
            { status: 202, headers: { "Content-Type": "application/json" } },
          );
        }
        if (
          request.method === "POST" &&
          url.pathname === `/api/v1/system/workers/${workerId}/self-test`
        ) {
          return new Response(
            JSON.stringify({
              worker_id: workerId,
              passed: true,
              checked_at: "2026-10-28T06:01:00Z",
              isolation_mode: "vm_isolated",
              detail: "All worker mTLS and confinement checks passed.",
              checks: [
                { check_id: "mtls_identity", passed: true, detail: "Active X.509 SPIFFE cert." },
              ],
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (request.method === "GET" && url.pathname === "/api/v1/workspaces/acme/workers/readiness") {
          return new Response(
            JSON.stringify({
              workspace_id: wsId,
              ready: true,
              eligible_online_workers: 1,
              available_profiles: ["python-3.12-node-22"],
              vm_isolation_available: true,
              trusted_local_warning: false,
              active_workspace_leases: [],
              degraded_reason: null,
              snapshot_at: "2026-10-28T06:01:05Z",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const workers = await client.listSystemWorkers({ status: "online" });
    assert.equal(workers.data.items.length, 1);
    assert.equal(workers.data.summary?.vm_isolated_count, 1);

    const enrollment = await client.createWorkerEnrollment({
      trust_domain: "red2pr.internal",
      profile_ids: ["python-3.12-node-22"],
      isolation_mode: "vm_isolated",
      ttl_minutes: 15,
      host_escape_risk_acknowledged: false,
    });
    assert.equal(enrollment.data.enrollment_id, enrollId);
    assert.equal(seenHeaders[1]?.csrf, "csrf-u14-token");

    const actionReceipt = await client.performWorkerAction(
      workerId,
      { action: "drain", reason: "Planned hypervisor kernel maintenance", expected_version: 1 },
      { idempotencyKey: "019a2900-0000-7000-8000-000000000999", ifMatch: '"v1"' },
    );
    assert.equal(actionReceipt.data.operation_id, opId);
    assert.equal(seenHeaders[2]?.idemKey, "019a2900-0000-7000-8000-000000000999");
    assert.equal(seenHeaders[2]?.ifMatch, '"v1"');

    const selfTest = await client.runWorkerSelfTest(workerId);
    assert.equal(selfTest.data.passed, true);

    const readiness = await client.getWorkspaceWorkerReadiness("acme");
    assert.equal(readiness.data.ready, true);
    assert.equal(readiness.data.vm_isolation_available, true);
  });

  it("types U15 S-21 & S-22 RunnerProfileManifest, ReproductionRunRecord, and FidelityGrade contracts", () => {
    const grade: FidelityGrade = "F3_VALIDATED";
    const manifest: RunnerProfileManifest = {
      schema_version: 1,
      profile_id: "python-pytest-linux",
      revision: 1,
      display_name: "Certified Linux Python pytest",
      ecosystem: "python",
      platform: "linux/amd64",
      base_image: "ghcr.io/red2pr/runner-python-pytest:3.12-bookworm",
      image_digest: "a".repeat(64),
      supported_lockfiles: ["uv.lock", "poetry.lock", "requirements.txt"],
      env_allowlist: ["PYTHONDONTWRITEBYTECODE", "PIP_NO_INDEX"],
      default_env: { PYTHONDONTWRITEBYTECODE: "1", PIP_NO_INDEX: "1" },
      requires_isolated_vm_tier: false,
      requires_admin_opt_in: false,
      commands: [
        {
          command_id: "pytest-repro",
          phase: "reproduce",
          argv: ["pytest", "-q", "--tb=short"],
          network_egress_allowed: false,
          description: "Execute pytest reproduction in offline sandbox",
        },
      ],
    };
    const record: ReproductionRunRecord = {
      id: "019a2a00-0000-7000-8000-000000000001",
      workspace_id: "019a2a00-0000-7000-8000-000000000002",
      repository_id: "019a2a00-0000-7000-8000-000000000003",
      repair_id: "019a2a00-0000-7000-8000-000000000004",
      ci_run_id: "019a2a00-0000-7000-8000-000000000005",
      ci_job_id: "019a2a00-0000-7000-8000-000000000006",
      phase: "baseline_a",
      baseline_reproduction_id: null,
      sandbox_job_id: "019a2a00-0000-7000-8000-000000000007",
      sandbox_lease_id: "019a2a00-0000-7000-8000-000000000008",
      profile_id: manifest.profile_id,
      profile_revision: manifest.revision,
      profile_digest: "b".repeat(64),
      image_digest: manifest.image_digest,
      base_sha: "c".repeat(40),
      source_archive_digest: "d".repeat(64),
      dependency_lock_digest: "e".repeat(64),
      cache_key: "019a2a00-0000-7000-8000-000000000002:python-pytest-linux:" + "e".repeat(64),
      patch_digest: null,
      command_ids: ["pytest-repro"],
      command_digest: "1".repeat(64),
      environment_digest: "f".repeat(64),
      expected_fingerprint_hash: "2".repeat(64),
      observed_fingerprint_hash: "2".repeat(64),
      fingerprint_matched: true,
      executed_tests_count: 12,
      passed_tests_count: 11,
      failed_tests_count: 1,
      skipped_tests_count: 0,
      exit_code: 1,
      termination: "exited",
      status: "repro_confirmed",
      fidelity_grade: grade,
      fidelity_differences: [],
      handoff_outcome: "proceed_to_patch",
      allow_patching: true,
      allow_publication: false,
      failure_reason_code: null,
      failure_detail: null,
      result_digest: "3".repeat(64),
      artifact_refs: [],
      immutable_sealed: true,
      started_at: "2026-10-28T09:00:00Z",
      finished_at: "2026-10-28T09:00:12Z",
      version: 2,
      created_at: "2026-10-28T09:00:00Z",
      updated_at: "2026-10-28T09:00:12Z",
    };

    assert.equal(manifest.commands[0]?.network_egress_allowed, false);
    assert.equal(record.fidelity_grade, "F3_VALIDATED");
    assert.equal(record.allow_patching, true);
    assert.equal(record.immutable_sealed, true);
  });

  it("serializes U16 A-20 & S-17 Meta models, consents, budgets, and paid capability probes", async () => {
    const wsId = "019a2b00-0000-7000-8000-000000000001";
    const consentId = "019a2b00-0000-7000-8000-000000000101";
    const acctId = "019a2b00-0000-7000-8000-000000000201";
    const snapId = "019a2b00-0000-7000-8000-000000000301";
    const opId = "019a2b00-0000-7000-8000-000000000401";
    const calls: Array<{ method: string; path: string; idem: string | null; ifMatch: string | null }> = [];

    const unknownUsage: ModelUsageRecord = {
      id: "019a2b00-0000-7000-8000-000000000501",
      workspace_id: wsId,
      repository_id: null,
      version: 1,
      created_at: "2026-10-28T14:00:00Z",
      updated_at: "2026-10-28T14:00:00Z",
      reservation_id: "019a2b00-0000-7000-8000-000000000601",
      provider_request_id: null,
      model_id: "muse-spark-1.3",
      input_tokens: null,
      output_tokens: null,
      estimated_cost: { amount: "0.120000", currency: "USD" },
      settled_cost: null,
      currency: "USD",
      pricing_revision: "meta-2026-10",
      status: "unknown",
    };

    const modelsPayload: WorkspaceModelsResponse = {
      workspace_id: wsId,
      version: 2,
      updated_at: "2026-10-28T14:00:00Z",
      endpoint_base_url: "https://api.meta.ai/v1",
      endpoint_registration_id: null,
      api_key_presence: { configured: true, secret_version: 1 },
      active_inference_consent_id: consentId,
      inference_consent_active: true,
      available_inference_consents: [],
      suspension_reason: null,
      status_detail: null,
      retry_after_seconds: null,
      ready_for_repair_inference: true,
      models: [
        {
          model_id: "muse-spark-1.3",
          display_name: "Muse Spark 1.3",
          vendor: "meta",
          tier_role: "primary",
          enabled: true,
          status: "available",
          pricing: {
            pricing_revision: "meta-2026-10",
            input_per_1m_tokens: { amount: "0.500000", currency: "USD" },
            output_per_1m_tokens: { amount: "2.000000", currency: "USD" },
            configured: true,
          },
          latest_snapshot: null,
        },
      ],
      budget_policy: {
        max_calls_per_session: 30,
        max_tokens_per_session: 120000,
        max_patch_attempts: 2,
        max_wall_seconds: 1800,
        max_cost_per_session: { amount: "5.000000", currency: "USD" },
        daily_workspace_cap: { amount: "25.000000", currency: "USD" },
        alert_threshold_percent: 80,
      },
      escalation_policy: {
        escalation_enabled: false,
        escalation_model_id: "muse-wonder-1.0",
        escalate_after_failed_attempts: 1,
        require_probed_availability: true,
        allow_non_meta_fallback: false,
      },
      workspace_budget: {
        id: acctId,
        workspace_id: wsId,
        repository_id: null,
        version: 1,
        created_at: "2026-10-28T00:00:00Z",
        updated_at: "2026-10-28T14:00:00Z",
        scope_kind: "workspace_daily",
        scope_key: "daily:2026-10-28",
        currency: "USD",
        cost_cap: { amount: "25.000000", currency: "USD" },
        reserved_cost: { amount: "0.000000", currency: "USD" },
        settled_cost: { amount: "0.000402", currency: "USD" },
        unknown_cost: { amount: "0.120000", currency: "USD" },
        remaining_cost: { amount: "24.879598", currency: "USD" },
        token_cap: 2400000,
        reserved_tokens: 0,
        settled_tokens: 516,
        unknown_tokens: 5000,
        call_cap: 600,
        reserved_calls: 0,
        settled_calls: 1,
        unknown_calls: 1,
        max_patch_attempts: 50,
        patch_attempts_used: 0,
        max_wall_seconds: 86400,
        window_started_at: "2026-10-28T00:00:00Z",
        window_ends_at: "2026-10-29T00:00:00Z",
        cancelled_at: null,
      },
      recent_usage: [unknownUsage],
    };

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      getCsrfToken: () => "csrf-u16",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        calls.push({
          method: request.method,
          path: url.pathname,
          idem: request.headers.get("Idempotency-Key"),
          ifMatch: request.headers.get("If-Match"),
        });
        if (request.method === "GET" && url.pathname === "/api/v1/workspaces/acme/models") {
          return new Response(JSON.stringify(modelsPayload), {
            status: 200,
            headers: { "Content-Type": "application/json", ETag: '"2"' },
          });
        }
        if (request.method === "PATCH" && url.pathname === "/api/v1/workspaces/acme/models/config") {
          return new Response(
            JSON.stringify({
              receipt: {
                operation_id: opId,
                resource_id: wsId,
                state: "succeeded",
                correlation_id: "corr-u16-cfg",
                status_url: `/api/v1/operations/${opId}`,
                result_id: wsId,
              },
              models_state: modelsPayload,
            }),
            { status: 200, headers: { "Content-Type": "application/json", ETag: '"3"' } },
          );
        }
        if (request.method === "POST" && url.pathname === "/api/v1/workspaces/acme/model-probes") {
          return new Response(
            JSON.stringify({
              receipt: {
                operation_id: opId,
                resource_id: snapId,
                state: "succeeded",
                correlation_id: "corr-u16-probe",
                status_url: `/api/v1/operations/${opId}`,
                result_id: snapId,
              },
              snapshot: {
                id: snapId,
                workspace_id: wsId,
                repository_id: null,
                version: 1,
                created_at: "2026-10-28T14:00:00Z",
                updated_at: "2026-10-28T14:00:00Z",
                model_id: "muse-spark-1.3",
                tier_role: "primary",
                status: "available",
                capabilities: {
                  structured_output: true,
                  tool_calling: true,
                  reasoning_effort: true,
                  vision: false,
                },
                provider_request_id: "req_spark_01",
                consent_id: consentId,
                probed_at: "2026-10-28T14:00:00Z",
                status_detail: "OK",
                suspension_reason: null,
                retry_after_seconds: null,
              },
              usage_record: null,
              models_state: modelsPayload,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const listed = await client.listWorkspaceModels("acme");
    assert.equal(listed.etag, '"2"');
    assert.equal(listed.data.recent_usage?.[0]?.status, "unknown");
    assert.equal(listed.data.recent_usage?.[0]?.settled_cost, null);

    await client.updateWorkspaceModelsConfig(
      "acme",
      {
        api_key: "meta-write-only-key",
        revoke_api_key: false,
        clear_endpoint_registration: false,
        clear_inference_consent: false,
        clear_suspension: false,
      },
      { idempotencyKey: "019a2b00-0000-7000-8000-000000000901", ifMatch: '"2"' },
    );

    const probed = await client.createWorkspaceModelProbe(
      "acme",
      {
        model_id: "muse-spark-1.3",
        consent_id: consentId,
        max_cost: { amount: "0.050000", currency: "USD" },
        max_output_tokens: 64,
      },
      { idempotencyKey: "019a2b00-0000-7000-8000-000000000902" },
    );
    assert.equal(probed.data.snapshot.status, "available");
    assert.equal(calls.length, 3);
    assert.equal(calls[1]?.ifMatch, '"2"');
    assert.equal(calls[2]?.idem, "019a2b00-0000-7000-8000-000000000902");
  });

  it("serializes U17 A-20 & S-20 workspace agent profiles and immutable capability matrix", async () => {
    const wsId = "019a2c00-0000-7000-8000-000000000001";
    const profileId = "019a2c00-0000-7000-8000-000000000101";
    const opId = "019a2c00-0000-7000-8000-000000000202";
    const calls: Array<{ method: string; path: string; idem: string | null; ifMatch: string | null }> = [];

    const diagProfile = {
      id: profileId,
      workspace_id: wsId,
      version: 1,
      created_at: "2026-10-28T16:00:00Z",
      updated_at: "2026-10-28T16:00:00Z",
      role_key: "triage_diagnosis" as const,
      display_name: "Triage & Diagnosis Agent",
      description: "Evidence-cited failure triage, abstention, and Sandbox A reproduction planning.",
      model_id: "muse-spark-1.3" as const,
      escalation_model_id: null,
      reasoning_effort: "medium" as const,
      allowed_tools: [
        "read_file",
        "search_repo",
        "read_log_excerpt",
        "read_commit_diff",
        "request_reproduction",
        "get_execution_result",
      ] as const,
      immutable_role_tool_ceiling: [
        "read_file",
        "search_repo",
        "read_log_excerpt",
        "read_commit_diff",
        "request_reproduction",
        "get_execution_result",
      ] as const,
      max_steps: 6,
      max_tool_calls_per_step: 4,
      max_schema_repair_retries: 2,
      arbitrary_prompt_override_allowed: false as const,
      enabled: true,
      updated_by_user_id: null,
    };

    const profilesPayload = {
      workspace_id: wsId,
      profiles: [diagProfile],
      tool_matrix: [
        {
          name: "read_file",
          category: "s20_allowed" as const,
          description: "Read bounded pinned file slice.",
          permitted_for_diagnosis: true,
          permitted_for_patch: true,
          immutable_reason: "Allowlisted S-20 read tool.",
        },
        {
          name: "publish",
          category: "prohibited" as const,
          description: "Create or update remote PRs/MRs.",
          permitted_for_diagnosis: false,
          permitted_for_patch: false,
          immutable_reason: "Forbidden by SEC-028; only Z2 publisher after policy + approval.",
        },
      ],
      prohibited_capabilities: [
        "publish",
        "merge",
        "approve",
        "rotate_secret",
        "edit_policy",
        "send_network_request",
        "run_host_shell",
      ],
      recent_steps: [],
      ready_for_repair_inference: true,
      suspension_reason: null,
    };

    const client = createRed2PrClient({
      baseUrl: "http://127.0.0.1:4280",
      getCsrfToken: () => "csrf-u17-token",
      fetch: async (request: Request) => {
        const url = new URL(request.url);
        calls.push({
          method: request.method,
          path: url.pathname,
          idem: request.headers.get("Idempotency-Key"),
          ifMatch: request.headers.get("If-Match"),
        });
        if (request.method === "GET" && url.pathname === "/api/v1/workspaces/acme/agent-profiles") {
          return new Response(JSON.stringify(profilesPayload), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (
          request.method === "GET" &&
          url.pathname === `/api/v1/workspaces/acme/agent-profiles/${profileId}`
        ) {
          return new Response(JSON.stringify(diagProfile), {
            status: 200,
            headers: { "Content-Type": "application/json", ETag: '"1"' },
          });
        }
        if (
          request.method === "PATCH" &&
          url.pathname === `/api/v1/workspaces/acme/agent-profiles/${profileId}`
        ) {
          const updated = { ...diagProfile, version: 2, reasoning_effort: "high" as const };
          return new Response(
            JSON.stringify({
              receipt: {
                operation_id: opId,
                resource_id: profileId,
                state: "succeeded",
                correlation_id: "corr-u17-prof",
                status_url: `/api/v1/operations/${opId}`,
                result_id: profileId,
              },
              profile: updated,
              profiles_state: { ...profilesPayload, profiles: [updated] },
            }),
            { status: 200, headers: { "Content-Type": "application/json", ETag: '"2"' } },
          );
        }
        throw new Error(`Unexpected ${request.method} ${url.pathname}`);
      },
    });

    const listed = await client.listWorkspaceAgentProfiles("acme");
    assert.equal(listed.data.prohibited_capabilities.includes("publish"), true);
    assert.equal(listed.data.profiles[0]?.arbitrary_prompt_override_allowed, false);

    const detail = await client.getWorkspaceAgentProfile("acme", profileId);
    assert.equal(detail.etag, '"1"');

    const updated = await client.updateWorkspaceAgentProfile(
      "acme",
      profileId,
      { expected_version: 1, reasoning_effort: "high", clear_escalation_model: false },
      { idempotencyKey: "019a2c00-0000-7000-8000-000000000901", ifMatch: '"1"' },
    );
    assert.equal(updated.data.profile.version, 2);
    assert.equal(updated.etag, '"2"');
    assert.equal(calls[2]?.ifMatch, '"1"');
    assert.equal(calls[2]?.idem, "019a2c00-0000-7000-8000-000000000901");
  });
});
