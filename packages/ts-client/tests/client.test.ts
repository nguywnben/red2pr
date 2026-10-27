import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createRed2PrClient,
  Red2PrApiError,
  type Membership,
  type Problem,
  type RepositoryPolicy,
  type SetupState,
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
});
