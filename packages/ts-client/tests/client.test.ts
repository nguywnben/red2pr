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
});
