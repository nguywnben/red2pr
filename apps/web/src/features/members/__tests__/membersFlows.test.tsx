import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter, useLocation } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AppRoutes } from "../../../app/App";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { THEME_STORAGE_KEY, ThemeProvider } from "../../../shared/theme";

const OWNER_USER_ID = "0196ed00-0000-7000-8000-000000000101";
const BOB_USER_ID = "0196ed00-0000-7000-8000-000000000102";
const SESSION_ID = "0196ed00-0000-7000-8000-000000000201";
const WS_ACME_ID = "0196ed00-0000-7000-8000-000000000301";
const WS_SECRET_ID = "0196ed00-0000-7000-8000-000000000302";
const WS_JOINED_ID = "0196ed00-0000-7000-8000-000000000303";
const MEM_ADMIN_ID = "0196ed00-0000-7000-8000-000000000401";
const MEM_BOB_ID = "0196ed00-0000-7000-8000-000000000402";
const INVITE_PENDING_ID = "0196ed00-0000-7000-8000-000000000501";
const INVITE_CREATED_ID = "0196ed00-0000-7000-8000-000000000502";
const BG_GRANT_ID = "0196ed00-0000-7000-8000-000000000601";
const REPO_ONE_ID = "0196ed00-0000-7000-8000-000000000901";
const REPO_TWO_ID = "0196ed00-0000-7000-8000-000000000902";
const NOW_ISO = "2026-10-27T10:00:00Z";
const EXPIRES_ISO = "2026-10-27T22:00:00Z";

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
    "X-Correlation-Id": init.correlationId ?? "corr-u06-test-01",
    ...(init.extraHeaders ?? {}),
  });
  return new Response(body === null ? null : JSON.stringify(body), { status, headers });
}

function problemResponse(params: {
  status: number;
  code: string;
  title: string;
  detail: string;
  correlationId?: string;
}): Response {
  const cid = params.correlationId ?? "corr-u06-err-01";
  return jsonResponse(
    {
      type: `https://red2pr.local/problems/${params.code}`,
      title: params.title,
      status: params.status,
      code: params.code,
      detail: params.detail,
      correlation_id: cid,
      errors: null,
    },
    {
      status: params.status,
      correlationId: cid,
      contentType: "application/problem+json",
    },
  );
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

function LocationProbe(): React.JSX.Element {
  const location = useLocation();
  return <div data-testid="router-location">{`${location.pathname}${location.search}`}</div>;
}

function renderAppRouter(opts: {
  initialEntry: string;
  fetchImpl: typeof fetch;
  themeMode?: "light" | "dark";
}) {
  const queryClient = createWorkspaceQueryClient();
  const rendered = render(
    <I18nProvider>
      <ThemeProvider defaultMode={opts.themeMode ?? "light"}>
        <ApiClientProvider
          queryClient={queryClient}
          clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: opts.fetchImpl }}
        >
          <MemoryRouter initialEntries={[opts.initialEntry]}>
            <LocationProbe />
            <AppRoutes />
          </MemoryRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
  return { ...rendered, queryClient };
}

function assertZeroWebStorageSecrets(): void {
  for (let i = 0; i < window.localStorage.length; i += 1) {
    const key = window.localStorage.key(i);
    expect(key).toBe(THEME_STORAGE_KEY);
    const val = key ? window.localStorage.getItem(key) : null;
    expect(["light", "dark", "system"]).toContain(val);
  }
  expect(window.sessionStorage.length).toBe(0);
}

function buildMePayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    user: {
      id: OWNER_USER_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      display_name: "Alice Admin",
      email: "alice@example.org",
      status: "active",
    },
    session: {
      id: SESSION_ID,
      version: 1,
      created_at: NOW_ISO,
      updated_at: NOW_ISO,
      user_id: OWNER_USER_ID,
      expires_at: EXPIRES_ISO,
      auth_strength: "mfa",
      step_up_at: NOW_ISO,
      grant_epoch: 1,
    },
    is_instance_owner: false,
    mfa_enabled: true,
    mfa_required_for_privileged: true,
    step_up_valid_until: "2099-01-01T00:05:00Z",
    csrf_token: "csrf.u06.session.token.0001",
    workspaces: [
      {
        id: WS_ACME_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        slug: "acme",
        name: "Acme Corp",
        paused: false,
        default_policy_version: 1,
      },
    ],
    memberships: [
      {
        id: MEM_ADMIN_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        workspace_id: WS_ACME_ID,
        user_id: OWNER_USER_ID,
        role: "admin",
        repository_grants: [],
      },
    ],
    telegram_link: { status: "not_configured" },
    ...overrides,
  };
}

describe("U06 Multi-Workspace Route Guards, Members & Access UI, Break-Glass & Live SSE Revocation (UI-S19, FE-02, UX-ACCESS-001, SEC-032)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("redirects anonymous direct navigation on /w/:ws/members to /login?next=... (FE-02)", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me" && req.method === "GET") {
        return problemResponse({
          status: 401,
          code: "unauthenticated",
          title: "Authentication required",
          detail: "Sign in to access this workspace.",
        });
      }
      if (url.pathname === "/api/v1/auth/csrf" && req.method === "GET") {
        return jsonResponse({
          csrf_token: "anon.csrf.token.u06",
          bootstrap_claim_required: false,
        });
      }
      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    renderAppRouter({
      initialEntry: "/w/acme/members?filter=pending",
      fetchImpl: fetchMock,
    });

    await waitFor(() => {
      expect(screen.getByTestId("router-location")).toHaveTextContent(
        "/login?next=%2Fw%2Facme%2Fmembers%3Ffilter%3Dpending",
      );
    });
    expect(
      await screen.findByRole("heading", { name: /Sign in to Red2PR/i }),
    ).toBeInTheDocument();
    assertZeroWebStorageSecrets();
  });

  it("blocks non-member workspace navigation with zero metadata leakage and allows switching to an authorized workspace (FE-02, UX-ACCESS-001)", async () => {
    const user = userEvent.setup();

    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me" && req.method === "GET") {
        return jsonResponse(buildMePayload({ is_instance_owner: false }));
      }
      if (url.pathname === "/api/v1/workspaces/secret-tenant" && req.method === "GET") {
        return problemResponse({
          status: 404,
          code: "workspace_not_found",
          title: "Not Found",
          detail: "Workspace not found.",
          correlationId: "corr-404-secret",
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme" && req.method === "GET") {
        return jsonResponse({
          id: WS_ACME_ID,
          version: 1,
          created_at: NOW_ISO,
          updated_at: NOW_ISO,
          slug: "acme",
          name: "Acme Corp",
          paused: false,
          default_policy_version: 1,
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme/events" && req.method === "GET") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/members" && req.method === "GET") {
        return jsonResponse({
          items: [
            {
              id: MEM_ADMIN_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              workspace_id: WS_ACME_ID,
              user_id: OWNER_USER_ID,
              user: {
                id: OWNER_USER_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                display_name: "Alice Admin",
                email: "alice@example.org",
                status: "active",
              },
              role: "admin",
              repository_grants: [],
            },
          ],
          next_cursor: null,
          snapshot_at: NOW_ISO,
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme/invitations" && req.method === "GET") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === "/api/v1/workspaces/acme/break-glass" && req.method === "GET") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
      }
      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    renderAppRouter({
      initialEntry: "/w/secret-tenant/members",
      fetchImpl: fetchMock,
    });

    const guard = await screen.findByTestId("workspace-access-guard");
    expect(guard).toBeInTheDocument();
    expect(screen.queryByTestId("owner-break-glass-panel")).not.toBeInTheDocument();

    await user.click(within(guard).getByRole("button", { name: /Open Acme Corp/i }));

    await waitFor(() => {
      expect(screen.getByTestId("router-location")).toHaveTextContent("/w/acme/members");
    });
    expect(await screen.findByTestId("members-page")).toBeInTheDocument();
  });

  it("enforces ADR-034 Instance Owner step-up break-glass activation, read-only banner, and early break-glass revocation", async () => {
    const user = userEvent.setup();
    let breakGlassActive = false;
    let stepUpVerified = false;
    const seenCsrfHeaders: (string | null)[] = [];

    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me" && req.method === "GET") {
        return jsonResponse(
          buildMePayload({
            is_instance_owner: true,
            mfa_enabled: false,
            step_up_valid_until: stepUpVerified ? "2099-01-01T00:05:00Z" : null,
            csrf_token: stepUpVerified
              ? "csrf.u06.rotated.stepup.0002"
              : "csrf.u06.session.token.0001",
            memberships: [],
          }),
        );
      }
      if (url.pathname === "/api/v1/workspaces/secret-tenant" && req.method === "GET") {
        if (!breakGlassActive) {
          return problemResponse({
            status: 404,
            code: "workspace_not_found",
            title: "Not Found",
            detail: "Workspace not found.",
          });
        }
        return jsonResponse({
          id: WS_SECRET_ID,
          version: 1,
          created_at: NOW_ISO,
          updated_at: NOW_ISO,
          slug: "secret-tenant",
          name: "Secret Tenant",
          paused: false,
          default_policy_version: 1,
        });
      }
      if (url.pathname === "/api/v1/auth/step-up" && req.method === "POST") {
        seenCsrfHeaders.push(req.headers.get("X-CSRF-Token"));
        stepUpVerified = true;
        return jsonResponse({
          session: {
            id: SESSION_ID,
            version: 2,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            user_id: OWNER_USER_ID,
            expires_at: EXPIRES_ISO,
            auth_strength: "password",
            step_up_at: NOW_ISO,
            grant_epoch: 1,
          },
          step_up_valid_until: "2099-01-01T00:05:00Z",
          csrf_token: "csrf.u06.rotated.stepup.0002",
        });
      }
      if (
        url.pathname === "/api/v1/workspaces/secret-tenant/break-glass" &&
        req.method === "POST"
      ) {
        seenCsrfHeaders.push(req.headers.get("X-CSRF-Token"));
        const body = (await req.json()) as { reason: string; duration_minutes: number };
        expect(body.reason).toBe("Investigating webhook incident #402");
        expect(body.duration_minutes).toBe(30);
        breakGlassActive = true;
        return jsonResponse(
          {
            id: BG_GRANT_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            workspace_id: WS_SECRET_ID,
            user_id: OWNER_USER_ID,
            reason: body.reason,
            expires_at: EXPIRES_ISO,
            revoked_at: null,
            active: true,
          },
          { status: 201 },
        );
      }
      if (url.pathname === "/api/v1/workspaces/secret-tenant/events" && req.method === "GET") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/secret-tenant/members" && req.method === "GET") {
        return jsonResponse({
          items: [
            {
              id: MEM_BOB_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              workspace_id: WS_SECRET_ID,
              user_id: BOB_USER_ID,
              user: {
                id: BOB_USER_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                display_name: "Bob SecAdmin",
                email: "bob@example.org",
                status: "active",
              },
              role: "admin",
              repository_grants: [],
            },
          ],
          next_cursor: null,
          snapshot_at: NOW_ISO,
        });
      }
      if (url.pathname === "/api/v1/workspaces/secret-tenant/invitations" && req.method === "GET") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === "/api/v1/workspaces/secret-tenant/break-glass" && req.method === "GET") {
        return jsonResponse({
          items: [
            {
              id: BG_GRANT_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              workspace_id: WS_SECRET_ID,
              user_id: OWNER_USER_ID,
              reason: "Investigating webhook incident #402",
              expires_at: EXPIRES_ISO,
              revoked_at: null,
              active: true,
            },
          ],
          next_cursor: null,
          snapshot_at: NOW_ISO,
        });
      }
      if (
        url.pathname === `/api/v1/workspaces/secret-tenant/break-glass/${BG_GRANT_ID}` &&
        req.method === "DELETE"
      ) {
        seenCsrfHeaders.push(req.headers.get("X-CSRF-Token"));
        breakGlassActive = false;
        return jsonResponse(null, { status: 204 });
      }
      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    renderAppRouter({
      initialEntry: "/w/secret-tenant/members",
      fetchImpl: fetchMock,
    });

    const bgPanel = await screen.findByTestId("owner-break-glass-panel");
    expect(bgPanel).toBeInTheDocument();

    await user.type(
      within(bgPanel).getByLabelText(/Mandatory audit reason/i),
      "Investigating webhook incident #402",
    );
    await user.click(
      within(bgPanel).getByRole("button", { name: /Activate audited break-glass read access/i }),
    );

    const stepUpDialog = await screen.findByTestId("step-up-dialog");
    await user.type(within(stepUpDialog).getByLabelText(/Current password/i), "OwnerPass!2026#99");
    await user.click(within(stepUpDialog).getByRole("button", { name: /Verify step-up/i }));

    expect(await screen.findByTestId("break-glass-active-banner")).toBeInTheDocument();
    expect(screen.getByTestId("effective-role-badge")).toHaveTextContent("break_glass");
    // Break-glass is strictly read-only: zero admin mutation buttons!
    expect(screen.queryByRole("button", { name: /Invite member/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Edit access/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Remove$/i })).not.toBeInTheDocument();

    // Early break-glass revocation reverts workspace access back to 404 guard
    await user.click(screen.getByRole("button", { name: /Revoke break-glass/i }));
    expect(await screen.findByTestId("workspace-access-guard")).toBeInTheDocument();
    expect(seenCsrfHeaders).toEqual([
      "csrf.u06.session.token.0001",
      "csrf.u06.rotated.stepup.0002",
      "csrf.u06.rotated.stepup.0002",
    ]);
    assertZeroWebStorageSecrets();
  });

  it(
    "supports admin invitation once-only token display, invitation revocation, If-Match member update, 409 last_admin rollback, invite redemption, and zero axe violations in light & dark themes (UI-S19)",
    async () => {
    const user = userEvent.setup();
    const patchHeaders: { ifMatch: string | null; csrf: string | null; body: unknown }[] = [];
    let bobRole: "maintainer" | "reviewer" = "reviewer";
    let bobRepos: string[] = [REPO_ONE_ID];
    let bobVersion = 1;
    let inviteRevoked = false;

    const makeFetchMock = () =>
      vi.fn<typeof fetch>(async (input, init) => {
        const req = input instanceof Request ? input : new Request(input, init);
        const url = new URL(req.url);

        if (url.pathname === "/api/v1/me" && req.method === "GET") {
          return jsonResponse(buildMePayload());
        }
        if (url.pathname === "/api/v1/workspaces/acme" && req.method === "GET") {
          return jsonResponse({
            id: WS_ACME_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            slug: "acme",
            name: "Acme Corp",
            paused: false,
            default_policy_version: 1,
          });
        }
        if (url.pathname === "/api/v1/workspaces/acme/events" && req.method === "GET") {
          return sseIdleConnectedResponse();
        }
        if (url.pathname === "/api/v1/workspaces/acme/members" && req.method === "GET") {
          return jsonResponse({
            items: [
              {
                id: MEM_ADMIN_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                workspace_id: WS_ACME_ID,
                user_id: OWNER_USER_ID,
                user: {
                  id: OWNER_USER_ID,
                  version: 1,
                  created_at: NOW_ISO,
                  updated_at: NOW_ISO,
                  display_name: "Alice Admin",
                  email: "alice@example.org",
                  status: "active",
                },
                role: "admin",
                repository_grants: [],
              },
              {
                id: MEM_BOB_ID,
                version: bobVersion,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                workspace_id: WS_ACME_ID,
                user_id: BOB_USER_ID,
                user: {
                  id: BOB_USER_ID,
                  version: 1,
                  created_at: NOW_ISO,
                  updated_at: NOW_ISO,
                  display_name: "Bob Reviewer",
                  email: "bob@example.org",
                  status: "active",
                },
                role: bobRole,
                repository_grants: bobRepos,
              },
            ],
            next_cursor: null,
            snapshot_at: NOW_ISO,
          });
        }
        if (url.pathname === "/api/v1/workspaces/acme/invitations" && req.method === "GET") {
          return jsonResponse({
            items: [
              {
                id: INVITE_PENDING_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                workspace_id: WS_ACME_ID,
                email: "pending.dev@example.org",
                role: "viewer",
                repository_grants: [],
                expires_at: EXPIRES_ISO,
                status: inviteRevoked ? "revoked" : "pending",
              },
            ],
            next_cursor: null,
            snapshot_at: NOW_ISO,
          });
        }
        if (url.pathname === "/api/v1/workspaces/acme/break-glass" && req.method === "GET") {
          return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
        }
        if (url.pathname === "/api/v1/workspaces/acme/invitations" && req.method === "POST") {
          const body = (await req.json()) as {
            email: string;
            role: string;
            repository_grants: string[];
          };
          expect(req.headers.get("X-CSRF-Token")).toBe("csrf.u06.session.token.0001");
          return jsonResponse(
            {
              invite: {
                id: INVITE_CREATED_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                workspace_id: WS_ACME_ID,
                email: body.email,
                role: body.role,
                repository_grants: body.repository_grants,
                expires_at: EXPIRES_ISO,
                status: "pending",
              },
              invite_token: "inv_test_single_use_token_0001",
            },
            { status: 201 },
          );
        }
        if (
          url.pathname === `/api/v1/workspaces/acme/invitations/${INVITE_PENDING_ID}` &&
          req.method === "DELETE"
        ) {
          inviteRevoked = true;
          return jsonResponse(null, { status: 204 });
        }
        if (
          url.pathname === `/api/v1/workspaces/acme/members/${MEM_BOB_ID}` &&
          req.method === "PATCH"
        ) {
          const body = (await req.json()) as {
            role: "maintainer" | "reviewer";
            repository_grants: string[];
            expected_version: number;
          };
          patchHeaders.push({
            ifMatch: req.headers.get("If-Match"),
            csrf: req.headers.get("X-CSRF-Token"),
            body,
          });
          bobRole = body.role;
          bobRepos = body.repository_grants;
          bobVersion += 1;
          return jsonResponse({
            id: MEM_BOB_ID,
            version: bobVersion,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            workspace_id: WS_ACME_ID,
            user_id: BOB_USER_ID,
            role: bobRole,
            repository_grants: bobRepos,
          });
        }
        if (
          url.pathname === `/api/v1/workspaces/acme/members/${MEM_ADMIN_ID}` &&
          req.method === "PATCH"
        ) {
          return problemResponse({
            status: 409,
            code: "last_admin",
            title: "Conflict",
            detail: "Cannot demote the last active workspace admin.",
            correlationId: "corr-last-admin-409",
          });
        }
        if (
          url.pathname === `/api/v1/workspaces/acme/members/${MEM_ADMIN_ID}` &&
          req.method === "DELETE"
        ) {
          return problemResponse({
            status: 409,
            code: "last_admin",
            title: "Conflict",
            detail: "Cannot remove the last active workspace admin.",
            correlationId: "corr-last-admin-del-409",
          });
        }
        if (url.pathname === "/api/v1/invitations/accept" && req.method === "POST") {
          const body = (await req.json()) as { token: string };
          expect(body.token).toBe("inv_test_single_use_token_0002");
          return jsonResponse({
            id: "0196ed00-0000-7000-8000-000000000499",
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            workspace_id: WS_JOINED_ID,
            user_id: OWNER_USER_ID,
            role: "viewer",
            repository_grants: [],
          });
        }
        if (url.pathname === `/api/v1/workspaces/${WS_JOINED_ID}` && req.method === "GET") {
          return jsonResponse({
            id: WS_JOINED_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            slug: "joined-team",
            name: "Joined Team",
            paused: false,
            default_policy_version: 1,
          });
        }
        if (url.pathname === "/api/v1/workspaces/joined-team/events" && req.method === "GET") {
          return sseIdleConnectedResponse();
        }
        if (url.pathname === "/api/v1/workspaces/joined-team/members" && req.method === "GET") {
          return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
        }
        throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
      });

    const { container, unmount } = renderAppRouter({
      initialEntry: "/w/acme/members",
      fetchImpl: makeFetchMock(),
      themeMode: "light",
    });

    expect(await screen.findByTestId("members-page")).toBeInTheDocument();
    expect(screen.getByText("Bob Reviewer")).toBeInTheDocument();
    expect(screen.getByText(REPO_ONE_ID)).toBeInTheDocument();

    // WCAG 2.2 AA check in Light theme
    const axeLight = await axe.run(container);
    expect(axeLight.violations).toEqual([]);

    // 1. Create single-use invitation -> token shown ONCE only -> wiped on dialog close
    await user.click(screen.getByRole("button", { name: /Invite member/i }));
    const inviteDialog = await screen.findByTestId("invite-member-dialog");
    await user.type(within(inviteDialog).getByLabelText(/Recipient email address/i), "new.dev@example.org");
    await user.selectOptions(
      within(inviteDialog).getByLabelText(/Initial workspace role/i),
      "maintainer",
    );
    await user.type(
      within(inviteDialog).getByLabelText(/Scoped repository IDs/i),
      REPO_ONE_ID,
    );
    await user.click(
      within(inviteDialog).getByRole("button", { name: /Generate one-time invitation/i }),
    );

    const onceTokenEl = await screen.findByTestId("invite-once-token-value");
    expect(onceTokenEl).toHaveTextContent("inv_test_single_use_token_0001");
    await user.click(screen.getByRole("button", { name: /I have copied this token/i }));

    await waitFor(() => {
      expect(screen.queryByTestId("invite-once-token-value")).not.toBeInTheDocument();
    });
    expect(document.body.textContent ?? "").not.toContain("inv_test_single_use_token_0001");
    assertZeroWebStorageSecrets();

    // 2. Revoke pending invitation
    await user.click(screen.getByRole("button", { name: /Revoke invitation/i }));
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: /Revoke invitation/i })).not.toBeInTheDocument();
    });

    // 3. Edit Bob's role & repository grants -> sends If-Match: "v1" + expected_version: 1
    const editButtons = screen.getAllByRole("button", { name: /Edit access/i });
    await user.click(editButtons[1]!);
    const editDialog = await screen.findByTestId("edit-member-dialog");
    await user.selectOptions(within(editDialog).getByLabelText(/Workspace role/i), "maintainer");
    const repoArea = within(editDialog).getByLabelText(/Scoped repository IDs/i);
    await user.clear(repoArea);
    await user.type(repoArea, `${REPO_ONE_ID}, ${REPO_TWO_ID}`);
    await user.click(within(editDialog).getByRole("button", { name: /Save access changes/i }));

    await waitFor(() => {
      expect(screen.queryByTestId("edit-member-dialog")).not.toBeInTheDocument();
    });
    expect(patchHeaders).toEqual([
      {
        ifMatch: '"v1"',
        csrf: "csrf.u06.session.token.0001",
        body: {
          role: "maintainer",
          repository_grants: [REPO_ONE_ID, REPO_TWO_ID],
          expected_version: 1,
        },
      },
    ]);
    expect(await screen.findByText(REPO_TWO_ID)).toBeInTheDocument();

    // 4. Attempting to demote last admin -> 409 last_admin surfaces correlation ID & rolls back select!
    const refreshedEditButtons = screen.getAllByRole("button", { name: /Edit access/i });
    await user.click(refreshedEditButtons[0]!);
    const adminEditDialog = await screen.findByTestId("edit-member-dialog");
    const adminRoleSelect = within(adminEditDialog).getByLabelText(
      /Workspace role/i,
    ) as HTMLSelectElement;
    await user.selectOptions(adminRoleSelect, "viewer");
    await user.click(within(adminEditDialog).getByRole("button", { name: /Save access changes/i }));

    const editErr = await screen.findByTestId("edit-member-error");
    expect(editErr).toHaveTextContent(/Cannot demote the last active workspace admin/i);
    expect(adminEditDialog).toHaveTextContent("corr-last-admin-409");
    // Rolled back to authoritative "admin" role!
    expect(adminRoleSelect.value).toBe("admin");
    await user.click(within(adminEditDialog).getByRole("button", { name: /^Cancel$/i }));

    // 5. Attempting to remove last admin -> 409 last_admin surfaces correlation ID
    const removeButtons = screen.getAllByRole("button", { name: /^Remove$/i });
    await user.click(removeButtons[0]!);
    const removeDialog = await screen.findByTestId("remove-member-dialog");
    await user.click(within(removeDialog).getByRole("button", { name: /Confirm member removal/i }));
    const removeErr = await screen.findByTestId("remove-member-error");
    expect(removeErr).toHaveTextContent(/Cannot remove the last active workspace admin/i);
    expect(removeDialog).toHaveTextContent("corr-last-admin-del-409");
    await user.click(within(removeDialog).getByRole("button", { name: /^Cancel$/i }));

    // 6. Redeem single-use invitation token
    await user.click(screen.getByRole("button", { name: /Redeem invitation token/i }));
    const acceptDialog = await screen.findByTestId("accept-invite-dialog");
    await user.type(
      within(acceptDialog).getByLabelText(/Single-use invitation token/i),
      "inv_test_single_use_token_0002",
    );
    await user.click(within(acceptDialog).getByRole("button", { name: /Accept invitation/i }));

    await waitFor(() => {
      expect(screen.getByTestId("router-location")).toHaveTextContent(
        `/w/${WS_JOINED_ID}/members`,
      );
    });

    unmount();

    // WCAG 2.2 AA check in Dark theme
    window.localStorage.clear();
    const darkRender = renderAppRouter({
      initialEntry: "/w/acme/members",
      fetchImpl: makeFetchMock(),
      themeMode: "dark",
    });
    expect(await screen.findByTestId("members-page")).toBeInTheDocument();
    const axeDark = await axe.run(darkRender.container);
    expect(axeDark.violations).toEqual([]);
  },
  15_000,
);

  it("hides admin mutation affordances and invitations table for non-admin viewer role (UX-ACCESS-001)", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me" && req.method === "GET") {
        return jsonResponse(
          buildMePayload({
            memberships: [
              {
                id: MEM_BOB_ID,
                version: 1,
                created_at: NOW_ISO,
                updated_at: NOW_ISO,
                workspace_id: WS_ACME_ID,
                user_id: OWNER_USER_ID,
                role: "viewer",
                repository_grants: [REPO_ONE_ID],
              },
            ],
          }),
        );
      }
      if (url.pathname === "/api/v1/workspaces/acme" && req.method === "GET") {
        return jsonResponse({
          id: WS_ACME_ID,
          version: 1,
          created_at: NOW_ISO,
          updated_at: NOW_ISO,
          slug: "acme",
          name: "Acme Corp",
          paused: false,
          default_policy_version: 1,
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme/events" && req.method === "GET") {
        return sseIdleConnectedResponse();
      }
      if (url.pathname === "/api/v1/workspaces/acme/members" && req.method === "GET") {
        return jsonResponse({
          items: [
            {
              id: MEM_BOB_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              workspace_id: WS_ACME_ID,
              user_id: OWNER_USER_ID,
              role: "viewer",
              repository_grants: [REPO_ONE_ID],
            },
          ],
          next_cursor: null,
          snapshot_at: NOW_ISO,
        });
      }
      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    renderAppRouter({
      initialEntry: "/w/acme/members",
      fetchImpl: fetchMock,
    });

    expect(await screen.findByTestId("members-readonly-notice")).toBeInTheDocument();
    expect(screen.getByTestId("effective-role-badge")).toHaveTextContent("viewer");
    expect(screen.queryByRole("button", { name: /Invite member/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Edit access/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Remove$/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/Workspace Invitations/i)).not.toBeInTheDocument();
  });

  it("severs live workspace SSE stream on identity.permission_revoked, purges cached workspace state, and renders revoked guard (SEC-032, NFR-04)", async () => {
    let pushSseChunk: ((raw: string) => void) | null = null;
    const encoder = new TextEncoder();

    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me" && req.method === "GET") {
        return jsonResponse(buildMePayload());
      }
      if (url.pathname === "/api/v1/workspaces/acme" && req.method === "GET") {
        return jsonResponse({
          id: WS_ACME_ID,
          version: 1,
          created_at: NOW_ISO,
          updated_at: NOW_ISO,
          slug: "acme",
          name: "Acme Corp",
          paused: false,
          default_policy_version: 1,
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme/events" && req.method === "GET") {
        const stream = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(encoder.encode(": connected\n\n"));
            pushSseChunk = (raw: string) => {
              controller.enqueue(encoder.encode(raw));
            };
          },
        });
        return new Response(stream, {
          status: 200,
          headers: { "Content-Type": "text/event-stream; charset=utf-8" },
        });
      }
      if (url.pathname === "/api/v1/workspaces/acme/members" && req.method === "GET") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === "/api/v1/workspaces/acme/invitations" && req.method === "GET") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
      }
      if (url.pathname === "/api/v1/workspaces/acme/break-glass" && req.method === "GET") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
      }
      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    const { queryClient } = renderAppRouter({
      initialEntry: "/w/acme/members",
      fetchImpl: fetchMock,
    });

    expect(await screen.findByTestId("members-page")).toBeInTheDocument();
    await waitFor(() => {
      expect(pushSseChunk).not.toBeNull();
    });

    const revokedEnvelope = {
      schema_version: 1,
      event_id: "0196ed00-0000-7000-8000-000000000777",
      type: "identity.permission_revoked",
      occurred_at: NOW_ISO,
      workspace_id: WS_ACME_ID,
      repository_id: null,
      session_id: null,
      aggregate_id: MEM_ADMIN_ID,
      aggregate_version: 2,
      correlation_id: "corr-sse-revoked-01",
      causation_id: null,
      payload: {
        target_id: OWNER_USER_ID,
        reason_code: "member_removed",
      },
    };
    act(() => {
      pushSseChunk!(
        `id: sse-revoked-1\nevent: identity.permission_revoked\ndata: ${JSON.stringify(revokedEnvelope)}\n\n`,
      );
    });

    expect(await screen.findByTestId("workspace-revoked-guard")).toBeInTheDocument();
    // Workspace-scoped React Query cache entries for "acme" are immediately purged!
    expect(queryClient.getQueryData(["workspace", "acme", "members", "first"])).toBeUndefined();
  });
});
