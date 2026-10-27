import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { THEME_STORAGE_KEY, ThemeProvider } from "../../../shared/theme";
import { AppShell } from "../../../shared/ui";
import { AccountPage, LoginPage, resolveSafePostLoginPath } from "../index";

const USER_ID = "0196ed00-0000-7000-8000-000000000001";
const SESSION_CURRENT_ID = "0196ed00-0000-7000-8000-000000000011";
const SESSION_SECOND_ID = "0196ed00-0000-7000-8000-000000000012";
const CHALLENGE_ID = "0196ed00-0000-7000-8000-000000000021";
const ENROLL_CHALLENGE_ID = "0196ed00-0000-7000-8000-000000000031";
const NOW_ISO = "2026-10-27T08:00:00Z";
const EXPIRES_ISO = "2026-10-27T20:00:00Z";

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
    "X-Correlation-Id": init.correlationId ?? "corr-auth-test-01",
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
  retryAfter?: string;
}): Response {
  const extraHeaders: Record<string, string> = {};
  if (params.retryAfter !== undefined) {
    extraHeaders["Retry-After"] = params.retryAfter;
  }
  return jsonResponse(
    {
      type: `https://red2pr.local/problems/${params.code}`,
      title: params.title,
      status: params.status,
      code: params.code,
      detail: params.detail,
      correlation_id: params.correlationId ?? "corr-auth-err-01",
      errors: null,
    },
    {
      status: params.status,
      correlationId: params.correlationId ?? "corr-auth-err-01",
      contentType: "application/problem+json",
      extraHeaders,
    },
  );
}

function LocationProbe(): React.JSX.Element {
  const location = useLocation();
  return <div data-testid="router-location">{`${location.pathname}${location.search}`}</div>;
}

function renderAuthRouter(opts: {
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
            <LocationProbe />
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route
                path="/account"
                element={
                  <AppShell activePath="/account" activeWorkspaceSlug="default" sseState="offline">
                    <AccountPage />
                  </AppShell>
                }
              />
            </Routes>
          </MemoryRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
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

describe("U05 Auth Screens, CSRF/Step-Up/MFA Flows & WCAG 2.2 AA Accessibility (UI-S02, UI-S21, UX-LOGIN-001, SEC-026)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("rejects open-redirect schemes and protocol-relative next targets (SEC-040)", () => {
    expect(resolveSafePostLoginPath("?next=%2Fw%2Facme%2Frepairs")).toBe("/w/acme/repairs");
    expect(resolveSafePostLoginPath("?next=%2F%2Fevil.example%2Fsteal")).toBe("/account");
    expect(resolveSafePostLoginPath("?next=https%3A%2F%2Fevil.example")).toBe("/account");
    expect(resolveSafePostLoginPath("?next=javascript%3Aalert(1)")).toBe("/account");
    expect(resolveSafePostLoginPath("?next=%2Flogin")).toBe("/account");
  });

  it("completes initial bootstrap owner claim with X-CSRF-Token and zero Web Storage token persistence", async () => {
    const user = userEvent.setup();
    const seenCsrfHeaders: (string | null)[] = [];

    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/auth/csrf" && req.method === "GET") {
        return jsonResponse({
          csrf_token: "anon.csrf.token.0000000001",
          bootstrap_claim_required: true,
        });
      }
      if (url.pathname === "/api/v1/setup/claim" && req.method === "POST") {
        seenCsrfHeaders.push(req.headers.get("X-CSRF-Token"));
        return jsonResponse(
          {
            user: {
              id: USER_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              display_name: "Alice Owner",
              email: "alice@example.org",
              status: "active",
            },
            session: {
              id: SESSION_CURRENT_ID,
              version: 1,
              created_at: NOW_ISO,
              updated_at: NOW_ISO,
              user_id: USER_ID,
              expires_at: EXPIRES_ISO,
              auth_strength: "password",
              step_up_at: NOW_ISO,
              grant_epoch: 1,
            },
            csrf_token: "sess.csrf.token.0000000002",
            is_instance_owner: true,
          },
          { status: 201 },
        );
      }
      if (url.pathname === "/api/v1/me" && req.method === "GET") {
        return jsonResponse({
          user: {
            id: USER_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            display_name: "Alice Owner",
            email: "alice@example.org",
            status: "active",
          },
          session: {
            id: SESSION_CURRENT_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            user_id: USER_ID,
            expires_at: EXPIRES_ISO,
            auth_strength: "password",
            step_up_at: NOW_ISO,
            grant_epoch: 1,
          },
          is_instance_owner: true,
          mfa_enabled: false,
          mfa_required_for_privileged: true,
          step_up_valid_until: "2099-01-01T00:05:00Z",
          csrf_token: "sess.csrf.token.0000000002",
          memberships: [],
          telegram_link: { status: "not_configured" },
        });
      }
      if (url.pathname === "/api/v1/me/sessions" && req.method === "GET") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
      }
      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    const { container } = renderAuthRouter({
      initialEntry: "/login",
      fetchImpl: fetchMock,
      themeMode: "light",
    });

    await waitFor(() => {
      expect(screen.getByTestId("bootstrap-claim-form")).toBeInTheDocument();
    });

    await user.type(
      screen.getByLabelText(/One-time bootstrap token/i),
      "r2pr_boot_secret_token_value_123456",
    );
    await user.type(screen.getByLabelText(/Display name/i), "Alice Owner");
    await user.type(screen.getByLabelText(/Email address/i), "alice@example.org");
    await user.type(screen.getByLabelText(/Owner password/i), "CorrectHorseBatteryStaple!99");

    const axeLogin = await axe.run(container);
    expect(axeLogin.violations).toEqual([]);

    await user.click(screen.getByRole("button", { name: /Claim owner & sign in/i }));

    await waitFor(() => {
      expect(screen.getByTestId("router-location")).toHaveTextContent("/account");
    });
    expect(await screen.findByText("Alice Owner")).toBeInTheDocument();
    expect(seenCsrfHeaders).toEqual(["anon.csrf.token.0000000001"]);
    assertZeroWebStorageSecrets();
  });

  it("handles two-step password -> cookie-free MFA challenge -> TOTP login, generic errors, 429 cooldown, and recovery reset", async () => {
    const user = userEvent.setup();
    let loginCallIndex = 0;

    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/auth/csrf") {
        return jsonResponse({
          csrf_token: "anon.csrf.token.0000000009",
          bootstrap_claim_required: false,
        });
      }
      if (url.pathname === "/api/v1/auth/login" && req.method === "POST") {
        loginCallIndex += 1;
        const payload = (await req.json()) as Record<string, unknown>;
        if (loginCallIndex === 1) {
          return problemResponse({
            status: 401,
            code: "invalid_credentials",
            title: "Authentication failed",
            detail: "Invalid identifier or password.",
            correlationId: "corr-anti-enum-1",
          });
        }
        if (loginCallIndex === 2) {
          return problemResponse({
            status: 429,
            code: "rate_limited",
            title: "Too many requests",
            detail: "Too many failed sign-in attempts.",
            correlationId: "corr-ratelimit-2",
            retryAfter: "840",
          });
        }
        if (loginCallIndex === 3) {
          expect(payload.otp ?? null).toBeNull();
          return jsonResponse({
            status: "mfa_required",
            mfa_challenge_id: CHALLENGE_ID,
          });
        }
        expect(payload.mfa_challenge_id).toBe(CHALLENGE_ID);
        expect(payload.otp).toBe("482910");
        return jsonResponse({
          status: "authenticated",
          user: {
            id: USER_ID,
            version: 2,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            display_name: "Alice Owner",
            email: "alice@example.org",
            status: "active",
          },
          session: {
            id: SESSION_CURRENT_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            user_id: USER_ID,
            expires_at: EXPIRES_ISO,
            auth_strength: "mfa",
            step_up_at: NOW_ISO,
            grant_epoch: 1,
          },
          csrf_token: "sess.csrf.token.0000000010",
        });
      }
      if (url.pathname === "/api/v1/me") {
        return jsonResponse({
          user: {
            id: USER_ID,
            version: 2,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            display_name: "Alice Owner",
            email: "alice@example.org",
            status: "active",
          },
          session: {
            id: SESSION_CURRENT_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            user_id: USER_ID,
            expires_at: EXPIRES_ISO,
            auth_strength: "mfa",
            step_up_at: NOW_ISO,
            grant_epoch: 1,
          },
          is_instance_owner: true,
          mfa_enabled: true,
          mfa_required_for_privileged: true,
          step_up_valid_until: "2099-01-01T00:05:00Z",
          csrf_token: "sess.csrf.token.0000000010",
          memberships: [],
          telegram_link: { status: "not_configured" },
        });
      }
      if (url.pathname === "/api/v1/me/sessions") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
      }
      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    const { container } = renderAuthRouter({
      initialEntry: "/login?next=%2F%2Fevil.example%2Fphish",
      fetchImpl: fetchMock,
      themeMode: "dark",
    });

    const identInput = await screen.findByLabelText(/Email or display name/i);
    const pwInput = screen.getByLabelText(/^Password$/i);

    await user.type(identInput, "alice@example.org");
    await user.type(pwInput, "WrongPassword!123");
    await user.click(screen.getByRole("button", { name: /^Sign in$/i }));

    // 1. Generic anti-enumeration error + correlation ID
    const errBanner1 = await screen.findByTestId("auth-error-banner");
    expect(errBanner1).toHaveTextContent("Invalid identifier or password.");
    expect(errBanner1).toHaveTextContent("corr-anti-enum-1");

    // 2. 429 rate-limit banner with Retry-After seconds
    await user.click(screen.getByRole("button", { name: /^Sign in$/i }));
    const errBanner2 = await screen.findByTestId("auth-error-banner");
    expect(errBanner2).toHaveTextContent("Wait 840 seconds before trying again.");
    expect(errBanner2).toHaveTextContent("corr-ratelimit-2");

    // 3. Valid password -> cookie-free MFA challenge step
    await user.clear(pwInput);
    await user.type(pwInput, "ValidOwnerPassphrase!2026");
    await user.click(screen.getByRole("button", { name: /^Sign in$/i }));

    const mfaForm = await screen.findByTestId("mfa-challenge-form");
    expect(mfaForm).toBeInTheDocument();
    expect(screen.getByTestId("router-location")).toHaveTextContent("/login");

    // Dark-mode WCAG 2.2 AA axe check on MFA challenge screen
    const axeDarkMfa = await axe.run(container);
    expect(axeDarkMfa.violations).toEqual([]);

    await user.type(within(mfaForm).getByLabelText(/6-digit authenticator code/i), "482910");
    await user.click(within(mfaForm).getByRole("button", { name: /Verify code & sign in/i }));

    // Hostile //evil.example redirect was neutralized to /account
    await waitFor(() => {
      expect(screen.getByTestId("router-location")).toHaveTextContent("/account");
    });
    assertZeroWebStorageSecrets();
  });

  it("enforces 5m StepUpDialog, displays TOTP secret & 10 recovery codes once only, surfaces mandatory MFA policy 403, and revokes sessions", async () => {
    const user = userEvent.setup();
    let mfaEnabledState = false;
    let stepUpValidUntilState: string | null = null;
    let activeSessions = [
      {
        id: SESSION_CURRENT_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        user_id: USER_ID,
        expires_at: EXPIRES_ISO,
        auth_strength: "password",
        step_up_at: null,
        grant_epoch: 1,
        is_current: true,
        last_seen_at: NOW_ISO,
        idle_expires_at: "2026-10-27T08:30:00Z",
        client_ip: "127.0.0.1",
        user_agent_summary: "Firefox/132.0 Linux",
      },
      {
        id: SESSION_SECOND_ID,
        version: 1,
        created_at: NOW_ISO,
        updated_at: NOW_ISO,
        user_id: USER_ID,
        expires_at: EXPIRES_ISO,
        auth_strength: "password",
        step_up_at: null,
        grant_epoch: 1,
        is_current: false,
        last_seen_at: NOW_ISO,
        idle_expires_at: "2026-10-27T08:30:00Z",
        client_ip: "10.0.0.42",
        user_agent_summary: "Chrome/131.0 macOS",
      },
    ];

    const recoveryBatch = Array.from(
      { length: 10 },
      (_, idx) => `R2PR-AAAA-BBBB-000${String(idx)}`,
    );

    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me" && req.method === "GET") {
        return jsonResponse({
          user: {
            id: USER_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            display_name: "Alice Owner",
            email: "alice@example.org",
            status: "active",
          },
          session: {
            id: SESSION_CURRENT_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            user_id: USER_ID,
            expires_at: EXPIRES_ISO,
            auth_strength: mfaEnabledState ? "mfa" : "password",
            step_up_at: stepUpValidUntilState ? NOW_ISO : null,
            grant_epoch: 1,
          },
          is_instance_owner: true,
          mfa_enabled: mfaEnabledState,
          mfa_required_for_privileged: true,
          step_up_valid_until: stepUpValidUntilState,
          csrf_token: "sess.csrf.token.account01",
          memberships: [],
          telegram_link: { status: "not_configured" },
        });
      }

      if (url.pathname === "/api/v1/me/sessions" && req.method === "GET") {
        return jsonResponse({
          items: activeSessions,
          next_cursor: null,
          snapshot_at: NOW_ISO,
        });
      }

      if (url.pathname === `/api/v1/me/sessions/${SESSION_SECOND_ID}` && req.method === "DELETE") {
        activeSessions = activeSessions.filter((s) => s.id !== SESSION_SECOND_ID);
        return jsonResponse(null, { status: 204 });
      }

      if (url.pathname === "/api/v1/auth/step-up" && req.method === "POST") {
        stepUpValidUntilState = "2099-01-01T00:05:00Z";
        return jsonResponse({
          session: {
            id: SESSION_CURRENT_ID,
            version: 2,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            user_id: USER_ID,
            expires_at: EXPIRES_ISO,
            auth_strength: mfaEnabledState ? "mfa" : "password",
            step_up_at: NOW_ISO,
            grant_epoch: 1,
          },
          step_up_valid_until: stepUpValidUntilState,
          csrf_token: "sess.csrf.token.account02",
        });
      }

      if (url.pathname === "/api/v1/me/mfa" && req.method === "POST") {
        const body = (await req.json()) as { challenge_id?: string | null; otp?: string | null };
        if (!body.challenge_id) {
          return jsonResponse({
            status: "enrollment_pending",
            challenge_id: ENROLL_CHALLENGE_ID,
            secret_base32: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            otpauth_uri:
              "otpauth://totp/Red2PR:alice%40example.org?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Red2PR",
            expires_at: EXPIRES_ISO,
          });
        }
        mfaEnabledState = true;
        return jsonResponse({
          status: "active",
          user: {
            id: USER_ID,
            version: 2,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            display_name: "Alice Owner",
            email: "alice@example.org",
            status: "active",
          },
          session: {
            id: SESSION_CURRENT_ID,
            version: 3,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            user_id: USER_ID,
            expires_at: EXPIRES_ISO,
            auth_strength: "mfa",
            step_up_at: NOW_ISO,
            grant_epoch: 1,
          },
          recovery_codes: recoveryBatch,
          csrf_token: "sess.csrf.token.account03",
        });
      }

      if (url.pathname === "/api/v1/me/mfa" && req.method === "DELETE") {
        return problemResponse({
          status: 403,
          code: "mfa_policy_mandatory",
          title: "Forbidden",
          detail:
            "Multi-factor authentication is mandatory for privileged accounts and cannot be disabled.",
          correlationId: "corr-mfa-mandatory-99",
        });
      }

      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    const { container } = renderAuthRouter({
      initialEntry: "/account",
      fetchImpl: fetchMock,
      themeMode: "light",
    });

    expect(await screen.findByText("Alice Owner")).toBeInTheDocument();
    expect(screen.getByText("Not Configured")).toBeInTheDocument();
    expect(await screen.findByText("Chrome/131.0 macOS")).toBeInTheDocument();

    // WCAG 2.2 AA check on full /account inside AppShell
    const axeAccount = await axe.run(container);
    expect(axeAccount.violations).toEqual([]);

    // Revoke secondary session
    const sessionsTable = screen.getByRole("table", { name: /Active account sessions/i });
    const revokeButtons = within(sessionsTable).getAllByRole("button", { name: /^Revoke$/i });
    expect(revokeButtons).toHaveLength(2);
    await user.click(revokeButtons[1]!);

    await waitFor(() => {
      expect(screen.queryByText("Chrome/131.0 macOS")).not.toBeInTheDocument();
    });

    // Clicking "Set up authenticator MFA" without fresh step_up opens StepUpDialog first
    await user.click(screen.getByRole("button", { name: /Set up authenticator MFA/i }));
    const stepUpDialog = await screen.findByRole("dialog", {
      name: /Confirm privileged step-up/i,
    });

    await user.type(within(stepUpDialog).getByLabelText(/Current password/i), "OwnerPassphrase!123");
    await user.click(within(stepUpDialog).getByRole("button", { name: /Verify step-up/i }));

    // Stage 1: once-only secret displayed
    const secretNode = await screen.findByTestId("mfa-secret-once");
    expect(secretNode).toHaveTextContent("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");

    await user.type(
      screen.getByLabelText(/Enter 6-digit code from your authenticator/i),
      "123456",
    );
    await user.click(screen.getByRole("button", { name: /Activate TOTP MFA/i }));

    // Stage 2: 10 single-use recovery codes displayed once, secret is gone from DOM
    const recoveryPanel = await screen.findByTestId("mfa-recovery-codes-panel");
    expect(screen.queryByTestId("mfa-secret-once")).not.toBeInTheDocument();
    for (const code of recoveryBatch) {
      expect(within(recoveryPanel).getByText(code)).toBeInTheDocument();
    }

    await user.click(
      within(recoveryPanel).getByRole("button", { name: /I have saved these recovery codes/i }),
    );
    expect(screen.queryByTestId("mfa-recovery-codes-panel")).not.toBeInTheDocument();

    // Attempting to disable MFA as Instance Owner shows mandatory policy 403 + correlation ID
    await user.type(
      screen.getByLabelText(/Single-use recovery code authorization/i),
      "R2PR-AAAA-BBBB-0000",
    );
    await user.click(screen.getByRole("button", { name: /^Disable MFA$/i }));

    const accountBanner = await screen.findByTestId("account-error-banner");
    expect(accountBanner).toHaveTextContent(/mandatory for privileged accounts/i);
    expect(accountBanner).toHaveTextContent("corr-mfa-mandatory-99");
    assertZeroWebStorageSecrets();
  });

  it("redirects unauthenticated 401 access on /account cleanly to /login?next=%2Faccount", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/me") {
        return problemResponse({
          status: 401,
          code: "unauthenticated",
          title: "Authentication required",
          detail: "No active session cookie.",
        });
      }
      if (url.pathname === "/api/v1/auth/csrf") {
        return jsonResponse({
          csrf_token: "anon.csrf.token.redirect01",
          bootstrap_claim_required: false,
        });
      }
      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    renderAuthRouter({
      initialEntry: "/account",
      fetchImpl: fetchMock,
      themeMode: "dark",
    });

    await waitFor(() => {
      expect(screen.getByTestId("router-location")).toHaveTextContent("/login?next=%2Faccount");
    });
    expect(await screen.findByRole("heading", { name: /Sign in to Red2PR/i })).toBeInTheDocument();
  });

  it("supports single-use recovery code reset on /login and routes to /account for MFA re-enrollment", async () => {
    const user = userEvent.setup();

    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);

      if (url.pathname === "/api/v1/auth/csrf") {
        return jsonResponse({
          csrf_token: "anon.csrf.token.rec01",
          bootstrap_claim_required: false,
        });
      }
      if (url.pathname === "/api/v1/auth/recovery" && req.method === "POST") {
        const body = (await req.json()) as Record<string, unknown>;
        expect(body.single_use_code).toBe("R2PR-9999-8888-7777");
        return jsonResponse({
          user: {
            id: USER_ID,
            version: 3,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            display_name: "Alice Owner",
            email: "alice@example.org",
            status: "active",
          },
          session: {
            id: SESSION_CURRENT_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            user_id: USER_ID,
            expires_at: EXPIRES_ISO,
            auth_strength: "password",
            step_up_at: NOW_ISO,
            grant_epoch: 2,
          },
          csrf_token: "sess.csrf.token.rec02",
          mfa_re_enrollment_required: true,
        });
      }
      if (url.pathname === "/api/v1/me") {
        return jsonResponse({
          user: {
            id: USER_ID,
            version: 3,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            display_name: "Alice Owner",
            email: "alice@example.org",
            status: "active",
          },
          session: {
            id: SESSION_CURRENT_ID,
            version: 1,
            created_at: NOW_ISO,
            updated_at: NOW_ISO,
            user_id: USER_ID,
            expires_at: EXPIRES_ISO,
            auth_strength: "password",
            step_up_at: NOW_ISO,
            grant_epoch: 2,
          },
          is_instance_owner: true,
          mfa_enabled: false,
          mfa_required_for_privileged: true,
          step_up_valid_until: "2099-01-01T00:05:00Z",
          csrf_token: "sess.csrf.token.rec02",
          memberships: [],
          telegram_link: { status: "not_configured" },
        });
      }
      if (url.pathname === "/api/v1/me/sessions") {
        return jsonResponse({ items: [], next_cursor: null, snapshot_at: NOW_ISO });
      }
      throw new Error(`Unhandled request: ${req.method} ${url.pathname}`);
    });

    const { container } = renderAuthRouter({
      initialEntry: "/login?next=%2Fw%2Facme%2Frepairs",
      fetchImpl: fetchMock,
      themeMode: "light",
    });

    await user.click(await screen.findByRole("button", { name: /Recovery code reset/i }));
    const recForm = await screen.findByTestId("recovery-reset-form");

    const axeRecovery = await axe.run(container);
    expect(axeRecovery.violations).toEqual([]);

    await user.type(
      within(recForm).getByLabelText(/Single-use recovery code/i),
      "R2PR-9999-8888-7777",
    );
    await user.type(within(recForm).getByLabelText(/^New password$/i), "RotatedOwnerPassphrase!2026");
    await user.click(within(recForm).getByRole("button", { name: /Reset password & sign in/i }));

    await waitFor(() => {
      expect(screen.getByTestId("router-location")).toHaveTextContent("/account");
    });
    assertZeroWebStorageSecrets();
  });
});
