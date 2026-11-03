import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";
import { ThemeProvider } from "../../../shared/theme";
import { AccountRecoveryPage } from "../AccountRecoveryPage";
import { LoginPage } from "../LoginPage";

function createFetch() {
  return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
    const rawUrl = input instanceof Request ? input.url : input.toString();
    const pathname = new URL(rawUrl, "http://127.0.0.1:4280").pathname;
    const body = pathname.endsWith("/auth/csrf")
      ? { csrf_token: "c".repeat(32), bootstrap_claim_required: false }
      : pathname.endsWith("/api/v1/setup")
        ? { owner_claimed: true }
      : pathname.endsWith("/system/capabilities")
        ? { oidc_providers: [] }
        : { data: {} };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-Correlation-Id": "corr-clean-login-test",
      },
    });
  });
}

function renderLogin(fetchImpl: typeof fetch) {
  return render(
    <I18nProvider>
      <ThemeProvider defaultMode="light">
        <ApiClientProvider
          queryClient={createWorkspaceQueryClient()}
          clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchImpl }}
        >
          <MemoryRouter initialEntries={["/login"]}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/login/recovery" element={<AccountRecoveryPage />} />
              <Route path="/setup/*" element={<p>Setup flow</p>} />
            </Routes>
          </MemoryRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>,
  );
}

describe("clean sign-in entry", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it("shows only the primary sign-in flow and links to separate setup/recovery journeys", async () => {
    renderLogin(createFetch());

    expect(await screen.findByRole("heading", { name: /sign in to red2pr/i })).toBeVisible();
    expect(screen.getByRole("textbox", { name: /email or display name/i })).toBeVisible();
    expect(screen.getByLabelText(/password/i)).toBeVisible();
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /initial owner claim|recovery code reset/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/httponly|csrf tokens/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/theme mode/i)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("link", { name: /can't sign in/i }));
    expect(await screen.findByRole("heading", { name: /recover your account/i })).toBeVisible();
  });

  it("routes directly to setup whenever the instance has no owner", async () => {
    const fetchImpl = createFetch();
    fetchImpl.mockImplementation(async (input: RequestInfo | URL): Promise<Response> => {
      const rawUrl = input instanceof Request ? input.url : input.toString();
      const pathname = new URL(rawUrl, "http://127.0.0.1:4280").pathname;
      const body = pathname.endsWith("/auth/csrf")
        ? { csrf_token: "c".repeat(32), bootstrap_claim_required: true }
        : pathname.endsWith("/api/v1/setup")
          ? { owner_claimed: false }
        : pathname.endsWith("/system/capabilities")
          ? { oidc_providers: [] }
          : { data: {} };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr-clean-login-test" },
      });
    });

    renderLogin(fetchImpl);

    expect(await screen.findByText("Setup flow")).toBeVisible();
    expect(screen.queryByRole("heading", { name: /sign in to red2pr/i })).not.toBeInTheDocument();
  });

  it("does not flash the sign-in form while checking whether initial setup is required", async () => {
    let resolveSetup!: (response: Response) => void;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const rawUrl = input instanceof Request ? input.url : input.toString();
      const pathname = new URL(rawUrl, "http://127.0.0.1:4280").pathname;
      if (pathname.endsWith("/api/v1/setup")) {
        return new Promise<Response>((resolve) => {
          resolveSetup = resolve;
        });
      }
      const body = pathname.endsWith("/auth/csrf")
        ? { csrf_token: "c".repeat(32), bootstrap_claim_required: true }
        : pathname.endsWith("/system/capabilities")
          ? { oidc_providers: [] }
          : { data: {} };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    renderLogin(fetchImpl);

    expect(screen.getByRole("heading", { name: "Loading setup" })).toBeVisible();
    expect(screen.queryByRole("heading", { name: /sign in to red2pr/i })).not.toBeInTheDocument();

    await waitFor(() => expect(resolveSetup).toBeTypeOf("function"));
    await act(async () => {
      resolveSetup(
        new Response(JSON.stringify({ owner_claimed: false }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });

    expect(await screen.findByText("Setup flow")).toBeVisible();
    expect(screen.queryByRole("heading", { name: /sign in to red2pr/i })).not.toBeInTheDocument();
  });
});
