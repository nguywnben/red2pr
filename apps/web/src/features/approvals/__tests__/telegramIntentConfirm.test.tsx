import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { BrowserRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TelegramIntentConfirmPage } from "../TelegramIntentConfirmPage";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { I18nProvider } from "../../../shared/i18n";

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr-u22-intent" },
  });
}

describe("U22 web-confirm page (NOT-03, SEC-004, SEC-034)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("previews without mutation and confirms only after an explicit click", async () => {
    window.history.replaceState({}, "", "/telegram/confirm#challengeToken012345678901234567890123456789");
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/auth/csrf") {
        return jsonResponse({ csrf_token: "csrf-u22-intent", bootstrap_claim_required: false });
      }
      if (url.pathname === "/api/v1/me") return jsonResponse({ mfa_enabled: false });
      if (url.pathname === "/api/v1/me/telegram-intents/preview") {
        expect(request.method).toBe("POST");
        return jsonResponse({ action: "unlink", workspace_id: null, target_id: null, scope_description: "Unlink this personal Telegram account from Red2PR.", expires_at: "2026-10-30T12:05:00Z", already_confirmed: false });
      }
      if (url.pathname === "/api/v1/me/telegram-intents/confirm") {
        expect(request.method).toBe("POST");
        return jsonResponse({ state: "confirmed", operation_id: "0196ed00-0000-7000-8000-000000000021", status_url: null });
      }
      throw new Error(`Unexpected ${request.method} ${url.pathname}`);
    });
    const queryClient = createWorkspaceQueryClient();
    render(
      <I18nProvider>
        <ApiClientProvider queryClient={queryClient} clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchMock }}>
          <BrowserRouter>
            <Routes><Route path="/telegram/confirm" element={<TelegramIntentConfirmPage />} /></Routes>
          </BrowserRouter>
        </ApiClientProvider>
      </I18nProvider>,
    );
    expect(await screen.findByText("Unlink this personal Telegram account from Red2PR.")).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input]) => {
      const request = input instanceof Request ? input : new Request(input);
      return new URL(request.url).pathname === "/api/v1/me/telegram-intents/confirm";
    })).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Confirm /unlink" }));
    expect(await screen.findByText("This action has already been confirmed.")).toBeInTheDocument();
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => {
      const request = input instanceof Request ? input : new Request(input);
      return new URL(request.url).pathname === "/api/v1/me/telegram-intents/confirm";
    })).toBe(true));
    expect(window.location.hash).toBe("");
  });

  it("requires sign-in without putting the bearer token in a login URL or preview request", async () => {
    window.history.replaceState({}, "", "/telegram/confirm#challengeToken012345678901234567890123456789");
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/auth/csrf") {
        return jsonResponse({ csrf_token: "csrf-u22-anon", bootstrap_claim_required: false });
      }
      if (url.pathname === "/api/v1/me") {
        return new Response(JSON.stringify({ status: 401, code: "unauthenticated", title: "Sign in", detail: "Sign in required" }), {
          status: 401,
          headers: { "Content-Type": "application/problem+json", "X-Correlation-Id": "corr-u22-anon" },
        });
      }
      throw new Error(`Unexpected ${request.method} ${url.pathname}`);
    });
    render(
      <I18nProvider>
        <ApiClientProvider queryClient={createWorkspaceQueryClient()} clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchMock }}>
          <BrowserRouter>
            <Routes><Route path="/telegram/confirm" element={<TelegramIntentConfirmPage />} /></Routes>
          </BrowserRouter>
        </ApiClientProvider>
      </I18nProvider>,
    );
    expect(await screen.findByTestId("telegram-intent-sign-in-required")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign in to Red2PR" })).toHaveAttribute(
      "href",
      "/login?next=%2Faccount",
    );
    expect(fetchMock.mock.calls.some(([input]) => {
      const request = input instanceof Request ? input : new Request(input);
      return new URL(request.url).pathname === "/api/v1/me/telegram-intents/preview";
    })).toBe(false);
  });
});
