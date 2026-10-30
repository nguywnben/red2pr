import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClientProvider, createWorkspaceQueryClient } from "../../../shared/api";
import { TelegramLinkCard } from "../TelegramLinkCard";

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr-u22-ui" },
  });
}

describe("U22 Telegram account-link card (UI-S21, NOT-02)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("requests a one-use link and renders the Telegram deep link without storing it", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/auth/csrf") {
        return jsonResponse({ csrf_token: "csrf-u22-card", bootstrap_claim_required: false });
      }
      if (url.pathname === "/api/v1/me/telegram-link-challenges" && request.method === "POST") {
        return new Response(JSON.stringify({
            bot_username: "red2pr_test_bot",
            deep_link: "https://t.me/red2pr_test_bot?start=challengeToken012345678901234567890123456789",
            expires_at: "2026-10-30T12:10:00Z",
        }), { status: 201, headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr-u22-ui" } });
      }
      throw new Error(`Unexpected ${request.method} ${url.pathname}`);
    });
    const queryClient = createWorkspaceQueryClient();
    render(
      <ApiClientProvider queryClient={queryClient} clientOptions={{ baseUrl: "http://127.0.0.1:4280", fetch: fetchMock }}>
        <TelegramLinkCard link={{ status: "not_configured" }} requireStepUpThen={(action) => action()} />
      </ApiClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /create one-time telegram link/i }));
    const anchor = await screen.findByRole("link", { name: /open telegram/i });
    expect(anchor).toHaveAttribute("href", expect.stringContaining("https://t.me/red2pr_test_bot?start="));
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => {
      const request = input instanceof Request ? input : new Request(input);
      return new URL(request.url).pathname === "/api/v1/me/telegram-link-challenges";
    })).toBe(true));
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});
