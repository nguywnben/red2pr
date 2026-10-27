import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { I18nProvider } from "../../i18n";
import { ThemeProvider } from "../../theme";
import {
  SafeDiffViewer,
  SafeLogViewer,
  sanitizeNavigationHref,
  sanitizeUntrustedText,
} from "../index";

function ViewerHarness({ children }: { readonly children: React.ReactNode }): React.JSX.Element {
  return (
    <MemoryRouter>
      <I18nProvider>
        <ThemeProvider defaultMode="light">{children}</ThemeProvider>
      </I18nProvider>
    </MemoryRouter>
  );
}

describe("U04 SEC-040 Untrusted Log/Diff Sanitization & NFR-12 50k Virtualization (T-UI-01-N)", () => {
  it("strips ANSI CSI/OSC-52/OSC-8 terminal escapes, C0 controls, and Trojan-Source bidi overrides", () => {
    const hostileInput = [
      "\u001b[31mERROR:\u001b[0m Assertion failed",
      "\u001b]52;c;SGVsbG8gV29ybGQ=\u0007Clipboard hijack attempt",
      "\u001b]8;;javascript:alert(1)\u001b\\Click me\u001b]8;;\u001b\\",
      "accessLevel = \"user\u202e \u2066// Check admin\u2069\"",
      "<script>window.__pwned = true;</script><img src=x onerror=alert(1)>",
    ].join("\n");

    const result = sanitizeUntrustedText(hostileInput);
    expect(result.strippedSequences).toBeGreaterThanOrEqual(4);
    expect(result.bidiCount).toBe(3);
    expect(result.text).not.toContain("\u001b");
    expect(result.text).not.toContain("\u202e");
    expect(result.text).toContain("[BIDI-STRIPPED]");
    expect(result.text).toContain("Clipboard hijack attempt");
    expect(result.text).toContain("<script>window.__pwned = true;</script>");
  });

  it("blocks javascript:, data:, vbscript:, file:, and control-obfuscated URLs", () => {
    expect(sanitizeNavigationHref("javascript:alert(1)")).toBeNull();
    expect(sanitizeNavigationHref("  JaVa\tScRiPt:alert(1)")).toBeNull();
    expect(sanitizeNavigationHref("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")).toBeNull();
    expect(sanitizeNavigationHref("vbscript:msgbox(1)")).toBeNull();
    expect(sanitizeNavigationHref("file:///etc/passwd")).toBeNull();
    expect(sanitizeNavigationHref("//evil.example/phish")).toBeNull();

    expect(sanitizeNavigationHref("/w/acme/repairs/rep-1")).toBe("/w/acme/repairs/rep-1");
    expect(sanitizeNavigationHref("https://github.com/org/repo/pull/42")).toBe(
      "https://github.com/org/repo/pull/42",
    );
  });

  it("renders hostile XSS, markdown javascript: links, and ANSI escapes inertly in SafeLogViewer", () => {
    const hostileLines = [
      "<script>throw new Error('XSS executed')</script>",
      "<img src=x onerror=\"alert('xss')\" />",
      "[Open build log](javascript:alert(document.cookie))",
      "[Payload](data:text/html,<script>alert(1)</script>)",
      "\u001b]52;c;c2VjcmV0\u0007\u001b[2J\u001b[1;31mFAIL test_auth.py\u001b[0m",
    ];

    const { container } = render(
      <ViewerHarness>
        <SafeLogViewer lines={hostileLines} defaultMode="paged" />
      </ViewerHarness>,
    );

    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
    expect(container.querySelector('a[href^="data:"]')).toBeNull();

    // Literal payload text is visible for forensics while remaining completely inert
    expect(
      screen.getByText("<script>throw new Error('XSS executed')</script>"),
    ).toBeInTheDocument();
    expect(screen.getByText("FAIL test_auth.py")).toBeInTheDocument();
    expect(screen.getByText(/Sanitized \d+ unsafe control or bidi sequences/)).toBeInTheDocument();
  });

  it("renders hostile diff payloads inertly in SafeDiffViewer with non-color +/- semantics", () => {
    const hostileDiff = [
      "diff --git a/src/view.ts b/src/view.ts",
      "--- a/src/view.ts",
      "+++ b/src/view.ts",
      "@@ -10,3 +10,3 @@",
      " const safe = true;",
      "-\u001b]52;c;bad\u0007const oldHtml = '<img src=x onerror=alert(1)>';",
      "+const link = '[click](javascript:alert(1))'; // \u202ehidden",
    ].join("\n");

    const { container } = render(
      <ViewerHarness>
        <SafeDiffViewer rawDiff={hostileDiff} defaultMode="paged" />
      </ViewerHarness>,
    );

    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector('a[href^="javascript:"]')).toBeNull();

    expect(screen.getByText(/\[BIDI-STRIPPED\]/)).toBeInTheDocument();
    expect(screen.getAllByLabelText("Added line").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByLabelText("Removed line").length).toBeGreaterThanOrEqual(1);
  });

  it("virtualizes 50,000 log lines in <= 2000ms (NFR-12) with bounded DOM nodes and supports paged keyboard mode", async () => {
    const user = userEvent.setup();
    const lines = Array.from(
      { length: 50_000 },
      (_, idx) => `2026-10-27T07:00:00Z [worker-01] step=${idx + 1} pytest assertion check`,
    );

    const t0 = performance.now();
    const { container } = render(
      <ViewerHarness>
        <SafeLogViewer lines={lines} height={400} />
      </ViewerHarness>,
    );
    const elapsedMs = performance.now() - t0;

    expect(elapsedMs).toBeLessThan(2000);
    const renderedRows = container.querySelectorAll("[data-log-line]");
    expect(renderedRows.length).toBeGreaterThan(0);
    expect(renderedRows.length).toBeLessThan(120);

    // Toggle to paged keyboard mode and verify keyboard pagination works
    await user.click(screen.getByRole("button", { name: "Switch to paged keyboard view" }));
    const list = screen.getByRole("list", { name: /Sanitized Execution Log/i });
    expect(within(list).getAllByRole("listitem").length).toBeLessThanOrEqual(200);
  });

  it("virtualizes 50,000 unified diff lines in <= 2000ms (NFR-12) with bounded DOM nodes", () => {
    const bodyLines = Array.from({ length: 49_996 }, (_, idx) =>
      idx % 2 === 0 ? `+const added_${idx} = ${idx};` : `-const removed_${idx} = ${idx};`,
    );
    const hugeDiff = [
      "diff --git a/src/large.ts b/src/large.ts",
      "--- a/src/large.ts",
      "+++ b/src/large.ts",
      "@@ -1,25000 +1,25000 @@",
      ...bodyLines,
    ].join("\n");

    const t0 = performance.now();
    const { container } = render(
      <ViewerHarness>
        <SafeDiffViewer rawDiff={hugeDiff} height={400} />
      </ViewerHarness>,
    );
    const elapsedMs = performance.now() - t0;

    expect(elapsedMs).toBeLessThan(2000);
    const renderedDiffRows = container.querySelectorAll("[data-diff-row]");
    expect(renderedDiffRows.length).toBeGreaterThan(0);
    expect(renderedDiffRows.length).toBeLessThan(120);
  });
});
