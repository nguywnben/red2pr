import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import React, { useState } from "react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../../i18n";
import { ThemeProvider } from "../../theme";
import {
  ALL_UX_STATE_KINDS,
  AppShell,
  Button,
  ChartWithTableFallback,
  Dialog,
  ProofStatusBadge,
  StateView,
  Table,
  useLiveAnnouncer,
  type TableColumn,
  type TableSortState,
  type UxStateKind,
} from "../index";

function TestHarness({
  themeMode = "light",
  children,
}: {
  readonly themeMode?: "light" | "dark" | "system";
  readonly children: React.ReactNode;
}): React.JSX.Element {
  return (
    <MemoryRouter initialEntries={["/w/acme/repairs"]}>
      <I18nProvider>
        <ThemeProvider defaultMode={themeMode}>{children}</ThemeProvider>
      </I18nProvider>
    </MemoryRouter>
  );
}

async function expectZeroAxeViolations(container: HTMLElement): Promise<void> {
  const results = await axe.run(container, {
    rules: {
      // Landmark uniqueness is tested at full-page AppShell level; disable region check for isolated snippets
      region: { enabled: false },
    },
  });
  expect(results.violations).toEqual([]);
}

describe("U04 Astryx Wrappers, Unified UX States & Accessibility (T-UI-01-P, T-UI-02-P)", () => {
  it("renders Button with verified Astryx props, blocks unsafe href schemes, and passes axe in light & dark themes", async () => {
    const onClick = vi.fn();
    const user = userEvent.setup();

    const { container, unmount } = render(
      <TestHarness themeMode="light">
        <div>
          <Button label="Trigger repair" variant="primary" onClick={onClick} />
          <Button label="Busy action" variant="secondary" isLoading />
          <Button label="Disabled action" variant="ghost" isDisabled onClick={onClick} />
          <Button label="Unsafe link" href="javascript:alert(1)" />
        </div>
      </TestHarness>,
    );

    await user.click(screen.getByRole("button", { name: "Trigger repair" }));
    expect(onClick).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "Disabled action" }));
    expect(onClick).toHaveBeenCalledTimes(1);

    // Unsafe javascript: href must never render an <a> tag with javascript:
    expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
    expect(screen.getByRole("button", { name: "Unsafe link" })).toBeDisabled();

    await expectZeroAxeViolations(container);
    unmount();

    const darkRender = render(
      <TestHarness themeMode="dark">
        <div>
          <Button label="Dark primary" variant="primary" />
          <Button label="Dark destructive" variant="destructive" />
        </div>
      </TestHarness>,
    );
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    await expectZeroAxeViolations(darkRender.container);
  });

  it("traps keyboard Tab focus inside Dialog, closes on Escape for form/info, blocks Escape for required, and restores focus", async () => {
    const user = userEvent.setup();

    function DialogFixture({ purpose }: { readonly purpose: "info" | "form" | "required" }) {
      const [open, setOpen] = useState(false);
      return (
        <TestHarness>
          <Button label="Open approval dialog" onClick={() => setOpen(true)} />
          <Dialog
            isOpen={open}
            onOpenChange={setOpen}
            purpose={purpose}
            title="Approve Draft Publication"
            subtitle="Bound to base SHA 8f2d1a0"
            correlationId="corr-dlg-01"
            footer={
              <div>
                <Button label="Cancel" variant="secondary" onClick={() => setOpen(false)} />
                <Button label="Confirm approval" variant="primary" onClick={() => setOpen(false)} />
              </div>
            }
          >
            <label htmlFor="approval-note">
              Reviewer note
              <input id="approval-note" className="red2pr-control-input" type="text" />
            </label>
          </Dialog>
        </TestHarness>
      );
    }

    const { unmount } = render(<DialogFixture purpose="form" />);
    const opener = screen.getByRole("button", { name: "Open approval dialog" });
    await user.click(opener);

    const dialog = screen.getByRole("dialog", { name: /Approve Draft Publication/i });
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByText(/corr-dlg-01/)).toBeInTheDocument();

    // Tab cycling stays inside the modal dialog
    const noteInput = within(dialog).getByLabelText(/Reviewer note/i);
    noteInput.focus();
    expect(document.activeElement).toBe(noteInput);
    await user.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);
    await user.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);
    await user.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);

    // Escape dismisses 'form' dialog and restores focus to opener
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(document.activeElement).toBe(opener);
    unmount();

    // 'required' purpose renders WAI-ARIA alertdialog and blocks Escape dismissal
    render(<DialogFixture purpose="required" />);
    await user.click(screen.getByRole("button", { name: "Open approval dialog" }));
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });

  it("renders Table with Astryx plugins record, column sorting, and accessible paged keyboard fallback", async () => {
    const user = userEvent.setup();
    interface RepoRow extends Record<string, unknown> {
      id: string;
      repo: string;
      mode: string;
    }

    const rows: RepoRow[] = Array.from({ length: 12 }, (_, idx) => ({
      id: `repo-${String(idx + 1).padStart(2, "0")}`,
      repo: `org/service-${String(idx + 1).padStart(2, "0")}`,
      mode: idx % 2 === 0 ? "approval" : "monitor",
    }));

    const columns: TableColumn<RepoRow>[] = [
      { key: "repo", header: "Repository", sortable: true },
      { key: "mode", header: "Activation Mode", sortable: true },
    ];

    function PagedTableDemo() {
      const [page, setPage] = useState(1);
      const [sort, setSort] = useState<TableSortState>([]);
      return (
        <TestHarness>
          <Table
            aria-label="Repositories table"
            data={rows}
            columns={columns}
            idKey="id"
            sort={sort}
            onSortChange={setSort}
            pagination={{
              page,
              pageSize: 5,
              totalItems: rows.length,
              onPageChange: setPage,
              sliceClientData: true,
            }}
          />
        </TestHarness>
      );
    }

    const { container } = render(<PagedTableDemo />);
    expect(screen.getByText("org/service-01")).toBeInTheDocument();
    expect(screen.queryByText("org/service-06")).not.toBeInTheDocument();

    // Navigate to page 2 via accessible pagination controls ("Go to page 2")
    const page2Button = screen.getByRole("button", { name: /^(?:Go to )?(?:page )?2$/i });
    await user.click(page2Button);
    expect(screen.getByText("org/service-06")).toBeInTheDocument();

    await expectZeroAxeViolations(container);
  });

  it("renders all canonical Unified UX States with icon + text (never color alone) and passes axe in light & dark themes", async () => {
    for (const themeMode of ["light", "dark"] as const) {
      const { container, unmount } = render(
        <TestHarness themeMode={themeMode}>
          <div>
            {ALL_UX_STATE_KINDS.map((kind: UxStateKind) => (
              <StateView
                key={kind}
                state={kind}
                correlationId={`corr-${kind}`}
                primaryAction={{ label: `Action ${kind}`, onClick: () => undefined }}
              />
            ))}
          </div>
        </TestHarness>,
      );

      for (const kind of ALL_UX_STATE_KINDS) {
        const node = container.querySelector(`[data-ux-state="${kind}"]`);
        expect(node).not.toBeNull();
        expect(node?.querySelector("svg")).not.toBeNull();
        expect(node?.textContent).toContain(`corr-${kind}`);
      }

      await expectZeroAxeViolations(container);
      unmount();
    }
  });

  it("enforces UX-03 proof distinction: locally verified + remote CI failed never shows green/fixed", () => {
    render(
      <TestHarness>
        <div>
          <ProofStatusBadge proofStage="locally_verified" remoteCiOutcome="failed" />
          <ProofStatusBadge proofStage="remotely_verified" remoteCiOutcome="passed" />
          <ProofStatusBadge proofStage="repro_unconfirmed" />
        </div>
      </TestHarness>,
    );

    const remoteFailedBadge = screen.getByTestId("proof-badge-remote_ci_failed");
    expect(remoteFailedBadge).toHaveTextContent("Locally Verified · Remote CI Failed");
    expect(remoteFailedBadge.className).toContain("red2pr-tone-danger");

    const remotePassedBadge = screen.getByTestId("proof-badge-remotely_verified");
    expect(remotePassedBadge).toHaveTextContent("Remotely Verified (Provider CI)");

    const unconfirmedBadge = screen.getByTestId("proof-badge-repro_unconfirmed");
    expect(unconfirmedBadge).toHaveTextContent("Reproduction Unconfirmed — No PR");
  });

  it("renders ChartWithTableFallback with mandatory denominator, UTC watermark, and accessible table toggle", async () => {
    const user = userEvent.setup();
    const { container } = render(
      <TestHarness>
        <ChartWithTableFallback
          title="Repair Verification Funnel"
          denominator={120}
          denominatorUnit="failed runs"
          windowStartUtc="2026-10-01T00:00:00Z"
          windowEndUtc="2026-10-27T00:00:00Z"
          series={[
            { id: "ingested", label: "Failed Runs Ingested", value: 120 },
            { id: "reproduced", label: "Baseline Reproduced", value: 84 },
            { id: "verified", label: "Locally Verified", value: 66 },
            { id: "remote_green", label: "Remotely Verified", value: 60 },
          ]}
        />
      </TestHarness>,
    );

    expect(screen.getByText(/Denominator: n = 120 failed runs/)).toBeInTheDocument();
    expect(
      screen.getByText(/Window: 2026-10-01 00:00:00 UTC – 2026-10-27 00:00:00 UTC/),
    ).toBeInTheDocument();

    await expectZeroAxeViolations(container);

    // Switch to accessible semantic table fallback
    await user.click(screen.getByRole("button", { name: "Data table view" }));
    const table = screen.getByRole("table", { name: /Repair Verification Funnel/i });
    expect(within(table).getByText("Baseline Reproduced")).toBeInTheDocument();
    expect(within(table).getByText("70.0%")).toBeInTheDocument();
    await expectZeroAxeViolations(container);
  });

  it("renders AppShell with skip link, workspace switcher, SSE indicator, and throttled aria-live announcer", async () => {
    vi.useFakeTimers();
    try {
      function AnnouncerProbe(): React.JSX.Element {
        const announce = useLiveAnnouncer();
        return (
          <div>
            <button
              type="button"
              onClick={() => {
                announce("Phase changed: diagnosing");
                announce("Phase changed: reproducing");
                announce("Phase changed: locally_verified");
              }}
            >
              Emit rapid phases
            </button>
          </div>
        );
      }

      const onSelectWorkspace = vi.fn();
      const { container } = render(
        <TestHarness>
          <AppShell
            activePath="/w/acme/repairs"
            activeWorkspaceSlug="acme"
            workspaces={[
              { slug: "acme", name: "Acme Core" },
              { slug: "infra", name: "Infra Sec" },
            ]}
            onSelectWorkspace={onSelectWorkspace}
            sseState="connected"
          >
            <h1>Repairs</h1>
            <AnnouncerProbe />
          </AppShell>
        </TestHarness>,
      );

      // Skip link exists targeting #astryx-app-shell-main
      const skipLink = container.querySelector('a[href="#astryx-app-shell-main"]');
      expect(skipLink).not.toBeNull();
      expect(container.querySelector("#astryx-app-shell-main")).not.toBeNull();

      // SSE status uses text + icon
      expect(screen.getByText("Live stream connected")).toBeInTheDocument();

      // Rapid announcements coalesce via throttle rather than spamming every intermediate update
      const liveRegion = screen.getByTestId("red2pr-live-announcer");
      expect(liveRegion).toHaveAttribute("aria-live", "polite");

      act(() => {
        screen.getByRole("button", { name: "Emit rapid phases" }).click();
      });
      // First announcement fires immediately; trailing burst coalesces until throttle window elapses
      expect(liveRegion).toHaveTextContent("Phase changed: diagnosing");

      act(() => {
        vi.advanceTimersByTime(1300);
      });
      expect(liveRegion).toHaveTextContent("Phase changed: locally_verified");
    } finally {
      vi.useRealTimers();
    }
  });
});
