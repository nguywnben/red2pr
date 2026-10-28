import { AppShell as AstryxAppShell } from "@astryxdesign/core/AppShell";
import { SideNav, SideNavItem, SideNavSection } from "@astryxdesign/core/SideNav";
import { TopNav, TopNavHeading } from "@astryxdesign/core/TopNav";
import { VisuallyHidden } from "@astryxdesign/core/VisuallyHidden";
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import { useI18n, type MessageKey } from "../i18n";
import { useRed2PrTheme, type ThemeMode } from "../theme";
import { StatusGlyph } from "./StateViews";

export type SseConnectionStatus =
  | "connected"
  | "connecting"
  | "reconciling"
  | "stale"
  | "offline"
  | "unauthorized"
  | "forbidden";

export interface WorkspaceNavOption {
  readonly slug: string;
  readonly name: string;
}

export interface ShellNavItem {
  readonly id: string;
  readonly labelKey: MessageKey;
  readonly href: string;
}

const LiveAnnouncerContext = createContext<(message: string) => void>(() => undefined);

export function useLiveAnnouncer(): (message: string) => void {
  return useContext(LiveAnnouncerContext);
}

interface ThrottledLiveRegionProps {
  readonly throttleMs?: number;
  readonly children: React.ReactNode;
}

export function LiveRegionProvider({
  throttleMs = 1200,
  children,
}: ThrottledLiveRegionProps): React.JSX.Element {
  const [announcement, setAnnouncement] = useState<string>("");
  const lastAnnouncedAtRef = useRef<number>(0);
  const pendingMessageRef = useRef<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
      }
    };
  }, []);

  const announce = useCallback(
    (message: string): void => {
      const clean = message.trim();
      if (clean.length === 0) {
        return;
      }
      const now = Date.now();
      const elapsed = now - lastAnnouncedAtRef.current;
      if (lastAnnouncedAtRef.current === 0 || elapsed >= throttleMs) {
        lastAnnouncedAtRef.current = now;
        pendingMessageRef.current = null;
        if (timerRef.current !== null) {
          clearTimeout(timerRef.current);
          timerRef.current = null;
        }
        setAnnouncement(clean);
        return;
      }

      pendingMessageRef.current = clean;
      if (timerRef.current === null) {
        const remaining = Math.max(25, throttleMs - elapsed);
        timerRef.current = setTimeout(() => {
          timerRef.current = null;
          lastAnnouncedAtRef.current = Date.now();
          if (pendingMessageRef.current !== null) {
            setAnnouncement(pendingMessageRef.current);
            pendingMessageRef.current = null;
          }
        }, remaining);
      }
    },
    [throttleMs],
  );

  return (
    <LiveAnnouncerContext.Provider value={announce}>
      {children}
      <VisuallyHidden
        as="div"
        role="status"
        aria-live="polite"
        aria-atomic="true"
        data-testid="red2pr-live-announcer"
      >
        {announcement}
      </VisuallyHidden>
    </LiveAnnouncerContext.Provider>
  );
}

function buildDefaultNavItems(workspaceSlug: string | undefined): readonly ShellNavItem[] {
  const prefix = workspaceSlug ? `/w/${encodeURIComponent(workspaceSlug)}` : "";
  return [
    { id: "overview", labelKey: "app.nav.overview", href: `${prefix}/overview` },
    { id: "pipelines", labelKey: "app.nav.pipelines", href: `${prefix}/pipelines` },
    { id: "repairs", labelKey: "app.nav.repairs", href: `${prefix}/repairs` },
    { id: "approvals", labelKey: "app.nav.approvals", href: `${prefix}/approvals` },
    {
      id: "repositories",
      labelKey: "app.nav.repositories",
      href: `${prefix}/repositories`,
    },
    {
      id: "integrations",
      labelKey: "app.nav.integrations",
      href: `${prefix}/integrations`,
    },
    { id: "workers", labelKey: "app.nav.workers", href: `${prefix}/workers` },
    { id: "queues", labelKey: "app.nav.queues", href: `${prefix}/queues` },
    { id: "models", labelKey: "app.nav.models", href: `${prefix}/models` },
    { id: "agents", labelKey: "app.nav.agents", href: `${prefix}/agents` },
    {
      id: "notifications",
      labelKey: "app.nav.notifications",
      href: `${prefix}/notifications`,
    },
    { id: "analytics", labelKey: "app.nav.analytics", href: `${prefix}/analytics` },
    { id: "audit", labelKey: "app.nav.audit", href: `${prefix}/audit` },
    { id: "members", labelKey: "app.nav.members", href: `${prefix}/members` },
    { id: "settings", labelKey: "app.nav.settings", href: `${prefix}/settings` },
    { id: "operations", labelKey: "app.nav.operations", href: "/admin/operations" },
    { id: "account", labelKey: "app.nav.account", href: "/account" },
  ];
}

function SseStatusIndicator({ state }: { readonly state: SseConnectionStatus }): React.JSX.Element {
  const { t } = useI18n();
  const mapping: Record<
    SseConnectionStatus,
    {
      readonly key: MessageKey;
      readonly tone: string;
      readonly icon: "check" | "clock" | "warn" | "offline" | "lock";
    }
  > = {
    connected: { key: "app.sse.connected", tone: "red2pr-tone-success", icon: "check" },
    connecting: { key: "app.sse.connecting", tone: "red2pr-tone-info", icon: "clock" },
    reconciling: { key: "app.sse.reconciling", tone: "red2pr-tone-info", icon: "clock" },
    stale: { key: "app.sse.stale", tone: "red2pr-tone-warning", icon: "warn" },
    offline: { key: "app.sse.offline", tone: "red2pr-tone-danger", icon: "offline" },
    unauthorized: { key: "app.sse.unauthorized", tone: "red2pr-tone-warning", icon: "lock" },
    forbidden: { key: "app.sse.forbidden", tone: "red2pr-tone-danger", icon: "lock" },
  };
  const current = mapping[state];
  return (
    <span className={`red2pr-badge-pill ${current.tone}`} data-sse-status={state}>
      <StatusGlyph kind={current.icon} />
      <span>{t(current.key)}</span>
    </span>
  );
}

export interface Red2PrAppShellProps {
  readonly activePath: string;
  readonly activeWorkspaceSlug?: string;
  readonly workspaces?: readonly WorkspaceNavOption[];
  readonly onSelectWorkspace?: (workspaceSlug: string) => void;
  readonly navItems?: readonly ShellNavItem[];
  readonly sseState?: SseConnectionStatus;
  readonly banner?: React.ReactNode;
  readonly throttleAnnouncementMs?: number;
  readonly children: React.ReactNode;
}

export function AppShell({
  activePath,
  activeWorkspaceSlug,
  workspaces = [],
  onSelectWorkspace,
  navItems,
  sseState = "connected",
  banner,
  throttleAnnouncementMs = 1200,
  children,
}: Red2PrAppShellProps): React.JSX.Element {
  const { t } = useI18n();
  const { mode, setMode } = useRed2PrTheme();
  const wsSelectId = useId();
  const themeSelectId = useId();

  const resolvedNavItems = useMemo(
    () => navItems ?? buildDefaultNavItems(activeWorkspaceSlug),
    [activeWorkspaceSlug, navItems],
  );

  const handleWorkspaceChange = useCallback(
    (event: React.ChangeEvent<HTMLSelectElement>): void => {
      onSelectWorkspace?.(event.target.value);
    },
    [onSelectWorkspace],
  );

  const handleThemeChange = useCallback(
    (event: React.ChangeEvent<HTMLSelectElement>): void => {
      const value = event.target.value;
      if (value === "light" || value === "dark" || value === "system") {
        setMode(value as ThemeMode);
      }
    },
    [setMode],
  );

  return (
    <LiveRegionProvider throttleMs={throttleAnnouncementMs}>
      <AstryxAppShell
        variant="section"
        contentPadding={4}
        banner={banner}
        topNav={
          <TopNav
            label={t("app.nav.topBar")}
            heading={
              <TopNavHeading
                heading={t("app.brand")}
                subheading={t("app.tagline")}
                headingHref="/"
              />
            }
            endContent={
              <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10 }}>
                <SseStatusIndicator state={sseState} />
                {workspaces.length > 0 ? (
                  <div style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                    <label htmlFor={wsSelectId} style={{ fontSize: "0.8125rem", fontWeight: 500 }}>
                      {t("app.workspace.label")}
                    </label>
                    <select
                      id={wsSelectId}
                      className="red2pr-control-select"
                      value={activeWorkspaceSlug ?? ""}
                      onChange={handleWorkspaceChange}
                    >
                      {workspaces.map((ws) => (
                        <option key={ws.slug} value={ws.slug}>
                          {ws.name}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : null}
                <div style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                  <label htmlFor={themeSelectId} style={{ fontSize: "0.8125rem", fontWeight: 500 }}>
                    {t("app.theme.label")}
                  </label>
                  <select
                    id={themeSelectId}
                    className="red2pr-control-select"
                    value={mode}
                    onChange={handleThemeChange}
                  >
                    <option value="light">{t("app.theme.light")}</option>
                    <option value="dark">{t("app.theme.dark")}</option>
                    <option value="system">{t("app.theme.system")}</option>
                  </select>
                </div>
              </div>
            }
          />
        }
        sideNav={
          <SideNav aria-label={t("app.nav.primary")}>
            <SideNavSection title={t("app.nav.primary")} isHeaderHidden>
              {resolvedNavItems.map((item) => {
                const selected =
                  activePath === item.href || activePath.startsWith(`${item.href}/`);
                return (
                  <SideNavItem
                    key={item.id}
                    label={t(item.labelKey)}
                    href={item.href}
                    isSelected={selected}
                  />
                );
              })}
            </SideNavSection>
          </SideNav>
        }
      >
        {children}
      </AstryxAppShell>
    </LiveRegionProvider>
  );
}
