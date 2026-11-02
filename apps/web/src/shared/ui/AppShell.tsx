import { AppShell as AstryxAppShell } from "@astryxdesign/core/AppShell";
import { HStack } from "@astryxdesign/core/HStack";
import { Selector } from "@astryxdesign/core/Selector";
import {
  SideNav,
  SideNavHeading,
  SideNavItem,
  SideNavSection,
} from "@astryxdesign/core/SideNav";
import { Stack } from "@astryxdesign/core/Stack";
import { VisuallyHidden } from "@astryxdesign/core/VisuallyHidden";
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useI18n, type MessageKey } from "../i18n";
import { useRed2PrTheme, type ThemeMode } from "../theme";

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
  readonly group: "work" | "review" | "operations" | "access" | "instance";
}

type NavGlyphProps = React.SVGProps<SVGSVGElement>;
type NavGlyph = React.ComponentType<NavGlyphProps>;

function makeNavGlyph(path: string): NavGlyph {
  return function NavigationGlyph(props: NavGlyphProps): React.JSX.Element {
    return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}><path d={path} /></svg>;
  };
}

const NAV_ICONS: Record<string, NavGlyph> = {
  overview: makeNavGlyph("M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z"),
  repositories: makeNavGlyph("M4 4h16v16H4zM8 8h8M8 12h8M8 16h5"),
  pipelines: makeNavGlyph("M4 5h5v5H4zM15 14h5v5h-5zM9 7h3a3 3 0 0 1 3 3v4"),
  repairs: makeNavGlyph("M14 6a4 4 0 0 0-5 5l-5 5a2 2 0 0 0 3 3l5-5a4 4 0 0 0 5-5l-3 3-3-3z"),
  prs: makeNavGlyph("M6 3v18M18 7v10M6 7a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM18 7a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM18 21a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM6 7c0 5 12 3 12 10"),
  approvals: makeNavGlyph("m5 12 4 4L19 6M4 3h16v18H4z"),
  agents: makeNavGlyph("M12 3v3M5 6l2 2M3 13h3M18 8l2-2M18 13h3M8 18h8M9 21h6M8 14a4 4 0 1 1 8 0v4H8z"),
  models: makeNavGlyph("M12 3 3 8l9 5 9-5-9-5zM3 12l9 5 9-5M3 16l9 5 9-5"),
  workers: makeNavGlyph("M4 5h16v14H4zM8 9h3v3H8zM14 9h2M14 12h2M8 16h8"),
  queues: makeNavGlyph("M4 6h16M4 12h16M4 18h16M7 6v0M7 12v0M7 18v0"),
  integrations: makeNavGlyph("M8 12h8M12 8v8M7 4H5a2 2 0 0 0-2 2v2M17 4h2a2 2 0 0 1 2 2v2M7 20H5a2 2 0 0 1-2-2v-2M17 20h2a2 2 0 0 0 2-2v-2"),
  notifications: makeNavGlyph("M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"),
  analytics: makeNavGlyph("M4 19V5M4 19h17M8 15l3-4 3 2 5-7"),
  members: makeNavGlyph("M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M10 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM20 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"),
  security: makeNavGlyph("M12 3 20 6v5c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6zM9 12l2 2 4-4"),
  account: makeNavGlyph("M20 21a8 8 0 0 0-16 0M12 13a4 4 0 1 0 0-8 4 4 0 0 0 0 8z"),
  system: makeNavGlyph("M4 4h16v16H4zM8 8h8M8 12h5M8 16h8"),
};

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
        as="p"
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

function buildDefaultNavItems(
  workspaceSlug: string | undefined,
  isInstanceOwner: boolean,
): readonly ShellNavItem[] {
  const prefix = workspaceSlug ? `/w/${encodeURIComponent(workspaceSlug)}` : "";
  const items: ShellNavItem[] = [
    { id: "overview", labelKey: "app.nav.overview", href: `${prefix}/overview`, group: "work" },
    {
      id: "repositories",
      labelKey: "app.nav.repositories",
      href: `${prefix}/repositories`,
      group: "work",
    },
    { id: "pipelines", labelKey: "app.nav.pipelines", href: `${prefix}/pipelines`, group: "work" },
    { id: "repairs", labelKey: "app.nav.repairs", href: `${prefix}/repairs`, group: "work" },
    { id: "prs", labelKey: "app.nav.prs", href: `${prefix}/prs`, group: "work" },
    { id: "approvals", labelKey: "app.nav.approvals", href: `${prefix}/approvals`, group: "review" },
    { id: "agents", labelKey: "app.nav.agents", href: `${prefix}/agents`, group: "operations" },
    { id: "models", labelKey: "app.nav.models", href: `${prefix}/models`, group: "operations" },
    { id: "workers", labelKey: "app.nav.workers", href: `${prefix}/workers`, group: "operations" },
    { id: "queues", labelKey: "app.nav.queues", href: `${prefix}/queues`, group: "operations" },
    { id: "integrations", labelKey: "app.nav.integrations", href: `${prefix}/integrations`, group: "operations" },
    {
      id: "notifications",
      labelKey: "app.nav.notifications",
      href: `${prefix}/notifications`,
      group: "operations",
    },
    {
      id: "analytics",
      labelKey: "app.nav.analytics",
      href: `${prefix}/analytics`,
      group: "operations",
    },
    { id: "members", labelKey: "app.nav.members", href: `${prefix}/members`, group: "access" },
    { id: "security", labelKey: "app.nav.security", href: `${prefix}/security`, group: "access" },
  ];
  if (isInstanceOwner) {
    items.push({
      id: "system",
      labelKey: "app.nav.system",
      href: "/system",
      group: "instance",
    });
  }
  return items;
}

export interface Red2PrAppShellProps {
  readonly activePath: string;
  readonly activeWorkspaceSlug?: string;
  readonly workspaces?: readonly WorkspaceNavOption[];
  readonly onSelectWorkspace?: (workspaceSlug: string) => void;
  readonly navItems?: readonly ShellNavItem[];
  readonly isInstanceOwner?: boolean;
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
  isInstanceOwner = false,
  banner,
  throttleAnnouncementMs = 1200,
  children,
}: Red2PrAppShellProps): React.JSX.Element {
  const { t } = useI18n();
  const { mode, resolvedTheme, setMode } = useRed2PrTheme();

  const resolvedNavItems = useMemo(
    () => navItems ?? buildDefaultNavItems(activeWorkspaceSlug, isInstanceOwner),
    [activeWorkspaceSlug, isInstanceOwner, navItems],
  );

  const routeNavItem = resolvedNavItems.find(
    (item) => activePath === item.href || activePath.startsWith(`${item.href}/`),
  );
  const activeExpandableGroup = routeNavItem
    ? ["repositories", "pipelines", "repairs"].includes(routeNavItem.id)
      ? "work"
      : ["prs", "approvals", "notifications"].includes(routeNavItem.id)
        ? "review"
        : ["agents", "models", "workers", "queues", "integrations"].includes(routeNavItem.id)
          ? "operations"
          : ["members", "security"].includes(routeNavItem.id)
            ? "access"
            : null
    : null;
  const [expandedNavGroup, setExpandedNavGroup] = useState(activeExpandableGroup);

  useEffect(() => {
    setExpandedNavGroup(activeExpandableGroup);
  }, [activeExpandableGroup]);

  const workspaceOptions = workspaces.map((workspace) => ({
    value: workspace.slug,
    label: workspace.name,
  }));

  return (
    <LiveRegionProvider throttleMs={throttleAnnouncementMs}>
      <AstryxAppShell
        variant="section"
        height="auto"
        contentPadding={5}
        banner={banner}
        sideNav={
          <SideNav
            aria-label={t("app.nav.primary")}
            className="red2pr-sidebar"
            header={
              <SideNavHeading
                className="red2pr-brand-heading"
                heading={t("app.brand")}
                icon={
                  <img
                    className="red2pr-sidebar-logo"
                    src={resolvedTheme === "dark" ? "/brand/red2pr-logo-dark.svg" : "/brand/red2pr-logo.svg"}
                    alt=""
                  />
                }
                headingHref="/"
              />
            }
            topContent={workspaces.length > 1 ? (
              <Stack className="red2pr-sidebar-workspace">
                  <Selector label={t("app.workspace.label")} isLabelHidden variant="secondary"
                    presentation="adaptive" options={workspaceOptions} value={activeWorkspaceSlug ?? ""}
                    onChange={(workspaceSlug) => onSelectWorkspace?.(workspaceSlug)} />
              </Stack>
            ) : undefined}
            footer={
              <HStack gap={1} className="red2pr-footer-grid-row">
                <Stack className="red2pr-footer-tile red2pr-footer-tile-left">
                  <SideNavItem label={t("app.nav.account")} href="/account" icon={NAV_ICONS.account}
                    isSelected={activePath === "/account" || activePath.startsWith("/account/")} />
                </Stack>
                <Stack className="red2pr-footer-tile red2pr-footer-tile-right">
                  <Selector label={t("app.theme.label")} isLabelHidden
                    hasClear={false} hasSearch={false} placeholder="Select..."
                    size="md" variant="input" presentation="popover"
                    placement="above"
                    options={[{ value: "light", label: t("app.theme.light") }, { value: "dark", label: t("app.theme.dark") }, { value: "system", label: t("app.theme.system") }]}
                    value={mode}
                    onChange={(value) => {
                      if (value === "light" || value === "dark" || value === "system") setMode(value as ThemeMode);
                    }} />
                </Stack>
              </HStack>
            }
          >
            <SideNavSection
              title={workspaces.find((workspace) => workspace.slug === activeWorkspaceSlug)?.name ?? workspaces[0]?.name ?? "No workspace"}
            >
              {resolvedNavItems.filter((item) => item.id === "overview").map((item) => (
                <SideNavItem key={item.id} label={t(item.labelKey)} href={item.href}
                  isSelected={activePath === item.href || activePath.startsWith(`${item.href}/`)}
                  icon={NAV_ICONS[item.id]} />
              ))}
              <SideNavItem label={t("app.nav.group.work")} icon={NAV_ICONS.repositories} collapsible={{
                isCollapsed: expandedNavGroup !== "work",
                onCollapsedChange: (isCollapsed) => setExpandedNavGroup(isCollapsed ? null : "work"),
              }}>
                {resolvedNavItems.filter((item) => ["repositories", "pipelines", "repairs"].includes(item.id)).map((item) => (
                  <SideNavItem key={item.id} label={t(item.labelKey)} href={item.href}
                    isSelected={activePath === item.href || activePath.startsWith(`${item.href}/`)} icon={NAV_ICONS[item.id]} />
                ))}
              </SideNavItem>
              <SideNavItem label={t("app.nav.group.review")} icon={NAV_ICONS.approvals} collapsible={{
                isCollapsed: expandedNavGroup !== "review",
                onCollapsedChange: (isCollapsed) => setExpandedNavGroup(isCollapsed ? null : "review"),
              }}>
                {resolvedNavItems.filter((item) => ["prs", "approvals", "notifications"].includes(item.id)).map((item) => (
                  <SideNavItem key={item.id} label={t(item.labelKey)} href={item.href}
                    isSelected={activePath === item.href || activePath.startsWith(`${item.href}/`)} icon={NAV_ICONS[item.id]} />
                ))}
              </SideNavItem>
              <SideNavItem
                label={t("app.nav.group.operations")}
                icon={NAV_ICONS.agents}
                collapsible={{
                  isCollapsed: expandedNavGroup !== "operations",
                  onCollapsedChange: (isCollapsed) => setExpandedNavGroup(isCollapsed ? null : "operations"),
                }}
              >
                {resolvedNavItems.filter((item) => ["agents", "models", "workers", "queues", "integrations"].includes(item.id)).map((item) => (
                  <SideNavItem key={item.id} label={t(item.labelKey)} href={item.href}
                    isSelected={activePath === item.href || activePath.startsWith(`${item.href}/`)}
                    icon={NAV_ICONS[item.id]} />
                ))}
              </SideNavItem>
              {resolvedNavItems.filter((item) => item.id === "analytics").map((item) => (
                <SideNavItem key={item.id} label={t(item.labelKey)} href={item.href}
                  isSelected={activePath === item.href || activePath.startsWith(`${item.href}/`)} icon={NAV_ICONS[item.id]} />
              ))}
              <SideNavItem
                label={t("app.nav.group.access")}
                icon={NAV_ICONS.members}
                collapsible={{
                  isCollapsed: expandedNavGroup !== "access",
                  onCollapsedChange: (isCollapsed) => setExpandedNavGroup(isCollapsed ? null : "access"),
                }}
              >
                {resolvedNavItems.filter((item) => ["members", "security"].includes(item.id)).map((item) => (
                  <SideNavItem key={item.id} label={t(item.labelKey)} href={item.href}
                    isSelected={activePath === item.href || activePath.startsWith(`${item.href}/`)}
                    icon={NAV_ICONS[item.id]} />
                ))}
              </SideNavItem>
              {resolvedNavItems.filter((item) => item.id === "system").map((item) => (
                <SideNavItem key={item.id} label={t(item.labelKey)} href={item.href}
                  isSelected={activePath === item.href || activePath.startsWith(`${item.href}/`)}
                  icon={NAV_ICONS[item.id]} />
              ))}
            </SideNavSection>
          </SideNav>
        }
      >
        <div className="red2pr-shell-content">
          {children}
        </div>
      </AstryxAppShell>
    </LiveRegionProvider>
  );
}
