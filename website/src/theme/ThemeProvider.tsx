import { LinkProvider } from "@astryxdesign/core/Link";
import { Theme, type ThemeMode } from "@astryxdesign/core/theme";
import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { neutralTheme } from "../astryx-themes";

export type { ThemeMode };
export type ResolvedThemeMode = "light" | "dark";

const WEBSITE_THEME_STORAGE_KEY = "red2pr-website-theme";

export interface WebsiteThemeContextValue {
  readonly mode: ThemeMode;
  readonly resolvedTheme: ResolvedThemeMode;
  readonly setMode: (nextMode: ThemeMode) => void;
}

const WebsiteThemeContext = createContext<WebsiteThemeContextValue | null>(null);

function readStoredThemeMode(): ThemeMode {
  if (typeof window === "undefined") {
    return "system";
  }
  try {
    const raw = window.localStorage.getItem(WEBSITE_THEME_STORAGE_KEY);
    if (raw === "light" || raw === "dark" || raw === "system") {
      return raw;
    }
  } catch {
    // Ignore restricted storage environments
  }
  return "system";
}

function getSystemDarkPreference(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function sanitizeAnchorHref(href: string | undefined): string | null {
  if (typeof href !== "string") {
    return null;
  }
  const trimmed = href.trim();
  if (trimmed.length === 0) {
    return null;
  }
  if (trimmed.startsWith("#") || trimmed.startsWith("/")) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === "https:" || parsed.protocol === "http:") {
      return parsed.toString();
    }
  } catch {
    return null;
  }
  return null;
}

interface SafeAnchorProps extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  href?: string;
  ref?: React.Ref<HTMLAnchorElement>;
}

function SafeMarketingLink({ href, children, ref, target, rel, ...rest }: SafeAnchorProps): React.JSX.Element {
  const safeHref = sanitizeAnchorHref(href);
  if (safeHref === null) {
    return (
      <span {...rest} aria-disabled="true">
        {children}
      </span>
    );
  }
  const safeRel =
    target === "_blank" ? (rel ? `${rel} noopener noreferrer` : "noopener noreferrer") : rel;
  return (
    <a ref={ref} href={safeHref} target={target} rel={safeRel} {...rest}>
      {children}
    </a>
  );
}

export function WebsiteThemeProvider({ children }: { readonly children: React.ReactNode }): React.JSX.Element {
  const [mode, setModeState] = useState<ThemeMode>(readStoredThemeMode);
  const [systemDark, setSystemDark] = useState<boolean>(getSystemDarkPreference);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return undefined;
    }
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (event: MediaQueryListEvent): void => {
      setSystemDark(event.matches);
    };
    mql.addEventListener("change", onChange);
    return () => {
      mql.removeEventListener("change", onChange);
    };
  }, []);

  const resolvedTheme: ResolvedThemeMode =
    mode === "system" ? (systemDark ? "dark" : "light") : mode;

  useEffect(() => {
    if (typeof document === "undefined") {
      return;
    }
    const root = document.documentElement;
    root.setAttribute("data-astryx-theme", "neutral");
    root.setAttribute("data-theme", resolvedTheme);
    root.setAttribute("data-theme-preference", mode);
    root.style.colorScheme = resolvedTheme;
  }, [mode, resolvedTheme]);

  const setMode = useCallback((nextMode: ThemeMode): void => {
    setModeState(nextMode);
    if (typeof window !== "undefined") {
      try {
        window.localStorage.setItem(WEBSITE_THEME_STORAGE_KEY, nextMode);
      } catch {
        // Ignore storage write errors
      }
    }
  }, []);

  const value = useMemo<WebsiteThemeContextValue>(
    () => ({
      mode,
      resolvedTheme,
      setMode,
    }),
    [mode, resolvedTheme, setMode],
  );

  return (
    <WebsiteThemeContext.Provider value={value}>
      <Theme theme={neutralTheme} mode={resolvedTheme}>
        <LinkProvider component={SafeMarketingLink}>{children}</LinkProvider>
      </Theme>
    </WebsiteThemeContext.Provider>
  );
}

export function useWebsiteTheme(): WebsiteThemeContextValue {
  const context = useContext(WebsiteThemeContext);
  if (context !== null) {
    return context;
  }
  return {
    mode: "light",
    resolvedTheme: "light",
    setMode: () => undefined,
  };
}
