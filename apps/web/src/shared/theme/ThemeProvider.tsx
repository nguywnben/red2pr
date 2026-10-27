import { LinkProvider } from "@astryxdesign/core/Link";
import { Theme, type ThemeMode } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral/built";
import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { Link as RouterLink } from "react-router";
import "./tokens.css";

export type { ThemeMode };
export type ResolvedThemeMode = "light" | "dark";

export const THEME_STORAGE_KEY = "red2pr.theme.mode";

export interface Red2PrThemeContextValue {
  readonly mode: ThemeMode;
  readonly resolvedTheme: ResolvedThemeMode;
  readonly prefersReducedMotion: boolean;
  readonly setMode: (nextMode: ThemeMode) => void;
}

const Red2PrThemeContext = createContext<Red2PrThemeContextValue | null>(null);

function readStoredThemeMode(storageKey: string, fallback: ThemeMode): ThemeMode {
  if (typeof window === "undefined") {
    return fallback;
  }
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (raw === "light" || raw === "dark" || raw === "system") {
      return raw;
    }
  } catch {
    // Ignore storage access errors in restricted browsing contexts
  }
  return fallback;
}

function getSystemDarkPreference(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function getSystemReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function isSafeLinkHref(href: string | undefined): string | null {
  if (typeof href !== "string") {
    return null;
  }
  const trimmed = href.trim();
  if (trimmed.length === 0) {
    return null;
  }
  // Strip ASCII whitespace/control characters before scheme check (SEC-040)
  let compact = "";
  for (let i = 0; i < trimmed.length; i += 1) {
    const code = trimmed.charCodeAt(i);
    if (code > 0x20 && code !== 0x7f) {
      compact += trimmed[i];
    }
  }
  const lower = compact.toLowerCase();
  if (
    lower.startsWith("javascript:") ||
    lower.startsWith("data:") ||
    lower.startsWith("vbscript:") ||
    lower.startsWith("file:") ||
    lower.startsWith("//")
  ) {
    return null;
  }
  if (trimmed.startsWith("/") || trimmed.startsWith("#")) {
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

function SafeAstryxLink({ href, children, ref, ...rest }: SafeAnchorProps): React.JSX.Element {
  const safeHref = isSafeLinkHref(href);
  if (safeHref === null) {
    return (
      <span {...rest} aria-disabled="true" data-unsafe-href-blocked="true">
        {children}
      </span>
    );
  }
  if (safeHref.startsWith("/")) {
    return (
      <RouterLink ref={ref} to={safeHref} {...rest}>
        {children}
      </RouterLink>
    );
  }
  return (
    <a ref={ref} href={safeHref} {...rest}>
      {children}
    </a>
  );
}

export interface ThemeProviderProps {
  readonly defaultMode?: ThemeMode;
  readonly storageKey?: string;
  readonly children: React.ReactNode;
}

export function ThemeProvider({
  defaultMode = "system",
  storageKey = THEME_STORAGE_KEY,
  children,
}: ThemeProviderProps): React.JSX.Element {
  const [mode, setModeState] = useState<ThemeMode>(() =>
    readStoredThemeMode(storageKey, defaultMode),
  );
  const [systemDark, setSystemDark] = useState<boolean>(getSystemDarkPreference);
  const [prefersReducedMotion, setPrefersReducedMotion] =
    useState<boolean>(getSystemReducedMotion);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return undefined;
    }
    const darkMql = window.matchMedia("(prefers-color-scheme: dark)");
    const motionMql = window.matchMedia("(prefers-reduced-motion: reduce)");

    const onDarkChange = (event: MediaQueryListEvent): void => {
      setSystemDark(event.matches);
    };
    const onMotionChange = (event: MediaQueryListEvent): void => {
      setPrefersReducedMotion(event.matches);
    };

    darkMql.addEventListener("change", onDarkChange);
    motionMql.addEventListener("change", onMotionChange);
    return () => {
      darkMql.removeEventListener("change", onDarkChange);
      motionMql.removeEventListener("change", onMotionChange);
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
  }, [mode, resolvedTheme]);

  const setMode = useCallback(
    (nextMode: ThemeMode): void => {
      setModeState(nextMode);
      if (typeof window !== "undefined") {
        try {
          window.localStorage.setItem(storageKey, nextMode);
        } catch {
          // Ignore storage write errors
        }
      }
    },
    [storageKey],
  );

  const contextValue = useMemo<Red2PrThemeContextValue>(
    () => ({
      mode,
      resolvedTheme,
      prefersReducedMotion,
      setMode,
    }),
    [mode, resolvedTheme, prefersReducedMotion, setMode],
  );

  return (
    <Red2PrThemeContext.Provider value={contextValue}>
      <Theme theme={neutralTheme} mode={resolvedTheme}>
        <LinkProvider component={SafeAstryxLink}>{children}</LinkProvider>
      </Theme>
    </Red2PrThemeContext.Provider>
  );
}

export function useRed2PrTheme(): Red2PrThemeContextValue {
  const ctx = useContext(Red2PrThemeContext);
  if (ctx !== null) {
    return ctx;
  }
  return {
    mode: "light",
    resolvedTheme: "light",
    prefersReducedMotion: false,
    setMode: () => undefined,
  };
}
