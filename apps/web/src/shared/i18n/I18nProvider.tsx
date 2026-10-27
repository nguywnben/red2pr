import { InternationalizationProvider } from "@astryxdesign/core/i18n";
import React, { createContext, useCallback, useContext, useMemo, useState } from "react";
import { EN_MESSAGES, type MessageCatalog, type MessageKey } from "./messages.en";

export type SupportedLocale = "en" | "vi";

export interface I18nContextValue {
  readonly locale: SupportedLocale;
  readonly setLocale: (next: SupportedLocale) => void;
  readonly t: (key: MessageKey, params?: Readonly<Record<string, string | number>>) => string;
  readonly formatDisplayTimestamp: (isoUtc: string) => {
    readonly localText: string;
    readonly utcText: string;
  };
  readonly formatUtcExportTimestamp: (isoUtc: string) => string;
}

function interpolate(
  template: string,
  params?: Readonly<Record<string, string | number>>,
): string {
  if (!params) {
    return template;
  }
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (full, token: string) => {
    const val = params[token];
    return val === undefined ? full : String(val);
  });
}

export function formatUtcTimestamp(isoUtc: string): string {
  const parsed = new Date(isoUtc);
  if (Number.isNaN(parsed.getTime())) {
    return "Invalid timestamp (UTC)";
  }
  const iso = parsed.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export interface I18nProviderProps {
  readonly initialLocale?: SupportedLocale;
  readonly catalogs?: Partial<Record<SupportedLocale, Partial<MessageCatalog>>>;
  readonly children: React.ReactNode;
}

export function I18nProvider({
  initialLocale = "en",
  catalogs,
  children,
}: I18nProviderProps): React.JSX.Element {
  const [locale, setLocale] = useState<SupportedLocale>(initialLocale);

  const activeCatalog = useMemo<MessageCatalog>(() => {
    const overrides = catalogs?.[locale];
    if (!overrides) {
      return EN_MESSAGES;
    }
    return {
      ...EN_MESSAGES,
      ...overrides,
    };
  }, [catalogs, locale]);

  const t = useCallback(
    (key: MessageKey, params?: Readonly<Record<string, string | number>>): string => {
      const template = activeCatalog[key] ?? EN_MESSAGES[key];
      return interpolate(template, params);
    },
    [activeCatalog],
  );

  const formatDisplayTimestamp = useCallback(
    (isoUtc: string) => {
      const parsed = new Date(isoUtc);
      const utcText = formatUtcTimestamp(isoUtc);
      if (Number.isNaN(parsed.getTime())) {
        return { localText: utcText, utcText };
      }
      const formatter = new Intl.DateTimeFormat(locale === "vi" ? "vi-VN" : "en-US", {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
      return {
        localText: formatter.format(parsed),
        utcText,
      };
    },
    [locale],
  );

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      setLocale,
      t,
      formatDisplayTimestamp,
      formatUtcExportTimestamp: formatUtcTimestamp,
    }),
    [locale, t, formatDisplayTimestamp],
  );

  return (
    <InternationalizationProvider locale={locale}>
      <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
    </InternationalizationProvider>
  );
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (ctx !== null) {
    return ctx;
  }
  return {
    locale: "en",
    setLocale: () => undefined,
    t: (key, params) => interpolate(EN_MESSAGES[key], params),
    formatDisplayTimestamp: (isoUtc: string) => {
      const utcText = formatUtcTimestamp(isoUtc);
      return { localText: utcText, utcText };
    },
    formatUtcExportTimestamp: formatUtcTimestamp,
  };
}
