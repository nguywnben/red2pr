import { Pagination } from "@astryxdesign/core/Pagination";
import { observeElementRect, useVirtualizer } from "@tanstack/react-virtual";
import React, { useEffect, useId, useMemo, useRef, useState } from "react";
import { useI18n } from "../i18n";
import { Button } from "./Button";
import { sanitizeUntrustedText } from "./sanitizeText";

const FAST_SAFE_PRINTABLE_ASCII_RE = /^[\u0020-\u007e\t]*$/;
const LOG_ROW_HEIGHT_PX = 22;

export interface SafeLogViewerProps {
  readonly lines?: readonly string[];
  readonly rawText?: string;
  readonly title?: string;
  readonly height?: number;
  readonly isStreaming?: boolean;
  readonly defaultPaused?: boolean;
  readonly defaultMode?: "virtualized" | "paged";
  readonly pageSize?: number;
}

interface SanitizedLogLine {
  readonly lineNumber: number;
  readonly text: string;
}

export function SafeLogViewer({
  lines,
  rawText,
  title,
  height = 380,
  isStreaming = false,
  defaultPaused = false,
  defaultMode = "virtualized",
  pageSize = 100,
}: SafeLogViewerProps): React.JSX.Element {
  const { t } = useI18n();
  const searchInputId = useId();
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);

  const [mode, setMode] = useState<"virtualized" | "paged">(defaultMode);
  const [isPaused, setIsPaused] = useState<boolean>(defaultPaused);
  const [query, setQuery] = useState<string>("");
  const [page, setPage] = useState<number>(1);

  const { sanitizedLines, strippedCount } = useMemo(() => {
    const rawLines = lines ?? (rawText !== undefined && rawText.length > 0 ? rawText.split(/\r?\n/) : []);
    let totalStripped = 0;
    const processed: SanitizedLogLine[] = new Array<SanitizedLogLine>(rawLines.length);

    for (let i = 0; i < rawLines.length; i += 1) {
      const candidate = rawLines[i] ?? "";
      if (FAST_SAFE_PRINTABLE_ASCII_RE.test(candidate)) {
        processed[i] = { lineNumber: i + 1, text: candidate };
      } else {
        const res = sanitizeUntrustedText(candidate);
        totalStripped += res.strippedSequences;
        processed[i] = { lineNumber: i + 1, text: res.text };
      }
    }

    return { sanitizedLines: processed, strippedCount: totalStripped };
  }, [lines, rawText]);

  const filteredLines = useMemo(() => {
    const trimmed = query.trim().toLowerCase();
    if (trimmed.length === 0) {
      return sanitizedLines;
    }
    return sanitizedLines.filter((item) => item.text.toLowerCase().includes(trimmed));
  }, [query, sanitizedLines]);

  const virtualizer = useVirtualizer({
    count: mode === "virtualized" ? filteredLines.length : 0,
    getScrollElement: () => scrollContainerRef.current,
    estimateSize: () => LOG_ROW_HEIGHT_PX,
    overscan: 8,
    initialRect: { width: 1024, height },
    observeElementRect: (instance, cb) =>
      observeElementRect(instance, (rect) => {
        cb({
          width: rect.width > 0 ? rect.width : 1024,
          height: rect.height > 0 ? rect.height : height,
        });
      }),
  });

  useEffect(() => {
    if (mode !== "virtualized" || !isStreaming || isPaused || filteredLines.length === 0) {
      return;
    }
    virtualizer.scrollToIndex(filteredLines.length - 1, { align: "end" });
  }, [filteredLines.length, isPaused, isStreaming, mode, virtualizer]);

  const resolvedTitle = title ?? t("logs.title");
  const virtualItems = mode === "virtualized" ? virtualizer.getVirtualItems() : [];

  const pagedSlice = useMemo(() => {
    if (mode !== "paged") {
      return [];
    }
    const start = (page - 1) * pageSize;
    return filteredLines.slice(start, start + pageSize);
  }, [filteredLines, mode, page, pageSize]);

  const rangeStart =
    filteredLines.length === 0
      ? 0
      : mode === "virtualized"
        ? (virtualItems[0]?.index ?? 0) + 1
        : (page - 1) * pageSize + 1;
  const rangeEnd =
    filteredLines.length === 0
      ? 0
      : mode === "virtualized"
        ? (virtualItems[virtualItems.length - 1]?.index ?? 0) + 1
        : Math.min(filteredLines.length, page * pageSize);

  return (
    <section className="red2pr-code-viewport" aria-label={resolvedTitle}>
      <div className="red2pr-toolbar">
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
          <strong>{resolvedTitle}</strong>
          <span style={{ fontSize: "0.75rem" }}>
            {t("logs.rangeSummary", {
              start: rangeStart,
              end: rangeEnd,
              total: filteredLines.length,
            })}
          </span>
          {query.trim().length > 0 ? (
            <span className="red2pr-badge-pill red2pr-tone-info">
              {t("logs.matchSummary", { matches: filteredLines.length })}
            </span>
          ) : null}
          {strippedCount > 0 ? (
            <span className="red2pr-badge-pill red2pr-tone-warning">
              {t("logs.sanitizedNotice", { count: strippedCount })}
            </span>
          ) : null}
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
          <label htmlFor={searchInputId} style={{ fontSize: "0.75rem", fontWeight: 500 }}>
            {t("logs.searchLabel")}
          </label>
          <input
            id={searchInputId}
            type="search"
            className="red2pr-control-input"
            value={query}
            placeholder={t("logs.searchPlaceholder")}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(1);
            }}
          />
          {isStreaming ? (
            <Button
              size="sm"
              variant="secondary"
              label={isPaused ? t("logs.resumeTail") : t("logs.pauseTail")}
              onClick={() => setIsPaused((prev) => !prev)}
            />
          ) : null}
          <Button
            size="sm"
            variant="secondary"
            label={
              mode === "virtualized" ? t("logs.switchToPaged") : t("logs.switchToVirtualized")
            }
            onClick={() => setMode((prev) => (prev === "virtualized" ? "paged" : "virtualized"))}
          />
        </div>
      </div>

      {filteredLines.length === 0 ? (
        <div style={{ padding: 16 }}>{t("logs.empty")}</div>
      ) : mode === "virtualized" ? (
        <div
          ref={scrollContainerRef}
          role="region"
          aria-label={`${resolvedTitle} viewport`}
          style={{
            height,
            overflow: "auto",
            position: "relative",
          }}
        >
          <div
            style={{
              height: virtualizer.getTotalSize(),
              width: "100%",
              position: "relative",
            }}
          >
            {virtualItems.map((virtualRow) => {
              const entry = filteredLines[virtualRow.index];
              if (!entry) {
                return null;
              }
              return (
                <div
                  key={entry.lineNumber}
                  data-log-line={entry.lineNumber}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: LOG_ROW_HEIGHT_PX,
                    transform: `translateY(${virtualRow.start}px)`,
                    display: "flex",
                    alignItems: "center",
                    paddingInline: 10,
                    whiteSpace: "pre",
                  }}
                >
                  <span
                    aria-hidden="true"
                    style={{
                      display: "inline-block",
                      minWidth: 56,
                      paddingRight: 10,
                      textAlign: "right",
                      userSelect: "none",
                      color: "var(--red2pr-text-muted)",
                    }}
                  >
                    {entry.lineNumber}
                  </span>
                  <span>{entry.text}</span>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div style={{ padding: 8 }}>
          <ol
            aria-label={`${resolvedTitle} viewport`}
            style={{
              margin: 0,
              padding: 0,
              listStyle: "none",
              maxHeight: height,
              overflow: "auto",
            }}
          >
            {pagedSlice.map((entry) => (
              <li
                key={entry.lineNumber}
                data-log-line={entry.lineNumber}
                style={{
                  display: "flex",
                  padding: "2px 8px",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                <span
                  aria-hidden="true"
                  style={{
                    minWidth: 56,
                    paddingRight: 10,
                    textAlign: "right",
                    userSelect: "none",
                    color: "var(--red2pr-text-muted)",
                  }}
                >
                  {entry.lineNumber}
                </span>
                <span>{entry.text}</span>
              </li>
            ))}
          </ol>
          {filteredLines.length > pageSize ? (
            <div style={{ marginTop: 8 }}>
              <Pagination
                page={page}
                onChange={setPage}
                totalItems={filteredLines.length}
                pageSize={pageSize}
                variant="compact"
                hasFirstLast
              />
            </div>
          ) : null}
        </div>
      )}
    </section>
  );
}
