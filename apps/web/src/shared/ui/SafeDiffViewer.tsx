import { SelectorControl } from "./SelectorControl";
import { Pagination } from "@astryxdesign/core/Pagination";
import { observeElementRect, useVirtualizer } from "@tanstack/react-virtual";
import React, { useId, useMemo, useRef, useState } from "react";
import { useI18n, type MessageKey } from "../i18n";
import { CodeBlock } from "./AstryxComponents";
import { Button } from "./Button";
import { sanitizeUntrustedText } from "./sanitizeText";

const FAST_SAFE_PRINTABLE_ASCII_RE = /^[\u0020-\u007e\t]*$/;
const HUNK_HEADER_RE = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/;
const DIFF_ROW_HEIGHT_PX = 24;
const VIRTUALIZATION_ROW_THRESHOLD = 500;

function inferCodeBlockLanguage(filePath: string | undefined): string {
  if (!filePath || filePath === "__all__") {
    return "plaintext";
  }
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".tsx")) return "tsx";
  if (lower.endsWith(".ts")) return "typescript";
  if (lower.endsWith(".jsx")) return "jsx";
  if (lower.endsWith(".js") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return "javascript";
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".yml") || lower.endsWith(".yaml")) return "yaml";
  if (lower.endsWith(".sh") || lower.endsWith(".bash") || lower.endsWith(".zsh")) return "bash";
  if (lower.endsWith(".css") || lower.endsWith(".scss") || lower.endsWith(".less")) return "css";
  if (lower.endsWith(".html") || lower.endsWith(".xml") || lower.endsWith(".svg")) return "html";
  if (lower.endsWith(".php")) return "php";
  if (lower.endsWith(".hh") || lower.endsWith(".hack")) return "hack";
  if (lower.endsWith(".md") || lower.endsWith(".mdx")) return "markdown";
  return "plaintext";
}

function buildCleanUnifiedDiffForCodeBlock(rows: readonly ParsedDiffRow[]): string {
  const lines: string[] = [];
  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    if (!row) {
      continue;
    }
    if (row.kind === "meta") {
      const isOldHeaderBeforeHunk =
        row.text.startsWith("--- ") &&
        (rows[i + 1]?.text.startsWith("+++ ") ?? false) &&
        rows[i + 2]?.kind === "hunk";
      const isNewHeaderBeforeHunk =
        row.text.startsWith("+++ ") &&
        (rows[i - 1]?.text.startsWith("--- ") ?? false) &&
        rows[i + 1]?.kind === "hunk";
      if (isOldHeaderBeforeHunk || isNewHeaderBeforeHunk) {
        lines.push(row.text);
      }
      continue;
    }
    if (row.kind === "hunk") {
      lines.push(row.text);
    } else if (row.kind === "added") {
      lines.push(`+${row.text}`);
    } else if (row.kind === "removed") {
      lines.push(`-${row.text}`);
    } else {
      lines.push(` ${row.text}`);
    }
  }
  return lines.join("\n");
}

export type DiffRowKind = "meta" | "hunk" | "added" | "removed" | "context";

export interface ParsedDiffRow {
  readonly index: number;
  readonly filePath: string;
  readonly kind: DiffRowKind;
  readonly prefix: string;
  readonly oldLine: number | null;
  readonly newLine: number | null;
  readonly text: string;
}

export interface SafeDiffViewerProps {
  readonly rawDiff: string;
  readonly title?: string;
  readonly height?: number;
  readonly defaultMode?: "virtualized" | "paged";
  readonly pageSize?: number;
}

function sanitizeLineFast(line: string): { readonly text: string; readonly stripped: number } {
  if (FAST_SAFE_PRINTABLE_ASCII_RE.test(line)) {
    return { text: line, stripped: 0 };
  }
  const result = sanitizeUntrustedText(line);
  return { text: result.text, stripped: result.strippedSequences };
}

export function parseSanitizedUnifiedDiff(rawDiff: string): {
  readonly rows: readonly ParsedDiffRow[];
  readonly files: readonly string[];
  readonly strippedCount: number;
} {
  if (rawDiff.trim().length === 0) {
    return { rows: [], files: [], strippedCount: 0 };
  }

  const normalizedDiff = rawDiff.replace(/\r?\n$/, "");
  const rawLines = normalizedDiff.split(/\r?\n/);
  const rows: ParsedDiffRow[] = new Array<ParsedDiffRow>(rawLines.length);
  const fileSet = new Set<string>();
  let currentFile = "(patch)";
  let oldCursor = 0;
  let newCursor = 0;
  let strippedCount = 0;

  for (let i = 0; i < rawLines.length; i += 1) {
    const rawLine = rawLines[i] ?? "";
    const { text: cleanLine, stripped } = sanitizeLineFast(rawLine);
    strippedCount += stripped;

    if (cleanLine.startsWith("diff --git ")) {
      const bIdx = cleanLine.indexOf(" b/");
      if (bIdx !== -1) {
        currentFile = cleanLine.slice(bIdx + 3).trim() || currentFile;
        fileSet.add(currentFile);
      }
      rows[i] = {
        index: i + 1,
        filePath: currentFile,
        kind: "meta",
        prefix: "#",
        oldLine: null,
        newLine: null,
        text: cleanLine,
      };
      continue;
    }

    if (cleanLine.startsWith("+++ b/")) {
      currentFile = cleanLine.slice(6).trim() || currentFile;
      fileSet.add(currentFile);
      rows[i] = {
        index: i + 1,
        filePath: currentFile,
        kind: "meta",
        prefix: "#",
        oldLine: null,
        newLine: null,
        text: cleanLine,
      };
      continue;
    }

    if (cleanLine.startsWith("--- ") || cleanLine.startsWith("index ")) {
      rows[i] = {
        index: i + 1,
        filePath: currentFile,
        kind: "meta",
        prefix: "#",
        oldLine: null,
        newLine: null,
        text: cleanLine,
      };
      continue;
    }

    const hunkMatch = HUNK_HEADER_RE.exec(cleanLine);
    if (hunkMatch) {
      oldCursor = Number.parseInt(hunkMatch[1] ?? "1", 10);
      newCursor = Number.parseInt(hunkMatch[2] ?? "1", 10);
      rows[i] = {
        index: i + 1,
        filePath: currentFile,
        kind: "hunk",
        prefix: "@",
        oldLine: null,
        newLine: null,
        text: cleanLine,
      };
      continue;
    }

    if (cleanLine.startsWith("+")) {
      const lineNum = newCursor > 0 ? newCursor : null;
      if (newCursor > 0) {
        newCursor += 1;
      }
      rows[i] = {
        index: i + 1,
        filePath: currentFile,
        kind: "added",
        prefix: "+",
        oldLine: null,
        newLine: lineNum,
        text: cleanLine.slice(1),
      };
      continue;
    }

    if (cleanLine.startsWith("-")) {
      const lineNum = oldCursor > 0 ? oldCursor : null;
      if (oldCursor > 0) {
        oldCursor += 1;
      }
      rows[i] = {
        index: i + 1,
        filePath: currentFile,
        kind: "removed",
        prefix: "-",
        oldLine: lineNum,
        newLine: null,
        text: cleanLine.slice(1),
      };
      continue;
    }

    const prevLine = oldCursor > 0 ? oldCursor : null;
    const nextLine = newCursor > 0 ? newCursor : null;
    if (oldCursor > 0) {
      oldCursor += 1;
    }
    if (newCursor > 0) {
      newCursor += 1;
    }
    rows[i] = {
      index: i + 1,
      filePath: currentFile,
      kind: "context",
      prefix: " ",
      oldLine: prevLine,
      newLine: nextLine,
      text: cleanLine.startsWith(" ") ? cleanLine.slice(1) : cleanLine,
    };
  }

  return { rows, files: Array.from(fileSet), strippedCount };
}

function rowStyleForKind(kind: DiffRowKind): React.CSSProperties {
  if (kind === "added") {
    return {
      backgroundColor: "var(--red2pr-diff-added-bg)",
      color: "var(--red2pr-diff-added-fg)",
    };
  }
  if (kind === "removed") {
    return {
      backgroundColor: "var(--red2pr-diff-removed-bg)",
      color: "var(--red2pr-diff-removed-fg)",
    };
  }
  if (kind === "hunk") {
    return {
      backgroundColor: "var(--red2pr-diff-hunk-bg)",
      color: "var(--red2pr-diff-hunk-fg)",
    };
  }
  return {};
}

export function SafeDiffViewer({
  rawDiff,
  title,
  height = 380,
  defaultMode = "virtualized",
  pageSize = 100,
}: SafeDiffViewerProps): React.JSX.Element {
  const { t } = useI18n();
  const fileSelectId = useId();
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);

  const [mode, setMode] = useState<"virtualized" | "paged">(defaultMode);
  const [selectedFile, setSelectedFile] = useState<string>("__all__");
  const [page, setPage] = useState<number>(1);

  const { rows, files, strippedCount } = useMemo(
    () => parseSanitizedUnifiedDiff(rawDiff),
    [rawDiff],
  );

  const filteredRows = useMemo(() => {
    if (selectedFile === "__all__") {
      return rows;
    }
    return rows.filter((row) => row.filePath === selectedFile);
  }, [rows, selectedFile]);

  const useAstryxCodeBlock =
    mode === "virtualized" &&
    filteredRows.length > 0 &&
    filteredRows.length <= VIRTUALIZATION_ROW_THRESHOLD;

  const codeBlockDiff = useMemo(
    () => (useAstryxCodeBlock ? buildCleanUnifiedDiffForCodeBlock(filteredRows) : ""),
    [filteredRows, useAstryxCodeBlock],
  );

  const inferredLanguage = useMemo(
    () => inferCodeBlockLanguage(selectedFile !== "__all__" ? selectedFile : files[0]),
    [files, selectedFile],
  );

  const virtualizer = useVirtualizer({
    count: mode === "virtualized" && !useAstryxCodeBlock ? filteredRows.length : 0,
    getScrollElement: () => scrollContainerRef.current,
    estimateSize: () => DIFF_ROW_HEIGHT_PX,
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

  const resolvedTitle = title ?? t("diff.title");
  const effectiveHeight = Math.min(height, Math.max(88, filteredRows.length * DIFF_ROW_HEIGHT_PX + 12));
  const virtualItems =
    mode === "virtualized" && !useAstryxCodeBlock ? virtualizer.getVirtualItems() : [];

  const pagedRows = useMemo(() => {
    if (mode !== "paged") {
      return [];
    }
    const offset = (page - 1) * pageSize;
    return filteredRows.slice(offset, offset + pageSize);
  }, [filteredRows, mode, page, pageSize]);

  const kindLabelKey: Record<DiffRowKind, MessageKey> = {
    added: "diff.kind.added",
    removed: "diff.kind.removed",
    context: "diff.kind.context",
    hunk: "diff.kind.hunk",
    meta: "diff.kind.meta",
  };

  const rangeStart =
    filteredRows.length === 0
      ? 0
      : useAstryxCodeBlock
        ? 1
        : mode === "virtualized"
        ? (virtualItems[0]?.index ?? 0) + 1
        : (page - 1) * pageSize + 1;
  const rangeEnd =
    filteredRows.length === 0
      ? 0
      : useAstryxCodeBlock
        ? filteredRows.length
        : mode === "virtualized"
        ? (virtualItems[virtualItems.length - 1]?.index ?? 0) + 1
        : Math.min(filteredRows.length, page * pageSize);

  return (
    <section className="red2pr-code-viewport" aria-label={resolvedTitle}>
      <div className="red2pr-toolbar">
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
          <strong>{resolvedTitle}</strong>
          <span style={{ fontSize: "0.75rem" }}>
            {t("diff.rangeSummary", {
              start: rangeStart,
              end: rangeEnd,
              total: filteredRows.length,
            })}
          </span>
          {strippedCount > 0 ? (
            <span className="red2pr-badge-pill red2pr-tone-warning">
              {t("logs.sanitizedNotice", { count: strippedCount })}
            </span>
          ) : null}
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
          {files.length > 0 ? (
            <>
              <label htmlFor={fileSelectId} style={{ fontSize: "0.75rem", fontWeight: 500 }}>
                {t("diff.fileFilterLabel")}
              </label>
              <SelectorControl
                id={fileSelectId}
                className="red2pr-control-select red2pr-toolbar-select"
                value={selectedFile}
                onChange={(e) => {
                  setSelectedFile(e.target.value);
                  setPage(1);
                }}
              >
                <option value="__all__">{t("diff.allFiles", { count: files.length })}</option>
                {files.map((filePath) => (
                  <option key={filePath} value={filePath}>
                    {filePath}
                  </option>
                ))}
              </SelectorControl>
            </>
          ) : null}
          {filteredRows.length > 0 ? (
            <Button
              size="sm"
              variant="secondary"
              label={
                mode === "virtualized" ? t("diff.switchToPaged") : t("diff.switchToVirtualized")
              }
              onClick={() => setMode((prev) => (prev === "virtualized" ? "paged" : "virtualized"))}
            />
          ) : null}
        </div>
      </div>

      {filteredRows.length === 0 ? (
        <div style={{ padding: 16 }}>{t("diff.empty")}</div>
      ) : useAstryxCodeBlock ? (
        <CodeBlock
          code={codeBlockDiff}
          language={inferredLanguage}
          isDiff
          hasLanguageLabel={false}
          hasLineNumbers
          hasCopyButton
          isWrapped
          maxHeight={height}
          size="sm"
          width="100%"
          container="section"
        />
      ) : mode === "virtualized" ? (
        <div
          ref={scrollContainerRef}
          role="region"
          aria-label={resolvedTitle}
          style={{
            height: effectiveHeight,
            overflow: "auto",
            position: "relative",
          }}
        >
          <div style={{ height: virtualizer.getTotalSize(), width: "100%", position: "relative" }}>
            {virtualItems.map((virtualRow) => {
              const row = filteredRows[virtualRow.index];
              if (!row) {
                return null;
              }
              return (
                <div
                  key={row.index}
                  data-diff-row={row.index}
                  data-diff-kind={row.kind}
                  aria-label={t(kindLabelKey[row.kind])}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: DIFF_ROW_HEIGHT_PX,
                    transform: `translateY(${virtualRow.start}px)`,
                    display: "flex",
                    alignItems: "center",
                    paddingInline: 10,
                    whiteSpace: "pre",
                    ...rowStyleForKind(row.kind),
                  }}
                >
                  <span
                    aria-hidden="true"
                    style={{ minWidth: 44, textAlign: "right", paddingRight: 6, userSelect: "none" }}
                  >
                    {row.oldLine ?? ""}
                  </span>
                  <span
                    aria-hidden="true"
                    style={{ minWidth: 44, textAlign: "right", paddingRight: 8, userSelect: "none" }}
                  >
                    {row.newLine ?? ""}
                  </span>
                  <strong aria-hidden="true" style={{ minWidth: 16 }}>
                    {row.prefix}
                  </strong>
                  <span>{row.text}</span>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div style={{ padding: 8 }}>
          <ol
            aria-label={resolvedTitle}
            style={{
              margin: 0,
              padding: 0,
              listStyle: "none",
              maxHeight: height,
              overflow: "auto",
            }}
          >
            {pagedRows.map((row) => (
              <li
                key={row.index}
                data-diff-row={row.index}
                data-diff-kind={row.kind}
                aria-label={t(kindLabelKey[row.kind])}
                style={{
                  display: "flex",
                  padding: "2px 8px",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  ...rowStyleForKind(row.kind),
                }}
              >
                <span
                  aria-hidden="true"
                  style={{ minWidth: 44, textAlign: "right", paddingRight: 6, userSelect: "none" }}
                >
                  {row.oldLine ?? ""}
                </span>
                <span
                  aria-hidden="true"
                  style={{ minWidth: 44, textAlign: "right", paddingRight: 8, userSelect: "none" }}
                >
                  {row.newLine ?? ""}
                </span>
                <strong aria-hidden="true" style={{ minWidth: 16 }}>
                  {row.prefix}
                </strong>
                <span>{row.text}</span>
              </li>
            ))}
          </ol>
          {filteredRows.length > pageSize ? (
            <div style={{ marginTop: 8 }}>
              <Pagination
                page={page}
                onChange={setPage}
                totalItems={filteredRows.length}
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
