import {
  Red2PrApiError,
  type Artifact,
  type CiConclusion,
  type CiJob,
  type CiRun,
  type CiRunIngestionState,
  type FailureFingerprintSummary,
  type FlakyClassification,
  type MeResponse,
  type Workspace,
} from "@red2pr/ts-client";
import { useMutation, useQuery } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  Button,
  SafeLogViewer,
  StateView,
  StatusGlyph,
  Table,
  sanitizeUntrustedText,
  useLiveAnnouncer,
  type TableColumn,
} from "../../shared/ui";
import {
  extractAuthProblemSummary,
  formatUtcTimestamp,
  type AuthProblemSummary,
} from "../auth";

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";

const CONCLUSION_OPTIONS: readonly ("all" | CiConclusion)[] = [
  "all",
  "failure",
  "success",
  "cancelled",
  "timed_out",
  "action_required",
  "skipped",
  "unknown",
];

const FLAKY_OPTIONS: readonly ("all" | FlakyClassification)[] = [
  "all",
  "flaky",
  "single_pass_unproven",
  "persistent_failure",
  "insufficient_history",
  "unknown",
];

function flakyAppearance(verdict: FlakyClassification | undefined): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (verdict) {
    case "flaky":
      return { glyph: "warn", tone: "red2pr-tone-warning", label: "Flaky (>=2 fails + pass)" };
    case "single_pass_unproven":
      return { glyph: "info", tone: "red2pr-tone-info", label: "Single pass (unproven)" };
    case "persistent_failure":
      return { glyph: "error", tone: "red2pr-tone-danger", label: "Persistent failure" };
    case "insufficient_history":
      return { glyph: "clock", tone: "red2pr-tone-info", label: "Insufficient history" };
    default:
      return { glyph: "clock", tone: "red2pr-tone-neutral", label: "Unknown" };
  }
}

function conclusionAppearance(conclusion: CiConclusion | null | undefined, status: string): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  if (status !== "completed" && !conclusion) {
    return { glyph: "clock", tone: "red2pr-tone-info", label: status };
  }
  switch (conclusion) {
    case "success":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Success" };
    case "failure":
    case "timed_out":
    case "action_required":
      return { glyph: "error", tone: "red2pr-tone-danger", label: conclusion };
    case "cancelled":
    case "skipped":
      return { glyph: "warn", tone: "red2pr-tone-warning", label: conclusion };
    default:
      return { glyph: "info", tone: "red2pr-tone-neutral", label: conclusion ?? status };
  }
}

function ingestionTone(state: CiRunIngestionState | undefined): string {
  if (state === "ingested") {
    return "red2pr-tone-success";
  }
  if (state === "stale_sha" || state === "failed") {
    return "red2pr-tone-danger";
  }
  return "red2pr-tone-warning";
}

interface CiRunTableRow extends Record<string, unknown> {
  readonly id: string;
  readonly run: CiRun;
}

function formatByteCount(bytes: number): string {
  if (bytes < 1024) {
    return `${String(bytes)} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KiB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

export interface PipelinesPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

export function PipelinesPage({ workspace }: PipelinesPageProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const announce = useLiveAnnouncer();
  const [searchParams, setSearchParams] = useSearchParams();
  const wsSlug = workspace.slug ?? workspace.id;

  const repoSelectId = useId();
  const conclusionSelectId = useId();
  const flakySelectId = useId();
  const shaInputId = useId();
  const flakyOnlyCheckId = useId();

  const [repoFilter, setRepoFilter] = useState<string>(
    () => searchParams.get("repository_id") ?? "all",
  );
  const [conclusionFilter, setConclusionFilter] = useState<"all" | CiConclusion>("all");
  const [flakyFilter, setFlakyFilter] = useState<"all" | FlakyClassification>("all");
  const [shaFilter, setShaFilter] = useState<string>("");
  const [flakyOnly, setFlakyOnly] = useState<boolean>(false);
  const [cursor, setCursor] = useState<string | null>(null);

  const [selectedRunId, setSelectedRunId] = useState<string | null>(() =>
    searchParams.get("run_id"),
  );
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [extraLogText, setExtraLogText] = useState<string>("");
  const [extraNextOffset, setExtraNextOffset] = useState<number | null>(null);
  const [extraHasMore, setExtraHasMore] = useState<boolean>(false);
  const [downloadBanner, setDownloadBanner] = useState<{
    readonly tone: "success" | "error";
    readonly message: string;
    readonly correlationId?: string | null;
  } | null>(null);

  const reposQuery = useQuery({
    queryKey: ["workspace", wsSlug, "repositories", "pipelines-facet"],
    queryFn: () => api.listRepositories(wsSlug, { limit: 100 }),
  });

  const runsQuery = useQuery({
    queryKey: [
      "workspace",
      wsSlug,
      "runs",
      { repoFilter, conclusionFilter, flakyFilter, shaFilter: shaFilter.trim(), flakyOnly, cursor },
    ],
    queryFn: () =>
      api.listRuns(wsSlug, {
        limit: 25,
        cursor,
        repository_id: repoFilter !== "all" ? repoFilter : null,
        conclusion: conclusionFilter !== "all" ? conclusionFilter : null,
        flaky_classification: flakyFilter !== "all" ? flakyFilter : null,
        head_sha: shaFilter.trim() !== "" ? shaFilter.trim() : null,
        flaky_only: flakyOnly,
      }),
  });

  const runs = useMemo<readonly CiRun[]>(
    () => runsQuery.data?.data.items ?? [],
    [runsQuery.data?.data.items],
  );
  const nextCursor = runsQuery.data?.data.next_cursor ?? null;
  const activeRunId = selectedRunId ?? runs[0]?.id ?? null;

  const runDetailQuery = useQuery({
    queryKey: ["workspace", wsSlug, "runs", "detail", activeRunId],
    queryFn: () => api.getRun(wsSlug, activeRunId ?? ""),
    enabled: activeRunId !== null,
    retry: false,
  });

  const runDetail = runDetailQuery.data?.data ?? null;
  const runJobs = useMemo<readonly CiJob[]>(
    () => runDetail?.jobs ?? [],
    [runDetail?.jobs],
  );
  const runArtifacts: readonly Artifact[] = runDetail?.artifacts ?? [];
  const runFingerprints: readonly FailureFingerprintSummary[] = runDetail?.fingerprints ?? [];
  const siblingAttempts: readonly CiRun[] = runDetail?.sibling_attempts ?? [];

  const activeJobId = useMemo<string | null>(() => {
    if (runJobs.length === 0) {
      return null;
    }
    if (selectedJobId !== null && runJobs.some((j) => j.id === selectedJobId)) {
      return selectedJobId;
    }
    const firstFailed = runJobs.find((j) => j.conclusion === "failure") ?? runJobs[0];
    return firstFailed?.id ?? null;
  }, [runJobs, selectedJobId]);

  const selectedJob = useMemo(
    () => runJobs.find((j) => j.id === activeJobId) ?? null,
    [runJobs, activeJobId],
  );

  const jobLogQuery = useQuery({
    queryKey: ["workspace", wsSlug, "jobs", activeJobId, "log-head"],
    queryFn: () => api.getJobLog(wsSlug, activeJobId ?? "", { start_offset: 0, max_bytes: 65536 }),
    enabled: activeJobId !== null && selectedJob?.log_status !== "expired",
    retry: false,
  });

  const loadMoreLogMutation = useMutation({
    mutationFn: async (offset: number) =>
      api.getJobLog(wsSlug, activeJobId ?? "", { start_offset: offset, max_bytes: 65536 }),
    onSuccess: (envelope) => {
      setExtraLogText((prev) => prev + envelope.data.content);
      setExtraNextOffset(envelope.data.next_offset);
      setExtraHasMore(envelope.data.has_more);
      announce(`Loaded ${String(envelope.data.returned_bytes)} more log bytes.`);
    },
  });

  const downloadMutation = useMutation({
    mutationFn: async (artifact: Artifact) => {
      const resp = await api.downloadArtifact(wsSlug, artifact.id);
      return { artifact, resp };
    },
    onSuccess: ({ artifact, resp }) => {
      const safeName = sanitizeUntrustedText(
        resp.data.filename ?? artifact.name ?? `artifact-${artifact.id}.bin`,
      ).text;
      if (typeof URL !== "undefined" && typeof URL.createObjectURL === "function") {
        const blob = new Blob([resp.data.bytes], { type: resp.data.contentType });
        const objectUrl = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = safeName;
        anchor.click();
        URL.revokeObjectURL(objectUrl);
      }
      const msg = `Downloaded verified artifact ${safeName} (${formatByteCount(resp.data.bytes.byteLength)}).`;
      setDownloadBanner({ tone: "success", message: msg, correlationId: resp.correlationId });
      announce(msg);
    },
    onError: (err) => {
      const summary: AuthProblemSummary = extractAuthProblemSummary(
        err,
        t("state.error.description"),
      );
      setDownloadBanner({
        tone: "error",
        message: `${summary.code}: ${summary.detail}`,
        correlationId: summary.correlationId,
      });
      announce(`Artifact download failed: ${summary.detail}`);
    },
  });

  const handleSelectRun = useCallback(
    (runId: string): void => {
      setSelectedRunId(runId);
      setSelectedJobId(null);
      setExtraLogText("");
      setExtraNextOffset(null);
      setExtraHasMore(false);
      setDownloadBanner(null);
      const nextParams = new URLSearchParams(searchParams);
      nextParams.set("run_id", runId);
      setSearchParams(nextParams, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  const handleSelectJob = useCallback((jobId: string): void => {
    setSelectedJobId(jobId);
    setExtraLogText("");
    setExtraNextOffset(null);
    setExtraHasMore(false);
  }, []);

  const resetFilters = useCallback((): void => {
    setRepoFilter("all");
    setConclusionFilter("all");
    setFlakyFilter("all");
    setShaFilter("");
    setFlakyOnly(false);
    setCursor(null);
  }, []);

  const tableRows = useMemo<CiRunTableRow[]>(
    () => runs.map((run) => ({ id: run.id, run })),
    [runs],
  );

  const columns = useMemo<TableColumn<CiRunTableRow>[]>(
    () => [
      {
        key: "repository",
        header: "Repository",
        renderCell: ({ run }) => {
          const safeRepo = sanitizeUntrustedText(run.repository_name ?? run.repository_id).text;
          return (
            <div>
              <strong>{safeRepo}</strong>
              <div style={{ fontSize: "0.75rem", opacity: 0.8 }}>{run.provider ?? "vcs"}</div>
            </div>
          );
        },
      },
      {
        key: "attempt",
        header: "Run / Attempt",
        renderCell: ({ run }) => {
          const safeAttempt = sanitizeUntrustedText(run.attempt_key).text;
          const safeRef = sanitizeUntrustedText(run.ref).text;
          return (
            <div>
              <code>#{sanitizeUntrustedText(run.external_id).text}</code>{" "}
              <span className="red2pr-badge-pill red2pr-tone-info">{safeAttempt}</span>
              <div style={{ fontSize: "0.75rem", opacity: 0.85 }}>
                {safeRef} · {sanitizeUntrustedText(run.event_type).text}
              </div>
            </div>
          );
        },
      },
      {
        key: "sha",
        header: "Source SHA",
        renderCell: ({ run }) => (
          <div>
            <code>{sanitizeUntrustedText(run.head_sha.slice(0, 12)).text}</code>
            {run.head_sha_verified === false ? (
              <div>
                <span className="red2pr-badge-pill red2pr-tone-danger">
                  <StatusGlyph kind="error" />
                  <span>SHA mismatch</span>
                </span>
              </div>
            ) : null}
          </div>
        ),
      },
      {
        key: "outcome",
        header: "Outcome & Evidence",
        renderCell: ({ run }) => {
          const out = conclusionAppearance(run.conclusion, run.status);
          const ingState = run.ingestion_state ?? "ingested";
          return (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              <span className={`red2pr-badge-pill ${out.tone}`}>
                <StatusGlyph kind={out.glyph} />
                <span>{out.label}</span>
              </span>
              <span className={`red2pr-badge-pill ${ingestionTone(ingState)}`}>{ingState}</span>
            </div>
          );
        },
      },
      {
        key: "flaky",
        header: "Flaky Analysis",
        renderCell: ({ run }) => {
          const fl = flakyAppearance(run.flaky_classification);
          return (
            <span className={`red2pr-badge-pill ${fl.tone}`}>
              <StatusGlyph kind={fl.glyph} />
              <span>{fl.label}</span>
            </span>
          );
        },
      },
      {
        key: "actions",
        header: "Inspect",
        renderCell: ({ run }) => (
          <Button
            size="sm"
            variant={activeRunId === run.id ? "primary" : "secondary"}
            label={activeRunId === run.id ? "Inspecting" : "Inspect run"}
            aria-pressed={activeRunId === run.id}
            onClick={() => handleSelectRun(run.id)}
          />
        ),
      },
    ],
    [activeRunId, handleSelectRun],
  );

  const isLogExpired =
    selectedJob?.log_status === "expired" ||
    (jobLogQuery.error instanceof Red2PrApiError &&
      (jobLogQuery.error.status === 410 || jobLogQuery.error.problem.code === "log_expired"));

  const baseChunk = jobLogQuery.data?.data ?? null;
  const combinedLogText = (baseChunk?.content ?? "") + extraLogText;
  const activeNextOffset = extraNextOffset ?? baseChunk?.next_offset ?? 0;
  const activeHasMore = extraNextOffset !== null ? extraHasMore : (baseChunk?.has_more ?? false);

  return (
    <section aria-labelledby="pipelines-heading" style={{ display: "grid", gap: 20 }}>
      <header style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1 id="pipelines-heading" style={{ margin: 0, fontSize: "1.4rem" }}>
            {t("pipelines.title")}
          </h1>
          <p style={{ margin: "4px 0 0", opacity: 0.85 }}>{t("pipelines.subtitle")}</p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {cursor !== null ? (
            <Button
              size="sm"
              variant="secondary"
              label="Newest runs"
              onClick={() => setCursor(null)}
            />
          ) : null}
          <Button
            size="sm"
            variant="secondary"
            label="Refresh runs"
            onClick={() => {
              void runsQuery.refetch();
              if (activeRunId !== null) {
                void runDetailQuery.refetch();
              }
            }}
          />
        </div>
      </header>

      <div
        className="red2pr-surface-card"
        style={{
          padding: 14,
          display: "flex",
          flexWrap: "wrap",
          gap: 12,
          alignItems: "flex-end",
        }}
      >
        <div>
          <label htmlFor={repoSelectId} style={{ display: "block", fontSize: "0.75rem", fontWeight: 600 }}>
            {t("pipelines.filterRepoLabel")}
          </label>
          <select
            id={repoSelectId}
            className="red2pr-control-input"
            value={repoFilter}
            onChange={(e) => {
              setRepoFilter(e.target.value);
              setCursor(null);
            }}
          >
            <option value="all">All authorized repositories</option>
            {(reposQuery.data?.data.items ?? []).map((repo) => (
              <option key={repo.id} value={repo.id}>
                {sanitizeUntrustedText(repo.name).text}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label
            htmlFor={conclusionSelectId}
            style={{ display: "block", fontSize: "0.75rem", fontWeight: 600 }}
          >
            {t("pipelines.filterConclusionLabel")}
          </label>
          <select
            id={conclusionSelectId}
            className="red2pr-control-input"
            value={conclusionFilter}
            onChange={(e) => {
              setConclusionFilter(e.target.value as "all" | CiConclusion);
              setCursor(null);
            }}
          >
            {CONCLUSION_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor={flakySelectId} style={{ display: "block", fontSize: "0.75rem", fontWeight: 600 }}>
            {t("pipelines.filterFlakyLabel")}
          </label>
          <select
            id={flakySelectId}
            className="red2pr-control-input"
            value={flakyFilter}
            onChange={(e) => {
              setFlakyFilter(e.target.value as "all" | FlakyClassification);
              setCursor(null);
            }}
          >
            {FLAKY_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor={shaInputId} style={{ display: "block", fontSize: "0.75rem", fontWeight: 600 }}>
            {t("pipelines.filterShaLabel")}
          </label>
          <input
            id={shaInputId}
            type="search"
            className="red2pr-control-input"
            placeholder={t("pipelines.filterShaPlaceholder")}
            value={shaFilter}
            onChange={(e) => {
              setShaFilter(e.target.value);
              setCursor(null);
            }}
          />
        </div>

        <label
          htmlFor={flakyOnlyCheckId}
          style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: "0.85rem" }}
        >
          <input
            id={flakyOnlyCheckId}
            type="checkbox"
            checked={flakyOnly}
            onChange={(e) => {
              setFlakyOnly(e.target.checked);
              setCursor(null);
            }}
          />
          <span>{t("pipelines.filterFlakyOnly")}</span>
        </label>

        <Button size="sm" variant="secondary" label="Reset filters" onClick={resetFilters} />
      </div>

      {runsQuery.isLoading ? (
        <StateView state="loading" />
      ) : runsQuery.isError ? (
        <StateView
          state="error"
          description={extractAuthProblemSummary(runsQuery.error, t("state.error.description")).detail}
        />
      ) : runs.length === 0 ? (
        <StateView
          state="empty"
          title={t("pipelines.emptyTitle")}
          description={t("pipelines.emptyDesc")}
        />
      ) : (
        <div style={{ display: "grid", gap: 10 }}>
          <Table
            aria-label={t("pipelines.tableLabel")}
            columns={columns}
            data={tableRows}
            density="compact"
          />
          {nextCursor !== null ? (
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <Button
                size="sm"
                variant="secondary"
                label="Next page"
                onClick={() => setCursor(nextCursor)}
              />
            </div>
          ) : null}
        </div>
      )}

      {activeRunId !== null && runDetail !== null ? (
        <section
          aria-label="Selected CI run attempt inspector"
          className="red2pr-surface-card"
          style={{ padding: 16, display: "grid", gap: 16 }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
            <div>
              <h2 style={{ margin: 0, fontSize: "1.1rem" }}>
                Run #{sanitizeUntrustedText(runDetail.run.external_id).text} ·{" "}
                <code>{sanitizeUntrustedText(runDetail.run.attempt_key ?? "attempt:1").text}</code>
              </h2>
              <div style={{ fontSize: "0.82rem", opacity: 0.85, marginTop: 4 }}>
                Repository:{" "}
                <strong>
                  {sanitizeUntrustedText(
                    runDetail.run.repository_name ?? runDetail.run.repository_id,
                  ).text}
                </strong>{" "}
                · SHA <code>{sanitizeUntrustedText(runDetail.run.head_sha).text}</code> · Ref{" "}
                <code>{sanitizeUntrustedText(runDetail.run.ref).text}</code> · Collected{" "}
                {formatUtcTimestamp(runDetail.run.created_at)}
              </div>
            </div>

            {siblingAttempts.length > 1 ? (
              <div
                role="group"
                aria-label="Rerun attempt selector"
                style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}
              >
                <span style={{ fontSize: "0.78rem", fontWeight: 600 }}>Attempts:</span>
                {siblingAttempts.map((sib) => {
                  const label = sanitizeUntrustedText(
                    sib.attempt_key ?? `attempt:${String(sib.attempt_number ?? 1)}`,
                  ).text;
                  return (
                    <Button
                      key={sib.id}
                      size="sm"
                      variant={sib.id === runDetail.run.id ? "primary" : "secondary"}
                      label={`${label} (${sib.conclusion ?? sib.status})`}
                      aria-pressed={sib.id === runDetail.run.id}
                      onClick={() => handleSelectRun(sib.id)}
                    />
                  );
                })}
              </div>
            ) : null}
          </div>

          {runDetail.run.head_sha_verified === false ||
          runDetail.run.ingestion_state === "stale_sha" ? (
            <div role="alert" className="red2pr-badge-pill red2pr-tone-danger" style={{ padding: 10 }}>
              <StatusGlyph kind="error" />
              <span>
                SEC-016 Stale/mismatched SHA blocked:{" "}
                {sanitizeUntrustedText(
                  runDetail.run.incomplete_reason ??
                    "Provider run SHA diverged from trigger SHA; evidence quarantined from repair.",
                ).text}
              </span>
            </div>
          ) : null}

          {runDetail.run.ingestion_state === "incomplete" ? (
            <div role="status" className="red2pr-badge-pill red2pr-tone-warning" style={{ padding: 10 }}>
              <StatusGlyph kind="warn" />
              <span>
                Incomplete evidence (never assumed passing):{" "}
                {sanitizeUntrustedText(
                  runDetail.run.incomplete_reason ?? "Upstream logs or artifacts were incomplete.",
                ).text}
              </span>
            </div>
          ) : null}

          {runDetail.run.flaky_classification === "single_pass_unproven" ||
          selectedJob?.flaky_classification === "single_pass_unproven" ? (
            <div role="note" className="red2pr-badge-pill red2pr-tone-info" style={{ padding: 10 }}>
              <StatusGlyph kind="info" />
              <span>{t("pipelines.singlePassNotice")}</span>
            </div>
          ) : null}

          {(runDetail.run.child_pipeline_ids ?? []).length > 0 ? (
            <div style={{ fontSize: "0.82rem" }}>
              <strong>Downstream child pipelines:</strong>{" "}
              {(runDetail.run.child_pipeline_ids ?? [])
                .map((cid) => sanitizeUntrustedText(cid).text)
                .join(", ")}
            </div>
          ) : null}

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "minmax(240px, 320px) minmax(0, 1fr)",
              gap: 16,
              alignItems: "start",
            }}
          >
            <div aria-label="Matrix and retry CI jobs" style={{ display: "grid", gap: 8 }}>
              <h3 style={{ margin: 0, fontSize: "0.95rem" }}>
                Jobs ({String(runJobs.length)})
              </h3>
              {runJobs.map((job) => {
                const jobName = sanitizeUntrustedText(job.name).text;
                const dims = Object.entries(job.matrix_dimensions ?? {});
                const fl = flakyAppearance(job.flaky_classification);
                const out = conclusionAppearance(job.conclusion, job.status);
                const isSelected = job.id === activeJobId;
                return (
                  <button
                    key={job.id}
                    type="button"
                    aria-pressed={isSelected}
                    onClick={() => handleSelectJob(job.id)}
                    className="red2pr-surface-card"
                    style={{
                      textAlign: "left",
                      padding: 10,
                      cursor: "pointer",
                      border: isSelected
                        ? "2px solid var(--red2pr-accent, #2563eb)"
                        : "1px solid rgba(128,128,128,0.28)",
                    }}
                  >
                    <div style={{ fontWeight: 600 }}>{jobName}</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
                      <span className={`red2pr-badge-pill ${out.tone}`}>{out.label}</span>
                      <span className={`red2pr-badge-pill ${fl.tone}`}>{fl.label}</span>
                      {job.is_child_pipeline_job ? (
                        <span className="red2pr-badge-pill red2pr-tone-info">child pipeline</span>
                      ) : null}
                      {job.retry_of_id ? (
                        <span className="red2pr-badge-pill red2pr-tone-warning">
                          retry of #{sanitizeUntrustedText(job.retry_of_id).text}
                        </span>
                      ) : null}
                    </div>
                    {dims.length > 0 ? (
                      <div style={{ fontSize: "0.75rem", marginTop: 6, opacity: 0.85 }}>
                        Matrix:{" "}
                        {dims
                          .map(
                            ([k, v]) =>
                              `${sanitizeUntrustedText(k).text}=${sanitizeUntrustedText(v).text}`,
                          )
                          .join(", ")}
                      </div>
                    ) : null}
                  </button>
                );
              })}
            </div>

            <div style={{ display: "grid", gap: 10, minWidth: 0 }}>
              {selectedJob === null ? (
                <StateView state="empty" title="Select a job to inspect logs" />
              ) : isLogExpired ? (
                <StateView
                  state="partial_evidence"
                  title={t("pipelines.expiredLogTitle")}
                  description={t("pipelines.expiredLogDesc")}
                />
              ) : jobLogQuery.isLoading ? (
                <StateView state="loading" />
              ) : jobLogQuery.isError ? (
                <StateView
                  state="error"
                  description={
                    extractAuthProblemSummary(jobLogQuery.error, t("state.error.description")).detail
                  }
                />
              ) : (
                <>
                  {baseChunk?.truncated ? (
                    <div
                      role="status"
                      className="red2pr-badge-pill red2pr-tone-warning"
                      style={{ padding: 8 }}
                    >
                      <StatusGlyph kind="warn" />
                      <span>
                        Truncated log ({formatByteCount(baseChunk.total_bytes)} stored; tail preserved
                        under NFR-14 20 MiB cap · redaction v{String(baseChunk.redaction_version)}).
                      </span>
                    </div>
                  ) : null}
                  <SafeLogViewer
                    title={`${sanitizeUntrustedText(selectedJob.name).text} — Redacted Log`}
                    rawText={combinedLogText}
                    height={380}
                  />
                  {activeHasMore ? (
                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                      <Button
                        size="sm"
                        variant="secondary"
                        label={
                          loadMoreLogMutation.isPending
                            ? "Loading..."
                            : `Load next chunk (from byte ${String(activeNextOffset)})`
                        }
                        isDisabled={loadMoreLogMutation.isPending}
                        onClick={() => loadMoreLogMutation.mutate(activeNextOffset)}
                      />
                    </div>
                  ) : null}
                </>
              )}
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
              gap: 16,
            }}
          >
            <section aria-label="Encrypted CI artifacts" style={{ display: "grid", gap: 8 }}>
              <h3 style={{ margin: 0, fontSize: "0.95rem" }}>
                Verified Encrypted Artifacts ({String(runArtifacts.length)})
              </h3>
              {downloadBanner !== null ? (
                <div
                  role={downloadBanner.tone === "error" ? "alert" : "status"}
                  className={`red2pr-badge-pill ${
                    downloadBanner.tone === "error" ? "red2pr-tone-danger" : "red2pr-tone-success"
                  }`}
                  style={{ padding: 8 }}
                >
                  <StatusGlyph kind={downloadBanner.tone === "error" ? "error" : "check"} />
                  <span>{downloadBanner.message}</span>
                </div>
              ) : null}
              {runArtifacts.length === 0 ? (
                <p style={{ margin: 0, fontSize: "0.85rem", opacity: 0.8 }}>
                  No downloadable archive artifacts attached to this CI run attempt.
                </p>
              ) : (
                runArtifacts.map((art) => {
                  const safeArtName = sanitizeUntrustedText(art.name ?? art.kind).text;
                  return (
                    <div
                      key={art.id}
                      className="red2pr-surface-card"
                      style={{
                        padding: 10,
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: 10,
                        flexWrap: "wrap",
                      }}
                    >
                      <div>
                        <strong>{safeArtName}</strong>{" "}
                        <span className="red2pr-badge-pill red2pr-tone-info">{art.kind}</span>{" "}
                        <span className="red2pr-badge-pill red2pr-tone-neutral">
                          {art.access_class}
                        </span>
                        <div style={{ fontSize: "0.75rem", opacity: 0.85, marginTop: 4 }}>
                          {formatByteCount(art.size_bytes)} · SHA-256{" "}
                          <code>{art.digest.slice(0, 16)}…</code> · Retain until{" "}
                          {formatUtcTimestamp(art.retention_until)}
                        </div>
                        {art.available === false ? (
                          <div style={{ fontSize: "0.75rem" }} className="red2pr-tone-danger">
                            Expired / purged ({sanitizeUntrustedText(art.purge_reason ?? "retention_expired").text})
                          </div>
                        ) : null}
                      </div>
                      <Button
                        size="sm"
                        variant="secondary"
                        label={`Download ${safeArtName}`}
                        isDisabled={downloadMutation.isPending}
                        onClick={() => downloadMutation.mutate(art)}
                      />
                    </div>
                  );
                })
              )}
            </section>

            <section aria-label="Historical failure fingerprints" style={{ display: "grid", gap: 8 }}>
              <h3 style={{ margin: 0, fontSize: "0.95rem" }}>
                Historical Failure Fingerprints ({String(runFingerprints.length)})
              </h3>
              {runFingerprints.length === 0 ? (
                <p style={{ margin: 0, fontSize: "0.85rem", opacity: 0.8 }}>
                  No failure signatures recorded for this attempt.
                </p>
              ) : (
                runFingerprints.map((fp) => {
                  const fl = flakyAppearance(fp.classification);
                  return (
                    <div key={fp.id} className="red2pr-surface-card" style={{ padding: 10 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
                        <strong>{sanitizeUntrustedText(fp.signature_label).text}</strong>
                        <span className={`red2pr-badge-pill ${fl.tone}`}>
                          <StatusGlyph kind={fl.glyph} />
                          <span>{fl.label}</span>
                        </span>
                      </div>
                      <div style={{ fontSize: "0.78rem", marginTop: 4 }}>
                        Failures: <strong>{String(fp.failure_count)}</strong> · Same-SHA green reruns:{" "}
                        <strong>{String(fp.pass_on_same_sha_count)}</strong> · Distinct SHAs:{" "}
                        <strong>{String(fp.distinct_sha_count)}</strong>
                      </div>
                      <div style={{ fontSize: "0.76rem", opacity: 0.85, marginTop: 4 }}>
                        {sanitizeUntrustedText(fp.confidence_reason).text}
                      </div>
                    </div>
                  );
                })
              )}
            </section>
          </div>
        </section>
      ) : null}
    </section>
  );
}
