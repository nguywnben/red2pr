import {
  type ActionReceipt,
  type MeResponse,
  type QueueTransportStatus,
  type TaskAttemptState,
  type TaskJob,
  type TaskJobActionRequest,
  type TaskJobReconcileOutcome,
  type TaskJobState,
  type Workspace,
  type WorkspaceRole,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useState } from "react";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  Button,
  Dialog,
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

const JOB_STATE_FILTER_OPTIONS: readonly ("all" | TaskJobState)[] = [
  "all",
  "queued",
  "leased",
  "running",
  "cancel_requested",
  "dead_letter",
  "succeeded",
  "failed",
  "cancelled",
];

/**
 * Generate an RFC 9562 UUIDv7 string using current Unix epoch milliseconds and CSPRNG bytes.
 */
export function generateClientUuidV7(nowMs: number = Date.now()): string {
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }

  const ts = BigInt(Math.max(0, Math.trunc(nowMs)));
  bytes[0] = Number((ts >> 40n) & 0xffn);
  bytes[1] = Number((ts >> 32n) & 0xffn);
  bytes[2] = Number((ts >> 24n) & 0xffn);
  bytes[3] = Number((ts >> 16n) & 0xffn);
  bytes[4] = Number((ts >> 8n) & 0xffn);
  bytes[5] = Number(ts & 0xffn);

  // Version 7 (0111xxxx) and RFC 9562 variant (10xxxxxx)
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x70;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;

  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function jobStateAppearance(state: TaskJobState): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (state) {
    case "queued":
      return { glyph: "clock", tone: "red2pr-tone-info", label: "Queued" };
    case "leased":
      return { glyph: "clock", tone: "red2pr-tone-info", label: "Leased" };
    case "running":
      return { glyph: "info", tone: "red2pr-tone-info", label: "Running" };
    case "cancel_requested":
      return { glyph: "warn", tone: "red2pr-tone-warning", label: "Cancel Requested" };
    case "succeeded":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Succeeded" };
    case "failed":
      return { glyph: "error", tone: "red2pr-tone-danger", label: "Failed" };
    case "cancelled":
      return { glyph: "info", tone: "red2pr-tone-neutral", label: "Cancelled" };
    case "dead_letter":
      return { glyph: "error", tone: "red2pr-tone-danger", label: "Dead Letter (DLQ)" };
  }
}

function attemptStateGlyph(state: TaskAttemptState): GlyphKind {
  switch (state) {
    case "succeeded":
      return "check";
    case "leased":
    case "running":
      return "clock";
    case "orphaned":
      return "warn";
    case "cancelled":
      return "info";
    case "failed":
      return "error";
  }
}

function transportAppearance(status: QueueTransportStatus): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (status) {
    case "healthy":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Redis 7 Healthy" };
    case "degraded":
      return { glyph: "warn", tone: "red2pr-tone-warning", label: "Degraded (DB Durable)" };
    case "unconfigured":
      return { glyph: "info", tone: "red2pr-tone-neutral", label: "DB Polling Mode" };
  }
}

interface TaskJobTableRow extends Record<string, unknown> {
  readonly id: string;
  readonly kind: string;
  readonly state: TaskJobState;
  readonly version: number;
  readonly lease_epoch: number;
  readonly attempt: number;
  readonly max_attempts: number;
  readonly priority: number;
  readonly repository_id: string | null;
  readonly correlation_id: string;
  readonly logical_effect_key: string;
  readonly budget_key: string | null;
  readonly leased_by_worker_id: string | null;
  readonly created_at: string;
  readonly not_before: string;
  readonly lease_expires_at: string | null;
  readonly last_error_code: string | null;
  readonly last_error_detail: string | null;
  readonly recoverable: boolean;
  readonly reconcile_required: boolean;
}

function toJobRow(item: TaskJob): TaskJobTableRow {
  return {
    id: item.id,
    kind: sanitizeUntrustedText(item.kind).text,
    state: item.state,
    version: item.version,
    lease_epoch: item.lease_epoch,
    attempt: item.attempt,
    max_attempts: item.max_attempts ?? 3,
    priority: item.priority ?? 100,
    repository_id: item.repository_id ?? null,
    correlation_id: item.correlation_id
      ? sanitizeUntrustedText(item.correlation_id).text
      : "—",
    logical_effect_key: item.logical_effect_key
      ? sanitizeUntrustedText(item.logical_effect_key).text
      : "—",
    budget_key: item.budget_key ? sanitizeUntrustedText(item.budget_key).text : null,
    leased_by_worker_id: item.leased_by_worker_id ?? null,
    created_at: item.created_at,
    not_before: item.not_before,
    lease_expires_at: item.lease_expires_at ?? null,
    last_error_code: item.last_error_code
      ? sanitizeUntrustedText(item.last_error_code).text
      : null,
    last_error_detail: item.last_error_detail
      ? sanitizeUntrustedText(item.last_error_detail).text
      : null,
    recoverable: item.recoverable ?? true,
    reconcile_required: item.reconcile_required ?? false,
  };
}

interface PendingJobActionModal {
  readonly mode: "cancel" | "requeue" | "reconcile";
  readonly job: TaskJobTableRow;
  readonly idempotencyKey: string;
}

export interface QueuesPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

export function QueuesPage({ workspace, me }: QueuesPageProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const announce = useLiveAnnouncer();

  const wsSlug = workspace.slug ?? workspace.id;

  const callerMembership = useMemo(
    () => (me.memberships ?? []).find((entry) => entry.workspace_id === workspace.id) ?? null,
    [me.memberships, workspace.id],
  );
  const effectiveRole: WorkspaceRole | "break_glass" = callerMembership?.role ?? "break_glass";
  const canOperateQueue = effectiveRole === "admin" || effectiveRole === "maintainer";

  const stateFilterId = useId();
  const kindFilterId = useId();
  const actionReasonId = useId();
  const reconcileOutcomeId = useId();

  // Filter & signed S-04 cursor pagination state
  const [stateFilter, setStateFilter] = useState<"all" | TaskJobState>("all");
  const [kindInput, setKindInput] = useState("");
  const [appliedKind, setAppliedKind] = useState<string | null>(null);
  const [cursorStack, setCursorStack] = useState<readonly (string | null)[]>([null]);
  const activeCursor = cursorStack[cursorStack.length - 1] ?? null;

  // Inspection & action dialog state
  const [inspectingJobId, setInspectingJobId] = useState<string | null>(null);
  const [actionModal, setActionModal] = useState<PendingJobActionModal | null>(null);
  const [actionReason, setActionReason] = useState("");
  const [reconcileOutcome, setReconcileOutcome] =
    useState<TaskJobReconcileOutcome>("confirmed_absent");
  const [actionDialogError, setActionDialogError] = useState<AuthProblemSummary | null>(null);
  const [pageError, setPageError] = useState<AuthProblemSummary | null>(null);
  const [latestReceipt, setLatestReceipt] = useState<ActionReceipt | null>(null);

  const jobsQuery = useQuery({
    queryKey: [
      "workspace",
      wsSlug,
      "task-jobs",
      stateFilter,
      appliedKind ?? "all",
      activeCursor ?? "first",
    ],
    queryFn: () =>
      api.listTaskJobs(wsSlug, {
        state: stateFilter === "all" ? null : stateFilter,
        kind: appliedKind,
        cursor: activeCursor,
        limit: 25,
      }),
    retry: false,
  });

  const jobDetailQuery = useQuery({
    queryKey: ["workspace", wsSlug, "task-job-detail", inspectingJobId ?? "none"],
    queryFn: () => api.getTaskJob(wsSlug, inspectingJobId ?? ""),
    enabled: inspectingJobId !== null,
    retry: false,
  });

  const refreshQueueState = useCallback(async (): Promise<void> => {
    await invalidateWorkspaceQueries(queryClient, wsSlug);
    if (inspectingJobId !== null) {
      await queryClient.invalidateQueries({
        queryKey: ["workspace", wsSlug, "task-job-detail", inspectingJobId],
      });
    }
  }, [inspectingJobId, queryClient, wsSlug]);

  const openActionModal = useCallback(
    (mode: "cancel" | "requeue" | "reconcile", job: TaskJobTableRow): void => {
      setActionModal({
        mode,
        job,
        idempotencyKey: generateClientUuidV7(),
      });
      setActionReason("");
      setReconcileOutcome("confirmed_absent");
      setActionDialogError(null);
    },
    [],
  );

  const closeActionModal = useCallback((nextOpen: boolean): void => {
    if (!nextOpen) {
      setActionModal(null);
      setActionReason("");
      setActionDialogError(null);
    }
  }, []);

  const jobActionMutation = useMutation({
    mutationFn: async (modal: PendingJobActionModal) => {
      const payload: TaskJobActionRequest = {
        action: modal.mode,
        reason: actionReason.trim(),
        expected_version: modal.job.version,
        ...(modal.mode === "reconcile" ? { reconciled_outcome: reconcileOutcome } : {}),
      };
      return api.performTaskJobAction(wsSlug, modal.job.id, payload, {
        idempotencyKey: modal.idempotencyKey,
        ifMatch: `"v${String(modal.job.version)}"`,
      });
    },
    onSuccess: async (envelope, modal) => {
      setActionDialogError(null);
      setPageError(null);
      setLatestReceipt(envelope.data);
      setActionModal(null);
      setActionReason("");
      announce(`Queue action ${modal.mode} accepted (${envelope.data.state}).`);
      await refreshQueueState();
    },
    onError: async (err) => {
      setActionDialogError(extractAuthProblemSummary(err, t("state.error.description")));
      await refreshQueueState();
    },
  });

  const pollReceiptMutation = useMutation({
    mutationFn: async (operationId: string) => api.getOperationReceipt(operationId),
    onSuccess: async (envelope) => {
      setPageError(null);
      setLatestReceipt(envelope.data);
      await refreshQueueState();
    },
    onError: (err) => {
      setPageError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const handleStateFilterChange = useCallback(
    (event: React.ChangeEvent<HTMLSelectElement>): void => {
      const val = event.target.value as "all" | TaskJobState;
      setStateFilter(val);
      setCursorStack([null]);
    },
    [],
  );

  const handleApplyKindFilter = useCallback(
    (event: React.FormEvent<HTMLFormElement>): void => {
      event.preventDefault();
      const clean = kindInput.trim();
      setAppliedKind(clean.length > 0 ? clean : null);
      setCursorStack([null]);
    },
    [kindInput],
  );

  const handleClearFilters = useCallback((): void => {
    setStateFilter("all");
    setKindInput("");
    setAppliedKind(null);
    setCursorStack([null]);
  }, []);

  const jobPage = jobsQuery.data?.data ?? null;
  const fairness = jobPage?.summary ?? null;
  const nextCursor = jobPage?.next_cursor ?? null;

  const tableRows = useMemo<TaskJobTableRow[]>(
    () => (jobPage?.items ?? []).map(toJobRow),
    [jobPage?.items],
  );

  const columns = useMemo<TableColumn<TaskJobTableRow>[]>(() => {
    return [
      {
        key: "kind",
        header: t("queues.colJob"),
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span style={{ fontWeight: 600 }}>{row.kind}</span>
            <span className="red2pr-field-hint" style={{ fontFamily: "monospace" }}>
              {row.id}
            </span>
            <span className="red2pr-field-hint">
              Priority {String(row.priority)}
              {row.repository_id ? ` · Repo ${row.repository_id.slice(0, 8)}` : " · Workspace"}
            </span>
          </div>
        ),
      },
      {
        key: "state",
        header: t("queues.colState"),
        renderCell: (row) => {
          const badge = jobStateAppearance(row.state);
          return (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 4 }}>
              <span className={`red2pr-badge-pill ${badge.tone}`}>
                <StatusGlyph kind={badge.glyph} />
                <span>{badge.label}</span>
              </span>
              {row.reconcile_required ? (
                <span className="red2pr-badge-pill red2pr-tone-warning">
                  <StatusGlyph kind="warn" />
                  <span>Reconcile Required</span>
                </span>
              ) : null}
              {row.last_error_code ? (
                <span className="red2pr-field-hint" style={{ fontFamily: "monospace" }}>
                  {row.last_error_code}
                </span>
              ) : null}
            </div>
          );
        },
      },
      {
        key: "lease",
        header: t("queues.colLease"),
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span>
              Attempt {String(row.attempt)} / {String(row.max_attempts)} · Epoch{" "}
              <strong>{String(row.lease_epoch)}</strong>
            </span>
            {row.leased_by_worker_id ? (
              <span className="red2pr-field-hint" style={{ fontFamily: "monospace" }}>
                Worker {row.leased_by_worker_id.slice(0, 12)}
              </span>
            ) : (
              <span className="red2pr-field-hint">Unleased</span>
            )}
          </div>
        ),
      },
      {
        key: "correlation",
        header: t("queues.colCorrelation"),
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <code style={{ fontSize: "0.8125rem" }}>{row.correlation_id}</code>
            <span className="red2pr-field-hint" style={{ fontFamily: "monospace" }}>
              {row.logical_effect_key}
            </span>
          </div>
        ),
      },
      {
        key: "timing",
        header: t("queues.colTiming"),
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2, fontSize: "0.8125rem" }}>
            <span>Created: {formatUtcTimestamp(row.created_at)}</span>
            {row.lease_expires_at ? (
              <span className="red2pr-field-hint">
                Lease TTL: {formatUtcTimestamp(row.lease_expires_at)}
              </span>
            ) : (
              <span className="red2pr-field-hint">
                Ready: {formatUtcTimestamp(row.not_before)}
              </span>
            )}
          </div>
        ),
      },
      {
        key: "actions",
        header: t("queues.colActions"),
        renderCell: (row) => {
          const canCancel =
            canOperateQueue &&
            (row.state === "queued" || row.state === "leased" || row.state === "running");
          const isDlqOrFailed = row.state === "dead_letter" || row.state === "failed";
          const showRequeue = canOperateQueue && isDlqOrFailed;
          const requeueBlocked = row.reconcile_required || !row.recoverable;
          const showReconcile =
            canOperateQueue && (row.reconcile_required || isDlqOrFailed);

          return (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              <Button
                label={t("queues.inspectAction")}
                variant="secondary"
                size="sm"
                onClick={() => {
                  setInspectingJobId(row.id);
                }}
              />
              {canCancel ? (
                <Button
                  label={t("queues.cancelAction")}
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    openActionModal("cancel", row);
                  }}
                />
              ) : null}
              {showReconcile ? (
                <Button
                  label={t("queues.reconcileAction")}
                  variant={row.reconcile_required ? "primary" : "secondary"}
                  size="sm"
                  onClick={() => {
                    openActionModal("reconcile", row);
                  }}
                />
              ) : null}
              {showRequeue ? (
                <Button
                  label={t("queues.requeueAction")}
                  variant="secondary"
                  size="sm"
                  isDisabled={requeueBlocked}
                  onClick={() => {
                    openActionModal("requeue", row);
                  }}
                />
              ) : null}
            </div>
          );
        },
      },
    ];
  }, [canOperateQueue, openActionModal, t]);

  if (jobsQuery.isPending) {
    return <StateView state="loading" />;
  }

  if (jobsQuery.isError) {
    const errSummary = extractAuthProblemSummary(jobsQuery.error, t("state.error.description"));
    return (
      <StateView
        state={
          errSummary.status === 403
            ? "forbidden"
            : errSummary.status === null
              ? "offline"
              : "error"
        }
        description={errSummary.detail}
        correlationId={errSummary.correlationId ?? undefined}
        primaryAction={{
          label: "Retry",
          onClick: () => {
            void jobsQuery.refetch();
          },
        }}
      />
    );
  }

  const transportBadge = fairness ? transportAppearance(fairness.transport_status) : null;
  const inspectedDetail = jobDetailQuery.data?.data ?? null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 12,
        }}
      >
        <div>
          <h1 style={{ margin: 0, fontSize: "1.5rem" }}>{t("queues.pageTitle")}</h1>
          <p className="red2pr-field-hint" style={{ marginTop: 4, marginBottom: 0 }}>
            {t("queues.pageSubtitle")}
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {!canOperateQueue ? (
            <span
              className="red2pr-badge-pill red2pr-tone-neutral"
              data-testid="queues-readonly-role-badge"
            >
              <StatusGlyph kind="lock" />
              <span>Read-only ({effectiveRole})</span>
            </span>
          ) : null}
          <Button
            label="Refresh queue"
            variant="secondary"
            size="sm"
            onClick={() => {
              void refreshQueueState();
            }}
          />
        </div>
      </div>

      {/* Degraded Redis / Paused / Backpressure Operational Banners */}
      {fairness?.transport_status === "degraded" ? (
        <div
          role="region"
          aria-label="Queue transport degraded notice"
          data-testid="queues-degraded-transport-banner"
          className="red2pr-card"
          style={{ borderLeft: "4px solid #b45309", padding: 12 }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="warn" />
            <span>Redis wakeup transport degraded — PostgreSQL durability intact</span>
          </div>
          <p className="red2pr-field-hint" style={{ marginTop: 4, marginBottom: 0 }}>
            {fairness.transport_detail
              ? sanitizeUntrustedText(fairness.transport_detail).text
              : "Zero acknowledged jobs are lost; eligible jobs rebuild automatically when Redis recovers."}
          </p>
        </div>
      ) : null}

      {fairness?.workspace_paused ? (
        <div
          role="region"
          aria-label="Workspace paused queue notice"
          data-testid="queues-workspace-paused-banner"
          className="red2pr-card"
          style={{ borderLeft: "4px solid #b45309", padding: 12 }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="warn" />
            <span>Workspace queue dispatch is paused</span>
          </div>
          <p className="red2pr-field-hint" style={{ marginTop: 4, marginBottom: 0 }}>
            New worker leases and dead-letter requeues remain blocked until a workspace admin
            unpauses this workspace.
          </p>
        </div>
      ) : fairness?.backpressure_active ? (
        <div
          role="region"
          aria-label="Workspace concurrency cap backpressure notice"
          data-testid="queues-backpressure-banner"
          className="red2pr-card"
          style={{ borderLeft: "4px solid #1d4ed8", padding: 12 }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="info" />
            <span>
              Per-workspace repair concurrency cap active ({String(fairness.active_running_repairs)}{" "}
              / {String(fairness.max_running_repairs)})
            </span>
          </div>
          <p className="red2pr-field-hint" style={{ marginTop: 4, marginBottom: 0 }}>
            Queued repairs wait fairly under deficit round-robin scheduling so noisy workspaces
            cannot starve peer tenants.
          </p>
        </div>
      ) : null}

      {pageError ? (
        <div
          role="alert"
          className="red2pr-card"
          data-testid="queues-page-error"
          style={{ borderLeft: "4px solid #b91c1c", padding: 12 }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="error" />
            <span>{pageError.code}</span>
          </div>
          <p style={{ margin: "4px 0 0 0" }}>{pageError.detail}</p>
          {pageError.correlationId ? (
            <p className="red2pr-field-hint" style={{ margin: "4px 0 0 0", fontFamily: "monospace" }}>
              Correlation ID: {pageError.correlationId}
            </p>
          ) : null}
        </div>
      ) : null}

      {/* Latest Asynchronous ActionReceipt Banner (A-24) */}
      {latestReceipt ? (
        <section
          aria-label="Latest queue operation receipt"
          data-testid="queues-latest-receipt"
          className="red2pr-card"
          style={{
            padding: 12,
            display: "flex",
            flexWrap: "wrap",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 12,
          }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <StatusGlyph kind={latestReceipt.state === "succeeded" ? "check" : "clock"} />
              <strong>Operation Receipt ({latestReceipt.state})</strong>
            </div>
            <span className="red2pr-field-hint" style={{ fontFamily: "monospace" }}>
              Operation ID: {latestReceipt.operation_id} · Correlation ID:{" "}
              {latestReceipt.correlation_id}
            </span>
          </div>
          <Button
            label="Refresh receipt status"
            variant="secondary"
            size="sm"
            isLoading={pollReceiptMutation.isPending}
            onClick={() => {
              pollReceiptMutation.mutate(latestReceipt.operation_id);
            }}
          />
        </section>
      ) : null}

      {/* Fairness & Concurrency Summary Cards */}
      {fairness ? (
        <section
          aria-label="Workspace queue fairness and capacity summary"
          data-testid="queues-fairness-summary"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
            gap: 12,
          }}
        >
          <div className="red2pr-card" style={{ padding: 12 }}>
            <div className="red2pr-field-hint">Running Repair Cap</div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                fontSize: "1.25rem",
                fontWeight: 700,
                marginTop: 4,
              }}
              data-testid="queues-cap-metric"
            >
              <StatusGlyph kind={fairness.backpressure_active ? "warn" : "check"} />
              <span>
                {String(fairness.active_running_repairs)} / {String(fairness.max_running_repairs)}
              </span>
            </div>
          </div>

          <div className="red2pr-card" style={{ padding: 12 }}>
            <div className="red2pr-field-hint">Queued Ready / Backoff</div>
            <div style={{ fontSize: "1.25rem", fontWeight: 700, marginTop: 4 }}>
              {String(fairness.queued_count)}
            </div>
          </div>

          <div className="red2pr-card" style={{ padding: 12 }}>
            <div className="red2pr-field-hint">Active Worker Leases</div>
            <div style={{ fontSize: "1.25rem", fontWeight: 700, marginTop: 4 }}>
              {String(fairness.leased_count + fairness.running_count)}
            </div>
            <div className="red2pr-field-hint">
              Leased {String(fairness.leased_count)} · Running {String(fairness.running_count)} ·
              Cancelling {String(fairness.cancel_requested_count)}
            </div>
          </div>

          <div className="red2pr-card" style={{ padding: 12 }}>
            <div className="red2pr-field-hint">Dead-Letter Queue (DLQ)</div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                fontSize: "1.25rem",
                fontWeight: 700,
                marginTop: 4,
              }}
              data-testid="queues-dlq-metric"
            >
              <StatusGlyph kind={fairness.dead_letter_count > 0 ? "error" : "check"} />
              <span>{String(fairness.dead_letter_count)}</span>
            </div>
          </div>

          {transportBadge ? (
            <div className="red2pr-card" style={{ padding: 12 }}>
              <div className="red2pr-field-hint">Wakeup Broker</div>
              <div style={{ marginTop: 6 }}>
                <span className={`red2pr-badge-pill ${transportBadge.tone}`}>
                  <StatusGlyph kind={transportBadge.glyph} />
                  <span>{transportBadge.label}</span>
                </span>
              </div>
            </div>
          ) : null}
        </section>
      ) : null}

      {/* Filter Bar */}
      <form
        onSubmit={handleApplyKindFilter}
        className="red2pr-card"
        style={{
          padding: 12,
          display: "flex",
          flexWrap: "wrap",
          alignItems: "flex-end",
          gap: 12,
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label htmlFor={stateFilterId} style={{ fontSize: "0.8125rem", fontWeight: 600 }}>
            {t("queues.filterStateLabel")}
          </label>
          <select
            id={stateFilterId}
            className="red2pr-select"
            value={stateFilter}
            onChange={handleStateFilterChange}
          >
            {JOB_STATE_FILTER_OPTIONS.map((st) => (
              <option key={st} value={st}>
                {st === "all" ? "All states" : st}
              </option>
            ))}
          </select>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 220 }}>
          <label htmlFor={kindFilterId} style={{ fontSize: "0.8125rem", fontWeight: 600 }}>
            {t("queues.filterKindLabel")}
          </label>
          <input
            id={kindFilterId}
            type="text"
            className="red2pr-input"
            placeholder="e.g. repair.verify"
            value={kindInput}
            onChange={(e) => {
              setKindInput(e.target.value);
            }}
          />
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <Button label="Apply filters" type="submit" variant="secondary" size="sm" />
          {stateFilter !== "all" || appliedKind !== null ? (
            <Button
              label="Clear filters"
              variant="secondary"
              size="sm"
              onClick={handleClearFilters}
            />
          ) : null}
        </div>
      </form>

      {/* Authoritative Queue Table */}
      <section aria-label={t("queues.tableLabel")}>
        <Table
          aria-label={t("queues.tableLabel")}
          data={tableRows}
          columns={columns}
          emptyTitle="No task jobs in this view"
          emptyDescription="Adjust queue filters or wait for new CI failure triage and repair jobs."
        />

        {/* Signed S-04 Cursor Pagination Controls */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginTop: 12,
            gap: 12,
          }}
        >
          <span className="red2pr-field-hint">
            Page {String(cursorStack.length)} · Showing {String(tableRows.length)} job(s)
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            <Button
              label="Previous page"
              variant="secondary"
              size="sm"
              isDisabled={cursorStack.length <= 1}
              onClick={() => {
                setCursorStack((prev) => (prev.length > 1 ? prev.slice(0, -1) : prev));
              }}
            />
            <Button
              label="Next page"
              variant="secondary"
              size="sm"
              isDisabled={nextCursor === null}
              onClick={() => {
                if (nextCursor !== null) {
                  setCursorStack((prev) => [...prev, nextCursor]);
                }
              }}
            />
          </div>
        </div>
      </section>

      {/* Job Detail & Attempt History Inspection Dialog */}
      <Dialog
        isOpen={inspectingJobId !== null}
        onOpenChange={(open) => {
          if (!open) {
            setInspectingJobId(null);
          }
        }}
        title="Task Job Details & Lease Attempts"
        subtitle={inspectingJobId ? `Job ID: ${inspectingJobId}` : undefined}
        width={680}
        data-testid="queue-inspect-dialog"
        footer={
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <Button
              label="Close detail"
              variant="secondary"
              onClick={() => {
                setInspectingJobId(null);
              }}
            />
          </div>
        }
      >
        {jobDetailQuery.isPending ? (
          <p>Loading authoritative task job detail...</p>
        ) : jobDetailQuery.isError || inspectedDetail === null ? (
          <p role="alert">
            {
              extractAuthProblemSummary(jobDetailQuery.error, t("state.error.description"))
                .detail
            }
          </p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <dl
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                gap: 10,
                margin: 0,
              }}
            >
              <div>
                <dt className="red2pr-field-hint">Kind & State</dt>
                <dd style={{ margin: 0, fontWeight: 600 }}>
                  {sanitizeUntrustedText(inspectedDetail.kind).text} · {inspectedDetail.state} (v
                  {String(inspectedDetail.version)})
                </dd>
              </div>
              <div>
                <dt className="red2pr-field-hint">Correlation ID</dt>
                <dd style={{ margin: 0, fontFamily: "monospace" }}>
                  {inspectedDetail.correlation_id
                    ? sanitizeUntrustedText(inspectedDetail.correlation_id).text
                    : "—"}
                </dd>
              </div>
              <div>
                <dt className="red2pr-field-hint">Logical Effect Key</dt>
                <dd style={{ margin: 0, fontFamily: "monospace" }}>
                  {inspectedDetail.logical_effect_key
                    ? sanitizeUntrustedText(inspectedDetail.logical_effect_key).text
                    : "—"}
                </dd>
              </div>
              <div>
                <dt className="red2pr-field-hint">Session Spend Budget Key</dt>
                <dd style={{ margin: 0, fontFamily: "monospace" }}>
                  {inspectedDetail.budget_key
                    ? sanitizeUntrustedText(inspectedDetail.budget_key).text
                    : "None"}
                </dd>
              </div>
            </dl>

            {inspectedDetail.dead_letter_entry ? (
              <div
                className="red2pr-card"
                data-testid="queue-inspect-dlq-box"
                style={{ padding: 10, borderLeft: "4px solid #b91c1c" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6, fontWeight: 600 }}>
                  <StatusGlyph kind="error" />
                  <span>
                    Dead-Letter Entry ({inspectedDetail.dead_letter_entry.status}) · Attempts:{" "}
                    {String(inspectedDetail.dead_letter_entry.attempts)}
                  </span>
                </div>
                <p style={{ margin: "4px 0 0 0", fontSize: "0.875rem" }}>
                  <strong>
                    {sanitizeUntrustedText(inspectedDetail.dead_letter_entry.error_code).text}:
                  </strong>{" "}
                  {sanitizeUntrustedText(inspectedDetail.dead_letter_entry.error_detail).text}
                </p>
              </div>
            ) : null}

            <div>
              <h3 style={{ margin: "0 0 8px 0", fontSize: "0.95rem" }}>
                Fenced Lease Attempt History ({String((inspectedDetail.attempts_history ?? []).length)})
              </h3>
              {(inspectedDetail.attempts_history ?? []).length === 0 ? (
                <p className="red2pr-field-hint" style={{ margin: 0 }}>
                  No worker lease attempts recorded yet.
                </p>
              ) : (
                <ul
                  style={{
                    listStyle: "none",
                    padding: 0,
                    margin: 0,
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                  }}
                >
                  {(inspectedDetail.attempts_history ?? []).map((att) => (
                    <li
                      key={att.id}
                      className="red2pr-card"
                      style={{ padding: 8, fontSize: "0.8125rem" }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontWeight: 600 }}>
                          <StatusGlyph kind={attemptStateGlyph(att.state)} />
                          <span>
                            Attempt #{String(att.attempt_number)} · Lease Epoch{" "}
                            {String(att.lease_epoch)} ({att.state})
                          </span>
                        </span>
                        <span style={{ fontFamily: "monospace" }}>
                          Worker {att.worker_id.slice(0, 12)}
                        </span>
                      </div>
                      <div className="red2pr-field-hint" style={{ marginTop: 4 }}>
                        Started {formatUtcTimestamp(att.started_at)} · Last Heartbeat{" "}
                        {formatUtcTimestamp(att.heartbeat_at)}
                        {att.ended_at ? ` · Ended ${formatUtcTimestamp(att.ended_at)}` : ""}
                      </div>
                      {att.error_code ? (
                        <div style={{ marginTop: 4, fontFamily: "monospace" }}>
                          {sanitizeUntrustedText(att.error_code).text}:{" "}
                          {att.error_detail ? sanitizeUntrustedText(att.error_detail).text : ""}
                        </div>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </Dialog>

      {/* Operator Action Dialog (Cancel / Scoped DLQ Requeue Preview / W-08 Reconcile) */}
      <Dialog
        isOpen={actionModal !== null}
        onOpenChange={closeActionModal}
        title={
          actionModal?.mode === "cancel"
            ? "Cancel Task Job"
            : actionModal?.mode === "requeue"
              ? "Scoped Dead-Letter Requeue Preview"
              : "Reconcile Ambiguous External Side Effects (W-08)"
        }
        subtitle={actionModal ? `${actionModal.job.kind} (${actionModal.job.id})` : undefined}
        purpose="form"
        width={580}
        correlationId={actionDialogError?.correlationId ?? undefined}
        data-testid={actionModal ? `queue-${actionModal.mode}-dialog` : "queue-action-dialog"}
        footer={
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <Button
              label="Dismiss"
              variant="secondary"
              onClick={() => {
                closeActionModal(false);
              }}
            />
            <Button
              label={
                actionModal?.mode === "cancel"
                  ? "Confirm cancel"
                  : actionModal?.mode === "requeue"
                    ? "Confirm scoped requeue"
                    : "Submit reconciliation"
              }
              variant={actionModal?.mode === "cancel" ? "destructive" : "primary"}
              isDisabled={
                actionReason.trim().length < 3 ||
                (actionModal?.mode === "requeue" && Boolean(fairness?.workspace_paused))
              }
              isLoading={jobActionMutation.isPending}
              onClick={() => {
                if (actionModal) {
                  jobActionMutation.mutate(actionModal);
                }
              }}
            />
          </div>
        }
      >
        {actionModal ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {actionDialogError ? (
              <div
                role="alert"
                className="red2pr-card"
                style={{ borderLeft: "4px solid #b91c1c", padding: 10 }}
              >
                <div style={{ fontWeight: 600 }}>{actionDialogError.code}</div>
                <div>{actionDialogError.detail}</div>
              </div>
            ) : null}

            {actionModal.mode === "requeue" ? (
              <div
                className="red2pr-card"
                data-testid="queue-requeue-scope-preview"
                style={{ padding: 10 }}
              >
                <div style={{ fontWeight: 600, marginBottom: 4 }}>
                  Preserved Idempotency & Spend Scope (JOB-02)
                </div>
                <p className="red2pr-field-hint" style={{ margin: "0 0 6px 0" }}>
                  Requeuing re-evaluates live workspace and repository grants without resetting
                  effect tombstones or session spend budgets:
                </p>
                <div style={{ fontSize: "0.8125rem", fontFamily: "monospace" }}>
                  <div>Logical Effect Key: {actionModal.job.logical_effect_key}</div>
                  <div>Budget Key: {actionModal.job.budget_key ?? "None"}</div>
                  <div>Optimistic Version: v{String(actionModal.job.version)}</div>
                </div>
              </div>
            ) : null}

            {actionModal.mode === "reconcile" ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label htmlFor={reconcileOutcomeId} style={{ fontWeight: 600 }}>
                  Verified upstream outcome
                </label>
                <select
                  id={reconcileOutcomeId}
                  className="red2pr-select"
                  value={reconcileOutcome}
                  onChange={(e) => {
                    setReconcileOutcome(e.target.value as TaskJobReconcileOutcome);
                  }}
                >
                  <option value="confirmed_absent">
                    confirmed_absent — Side effect NOT applied upstream (unlocks safe requeue)
                  </option>
                  <option value="confirmed_applied">
                    confirmed_applied — Side effect already applied upstream (marks succeeded &
                    seals tombstone)
                  </option>
                </select>
              </div>
            ) : null}

            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <label htmlFor={actionReasonId} style={{ fontWeight: 600 }}>
                Audited operator reason
              </label>
              <textarea
                id={actionReasonId}
                rows={3}
                className="red2pr-input"
                placeholder="Document why this queue control action is safe..."
                value={actionReason}
                onChange={(e) => {
                  setActionReason(e.target.value);
                }}
              />
            </div>
          </div>
        ) : null}
      </Dialog>
    </div>
  );
}
