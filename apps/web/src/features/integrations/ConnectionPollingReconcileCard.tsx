import {
  type Connection,
  type ProviderSyncCursor,
  type Repository,
  type SyncCursorStatus,
} from "@red2pr/ts-client";
import { useMutation } from "@tanstack/react-query";
import React, { useMemo } from "react";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  Button,
  StatusGlyph,
  Table,
  sanitizeUntrustedText,
  useLiveAnnouncer,
  type TableColumn,
} from "../../shared/ui";
import { extractAuthProblemSummary, formatUtcTimestamp } from "../auth";
import { generateClientUuidV7 } from "../queues/QueuesPage";

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";
type SyncCursorRow = ProviderSyncCursor & Record<string, unknown>;

export interface ReconcileFeedbackPayload {
  readonly tone: "success" | "warning" | "danger";
  readonly text: string;
  readonly correlationId: string | null;
}

export interface ConnectionPollingReconcileCardProps {
  readonly workspaceSlug: string;
  readonly connection: Connection;
  readonly repositories: readonly Repository[];
  readonly syncCursors: readonly ProviderSyncCursor[];
  readonly isAdmin: boolean;
  readonly onReconciled: (payload: ReconcileFeedbackPayload) => Promise<void> | void;
}

function cursorStatusAppearance(status: SyncCursorStatus | undefined): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (status ?? "idle") {
    case "ok":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Synced" };
    case "not_modified":
      return { glyph: "check", tone: "red2pr-tone-info", label: "304 Not Modified (ETag)" };
    case "rate_limited":
      return { glyph: "clock", tone: "red2pr-tone-warning", label: "429 Rate Limited (Backoff)" };
    case "gap_detected":
      return {
        glyph: "warn",
        tone: "red2pr-tone-danger",
        label: "History Gap Detected (Incomplete)",
      };
    case "error":
      return { glyph: "error", tone: "red2pr-tone-danger", label: "Poll Error" };
    case "revoked":
      return { glyph: "error", tone: "red2pr-tone-danger", label: "Revoked — Suspended" };
    case "idle":
      return { glyph: "clock", tone: "red2pr-tone-neutral", label: "Idle" };
  }
}

export function ConnectionPollingReconcileCard({
  workspaceSlug,
  connection,
  repositories,
  syncCursors,
  isAdmin,
  onReconciled,
}: ConnectionPollingReconcileCardProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const announce = useLiveAnnouncer();

  const repoNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const repo of repositories) {
      map.set(repo.id, repo.name);
    }
    return map;
  }, [repositories]);

  const gapCursors = useMemo(
    () => syncCursors.filter((cursor) => cursor.history_gap_detected === true),
    [syncCursors],
  );
  const rateLimitedCursors = useMemo(
    () => syncCursors.filter((cursor) => cursor.last_status === "rate_limited"),
    [syncCursors],
  );
  const cursorRows = useMemo<SyncCursorRow[]>(
    () => syncCursors.map((cursor) => ({ ...cursor })),
    [syncCursors],
  );

  const reconcileMutation = useMutation({
    mutationFn: async (params: { readonly acknowledgeHistoryGap: boolean }) => {
      return api.reconcileConnectionRuns(
        workspaceSlug,
        connection.id,
        {
          acknowledge_history_gap: params.acknowledgeHistoryGap,
          force_poll: true,
        },
        { idempotencyKey: generateClientUuidV7() },
      );
    },
    onSuccess: async (res) => {
      const d = res.data;
      if (!d.complete_recovery) {
        const incompleteReasons: string[] = [];
        if ((d.history_gap_count ?? 0) > 0) {
          incompleteReasons.push(`${d.history_gap_count} repository history gap(s)`);
        }
        if ((d.rate_limited_count ?? 0) > 0) {
          incompleteReasons.push(`${d.rate_limited_count} rate-limited cursor(s)`);
        }
        const reasonSummary =
          incompleteReasons.length > 0
            ? incompleteReasons.join(", ")
            : "pending or degraded cursors remain";
        const msg = `Reconcile finished with incomplete recovery (${reasonSummary}); ${d.polled_repository_count ?? 0} repository cursor(s) polled, ${d.triggers_created_count ?? 0} failure trigger(s) recorded.`;
        announce(msg);
        await onReconciled({
          tone: "warning",
          text: msg,
          correlationId: res.correlationId,
        });
        return;
      }

      const msg = `Reconciled ${d.polled_repository_count ?? 0} repository cursor(s) and ${d.pending_inbox_reconciled_count ?? 0} pending webhook(s); ${d.triggers_created_count ?? 0} failure trigger(s) recorded.`;
      announce(msg);
      await onReconciled({
        tone: "success",
        text: msg,
        correlationId: res.correlationId,
      });
    },
    onError: async (err) => {
      const prob = extractAuthProblemSummary(err, t("state.error.description"));
      announce(prob.detail);
      await onReconciled({
        tone: "danger",
        text: prob.detail,
        correlationId: prob.correlationId,
      });
    },
  });

  const cursorColumns = useMemo<TableColumn<SyncCursorRow>[]>(
    () => [
      {
        key: "repository",
        header: "Repository",
        renderCell: (row) => {
          const repoLabel = repoNameById.get(row.repository_id) ?? row.repository_id;
          return (
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              <span style={{ fontWeight: 600 }}>{sanitizeUntrustedText(repoLabel).text}</span>
              <span className="red2pr-field-hint">
                interval {row.poll_interval_seconds ?? 60}s · overlap {row.overlap_seconds ?? 300}s
              </span>
            </div>
          );
        },
      },
      {
        key: "status",
        header: "Cursor Status",
        renderCell: (row) => {
          const badge = cursorStatusAppearance(row.last_status);
          return (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <div>
                <span className={`red2pr-badge-pill ${badge.tone}`}>
                  <StatusGlyph kind={badge.glyph} />
                  <span>{badge.label}</span>
                </span>
              </div>
              {row.last_error_detail ? (
                <span className="red2pr-field-hint">
                  {sanitizeUntrustedText(row.last_error_detail).text}
                </span>
              ) : null}
            </div>
          );
        },
      },
      {
        key: "checkpoint",
        header: "High-Water Mark & ETag",
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span>
              {row.high_water_mark_at
                ? formatUtcTimestamp(row.high_water_mark_at)
                : "No runs observed yet"}
            </span>
            <span className="red2pr-field-hint">
              {row.etag
                ? `ETag cached (${sanitizeUntrustedText(row.etag).text})`
                : "No conditional ETag"}
              {row.last_seen_run_id
                ? ` · run ${sanitizeUntrustedText(row.last_seen_run_id).text}`
                : ""}
            </span>
          </div>
        ),
      },
      {
        key: "next_poll",
        header: "Next Poll / Cooldown (UTC)",
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span>
              {row.next_poll_after ? formatUtcTimestamp(row.next_poll_after) : "Due immediately"}
            </span>
            {row.rate_limit_reset_at ? (
              <span className="red2pr-field-hint">
                Rate-limit reset: {formatUtcTimestamp(row.rate_limit_reset_at)}
              </span>
            ) : null}
          </div>
        ),
      },
    ],
    [repoNameById],
  );

  const webhookIngressPath = `/api/v1/hooks/${connection.provider}/${connection.id}`;
  const isConnectionActionable =
    connection.status !== "revoked" && connection.status !== "unsupported";
  const headingId = `polling-heading-${connection.provider}-${connection.id}`;

  return (
    <section
      className="red2pr-surface red2pr-card-section"
      aria-labelledby={headingId}
      data-testid={`polling-reconcile-card-${connection.provider}`}
    >
      <div className="red2pr-card-header">
        <div>
          <h3 id={headingId} style={{ margin: 0, fontSize: "1.05rem" }}>
            {t("integrations.pollingSectionTitle")}
          </h3>
          <p className="red2pr-field-hint" style={{ marginTop: 4 }}>
            {t("integrations.pollingSectionSubtitle")}
          </p>
        </div>
        {isAdmin ? (
          <Button
            label={t("integrations.reconcileRunsAction")}
            variant="secondary"
            size="sm"
            isLoading={reconcileMutation.isPending}
            isDisabled={!isConnectionActionable || reconcileMutation.isPending}
            onClick={() => reconcileMutation.mutate({ acknowledgeHistoryGap: false })}
            data-testid="reconcile-connection-runs-btn"
          />
        ) : null}
      </div>

      <div className="red2pr-field-hint" style={{ marginTop: 8 }}>
        <strong>Webhook ingress endpoint (A-22):</strong>{" "}
        <code data-testid="webhook-ingress-endpoint">{webhookIngressPath}</code> ·{" "}
        {connection.provider === "github"
          ? "Raw-body X-Hub-Signature-256 verified before JSON parse; committed to PostgreSQL before 202 ack."
          : connection.auth_mode === "gitlab_legacy_token"
            ? "Pinned X-Gitlab-Token over HTTPS/TLS; committed to PostgreSQL before 202 ack."
            : "Pinned GitLab v19 Standard Webhooks HMAC (webhook-signature + 5m window); never downgrades to X-Gitlab-Token."}
      </div>

      {gapCursors.length > 0 ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-danger"
          style={{ marginTop: 12 }}
          data-testid="polling-history-gap-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="warn" />
            <span>
              Incomplete history recovery ({gapCursors.length} repository cursor
              {gapCursors.length === 1 ? "" : "s"}): offline duration or missed run volume exceeded
              provider retention — missed CI runs in the gap window cannot be recovered.
            </span>
          </div>
          <ul style={{ margin: "6px 0 0 0", paddingLeft: 20, fontSize: "0.84rem" }}>
            {gapCursors.map((cursor) => {
              const repoLabel = repoNameById.get(cursor.repository_id) ?? cursor.repository_id;
              return (
                <li key={cursor.id}>
                  <strong>{sanitizeUntrustedText(repoLabel).text}</strong>
                  {cursor.history_gap_since || cursor.history_gap_until
                    ? ` (${cursor.history_gap_since ? formatUtcTimestamp(cursor.history_gap_since) : "unknown"} – ${cursor.history_gap_until ? formatUtcTimestamp(cursor.history_gap_until) : "now"})`
                    : ""}
                  :{" "}
                  {
                    sanitizeUntrustedText(
                      cursor.history_gap_detail ??
                        "Missed runs prior to provider retention horizon cannot be replayed.",
                    ).text
                  }
                </li>
              );
            })}
          </ul>
          {isAdmin && isConnectionActionable ? (
            <div className="red2pr-button-row" style={{ marginTop: 8 }}>
              <Button
                label={t("integrations.acknowledgeGapAction")}
                variant="secondary"
                size="sm"
                isLoading={reconcileMutation.isPending}
                isDisabled={reconcileMutation.isPending}
                onClick={() => reconcileMutation.mutate({ acknowledgeHistoryGap: true })}
                data-testid="acknowledge-history-gap-btn"
              />
            </div>
          ) : null}
        </div>
      ) : null}

      {rateLimitedCursors.length > 0 ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-warning"
          style={{ marginTop: 12 }}
          data-testid="polling-rate-limit-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="clock" />
            <span>
              Provider rate-limit backoff active ({rateLimitedCursors.length} cursor
              {rateLimitedCursors.length === 1 ? "" : "s"}): local polling is honoring upstream{" "}
              <code>429 Retry-After</code> without storming.
            </span>
          </div>
          <ul style={{ margin: "6px 0 0 0", paddingLeft: 20, fontSize: "0.84rem" }}>
            {rateLimitedCursors.map((cursor) => {
              const repoLabel = repoNameById.get(cursor.repository_id) ?? cursor.repository_id;
              const cooldownUntil = cursor.next_poll_after ?? cursor.rate_limit_reset_at ?? null;
              return (
                <li key={cursor.id}>
                  <strong>{sanitizeUntrustedText(repoLabel).text}</strong>:{" "}
                  {cooldownUntil
                    ? `Polling paused until ${formatUtcTimestamp(cooldownUntil)}`
                    : "Waiting for provider cooldown window"}
                  {cursor.last_error_detail
                    ? ` (${sanitizeUntrustedText(cursor.last_error_detail).text})`
                    : ""}
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}

      <div style={{ marginTop: 12 }}>
        <Table
          aria-label={t("integrations.syncCursorsTableLabel")}
          columns={cursorColumns}
          data={cursorRows}
          emptyTitle="No polling cursors initialized yet"
          emptyDescription={
            isAdmin
              ? "Synchronize repositories and run Reconcile runs (or wait for the 60s local poller) to initialize resumable cursors."
              : "No polling cursors are currently visible for your repository grants."
          }
        />
      </div>
    </section>
  );
}
