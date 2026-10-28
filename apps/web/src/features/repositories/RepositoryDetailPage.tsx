import {
  Red2PrApiError,
  type AffectedInFlightItem,
  type MeResponse,
  type RepositoryAccessGrantSummary,
  type RepositoryHistoryEntry,
  type RepositoryRunTriggerSummary,
  type Workspace,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  Button,
  StateView,
  StatusGlyph,
  Table,
  sanitizeUntrustedText,
  useLiveAnnouncer,
  type TableColumn,
} from "../../shared/ui";
import {
  StepUpDialog,
  extractAuthProblemSummary,
  formatUtcTimestamp,
  type AuthProblemSummary,
} from "../auth";
import { PolicyEditor } from "./PolicyEditor";
import {
  hazardBadgeAppearance,
  modeBadgeAppearance,
  resolveRepositoryWorkspaceRole,
} from "./RepositoriesPage";

export const REPO_DETAIL_TABS = [
  "overview",
  "runs",
  "repairs",
  "policies",
  "branches",
  "access",
  "history",
] as const;

export type RepoDetailTabId = (typeof REPO_DETAIL_TABS)[number];

type RunRow = RepositoryRunTriggerSummary & Record<string, unknown>;
type ActiveJobRow = AffectedInFlightItem & Record<string, unknown>;
type GrantRow = RepositoryAccessGrantSummary & Record<string, unknown>;
type HistoryRow = RepositoryHistoryEntry & Record<string, unknown>;

export interface RepositoryDetailPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

function isRepoDetailTab(raw: string | null): raw is RepoDetailTabId {
  return raw !== null && (REPO_DETAIL_TABS as readonly string[]).includes(raw);
}

export function RepositoryDetailPage({
  workspace,
  me,
}: RepositoryDetailPageProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const announce = useLiveAnnouncer();
  const params = useParams<{ repoId?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();

  const workspaceSlug = workspace.slug ?? workspace.id;
  const repoId = params.repoId ?? "";
  const effectiveRole = resolveRepositoryWorkspaceRole(workspace, me);
  const isAdmin = effectiveRole === "admin";
  const canMutate = effectiveRole === "admin" || effectiveRole === "maintainer";

  const tabParam = searchParams.get("tab");
  const activeTab: RepoDetailTabId = isRepoDetailTab(tabParam) ? tabParam : "overview";

  const tabBaseId = useId();
  const tagsInputId = useId();
  const tabButtonRefs = useRef<Record<RepoDetailTabId, HTMLButtonElement | null>>({
    overview: null,
    runs: null,
    repairs: null,
    policies: null,
    branches: null,
    access: null,
    history: null,
  });

  const [tagsDraft, setTagsDraft] = useState<string | null>(null);
  const [actionError, setActionError] = useState<AuthProblemSummary | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingActionAfterStepUpRef = useRef<"ack_w02" | null>(null);

  const selectTab = useCallback(
    (nextTab: RepoDetailTabId, focusTab = false) => {
      const nextParams = new URLSearchParams(searchParams);
      if (nextTab === "overview") {
        nextParams.delete("tab");
      } else {
        nextParams.set("tab", nextTab);
      }
      setSearchParams(nextParams, { replace: true });
      if (focusTab) {
        tabButtonRefs.current[nextTab]?.focus();
      }
    },
    [searchParams, setSearchParams],
  );

  const detailQuery = useQuery({
    queryKey: ["workspace", workspaceSlug, "repository-detail", repoId],
    queryFn: () => api.getRepository(workspaceSlug, repoId),
    enabled: repoId.length > 0,
    retry: false,
  });

  const togglePauseMutation = useMutation({
    mutationFn: async (nextPaused: boolean) => {
      const repo = detailQuery.data?.data.repository;
      const ver = repo?.version ?? 1;
      const etag = detailQuery.data?.etag ?? `"v${String(ver)}"`;
      return api.updateRepository(
        workspaceSlug,
        repoId,
        {
          expected_version: ver,
          paused: nextPaused,
          acknowledge_grant_review: false,
          reason: nextPaused
            ? "Operator paused repository from Repository Detail."
            : "Operator resumed repository from Repository Detail.",
        },
        { ifMatch: etag },
      );
    },
    onSuccess: async (envelope) => {
      setActionError(null);
      announce(
        envelope.data.paused
          ? "Repository paused and queued repair jobs drained."
          : "Repository resumed.",
      );
      await invalidateWorkspaceQueries(queryClient, workspaceSlug);
    },
    onError: (err) => {
      setActionError(extractAuthProblemSummary(err, "Unable to update pause state"));
    },
  });

  const saveTagsMutation = useMutation({
    mutationFn: async (nextTags: string[]) => {
      const repo = detailQuery.data?.data.repository;
      const ver = repo?.version ?? 1;
      const etag = detailQuery.data?.etag ?? `"v${String(ver)}"`;
      return api.updateRepository(
        workspaceSlug,
        repoId,
        {
          expected_version: ver,
          tags: nextTags,
          acknowledge_grant_review: false,
          reason: "Updated repository catalog tags.",
        },
        { ifMatch: etag },
      );
    },
    onSuccess: async () => {
      setActionError(null);
      setTagsDraft(null);
      announce("Saved repository tags.");
      await invalidateWorkspaceQueries(queryClient, workspaceSlug);
    },
    onError: (err) => {
      setActionError(extractAuthProblemSummary(err, "Unable to save tags"));
    },
  });

  const ackGrantReviewMutation = useMutation({
    mutationFn: async () => {
      const repo = detailQuery.data?.data.repository;
      const ver = repo?.version ?? 1;
      const etag = detailQuery.data?.etag ?? `"v${String(ver)}"`;
      return api.updateRepository(
        workspaceSlug,
        repoId,
        {
          expected_version: ver,
          acknowledge_grant_review: true,
          reason: "Admin reviewed post-revocation W-02 repository grants.",
        },
        { ifMatch: etag },
      );
    },
    onSuccess: async () => {
      setActionError(null);
      announce("Cleared W-02 post-revocation grant review hold.");
      await invalidateWorkspaceQueries(queryClient, workspaceSlug);
    },
    onError: (err) => {
      if (
        err instanceof Red2PrApiError &&
        err.status === 403 &&
        err.problem.code === "step_up_required"
      ) {
        pendingActionAfterStepUpRef.current = "ack_w02";
        setStepUpOpen(true);
        return;
      }
      setActionError(extractAuthProblemSummary(err, "Unable to clear W-02 review hold"));
    },
  });

  const runColumns = useMemo<TableColumn<RunRow>[]>(
    () => [
      {
        key: "attempt_key",
        header: "Run Attempt",
        renderCell: (row) => (
          <div>
            <code>{sanitizeUntrustedText(row.attempt_key).text}</code>
            {row.is_rerun ? (
              <span className="red2pr-badge-pill red2pr-tone-info" style={{ marginLeft: 6 }}>
                Rerun
              </span>
            ) : null}
          </div>
        ),
      },
      {
        key: "ref",
        header: "Branch & SHA",
        renderCell: (row) => (
          <div>
            <code>{sanitizeUntrustedText(row.ref).text}</code> ·{" "}
            <code>{sanitizeUntrustedText(row.head_sha.slice(0, 12)).text}</code>
            {row.untrusted_fork ? (
              <span className="red2pr-badge-pill red2pr-tone-danger" style={{ marginLeft: 6 }}>
                <StatusGlyph kind="lock" />
                <span>Untrusted Fork</span>
              </span>
            ) : null}
          </div>
        ),
      },
      {
        key: "conclusion",
        header: "Conclusion & Source",
        renderCell: (row) => (
          <span>
            <strong>{row.conclusion}</strong> via {row.first_source}
          </span>
        ),
      },
      {
        key: "triggered_at",
        header: "Triggered (UTC)",
        renderCell: (row) => <span>{formatUtcTimestamp(row.triggered_at)}</span>,
      },
    ],
    [],
  );

  const activeJobColumns = useMemo<TableColumn<ActiveJobRow>[]>(
    () => [
      {
        key: "kind",
        header: "Task Kind",
        renderCell: (row) => <code>{sanitizeUntrustedText(row.kind).text}</code>,
      },
      {
        key: "state",
        header: "State & Pinned Policy",
        renderCell: (row) => (
          <span>
            {sanitizeUntrustedText(row.state).text} · pinned v{String(row.pinned_policy_revision)}
          </span>
        ),
      },
      {
        key: "impact_summary",
        header: "Governance Isolation",
        renderCell: (row) => <span>{sanitizeUntrustedText(row.impact_summary).text}</span>,
      },
    ],
    [],
  );

  const accessColumns = useMemo<TableColumn<GrantRow>[]>(
    () => [
      {
        key: "display_name",
        header: "Member",
        renderCell: (row) => (
          <div>
            <strong>{sanitizeUntrustedText(row.display_name).text}</strong>
            <div className="red2pr-field-hint">{sanitizeUntrustedText(row.email).text}</div>
          </div>
        ),
      },
      {
        key: "role",
        header: "Workspace Role",
        renderCell: (row) => <span className="red2pr-badge-pill red2pr-tone-info">{row.role}</span>,
      },
      {
        key: "grant_origin",
        header: "Grant Scope",
        renderCell: (row) => (
          <span>
            {row.grant_origin === "workspace_admin"
              ? "Workspace Admin (implicit)"
              : "Explicit repo_grants"}
          </span>
        ),
      },
    ],
    [],
  );

  const historyColumns = useMemo<TableColumn<HistoryRow>[]>(
    () => [
      {
        key: "occurred_at",
        header: "Occurred (UTC)",
        renderCell: (row) => <span>{formatUtcTimestamp(row.occurred_at)}</span>,
      },
      {
        key: "action",
        header: "Action & Decision",
        renderCell: (row) => (
          <div>
            <code>{sanitizeUntrustedText(row.action).text}</code> ·{" "}
            <strong>{sanitizeUntrustedText(row.decision).text}</strong>
            {row.policy_revision != null ? ` (v${String(row.policy_revision)})` : ""}
          </div>
        ),
      },
      {
        key: "summary",
        header: "Audit Summary",
        renderCell: (row) => <span>{sanitizeUntrustedText(row.summary).text}</span>,
      },
    ],
    [],
  );

  if (detailQuery.isLoading) {
    return <StateView state="loading" />;
  }

  if (detailQuery.isError || !detailQuery.data) {
    const err = detailQuery.error;
    const isNotFound = err instanceof Red2PrApiError && err.status === 404;
    const summary = extractAuthProblemSummary(err, "Repository unavailable");
    return (
      <div className="red2pr-page-stack" data-testid="repository-detail-error">
        <div>
          <Link to={`/w/${encodeURIComponent(workspaceSlug)}/repositories`}>
            ← {t("repoDetail.backToCatalog")}
          </Link>
        </div>
        <StateView
          state={isNotFound ? "empty" : "error"}
          title={isNotFound ? "Repository not found or not granted" : "Repository unavailable"}
          description={summary.detail}
          correlationId={summary.correlationId ?? undefined}
        />
      </div>
    );
  }

  const detail = detailQuery.data.data;
  const repo = detail.repository;
  const modeApp = modeBadgeAppearance(repo.mode, repo.paused);
  const hazardApp = hazardBadgeAppearance(repo.workflow_hazard_status);
  const effectiveTagsText = tagsDraft ?? (repo.tags ?? []).join(", ");

  const observedBranches = Array.from(
    new Set([repo.default_branch, ...(detail.recent_runs ?? []).map((r) => r.ref)]),
  );

  const handleTabKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, idx: number): void => {
    let nextIdx: number | null = null;
    if (event.key === "ArrowRight") {
      nextIdx = (idx + 1) % REPO_DETAIL_TABS.length;
    } else if (event.key === "ArrowLeft") {
      nextIdx = (idx - 1 + REPO_DETAIL_TABS.length) % REPO_DETAIL_TABS.length;
    } else if (event.key === "Home") {
      nextIdx = 0;
    } else if (event.key === "End") {
      nextIdx = REPO_DETAIL_TABS.length - 1;
    }
    if (nextIdx !== null) {
      event.preventDefault();
      const targetTab = REPO_DETAIL_TABS[nextIdx];
      if (targetTab) {
        selectTab(targetTab, true);
      }
    }
  };

  return (
    <div className="red2pr-page-stack" data-testid="repository-detail-page">
      <div>
        <Link to={`/w/${encodeURIComponent(workspaceSlug)}/repositories`}>
          ← {t("repoDetail.backToCatalog")}
        </Link>
      </div>

      <section
        aria-label="Repository summary"
        className="red2pr-surface red2pr-card-section"
      >
        <div className="red2pr-card-header">
          <div>
            <h1 style={{ margin: 0, fontSize: "1.45rem" }}>
              {sanitizeUntrustedText(repo.name).text}
            </h1>
            <p className="red2pr-field-hint" style={{ marginTop: 6 }}>
              {(repo.provider ?? "provider").toUpperCase()} · {repo.visibility} · default branch{" "}
              <code>{sanitizeUntrustedText(repo.default_branch).text}</code> · policy v
              {String(detail.current_policy_revision)} · connection{" "}
              <strong>{detail.connection_status}</strong>
            </p>
          </div>

          <div className="red2pr-button-row">
            <span className={`red2pr-badge-pill ${modeApp.tone}`}>
              <StatusGlyph kind={modeApp.glyph} />
              <span>{modeApp.label}</span>
            </span>
            <span className={`red2pr-badge-pill ${hazardApp.tone}`}>
              <StatusGlyph kind={hazardApp.glyph} />
              <span>{hazardApp.label}</span>
            </span>
            {canMutate ? (
              <Button
                label={repo.paused ? t("repoDetail.resumeAction") : t("repoDetail.pauseAction")}
                variant="secondary"
                isLoading={togglePauseMutation.isPending}
                onClick={() => togglePauseMutation.mutate(!repo.paused)}
              />
            ) : null}
            {isAdmin && detail.readiness_gates.grant_review_required ? (
              <Button
                label={t("repoDetail.ackGrantReviewAction")}
                variant="primary"
                isLoading={ackGrantReviewMutation.isPending}
                onClick={() => ackGrantReviewMutation.mutate()}
              />
            ) : null}
          </div>
        </div>

        {detail.readiness_gates.grant_review_required ? (
          <div
            role="status"
            className="red2pr-inline-alert red2pr-tone-warning"
            data-testid="repo-w02-review-alert"
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}>
              <StatusGlyph kind="lock" />
              <span>
                W-02 post-revocation grant review hold: repository remains locked in Monitor mode
                until a workspace admin acknowledges installation grants.
              </span>
            </div>
          </div>
        ) : null}

        {actionError ? (
          <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">
            <strong>{sanitizeUntrustedText(actionError.code).text}</strong>
            <span>{sanitizeUntrustedText(actionError.detail).text}</span>
          </div>
        ) : null}
      </section>

      <div
        className="red2pr-tab-strip"
        role="tablist"
        aria-label={t("repoDetail.tabsLabel")}
        data-testid="repository-detail-tablist"
      >
        {REPO_DETAIL_TABS.map((tabId, idx) => {
          const isSelected = activeTab === tabId;
          const labelKey = `repoDetail.tab.${tabId}` as const;
          return (
            <button
              key={tabId}
              ref={(el) => {
                tabButtonRefs.current[tabId] = el;
              }}
              id={`${tabBaseId}-tab-${tabId}`}
              type="button"
              role="tab"
              className="red2pr-tab-button"
              aria-selected={isSelected}
              aria-controls={`${tabBaseId}-panel-${tabId}`}
              tabIndex={isSelected ? 0 : -1}
              onClick={() => selectTab(tabId)}
              onKeyDown={(ev) => handleTabKeyDown(ev, idx)}
            >
              {t(labelKey)}
            </button>
          );
        })}
      </div>

      <div
        id={`${tabBaseId}-panel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`${tabBaseId}-tab-${activeTab}`}
        data-testid={`repository-tab-panel-${activeTab}`}
      >
        {activeTab === "overview" ? (
          <div className="red2pr-page-stack">
            <section className="red2pr-surface red2pr-card-section" aria-label="Repository overview">
              <dl className="red2pr-kv-grid">
                <div className="red2pr-kv-item">
                  <dt className="red2pr-kv-term">Effective Operating Mode</dt>
                  <dd className="red2pr-kv-detail">{detail.effective_policy.effective_mode}</dd>
                </div>
                <div className="red2pr-kv-item">
                  <dt className="red2pr-kv-term">Provider Connection</dt>
                  <dd className="red2pr-kv-detail">
                    {sanitizeUntrustedText(detail.connection_display_name ?? repo.connection_id).text}{" "}
                    ({detail.connection_status})
                  </dd>
                </div>
                <div className="red2pr-kv-item">
                  <dt className="red2pr-kv-term">Polling & Sync Cursor</dt>
                  <dd className="red2pr-kv-detail">
                    {detail.sync_cursor
                      ? `${detail.sync_cursor.last_status ?? "idle"}${
                          detail.sync_cursor.history_gap_detected ? " · History Gap" : ""
                        }`
                      : "Webhook-only / Not polled yet"}
                  </dd>
                </div>
                <div className="red2pr-kv-item">
                  <dt className="red2pr-kv-term">Sandbox Execution Allowed</dt>
                  <dd className="red2pr-kv-detail">
                    {detail.effective_policy.allow_sandbox_execution
                      ? "Yes (within policy)"
                      : "No (Monitor / Paused)"}
                  </dd>
                </div>
              </dl>

              <div className="red2pr-form-stack">
                <div className="red2pr-field">
                  <label className="red2pr-field-label" htmlFor={tagsInputId}>
                    Repository Catalog Tags (comma-separated)
                  </label>
                  <div className="red2pr-button-row">
                    <input
                      id={tagsInputId}
                      type="text"
                      className="red2pr-control-input"
                      style={{ flex: 1, minWidth: 220 }}
                      value={effectiveTagsText}
                      disabled={!canMutate || saveTagsMutation.isPending}
                      onChange={(ev) => setTagsDraft(ev.target.value)}
                    />
                    {canMutate ? (
                      <Button
                        label="Save tags"
                        variant="secondary"
                        isLoading={saveTagsMutation.isPending}
                        onClick={() => {
                          const parsed = effectiveTagsText
                            .split(",")
                            .map((s) => s.trim())
                            .filter((s) => s.length > 0);
                          saveTagsMutation.mutate(parsed);
                        }}
                      />
                    ) : null}
                  </div>
                </div>
              </div>
            </section>

            {(repo.workflow_hazards ?? []).length > 0 ? (
              <section
                className="red2pr-surface red2pr-card-section"
                aria-label="SEC-031 Workflow Hazards"
              >
                <h2 style={{ margin: 0, fontSize: "1.1rem" }}>
                  Flagged CI Workflow Hazards (SEC-031 — Blocks Auto-Repair)
                </h2>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {(repo.workflow_hazards ?? []).map((haz, idx) => (
                    <li key={idx}>
                      <code>{sanitizeUntrustedText(haz.workflow_path).text}</code> [
                      <strong>{haz.code}</strong> · {haz.severity}]:{" "}
                      {sanitizeUntrustedText(haz.detail).text}
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
          </div>
        ) : null}

        {activeTab === "runs" ? (
          <section className="red2pr-surface red2pr-card-section" aria-label="Normalized CI runs">
            <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Normalized Failing CI Run Triggers</h2>
            <Table<RunRow>
              aria-label="Normalized failing CI run triggers"
              data={(detail.recent_runs ?? []) as RunRow[]}
              columns={runColumns}
              emptyTitle="No failing CI triggers recorded"
              emptyDescription="Failing GitHub Actions or GitLab CI runs appear here after authenticated webhook ingress or local polling."
            />
          </section>
        ) : null}

        {activeTab === "repairs" ? (
          <div className="red2pr-page-stack">
            <section
              className="red2pr-surface red2pr-card-section"
              aria-label="Pinned active task jobs"
            >
              <h2 style={{ margin: 0, fontSize: "1.1rem" }}>
                In-Flight Task Jobs & Policy Revision Isolation
              </h2>
              <Table<ActiveJobRow>
                aria-label="Active repository task jobs"
                data={(detail.active_jobs ?? []) as ActiveJobRow[]}
                columns={activeJobColumns}
                emptyTitle="No active task jobs in flight"
                emptyDescription="Queued or leased triage/repair jobs pin the exact policy_revision active at trigger time."
              />
            </section>
            <StateView
              state="empty"
              title={t("repoDetail.repairsEmptyTitle")}
              description={t("repoDetail.repairsEmptyDesc")}
            />
          </div>
        ) : null}

        {activeTab === "policies" ? (
          <PolicyEditor
            workspaceSlug={workspaceSlug}
            repositoryId={repo.id}
            canMutate={canMutate}
            me={me}
            onSaved={() => void detailQuery.refetch()}
          />
        ) : null}

        {activeTab === "branches" ? (
          <section className="red2pr-surface red2pr-card-section" aria-label="Branch governance">
            <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Branch Allow/Deny Governance</h2>
            <dl className="red2pr-kv-grid">
              <div className="red2pr-kv-item">
                <dt className="red2pr-kv-term">Default Branch</dt>
                <dd className="red2pr-kv-detail">
                  <code>{sanitizeUntrustedText(repo.default_branch).text}</code>
                </dd>
              </div>
              <div className="red2pr-kv-item">
                <dt className="red2pr-kv-term">Effective Branch Allowlist</dt>
                <dd className="red2pr-kv-detail">
                  {(detail.effective_policy.branch_allowlist ?? []).length > 0
                    ? (detail.effective_policy.branch_allowlist ?? []).join(", ")
                    : "* (all non-denied branches)"}
                </dd>
              </div>
              <div className="red2pr-kv-item">
                <dt className="red2pr-kv-term">Effective Branch Denylist</dt>
                <dd className="red2pr-kv-detail">
                  {(detail.effective_policy.branch_denylist ?? []).length > 0
                    ? (detail.effective_policy.branch_denylist ?? []).join(", ")
                    : "None"}
                </dd>
              </div>
            </dl>
            <div>
              <h3 style={{ margin: "0 0 8px", fontSize: "0.95rem" }}>Observed Branches</h3>
              <ul className="red2pr-code-grid">
                {observedBranches.map((br) => (
                  <li key={br} className="red2pr-code-chip">
                    {sanitizeUntrustedText(br).text}
                    {br === repo.default_branch ? " (default)" : ""}
                  </li>
                ))}
              </ul>
            </div>
          </section>
        ) : null}

        {activeTab === "access" ? (
          <section className="red2pr-surface red2pr-card-section" aria-label="Repository access">
            <h2 style={{ margin: 0, fontSize: "1.1rem" }}>
              Authorized Principals (Deny-by-Default repo_grants)
            </h2>
            <Table<GrantRow>
              aria-label="Authorized repository principals"
              data={(detail.access_grants ?? []) as GrantRow[]}
              columns={accessColumns}
            />
          </section>
        ) : null}

        {activeTab === "history" ? (
          <section
            className="red2pr-surface red2pr-card-section"
            aria-label="Repository audit history"
          >
            <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Tamper-Evident Repository Audit Log</h2>
            <Table<HistoryRow>
              aria-label="Repository audit history"
              data={(detail.recent_history ?? []) as HistoryRow[]}
              columns={historyColumns}
              emptyTitle="No repository audit records yet"
              emptyDescription="Every policy update, pause action, and trigger decision is recorded in the workspace hash chain."
            />
          </section>
        ) : null}
      </div>

      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={Boolean(me.mfa_enabled)}
        onOpenChange={(nextOpen) => {
          setStepUpOpen(nextOpen);
          if (!nextOpen) {
            pendingActionAfterStepUpRef.current = null;
          }
        }}
        onVerified={() => {
          void queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
          if (pendingActionAfterStepUpRef.current === "ack_w02") {
            pendingActionAfterStepUpRef.current = null;
            ackGrantReviewMutation.mutate();
          }
        }}
      />
    </div>
  );
}
