import {
  Red2PrApiError,
  type BulkRepositoryPreviewResponse,
  type MeResponse,
  type ProviderKind,
  type Repository,
  type RepositoryMode,
  type WorkflowHazardStatus,
  type Workspace,
  type WorkspaceRole,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router";
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
  StepUpDialog,
  extractAuthProblemSummary,
  formatUtcTimestamp,
  type AuthProblemSummary,
} from "../auth";

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";
type RepositoryRow = Repository & Record<string, unknown>;

export interface RepositoriesPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

export function resolveRepositoryWorkspaceRole(
  workspace: Workspace,
  me: MeResponse,
): WorkspaceRole | "break_glass" | null {
  const membership = (me.memberships ?? []).find((m) => m.workspace_id === workspace.id);
  if (membership) {
    return membership.role;
  }
  if (me.is_instance_owner) {
    return "break_glass";
  }
  return null;
}

export function modeBadgeAppearance(
  mode: RepositoryMode,
  paused: boolean,
): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  if (paused) {
    return { glyph: "clock", tone: "red2pr-tone-warning", label: `Paused (${mode})` };
  }
  switch (mode) {
    case "monitor":
      return { glyph: "info", tone: "red2pr-tone-neutral", label: "Monitor" };
    case "approval":
      return { glyph: "lock", tone: "red2pr-tone-info", label: "Approval" };
    case "auto_repair":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Auto-Repair" };
  }
}

export function hazardBadgeAppearance(status: WorkflowHazardStatus | undefined): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (status) {
    case "flagged":
      return { glyph: "error", tone: "red2pr-tone-danger", label: "Hazard Flagged (SEC-031)" };
    case "clean":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Clean" };
    case "unscanned":
    default:
      return { glyph: "clock", tone: "red2pr-tone-neutral", label: "Unscanned" };
  }
}

function parseTagCsv(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t.length > 0),
    ),
  );
}

export function RepositoriesPage({ workspace, me }: RepositoriesPageProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const announce = useLiveAnnouncer();

  const workspaceSlug = workspace.slug ?? workspace.id;
  const effectiveRole = resolveRepositoryWorkspaceRole(workspace, me);
  const isAdmin = effectiveRole === "admin";
  const canMutate = effectiveRole === "admin" || effectiveRole === "maintainer";

  const searchInputId = useId();
  const providerSelectId = useId();
  const modeSelectId = useId();
  const hazardSelectId = useId();
  const pausedSelectId = useId();
  const tagSelectId = useId();
  const groupOrgCheckboxId = useId();
  const bulkModeId = useId();
  const bulkPausedId = useId();
  const bulkAddTagsId = useId();
  const bulkRemoveTagsId = useId();
  const bulkReasonId = useId();

  const [searchQuery, setSearchQuery] = useState("");
  const [providerFilter, setProviderFilter] = useState<ProviderKind | "">("");
  const [modeFilter, setModeFilter] = useState<RepositoryMode | "">("");
  const [hazardFilter, setHazardFilter] = useState<WorkflowHazardStatus | "">("");
  const [pausedFilter, setPausedFilter] = useState<"" | "paused" | "active">("");
  const [tagFilter, setTagFilter] = useState("");
  const [groupByOrg, setGroupByOrg] = useState(false);
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const activeCursor = cursorStack.length > 0 ? cursorStack[cursorStack.length - 1] ?? null : null;

  const [selectedIds, setSelectedIds] = useState<Record<string, boolean>>({});
  const [bulkDialogOpen, setBulkDialogOpen] = useState(false);
  const [bulkMode, setBulkMode] = useState<"" | RepositoryMode>("");
  const [bulkPaused, setBulkPaused] = useState<"" | "pause" | "resume">("");
  const [bulkAddTags, setBulkAddTags] = useState("");
  const [bulkRemoveTags, setBulkRemoveTags] = useState("");
  const [bulkReason, setBulkReason] = useState("");
  const [bulkPreview, setBulkPreview] = useState<BulkRepositoryPreviewResponse | null>(null);
  const [bulkError, setBulkError] = useState<AuthProblemSummary | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingBulkApplyRef = useRef(false);

  const resetPagination = useCallback(() => {
    setCursorStack([]);
  }, []);

  const queryParams = useMemo(
    () => ({
      cursor: activeCursor,
      limit: 25,
      q: searchQuery.trim() !== "" ? searchQuery.trim() : null,
      provider: providerFilter !== "" ? providerFilter : null,
      mode: modeFilter !== "" ? modeFilter : null,
      hazard_status: hazardFilter !== "" ? hazardFilter : null,
      paused: pausedFilter === "" ? null : pausedFilter === "paused",
      tag: tagFilter !== "" ? tagFilter : null,
    }),
    [activeCursor, hazardFilter, modeFilter, pausedFilter, providerFilter, searchQuery, tagFilter],
  );

  const catalogQuery = useQuery({
    queryKey: ["workspace", workspaceSlug, "repositories", queryParams],
    queryFn: () => api.listRepositories(workspaceSlug, queryParams),
    retry: false,
  });

  const items = useMemo(
    () => (catalogQuery.data?.data.items ?? []) as RepositoryRow[],
    [catalogQuery.data],
  );
  const facets = catalogQuery.data?.data.facets;

  const selectedRepoIds = useMemo(
    () => items.map((r) => r.id).filter((id) => Boolean(selectedIds[id])),
    [items, selectedIds],
  );

  const expectedVersionMap = useMemo(() => {
    const map: Record<string, number> = {};
    for (const repo of items) {
      if (selectedIds[repo.id]) {
        map[repo.id] = repo.version;
      }
    }
    return map;
  }, [items, selectedIds]);

  const bulkPreviewMutation = useMutation({
    mutationFn: async () => {
      return api.previewBulkRepositoryPolicies(workspaceSlug, {
        repository_ids: selectedRepoIds,
        mode: bulkMode !== "" ? bulkMode : null,
        paused: bulkPaused === "" ? null : bulkPaused === "pause",
        add_tags: parseTagCsv(bulkAddTags),
        remove_tags: parseTagCsv(bulkRemoveTags),
      });
    },
    onSuccess: (envelope) => {
      setBulkError(null);
      setBulkPreview(envelope.data);
      announce(
        envelope.data.can_apply_all
          ? "Bulk policy preview ready to apply."
          : "Bulk policy preview found blocking denials on one or more repositories.",
      );
    },
    onError: (err) => {
      setBulkError(extractAuthProblemSummary(err, "Bulk preview failed"));
    },
  });

  const bulkApplyMutation = useMutation({
    mutationFn: async () => {
      return api.bulkUpdateRepositories(workspaceSlug, {
        repository_ids: selectedRepoIds,
        expected_versions: expectedVersionMap,
        mode: bulkMode !== "" ? bulkMode : null,
        paused: bulkPaused === "" ? null : bulkPaused === "pause",
        add_tags: parseTagCsv(bulkAddTags),
        remove_tags: parseTagCsv(bulkRemoveTags),
        reason: bulkReason.trim() !== "" ? bulkReason.trim() : null,
      });
    },
    onSuccess: async (envelope) => {
      setBulkError(null);
      setBulkPreview(null);
      setBulkDialogOpen(false);
      setSelectedIds({});
      announce(
        `Applied bulk repository update across ${String(envelope.data.updated_repositories?.length ?? 0)} repositories.`,
      );
      await invalidateWorkspaceQueries(queryClient, workspaceSlug);
    },
    onError: (err) => {
      if (
        err instanceof Red2PrApiError &&
        err.status === 403 &&
        err.problem.code === "step_up_required"
      ) {
        pendingBulkApplyRef.current = true;
        setStepUpOpen(true);
        return;
      }
      setBulkError(extractAuthProblemSummary(err, "Bulk repository update failed"));
    },
  });

  const columns = useMemo<TableColumn<RepositoryRow>[]>(() => {
    const baseCols: TableColumn<RepositoryRow>[] = [];
    if (canMutate) {
      baseCols.push({
        key: "id",
        header: "Select",
        renderCell: (row) => {
          const cleanName = sanitizeUntrustedText(row.name).text;
          return (
            <input
              type="checkbox"
              aria-label={`Select repository ${cleanName}`}
              checked={Boolean(selectedIds[row.id])}
              onChange={(ev) =>
                setSelectedIds((prev) => ({
                  ...prev,
                  [row.id]: ev.target.checked,
                }))
              }
            />
          );
        },
      });
    }
    baseCols.push(
      {
        key: "name",
        header: "Repository",
        renderCell: (row) => {
          const cleanName = sanitizeUntrustedText(row.name).text;
          const cleanBranch = sanitizeUntrustedText(row.default_branch).text;
          return (
            <div>
              <Link
                to={`/w/${encodeURIComponent(workspaceSlug)}/repositories/${encodeURIComponent(row.id)}`}
                style={{ fontWeight: 700, color: "var(--red2pr-focus-ring)" }}
              >
                {cleanName}
              </Link>
              <div className="red2pr-field-hint" style={{ marginTop: 2 }}>
                {(row.provider ?? "provider").toUpperCase()} · {row.visibility} · default{" "}
                <code>{cleanBranch}</code> · policy v{String(row.policy_revision)}
              </div>
            </div>
          );
        },
      },
      {
        key: "mode",
        header: "Mode & Pause",
        renderCell: (row) => {
          const app = modeBadgeAppearance(row.mode, row.paused);
          return (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              <span className={`red2pr-badge-pill ${app.tone}`}>
                <StatusGlyph kind={app.glyph} />
                <span>{app.label}</span>
              </span>
              {row.grant_review_required ? (
                <span className="red2pr-badge-pill red2pr-tone-warning">
                  <StatusGlyph kind="lock" />
                  <span>W-02 Review Hold</span>
                </span>
              ) : null}
            </div>
          );
        },
      },
      {
        key: "workflow_hazard_status",
        header: "Workflow Posture",
        renderCell: (row) => {
          const app = hazardBadgeAppearance(row.workflow_hazard_status);
          return (
            <span className={`red2pr-badge-pill ${app.tone}`}>
              <StatusGlyph kind={app.glyph} />
              <span>{app.label}</span>
            </span>
          );
        },
      },
      {
        key: "tags",
        header: "Scoped Tags & CI",
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {(row.tags ?? []).length === 0 ? (
                <span className="red2pr-field-hint">No tags</span>
              ) : (
                (row.tags ?? []).map((tg) => (
                  <span key={tg} className="red2pr-badge-pill red2pr-tone-neutral">
                    {sanitizeUntrustedText(tg).text}
                  </span>
                ))
              )}
            </div>
            <span className="red2pr-field-hint">
              Sync: {row.sync_status ?? "idle"}
              {row.last_ci_conclusion ? ` · Latest CI: ${row.last_ci_conclusion}` : ""}
              {row.last_synced_at ? ` · ${formatUtcTimestamp(row.last_synced_at)}` : ""}
            </span>
          </div>
        ),
      },
    );
    return baseCols;
  }, [canMutate, selectedIds, workspaceSlug]);

  const groupedEntries = useMemo(() => {
    const groups = new Map<string, RepositoryRow[]>();
    for (const row of items) {
      const org = sanitizeUntrustedText(row.organization ?? "Ungrouped").text;
      const bucket = groups.get(org) ?? [];
      bucket.push(row);
      groups.set(org, bucket);
    }
    return Array.from(groups.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [items]);

  const hasActiveFilters =
    searchQuery.trim() !== "" ||
    providerFilter !== "" ||
    modeFilter !== "" ||
    hazardFilter !== "" ||
    pausedFilter !== "" ||
    tagFilter !== "";

  return (
    <div className="red2pr-page-stack" data-testid="repositories-page">
      <div className="red2pr-card-header">
        <div>
          <h1 style={{ margin: 0, fontSize: "1.5rem" }}>{t("repositories.pageTitle")}</h1>
          <p className="red2pr-field-hint" style={{ marginTop: 6 }}>
            {t("repositories.pageSubtitle")}
          </p>
        </div>
        {canMutate && selectedRepoIds.length > 0 ? (
          <Button
            label={t("repositories.bulkPreviewAction", { count: selectedRepoIds.length })}
            variant="primary"
            onClick={() => {
              setBulkPreview(null);
              setBulkError(null);
              setBulkDialogOpen(true);
            }}
          />
        ) : null}
      </div>

      {(facets?.partial_sync_connection_ids ?? []).length > 0 ? (
        <div
          role="status"
          className="red2pr-inline-alert red2pr-tone-warning"
          data-testid="repositories-partial-sync-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}>
            <StatusGlyph kind="warn" />
            <span>{t("repositories.partialSyncBanner")}</span>
          </div>
        </div>
      ) : null}

      <section className="red2pr-surface red2pr-card-section" aria-label="Catalog filters">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
            gap: 12,
          }}
        >
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={searchInputId}>
              {t("repositories.searchLabel")}
            </label>
            <input
              id={searchInputId}
              type="search"
              className="red2pr-control-input"
              placeholder={t("repositories.searchPlaceholder")}
              value={searchQuery}
              onChange={(ev) => {
                setSearchQuery(ev.target.value);
                resetPagination();
              }}
            />
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={providerSelectId}>
              {t("repositories.filterProviderLabel")}
            </label>
            <select
              id={providerSelectId}
              className="red2pr-control-select"
              value={providerFilter}
              onChange={(ev) => {
                setProviderFilter(ev.target.value as ProviderKind | "");
                resetPagination();
              }}
            >
              <option value="">All providers</option>
              <option value="github">GitHub</option>
              <option value="gitlab">GitLab</option>
            </select>
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={modeSelectId}>
              {t("repositories.filterModeLabel")}
            </label>
            <select
              id={modeSelectId}
              className="red2pr-control-select"
              value={modeFilter}
              onChange={(ev) => {
                setModeFilter(ev.target.value as RepositoryMode | "");
                resetPagination();
              }}
            >
              <option value="">All modes</option>
              <option value="monitor">Monitor</option>
              <option value="approval">Approval</option>
              <option value="auto_repair">Auto-Repair</option>
            </select>
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={hazardSelectId}>
              {t("repositories.filterHazardLabel")}
            </label>
            <select
              id={hazardSelectId}
              className="red2pr-control-select"
              value={hazardFilter}
              onChange={(ev) => {
                setHazardFilter(ev.target.value as WorkflowHazardStatus | "");
                resetPagination();
              }}
            >
              <option value="">All workflow postures</option>
              <option value="clean">Clean</option>
              <option value="flagged">Flagged (SEC-031)</option>
              <option value="unscanned">Unscanned</option>
            </select>
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={pausedSelectId}>
              {t("repositories.filterPausedLabel")}
            </label>
            <select
              id={pausedSelectId}
              className="red2pr-control-select"
              value={pausedFilter}
              onChange={(ev) => {
                setPausedFilter(ev.target.value as "" | "paused" | "active");
                resetPagination();
              }}
            >
              <option value="">All pause states</option>
              <option value="active">Active (unpaused)</option>
              <option value="paused">Paused</option>
            </select>
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={tagSelectId}>
              {t("repositories.filterTagLabel")}
            </label>
            <select
              id={tagSelectId}
              className="red2pr-control-select"
              value={tagFilter}
              onChange={(ev) => {
                setTagFilter(ev.target.value);
                resetPagination();
              }}
            >
              <option value="">All scoped tags</option>
              {(facets?.tags ?? []).map((tg) => (
                <option key={tg} value={tg}>
                  {sanitizeUntrustedText(tg).text}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
          }}
        >
          <label
            htmlFor={groupOrgCheckboxId}
            style={{ display: "inline-flex", alignItems: "center", gap: 8, fontWeight: 600 }}
          >
            <input
              id={groupOrgCheckboxId}
              type="checkbox"
              checked={groupByOrg}
              onChange={(ev) => setGroupByOrg(ev.target.checked)}
            />
            <span>{t("repositories.groupByOrgLabel")}</span>
          </label>

          {facets ? (
            <div className="red2pr-button-row" data-testid="repositories-scoped-facets">
              <span className="red2pr-badge-pill red2pr-tone-neutral">
                <span>Paused: {String(facets.paused_count)}</span>
              </span>
              <span
                className={`red2pr-badge-pill ${
                  facets.hazard_flagged_count > 0 ? "red2pr-tone-danger" : "red2pr-tone-success"
                }`}
              >
                <StatusGlyph kind={facets.hazard_flagged_count > 0 ? "error" : "check"} />
                <span>Hazards: {String(facets.hazard_flagged_count)}</span>
              </span>
              {items.some((r) => r.grant_review_required) ? (
                <span className="red2pr-badge-pill red2pr-tone-warning">
                  <StatusGlyph kind="lock" />
                  <span>
                    W-02 Review: {String(items.filter((r) => r.grant_review_required).length)}
                  </span>
                </span>
              ) : null}
            </div>
          ) : null}
        </div>
      </section>

      {catalogQuery.isLoading ? <StateView state="loading" /> : null}

      {catalogQuery.isError ? (
        <StateView
          state="error"
          title="Unable to load repository catalog"
          description={extractAuthProblemSummary(catalogQuery.error, "Catalog error").detail}
        />
      ) : null}

      {!catalogQuery.isLoading && !catalogQuery.isError && items.length === 0 ? (
        <StateView
          state="empty"
          title={
            hasActiveFilters
              ? t("state.empty.title")
              : isAdmin
                ? t("repositories.emptyAdminTitle")
                : t("repositories.emptyMemberTitle")
          }
          description={
            hasActiveFilters
              ? t("state.empty.description")
              : isAdmin
                ? t("repositories.emptyAdminDesc")
                : t("repositories.emptyMemberDesc")
          }
          primaryAction={
            !hasActiveFilters && isAdmin
              ? {
                  label: "Open Integrations",
                  variant: "primary",
                  onClick: () =>
                    void navigate(`/w/${encodeURIComponent(workspaceSlug)}/integrations`),
                }
              : undefined
          }
        />
      ) : null}

      {!catalogQuery.isLoading && !catalogQuery.isError && items.length > 0 ? (
        groupByOrg ? (
          <div className="red2pr-page-stack" data-testid="repositories-org-groups">
            {groupedEntries.map(([orgName, orgItems]) => (
              <section key={orgName} className="red2pr-surface red2pr-card-section">
                <h2 style={{ margin: 0, fontSize: "1.1rem" }}>
                  {orgName} ({String(orgItems.length)})
                </h2>
                <Table<RepositoryRow>
                  aria-label={`Repositories in ${orgName}`}
                  data={orgItems}
                  columns={columns}
                />
              </section>
            ))}
          </div>
        ) : (
          <section className="red2pr-surface red2pr-card-section">
            {canMutate ? (
              <div className="red2pr-button-row">
                <Button
                  label="Select all on page"
                  variant="secondary"
                  onClick={() => {
                    const next: Record<string, boolean> = {};
                    for (const row of items) {
                      next[row.id] = true;
                    }
                    setSelectedIds(next);
                  }}
                />
                {selectedRepoIds.length > 0 ? (
                  <Button
                    label="Clear selection"
                    variant="secondary"
                    onClick={() => setSelectedIds({})}
                  />
                ) : null}
              </div>
            ) : null}
            <Table<RepositoryRow>
              aria-label={t("repositories.tableLabel")}
              data={items}
              columns={columns}
            />
            <div className="red2pr-button-row" style={{ justifyContent: "space-between" }}>
              <Button
                label="Previous page"
                variant="secondary"
                isDisabled={cursorStack.length === 0}
                onClick={() => setCursorStack((prev) => prev.slice(0, -1))}
              />
              <Button
                label="Next page"
                variant="secondary"
                isDisabled={!catalogQuery.data?.data.next_cursor}
                onClick={() => {
                  const next = catalogQuery.data?.data.next_cursor;
                  if (next) {
                    setCursorStack((prev) => [...prev, next]);
                  }
                }}
              />
            </div>
          </section>
        )
      ) : null}

      <Dialog
        isOpen={bulkDialogOpen}
        onOpenChange={setBulkDialogOpen}
        purpose="form"
        width={640}
        title={t("repositories.bulkDialogTitle")}
        subtitle={t("repositories.bulkDialogSubtitle")}
        data-testid="bulk-policy-dialog"
        footer={
          <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
            <Button
              label="Cancel"
              variant="secondary"
              onClick={() => setBulkDialogOpen(false)}
            />
            <Button
              label="Run bulk preview"
              variant="secondary"
              isLoading={bulkPreviewMutation.isPending}
              onClick={() => bulkPreviewMutation.mutate()}
            />
            <Button
              label={t("repositories.bulkApplyAction")}
              variant="primary"
              isLoading={bulkApplyMutation.isPending}
              isDisabled={!bulkPreview || !bulkPreview.can_apply_all}
              onClick={() => bulkApplyMutation.mutate()}
            />
          </div>
        }
      >
        <div className="red2pr-form-stack">
          {bulkError ? (
            <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">
              <strong>{sanitizeUntrustedText(bulkError.code).text}</strong>
              <span>{sanitizeUntrustedText(bulkError.detail).text}</span>
            </div>
          ) : null}

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={bulkModeId}>
              Target Mode (optional)
            </label>
            <select
              id={bulkModeId}
              className="red2pr-control-select"
              value={bulkMode}
              onChange={(ev) => {
                setBulkMode(ev.target.value as "" | RepositoryMode);
                setBulkPreview(null);
              }}
            >
              <option value="">Keep current mode</option>
              <option value="monitor">Monitor</option>
              <option value="approval">Approval</option>
              <option value="auto_repair">Auto-Repair (5m step-up + readiness gates)</option>
            </select>
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={bulkPausedId}>
              Pause State (optional)
            </label>
            <select
              id={bulkPausedId}
              className="red2pr-control-select"
              value={bulkPaused}
              onChange={(ev) => {
                setBulkPaused(ev.target.value as "" | "pause" | "resume");
                setBulkPreview(null);
              }}
            >
              <option value="">Keep current pause state</option>
              <option value="pause">Pause selected repositories</option>
              <option value="resume">Resume selected repositories</option>
            </select>
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={bulkAddTagsId}>
              Add Tags (comma-separated)
            </label>
            <input
              id={bulkAddTagsId}
              type="text"
              className="red2pr-control-input"
              value={bulkAddTags}
              placeholder="tier-1, critical"
              onChange={(ev) => {
                setBulkAddTags(ev.target.value);
                setBulkPreview(null);
              }}
            />
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={bulkRemoveTagsId}>
              Remove Tags (comma-separated)
            </label>
            <input
              id={bulkRemoveTagsId}
              type="text"
              className="red2pr-control-input"
              value={bulkRemoveTags}
              placeholder="deprecated"
              onChange={(ev) => {
                setBulkRemoveTags(ev.target.value);
                setBulkPreview(null);
              }}
            />
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={bulkReasonId}>
              Audit Reason
            </label>
            <input
              id={bulkReasonId}
              type="text"
              className="red2pr-control-input"
              value={bulkReason}
              placeholder="Document bulk governance update..."
              onChange={(ev) => setBulkReason(ev.target.value)}
            />
          </div>

          {bulkPreview ? (
            <div className="red2pr-form-stack" data-testid="bulk-preview-results">
              <div
                className={`red2pr-inline-alert ${
                  bulkPreview.can_apply_all ? "red2pr-tone-success" : "red2pr-tone-danger"
                }`}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}>
                  <StatusGlyph kind={bulkPreview.can_apply_all ? "check" : "error"} />
                  <span>
                    {bulkPreview.can_apply_all
                      ? "All selected repositories pass policy validation."
                      : "Bulk update blocked: resolve repository denials before applying."}
                  </span>
                </div>
              </div>
              <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
                {(bulkPreview.items ?? []).map((item) => (
                  <li key={item.repository_id} className="red2pr-kv-item">
                    <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
                      <span
                        className={`red2pr-badge-pill ${
                          item.can_apply ? "red2pr-tone-success" : "red2pr-tone-danger"
                        }`}
                      >
                        <StatusGlyph kind={item.can_apply ? "check" : "error"} />
                        <span>{item.can_apply ? "Ready" : "Blocked"}</span>
                      </span>
                      <strong>{sanitizeUntrustedText(item.repository_name).text}</strong>
                      <span className="red2pr-field-hint">
                        {item.current_mode} → {item.target_mode} · active jobs:{" "}
                        {String(item.active_job_count)}
                      </span>
                    </div>
                    {(item.denials ?? []).map((denial, idx) => (
                      <p key={idx} className="red2pr-field-hint" style={{ marginTop: 4 }}>
                        {sanitizeUntrustedText(denial.code).text}:{" "}
                        {sanitizeUntrustedText(denial.detail).text}
                      </p>
                    ))}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      </Dialog>

      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={Boolean(me.mfa_enabled)}
        onOpenChange={(nextOpen) => {
          setStepUpOpen(nextOpen);
          if (!nextOpen) {
            pendingBulkApplyRef.current = false;
          }
        }}
        onVerified={() => {
          void queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
          if (pendingBulkApplyRef.current) {
            pendingBulkApplyRef.current = false;
            bulkApplyMutation.mutate();
          }
        }}
      />
    </div>
  );
}
