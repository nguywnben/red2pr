import {
  Red2PrApiError,
  type AgentProfile,
  type AgentStepRecord,
  type AgentToolName,
  type MeResponse,
  type MetaModelId,
  type ReasoningEffortLevel,
  type ToolCapabilityPolicyItem,
  type Workspace,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useRef, useState } from "react";
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
import { generateClientUuidV7 } from "../queues";

export interface AgentsPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";

interface ProfileDraft {
  readonly enabled: boolean;
  readonly modelId: MetaModelId;
  readonly escalationModelId: "" | "muse-wonder-1.0";
  readonly reasoningEffort: ReasoningEffortLevel;
  readonly maxSteps: string;
  readonly maxToolCallsPerStep: string;
  readonly maxSchemaRepairRetries: string;
  readonly allowedTools: readonly AgentToolName[];
}

interface CapabilityMatrixRow extends Record<string, unknown> {
  readonly id: string;
  readonly name: string;
  readonly category: ToolCapabilityPolicyItem["category"];
  readonly permitted_for_diagnosis: boolean;
  readonly permitted_for_patch: boolean;
  readonly description: string;
  readonly immutable_reason: string;
}

interface RecentStepRow extends Record<string, unknown> {
  readonly id: string;
  readonly step_label: string;
  readonly tool_label: string;
  readonly status: AgentStepRecord["status"];
  readonly denial_code: string | null;
  readonly summary: string;
  readonly created_at: string;
}

const STEP_STATUS_BADGE: Record<
  AgentStepRecord["status"],
  { readonly glyph: GlyphKind; readonly tone: string; readonly label: string }
> = {
  ok: { glyph: "check", tone: "red2pr-tone-success", label: "Allowed / OK" },
  pending: { glyph: "clock", tone: "red2pr-tone-info", label: "Pending" },
  denied: { glyph: "lock", tone: "red2pr-tone-danger", label: "Denied" },
  failed: { glyph: "error", tone: "red2pr-tone-warning", label: "Failed" },
};

function isStaleConflictError(err: unknown): boolean {
  return (
    err instanceof Red2PrApiError &&
    (err.status === 412 ||
      err.problem.code === "version_conflict" ||
      err.problem.code === "version_precondition_failed")
  );
}

function buildProfileDraft(profile: AgentProfile): ProfileDraft {
  return {
    enabled: profile.enabled,
    modelId: profile.model_id,
    escalationModelId:
      profile.escalation_model_id === "muse-wonder-1.0" ? "muse-wonder-1.0" : "",
    reasoningEffort: profile.reasoning_effort,
    maxSteps: String(profile.max_steps),
    maxToolCallsPerStep: String(profile.max_tool_calls_per_step),
    maxSchemaRepairRetries: String(profile.max_schema_repair_retries ?? 2),
    allowedTools: [...profile.allowed_tools],
  };
}

interface AgentProfileCardProps {
  readonly profile: AgentProfile;
  readonly draft: ProfileDraft;
  readonly isAdmin: boolean;
  readonly isSaving: boolean;
  readonly onChangeDraft: (profile: AgentProfile, next: ProfileDraft) => void;
  readonly onResetDraft: (profileId: string) => void;
  readonly onSaveProfile: (profile: AgentProfile, draft: ProfileDraft) => void;
}

function AgentProfileCard({
  profile,
  draft,
  isAdmin,
  isSaving,
  onChangeDraft,
  onResetDraft,
  onSaveProfile,
}: AgentProfileCardProps): React.JSX.Element {
  const baseId = useId();
  const headingId = `${baseId}-heading`;
  const enabledId = `${baseId}-enabled`;
  const modelId = `${baseId}-model`;
  const escalationId = `${baseId}-escalation`;
  const reasoningId = `${baseId}-reasoning`;
  const maxStepsId = `${baseId}-max-steps`;
  const maxToolCallsId = `${baseId}-max-tool-calls`;
  const maxRetriesId = `${baseId}-max-retries`;

  const displayName = sanitizeUntrustedText(profile.display_name).text;
  const description = sanitizeUntrustedText(profile.description).text;
  const controlsDisabled = !isAdmin || isSaving;

  const toggleTool = (tool: AgentToolName) => {
    const exists = draft.allowedTools.includes(tool);
    if (exists && draft.allowedTools.length <= 1) {
      return;
    }
    const nextTools = exists
      ? draft.allowedTools.filter((item) => item !== tool)
      : [...draft.allowedTools, tool];
    onChangeDraft(profile, { ...draft, allowedTools: nextTools });
  };

  return (
    <section
      className="red2pr-surface red2pr-card-section"
      aria-labelledby={headingId}
      data-testid={`agent-profile-card-${profile.role_key}`}
    >
      <div className="red2pr-card-header">
        <div>
          <h2 id={headingId} style={{ margin: 0, fontSize: "1.125rem" }}>
            {displayName}
          </h2>
          <p className="red2pr-field-hint">{description}</p>
        </div>
        <div className="red2pr-button-row">
          <span className="red2pr-badge-pill red2pr-tone-info">
            <StatusGlyph kind="info" />
            <span>
              Role: {profile.role_key} · v{profile.version}
            </span>
          </span>
          <span
            className={`red2pr-badge-pill ${
              profile.enabled ? "red2pr-tone-success" : "red2pr-tone-neutral"
            }`}
          >
            <StatusGlyph kind={profile.enabled ? "check" : "offline"} />
            <span>{profile.enabled ? "Enabled" : "Disabled"}</span>
          </span>
        </div>
      </div>

      <form
        className="red2pr-form-stack"
        onSubmit={(event) => {
          event.preventDefault();
          onSaveProfile(profile, draft);
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <input
            id={enabledId}
            type="checkbox"
            checked={draft.enabled}
            disabled={controlsDisabled}
            onChange={(event) =>
              onChangeDraft(profile, { ...draft, enabled: event.target.checked })
            }
          />
          <label htmlFor={enabledId}>Enable {displayName} execution</label>
        </div>

        <div className="red2pr-kv-grid">
          <div className="red2pr-field-group">
            <label className="red2pr-field-label" htmlFor={modelId}>
              Primary Meta Muse model ({profile.role_key})
            </label>
            <select
              id={modelId}
              className="red2pr-control-select"
              value={draft.modelId}
              disabled={controlsDisabled}
              onChange={(event) =>
                onChangeDraft(profile, {
                  ...draft,
                  modelId: event.target.value as MetaModelId,
                })
              }
            >
              <option value="muse-spark-1.3">muse-spark-1.3 (Primary)</option>
              <option value="muse-wonder-1.0">muse-wonder-1.0 (Probed Escalation)</option>
            </select>
          </div>

          <div className="red2pr-field-group">
            <label className="red2pr-field-label" htmlFor={escalationId}>
              Escalation model ({profile.role_key})
            </label>
            <select
              id={escalationId}
              className="red2pr-control-select"
              value={draft.escalationModelId}
              disabled={controlsDisabled}
              onChange={(event) =>
                onChangeDraft(profile, {
                  ...draft,
                  escalationModelId: event.target.value as "" | "muse-wonder-1.0",
                })
              }
            >
              <option value="">None (stay on primary model)</option>
              <option value="muse-wonder-1.0">muse-wonder-1.0 (requires verified probe)</option>
            </select>
          </div>

          <div className="red2pr-field-group">
            <label className="red2pr-field-label" htmlFor={reasoningId}>
              Reasoning effort ({profile.role_key})
            </label>
            <select
              id={reasoningId}
              className="red2pr-control-select"
              value={draft.reasoningEffort}
              disabled={controlsDisabled}
              onChange={(event) =>
                onChangeDraft(profile, {
                  ...draft,
                  reasoningEffort: event.target.value as ReasoningEffortLevel,
                })
              }
            >
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
            </select>
          </div>

          <div className="red2pr-field-group">
            <label className="red2pr-field-label" htmlFor={maxStepsId}>
              Max steps ({profile.role_key}, 1-16)
            </label>
            <input
              id={maxStepsId}
              className="red2pr-control-input"
              type="number"
              min={1}
              max={16}
              required
              disabled={controlsDisabled}
              value={draft.maxSteps}
              onChange={(event) =>
                onChangeDraft(profile, { ...draft, maxSteps: event.target.value })
              }
            />
          </div>

          <div className="red2pr-field-group">
            <label className="red2pr-field-label" htmlFor={maxToolCallsId}>
              Max tool calls / step ({profile.role_key}, 1-8)
            </label>
            <input
              id={maxToolCallsId}
              className="red2pr-control-input"
              type="number"
              min={1}
              max={8}
              required
              disabled={controlsDisabled}
              value={draft.maxToolCallsPerStep}
              onChange={(event) =>
                onChangeDraft(profile, { ...draft, maxToolCallsPerStep: event.target.value })
              }
            />
          </div>

          <div className="red2pr-field-group">
            <label className="red2pr-field-label" htmlFor={maxRetriesId}>
              Max schema repair retries ({profile.role_key}, 0-2)
            </label>
            <input
              id={maxRetriesId}
              className="red2pr-control-input"
              type="number"
              min={0}
              max={2}
              required
              disabled={controlsDisabled}
              value={draft.maxSchemaRepairRetries}
              onChange={(event) =>
                onChangeDraft(profile, {
                  ...draft,
                  maxSchemaRepairRetries: event.target.value,
                })
              }
            />
          </div>
        </div>

        <fieldset
          style={{
            border: "1px solid var(--red2pr-border-subtle, rgba(128,128,128,0.28))",
            borderRadius: "0.5rem",
            padding: "0.75rem",
            margin: 0,
          }}
        >
          <legend style={{ fontWeight: 600, padding: "0 0.25rem" }}>
            Allowed S-20 tools within immutable {profile.role_key} ceiling
          </legend>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
              gap: "0.5rem",
              marginTop: "0.35rem",
            }}
          >
            {profile.immutable_role_tool_ceiling.map((tool) => {
              const toolCheckboxId = `${baseId}-tool-${tool}`;
              const checked = draft.allowedTools.includes(tool);
              const lockLastTool = checked && draft.allowedTools.length <= 1;
              return (
                <div
                  key={tool}
                  style={{ display: "flex", alignItems: "center", gap: "0.45rem" }}
                >
                  <input
                    id={toolCheckboxId}
                    type="checkbox"
                    checked={checked}
                    disabled={controlsDisabled || lockLastTool}
                    onChange={() => toggleTool(tool)}
                  />
                  <label htmlFor={toolCheckboxId}>
                    <code>{tool}</code>
                  </label>
                </div>
              );
            })}
          </div>
          {profile.role_key === "triage_diagnosis" ? (
            <p style={{ margin: "0.5rem 0 0", fontSize: "0.875rem", opacity: 0.85 }}>
              Role boundary enforced: <code>apply_patch</code> and <code>run_targeted_test</code>{" "}
              are permanently excluded from Triage &amp; Diagnosis.
            </p>
          ) : null}
        </fieldset>

        {isAdmin ? (
          <div className="red2pr-button-row">
            <Button
              label={`Save ${displayName}`}
              type="submit"
              variant="primary"
              isDisabled={isSaving}
            />
            <Button
              label={`Reset ${displayName}`}
              variant="secondary"
              isDisabled={isSaving}
              onClick={() => onResetDraft(profile.id)}
            />
          </div>
        ) : null}
      </form>
    </section>
  );
}

export function AgentsPage({ workspace, me }: AgentsPageProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const announce = useLiveAnnouncer();
  const wsSlug = workspace.slug ?? workspace.id;

  const isAdmin = useMemo(
    () =>
      (me.memberships ?? []).some(
        (item) => item.workspace_id === workspace.id && item.role === "admin",
      ),
    [me.memberships, workspace.id],
  );

  const [draftOverrides, setDraftOverrides] = useState<
    Record<string, { readonly version: number; readonly draft: ProfileDraft }>
  >({});
  const [staleConflict, setStaleConflict] = useState(false);
  const [errorSummary, setErrorSummary] = useState<AuthProblemSummary | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingStepUpRetryRef = useRef<(() => void) | null>(null);

  const profilesQuery = useQuery({
    queryKey: ["workspace", wsSlug, "agent-profiles"],
    queryFn: () => api.listWorkspaceAgentProfiles(wsSlug),
  });

  const profilesState = profilesQuery.data?.data ?? null;

  const refreshAgentProfiles = useCallback(async () => {
    setStaleConflict(false);
    setErrorSummary(null);
    await invalidateWorkspaceQueries(queryClient, wsSlug);
    await profilesQuery.refetch();
  }, [profilesQuery, queryClient, wsSlug]);

  const updateMutation = useMutation({
    mutationFn: async (vars: {
      readonly profile: AgentProfile;
      readonly draft: ProfileDraft;
      readonly idempotencyKey: string;
    }) => {
      const { profile, draft, idempotencyKey } = vars;
      return api.updateWorkspaceAgentProfile(
        wsSlug,
        profile.id,
        {
          expected_version: profile.version,
          enabled: draft.enabled,
          model_id: draft.modelId,
          ...(draft.escalationModelId === "muse-wonder-1.0"
            ? { escalation_model_id: "muse-wonder-1.0", clear_escalation_model: false }
            : { clear_escalation_model: true }),
          reasoning_effort: draft.reasoningEffort,
          max_steps: Number.parseInt(draft.maxSteps, 10),
          max_tool_calls_per_step: Number.parseInt(draft.maxToolCallsPerStep, 10),
          max_schema_repair_retries: Number.parseInt(draft.maxSchemaRepairRetries, 10),
          allowed_tools: [...draft.allowedTools],
        },
        {
          idempotencyKey,
          ifMatch: `"v${profile.version}"`,
        },
      );
    },
    onSuccess: async (envelope, vars) => {
      setStaleConflict(false);
      setErrorSummary(null);
      setDraftOverrides((prev) => {
        const next = { ...prev };
        delete next[vars.profile.id];
        return next;
      });
      const msg = `${sanitizeUntrustedText(envelope.data.profile.display_name).text} updated to v${envelope.data.profile.version}.`;
      setNotice(msg);
      announce(msg);
      await invalidateWorkspaceQueries(queryClient, wsSlug);
      await profilesQuery.refetch();
    },
    onError: (err, vars) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        pendingStepUpRetryRef.current = () => {
          updateMutation.mutate(vars);
        };
        setStepUpOpen(true);
        return;
      }
      if (isStaleConflictError(err)) {
        setStaleConflict(true);
        const msg =
          "Agent profile version changed concurrently (HTTP 412). Reload latest profiles before saving.";
        setNotice(null);
        announce(msg);
        return;
      }
      const summary = extractAuthProblemSummary(err, t("state.error.description"));
      setErrorSummary(summary);
      setNotice(null);
      announce(summary.detail);
    },
  });

  const handleDraftChange = useCallback((profile: AgentProfile, nextDraft: ProfileDraft) => {
    setDraftOverrides((prev) => ({
      ...prev,
      [profile.id]: { version: profile.version, draft: nextDraft },
    }));
  }, []);

  const handleResetDraft = useCallback((profileId: string) => {
    setDraftOverrides((prev) => {
      const next = { ...prev };
      delete next[profileId];
      return next;
    });
  }, []);

  const handleSaveProfile = useCallback(
    (profile: AgentProfile, draft: ProfileDraft) => {
      if (!isAdmin) {
        return;
      }
      setErrorSummary(null);
      setNotice(null);
      updateMutation.mutate({
        profile,
        draft,
        idempotencyKey: generateClientUuidV7(),
      });
    },
    [isAdmin, updateMutation],
  );

  const matrixRows = useMemo<CapabilityMatrixRow[]>(
    () =>
      (profilesState?.tool_matrix ?? []).map((item) => ({
        id: item.name,
        name: sanitizeUntrustedText(item.name).text,
        category: item.category,
        permitted_for_diagnosis: item.permitted_for_diagnosis,
        permitted_for_patch: item.permitted_for_patch,
        description: sanitizeUntrustedText(item.description).text,
        immutable_reason: sanitizeUntrustedText(item.immutable_reason).text,
      })),
    [profilesState?.tool_matrix],
  );

  const matrixColumns = useMemo<TableColumn<CapabilityMatrixRow>[]>(
    () => [
      {
        key: "name",
        header: "Tool / Capability",
        renderCell: (row) => <code>{row.name}</code>,
      },
      {
        key: "category",
        header: "Governance Class",
        renderCell: (row) =>
          row.category === "s20_allowed" ? (
            <span className="red2pr-badge-pill red2pr-tone-success">
              <StatusGlyph kind="check" />
              <span>S-20 Allowlisted</span>
            </span>
          ) : (
            <span className="red2pr-badge-pill red2pr-tone-danger">
              <StatusGlyph kind="lock" />
              <span>Permanently Prohibited</span>
            </span>
          ),
      },
      {
        key: "permitted_for_diagnosis",
        header: "Triage & Diagnosis",
        renderCell: (row) => (
          <span>{row.permitted_for_diagnosis ? "Allowed" : "Blocked"}</span>
        ),
      },
      {
        key: "permitted_for_patch",
        header: "Bounded Patch",
        renderCell: (row) => <span>{row.permitted_for_patch ? "Allowed" : "Blocked"}</span>,
      },
      {
        key: "immutable_reason",
        header: "Broker & Policy Boundary",
        renderCell: (row) => (
          <span>
            {row.description} — {row.immutable_reason}
          </span>
        ),
      },
    ],
    [],
  );

  const stepRows = useMemo<RecentStepRow[]>(
    () =>
      (profilesState?.recent_steps ?? []).map((step) => ({
        id: step.id,
        step_label: `#${step.step_number} (${step.agent_role} / ${step.step_kind})`,
        tool_label: sanitizeUntrustedText(
          step.tool_name ?? step.model_id ?? "structured_inference",
        ).text,
        status: step.status,
        denial_code:
          step.deny_reason_code != null
            ? sanitizeUntrustedText(step.deny_reason_code).text
            : null,
        summary: sanitizeUntrustedText(
          step.deny_explanation ?? `context ${step.context_digest.slice(0, 20)}…`,
        ).text,
        created_at: formatUtcTimestamp(step.created_at),
      })),
    [profilesState?.recent_steps],
  );

  const stepColumns = useMemo<TableColumn<RecentStepRow>[]>(
    () => [
      {
        key: "step_label",
        header: "Step & Role",
        renderCell: (row) => <code>{row.step_label}</code>,
      },
      {
        key: "tool_label",
        header: "Tool / Action",
        renderCell: (row) => <code>{row.tool_label}</code>,
      },
      {
        key: "status",
        header: "Broker Verdict",
        renderCell: (row) => {
          const badge = STEP_STATUS_BADGE[row.status];
          return (
            <span className={`red2pr-badge-pill ${badge.tone}`}>
              <StatusGlyph kind={badge.glyph} />
              <span>
                {badge.label}
                {row.denial_code ? ` (${row.denial_code})` : ""}
              </span>
            </span>
          );
        },
      },
      {
        key: "summary",
        header: "Redacted Summary",
        renderCell: (row) => <span>{row.summary}</span>,
      },
      {
        key: "created_at",
        header: "UTC",
        renderCell: (row) => <span>{row.created_at}</span>,
      },
    ],
    [],
  );

  if (profilesQuery.isPending) {
    return <StateView state="loading" />;
  }

  if (profilesQuery.isError || profilesState === null) {
    const summary = extractAuthProblemSummary(profilesQuery.error, t("state.error.description"));
    return (
      <StateView
        state={
          summary.status === 403 ? "forbidden" : summary.status === null ? "offline" : "error"
        }
        description={summary.detail}
        correlationId={summary.correlationId ?? undefined}
        primaryAction={{
          label: "Reload agent profiles",
          onClick: () => {
            void profilesQuery.refetch();
          },
        }}
      />
    );
  }

  return (
    <div className="red2pr-page-stack" data-testid="agents-page">
      <div className="red2pr-card-header">
        <div>
          <h1 style={{ margin: 0, fontSize: "1.5rem" }}>Agents &amp; Tool Governance</h1>
          <p className="red2pr-field-hint">
            Bounded Triage/Diagnosis and Patch agent profiles within immutable S-20 tool ceilings
            and server-locked prompt fences.
          </p>
        </div>

        <div className="red2pr-button-row">
          <span
            className={`red2pr-badge-pill ${
              profilesState.ready_for_repair_inference
                ? "red2pr-tone-success"
                : "red2pr-tone-warning"
            }`}
          >
            <StatusGlyph kind={profilesState.ready_for_repair_inference ? "check" : "warn"} />
            <span>
              {profilesState.ready_for_repair_inference
                ? "Ready for Repair Inference"
                : profilesState.suspension_reason
                  ? `Paused (${sanitizeUntrustedText(profilesState.suspension_reason).text})`
                  : "Inference Prerequisites Needed"}
            </span>
          </span>
          <Button
            label="Refresh profiles"
            variant="secondary"
            size="sm"
            onClick={() => {
              void refreshAgentProfiles();
            }}
          />
        </div>
      </div>

      <div className="red2pr-inline-alert red2pr-tone-info" role="note">
        <span>
          <StatusGlyph kind="lock" />{" "}
          <strong>
            Server-Locked Prompt Boundary (<code>arbitrary_prompt_override_allowed: false</code>):
          </strong>{" "}
          system instructions, untrusted repository data fences, and ADR-031 baseline gates cannot
          be overridden. Prohibited capabilities ({profilesState.prohibited_capabilities.join(", ")})
          are denied in code and audited.
        </span>
      </div>

      {!isAdmin ? (
        <div
          className="red2pr-inline-alert red2pr-tone-neutral"
          data-testid="agents-readonly-banner"
        >
          <span>
            Read-only mode: workspace administrator role is required to update agent profiles.
          </span>
        </div>
      ) : null}

      {staleConflict ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-warning"
          data-testid="agents-stale-conflict-banner"
        >
          <span>
            Profile version changed concurrently (HTTP 412 stale If-Match). Reload the latest
            workspace state before re-applying changes.
          </span>
          <div className="red2pr-button-row">
            <Button
              label="Reload latest profiles"
              variant="secondary"
              size="sm"
              onClick={() => {
                void refreshAgentProfiles();
              }}
            />
          </div>
        </div>
      ) : null}

      {errorSummary !== null ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-danger"
          data-testid="agents-error-banner"
        >
          <span>
            {errorSummary.detail}
            {errorSummary.correlationId
              ? ` (Correlation ID: ${errorSummary.correlationId})`
              : ""}
          </span>
        </div>
      ) : null}

      {notice !== null ? (
        <div
          role="status"
          className="red2pr-surface red2pr-card-section"
          data-testid="agents-notice-banner"
        >
          <StatusGlyph kind="check" /> <span>{notice}</span>
        </div>
      ) : null}

      {profilesState.profiles.map((profile) => {
        const override = draftOverrides[profile.id];
        const draft =
          override !== undefined && override.version === profile.version
            ? override.draft
            : buildProfileDraft(profile);
        return (
          <AgentProfileCard
            key={profile.id}
            profile={profile}
            draft={draft}
            isAdmin={isAdmin}
            isSaving={updateMutation.isPending}
            onChangeDraft={handleDraftChange}
            onResetDraft={handleResetDraft}
            onSaveProfile={handleSaveProfile}
          />
        );
      })}

      <section
        className="red2pr-surface red2pr-card-section"
        aria-label="Immutable S-20 Tool and Prohibited Capability Matrix"
      >
        <h2 style={{ margin: 0, fontSize: "1.125rem" }}>
          Immutable S-20 Tool Broker &amp; Prohibited Capability Matrix
        </h2>
        <Table
          aria-label="Immutable S-20 tool and prohibited capability matrix"
          columns={matrixColumns}
          data={matrixRows}
        />
      </section>

      <section
        className="red2pr-surface red2pr-card-section"
        aria-label="Recent Agent Steps and Policy Denials"
      >
        <h2 style={{ margin: 0, fontSize: "1.125rem" }}>
          Recent Agent Steps &amp; Broker Policy Denials
        </h2>
        {stepRows.length === 0 ? (
          <p style={{ margin: "0.35rem 0 0", opacity: 0.85 }}>
            No agent steps or tool broker decisions recorded for this workspace yet.
          </p>
        ) : (
          <Table
            aria-label="Recent agent steps and policy denials"
            columns={stepColumns}
            data={stepRows}
          />
        )}
      </section>

      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={Boolean(me.mfa_enabled)}
        onOpenChange={(nextOpen) => {
          setStepUpOpen(nextOpen);
          if (!nextOpen) {
            pendingStepUpRetryRef.current = null;
          }
        }}
        onVerified={() => {
          const retry = pendingStepUpRetryRef.current;
          pendingStepUpRetryRef.current = null;
          if (retry !== null) {
            retry();
          }
        }}
      />
    </div>
  );
}
