import {
  Red2PrApiError,
  type ApiEnvelope,
  type MeResponse,
  type PolicyEvaluationVerdict,
  type PolicyScopeLayer,
  type RepositoryMode,
  type RepositoryPolicyPreviewResponse,
  type RepositoryPolicyStateResponse,
  type RepositoryPolicyUpdateRequest,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useRef, useState } from "react";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  Button,
  StateView,
  StatusGlyph,
  sanitizeUntrustedText,
  useLiveAnnouncer,
} from "../../shared/ui";
import {
  StepUpDialog,
  extractAuthProblemSummary,
  formatUtcTimestamp,
  type AuthProblemSummary,
} from "../auth";

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";

export interface PolicyEditorProps {
  readonly workspaceSlug: string;
  readonly repositoryId: string;
  readonly canMutate: boolean;
  readonly me: MeResponse;
  readonly onSaved?: () => void;
}

function parseGlobLines(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[\r\n,]+/)
        .map((item) => item.trim())
        .filter((item) => item.length > 0),
    ),
  );
}

function formatGlobLines(items: readonly string[] | undefined): string {
  return (items ?? []).join("\n");
}

function parseExactNameLines(raw: string): string[] {
  return raw.split(/[\r\n]+/).map((item) => item.trim()).filter((item) => item.length > 0);
}

function verdictAppearance(verdict: PolicyEvaluationVerdict): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (verdict) {
    case "allow":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Allow" };
    case "requires_approval":
      return { glyph: "lock", tone: "red2pr-tone-warning", label: "Requires Approval" };
    case "deny":
      return { glyph: "error", tone: "red2pr-tone-danger", label: "Deny" };
  }
}

function layerLabel(layer: PolicyScopeLayer | undefined): string {
  switch (layer) {
    case "hard_invariant":
      return "Hard Invariant";
    case "instance":
      return "Instance Policy";
    case "workspace":
      return "Workspace Policy";
    case "repository":
    default:
      return "Repository Policy";
  }
}

export function PolicyEditor({
  workspaceSlug,
  repositoryId,
  canMutate,
  me,
  onSaved,
}: PolicyEditorProps): React.JSX.Element {
  const api = useRed2PrApi();

  const policyQuery = useQuery({
    queryKey: ["workspace", workspaceSlug, "repository-policy", repositoryId],
    queryFn: () => api.getRepositoryPolicy(workspaceSlug, repositoryId),
    retry: false,
  });

  if (policyQuery.isLoading) {
    return <StateView state="loading" />;
  }

  if (policyQuery.isError || !policyQuery.data) {
    const summary = extractAuthProblemSummary(policyQuery.error, "Unable to load repository policy");
    return (
      <StateView
        state="error"
        title="Unable to load repository policy"
        description={summary.detail}
        correlationId={summary.correlationId ?? undefined}
      />
    );
  }

  return (
    <PolicyEditorForm
      key={repositoryId}
      workspaceSlug={workspaceSlug}
      repositoryId={repositoryId}
      canMutate={canMutate}
      me={me}
      envelope={policyQuery.data}
      onRefetchPolicy={async () => {
        const res = await policyQuery.refetch();
        return res.data ?? null;
      }}
      onSaved={onSaved}
    />
  );
}

interface PolicyEditorFormProps extends PolicyEditorProps {
  readonly envelope: ApiEnvelope<RepositoryPolicyStateResponse>;
  readonly onRefetchPolicy: () => Promise<ApiEnvelope<RepositoryPolicyStateResponse> | null>;
}

function PolicyEditorForm({
  workspaceSlug,
  repositoryId,
  canMutate,
  me,
  envelope,
  onRefetchPolicy,
  onSaved,
}: PolicyEditorFormProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const announce = useLiveAnnouncer();

  const initialData = envelope.data;
  const initialPol = initialData.policy;

  const modeSelectId = useId();
  const pausedCheckboxId = useId();
  const branchAllowId = useId();
  const branchDenyId = useId();
  const fileAllowId = useId();
  const fileDenyId = useId();
  const sensitiveRulesId = useId();
  const requiredChecksId = useId();
  const allowTestsId = useId();
  const allowConfigsId = useId();
  const maxAttemptsId = useId();
  const maxDiffLinesId = useId();
  const maxCallsId = useId();
  const maxTokensId = useId();
  const maxWallId = useId();
  const maxCostAmountId = useId();
  const maxCostCurrencyId = useId();
  const runtimeProfileIdInput = useId();
  const reasonInputId = useId();
  const sampleBranchesId = useId();
  const samplePathsId = useId();
  const sampleDiffLinesId = useId();

  const [initializedRevision, setInitializedRevision] = useState<number>(
    initialData.current_revision,
  );
  const [mode, setMode] = useState<RepositoryMode>(initialData.mode);
  const [paused, setPaused] = useState(initialData.paused);
  const [branchAllowText, setBranchAllowText] = useState(() =>
    formatGlobLines(initialPol.branch_allowlist),
  );
  const [branchDenyText, setBranchDenyText] = useState(() =>
    formatGlobLines(initialPol.branch_denylist),
  );
  const [fileAllowText, setFileAllowText] = useState(() =>
    formatGlobLines(initialPol.file_allowlist),
  );
  const [fileDenyText, setFileDenyText] = useState(() =>
    formatGlobLines(initialPol.file_denylist),
  );
  const [sensitiveRulesText, setSensitiveRulesText] = useState(() =>
    formatGlobLines(initialPol.sensitive_rules),
  );
  const [requiredCheckNamesText, setRequiredCheckNamesText] = useState(() =>
    formatGlobLines(initialPol.required_check_names),
  );
  const [allowTestEdits, setAllowTestEdits] = useState(() => Boolean(initialPol.allow_test_edits));
  const [allowConfigEdits, setAllowConfigEdits] = useState(() =>
    Boolean(initialPol.allow_config_edits),
  );
  const [maxAttempts, setMaxAttempts] = useState(() => initialPol.max_attempts ?? 3);
  const [maxDiffLines, setMaxDiffLines] = useState(() => initialPol.max_diff_lines ?? 500);
  const [maxCalls, setMaxCalls] = useState(() =>
    initialPol.max_calls_per_session != null ? String(initialPol.max_calls_per_session) : "",
  );
  const [maxTokens, setMaxTokens] = useState(() =>
    initialPol.max_tokens_per_session != null ? String(initialPol.max_tokens_per_session) : "",
  );
  const [maxWallSeconds, setMaxWallSeconds] = useState(() =>
    initialPol.max_wall_seconds != null ? String(initialPol.max_wall_seconds) : "",
  );
  const [maxCostAmount, setMaxCostAmount] = useState(
    () => initialPol.max_cost_per_session?.amount ?? "",
  );
  const [maxCostCurrency, setMaxCostCurrency] = useState(
    () => initialPol.max_cost_per_session?.currency ?? "USD",
  );
  const [runtimeProfileId, setRuntimeProfileId] = useState(
    () => initialPol.runtime_profile_id ?? "",
  );
  const [reason, setReason] = useState("");

  const [sampleBranchesText, setSampleBranchesText] = useState("main\nrelease/1.0");
  const [samplePathsText, setSamplePathsText] = useState(
    "src/service.py\n.github/workflows/ci.yml\n.env",
  );
  const [sampleDiffLines, setSampleDiffLines] = useState("45");

  const [previewResult, setPreviewResult] = useState<RepositoryPolicyPreviewResponse | null>(null);
  const [staleConflict, setStaleConflict] = useState(false);
  const [errorSummary, setErrorSummary] = useState<AuthProblemSummary | null>(null);
  const [saveSuccessBanner, setSaveSuccessBanner] = useState<string | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingSaveAfterStepUpRef = useRef(false);

  const hydrateFromState = useCallback(
    (
      rev: number,
      nextMode: RepositoryMode,
      nextPaused: boolean,
      pol: RepositoryPolicyStateResponse["policy"],
    ): void => {
      setInitializedRevision(rev);
      setMode(nextMode);
      setPaused(nextPaused);
      setBranchAllowText(formatGlobLines(pol.branch_allowlist));
      setBranchDenyText(formatGlobLines(pol.branch_denylist));
      setFileAllowText(formatGlobLines(pol.file_allowlist));
      setFileDenyText(formatGlobLines(pol.file_denylist));
      setSensitiveRulesText(formatGlobLines(pol.sensitive_rules));
      setRequiredCheckNamesText(formatGlobLines(pol.required_check_names));
      setAllowTestEdits(Boolean(pol.allow_test_edits));
      setAllowConfigEdits(Boolean(pol.allow_config_edits));
      setMaxAttempts(pol.max_attempts ?? 3);
      setMaxDiffLines(pol.max_diff_lines ?? 500);
      setMaxCalls(pol.max_calls_per_session != null ? String(pol.max_calls_per_session) : "");
      setMaxTokens(pol.max_tokens_per_session != null ? String(pol.max_tokens_per_session) : "");
      setMaxWallSeconds(pol.max_wall_seconds != null ? String(pol.max_wall_seconds) : "");
      setMaxCostAmount(pol.max_cost_per_session?.amount ?? "");
      setMaxCostCurrency(pol.max_cost_per_session?.currency ?? "USD");
      setRuntimeProfileId(pol.runtime_profile_id ?? "");
    },
    [],
  );

  const candidatePolicy = useMemo((): RepositoryPolicyUpdateRequest["policy"] => {
    const baseConsentId = envelope.data.policy.inference_consent_id ?? null;
    const fallbackProfileId =
      envelope.data.policy.runtime_profile_id ?? "python-3.12-isolated";
    const parsedCalls = maxCalls.trim() !== "" ? Number.parseInt(maxCalls.trim(), 10) : null;
    const parsedTokens = maxTokens.trim() !== "" ? Number.parseInt(maxTokens.trim(), 10) : null;
    const parsedWall =
      maxWallSeconds.trim() !== "" ? Number.parseInt(maxWallSeconds.trim(), 10) : null;

    return {
      branch_allowlist: parseGlobLines(branchAllowText),
      branch_denylist: parseGlobLines(branchDenyText),
      file_allowlist: parseGlobLines(fileAllowText),
      file_denylist: parseGlobLines(fileDenyText),
      sensitive_rules: parseGlobLines(sensitiveRulesText),
      required_check_names: parseExactNameLines(requiredCheckNamesText),
      allow_test_edits: allowTestEdits,
      allow_config_edits: allowConfigEdits,
      max_attempts: Number.isFinite(maxAttempts) ? maxAttempts : 3,
      max_diff_lines: Number.isFinite(maxDiffLines) ? maxDiffLines : 500,
      max_calls_per_session: parsedCalls !== null && Number.isFinite(parsedCalls) ? parsedCalls : null,
      max_tokens_per_session:
        parsedTokens !== null && Number.isFinite(parsedTokens) ? parsedTokens : null,
      max_wall_seconds: parsedWall !== null && Number.isFinite(parsedWall) ? parsedWall : null,
      max_cost_per_session:
        maxCostAmount.trim() !== ""
          ? { amount: maxCostAmount.trim(), currency: maxCostCurrency.trim().toUpperCase() || "USD" }
          : null,
      require_baseline: true,
      inference_consent_id: baseConsentId,
      runtime_profile_id: runtimeProfileId.trim() !== "" ? runtimeProfileId.trim() : fallbackProfileId,
    };
  }, [
    allowConfigEdits,
    allowTestEdits,
    branchAllowText,
    branchDenyText,
    envelope.data.policy.inference_consent_id,
    envelope.data.policy.runtime_profile_id,
    fileAllowText,
    fileDenyText,
    maxAttempts,
    maxCalls,
    maxCostAmount,
    maxCostCurrency,
    maxDiffLines,
    maxTokens,
    maxWallSeconds,
    runtimeProfileId,
    requiredCheckNamesText,
    sensitiveRulesText,
  ]);

  const previewMutation = useMutation({
    mutationFn: async () => {
      const parsedDiff =
        sampleDiffLines.trim() !== "" ? Number.parseInt(sampleDiffLines.trim(), 10) : null;
      return api.previewRepositoryPolicy(workspaceSlug, repositoryId, {
        mode,
        paused,
        policy: candidatePolicy,
        sample_branches: parseGlobLines(sampleBranchesText),
        sample_paths: parseGlobLines(samplePathsText),
        sample_diff_lines: parsedDiff !== null && Number.isFinite(parsedDiff) ? parsedDiff : null,
      });
    },
    onSuccess: (previewEnv) => {
      setErrorSummary(null);
      setPreviewResult(previewEnv.data);
      announce(
        previewEnv.data.can_apply
          ? "Dry-run simulation completed: candidate policy is valid."
          : "Dry-run simulation completed: one or more guardrails block saving.",
      );
    },
    onError: (err) => {
      setErrorSummary(extractAuthProblemSummary(err, "Unable to run policy simulation"));
    },
  });

  const saveMutation = useMutation({
    mutationFn: async () => {
      const currentRev = initializedRevision;
      const etag =
        envelope.data.current_revision === currentRev && envelope.etag
          ? envelope.etag
          : `"v${String(currentRev)}"`;
      return api.updateRepositoryPolicy(
        workspaceSlug,
        repositoryId,
        {
          expected_revision: currentRev,
          mode,
          paused,
          policy: candidatePolicy,
          reason: reason.trim() !== "" ? reason.trim() : null,
        },
        { ifMatch: etag },
      );
    },
    onSuccess: async (savedEnv) => {
      setErrorSummary(null);
      setStaleConflict(false);
      setPreviewResult(null);
      setReason("");
      hydrateFromState(
        savedEnv.data.current_revision,
        savedEnv.data.mode,
        savedEnv.data.paused,
        savedEnv.data.policy,
      );
      setSaveSuccessBanner(
        `Saved immutable policy snapshot v${String(savedEnv.data.current_revision)}.`,
      );
      announce(`Saved policy revision v${String(savedEnv.data.current_revision)}.`);
      await invalidateWorkspaceQueries(queryClient, workspaceSlug);
      onSaved?.();
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError) {
        if (err.status === 409 && err.problem.code === "version_conflict") {
          setStaleConflict(true);
        } else if (err.status === 412) {
          setStaleConflict(true);
        } else if (err.status === 403 && err.problem.code === "step_up_required") {
          pendingSaveAfterStepUpRef.current = true;
          setStepUpOpen(true);
          return;
        }
      }
      setErrorSummary(extractAuthProblemSummary(err, "Policy update rejected"));
    },
  });

  const handleReloadLatest = useCallback(async () => {
    setStaleConflict(false);
    setErrorSummary(null);
    const refreshed = await onRefetchPolicy();
    if (refreshed?.data) {
      hydrateFromState(
        refreshed.data.current_revision,
        refreshed.data.mode,
        refreshed.data.paused,
        refreshed.data.policy,
      );
      announce(
        `Reloaded authoritative policy snapshot v${String(refreshed.data.current_revision)}.`,
      );
    }
  }, [announce, hydrateFromState, onRefetchPolicy]);

  const state = envelope.data;
  const gates = state.readiness_gates;
  const autoRepairEligible =
    gates.worker_isolation_ready &&
    gates.inference_consent_ready &&
    !gates.workflow_hazard_blocked &&
    !gates.grant_review_required &&
    !gates.instance_paused &&
    !gates.workspace_paused &&
    (gates.blocking_reasons?.length ?? 0) === 0;
  const effective = state.effective_policy;
  const fieldSources = effective.field_sources ?? {};

  return (
    <div className="red2pr-page-stack" data-testid="policy-editor">
      <section className="red2pr-surface red2pr-card-section" aria-label={t("policyEditor.title")}>
        <div className="red2pr-card-header">
          <div>
            <h2 style={{ margin: 0, fontSize: "1.15rem" }}>{t("policyEditor.title")}</h2>
            <p className="red2pr-field-hint" style={{ marginTop: 4 }}>
              {t("policyEditor.subtitle")}
            </p>
          </div>
          <div className="red2pr-button-row">
            <span className="red2pr-badge-pill red2pr-tone-info" data-testid="policy-current-revision">
              <StatusGlyph kind="lock" />
              <span>Revision v{String(state.current_revision)}</span>
            </span>
            <span className="red2pr-badge-pill red2pr-tone-success">
              <StatusGlyph kind="check" />
              <span>require_baseline = true (Locked)</span>
            </span>
            <span className="red2pr-badge-pill red2pr-tone-neutral">
              <StatusGlyph kind="lock" />
              <span>auto_merge = false (Locked)</span>
            </span>
          </div>
        </div>

        {staleConflict ? (
          <div
            role="alert"
            className="red2pr-inline-alert red2pr-tone-warning"
            data-testid="policy-stale-conflict-banner"
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}>
              <StatusGlyph kind="warn" />
              <span>{t("policyEditor.staleConflictBanner")}</span>
            </div>
            <div>
              <Button
                label={t("policyEditor.reloadAction")}
                variant="secondary"
                onClick={() => void handleReloadLatest()}
              />
            </div>
          </div>
        ) : null}

        {errorSummary ? (
          <div
            role="alert"
            className="red2pr-inline-alert red2pr-tone-danger"
            data-testid="policy-error-banner"
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}>
              <StatusGlyph kind="error" />
              <span>{sanitizeUntrustedText(errorSummary.code).text}</span>
            </div>
            <div>{sanitizeUntrustedText(errorSummary.detail).text}</div>
          </div>
        ) : null}

        {saveSuccessBanner ? (
          <div
            role="status"
            className="red2pr-inline-alert red2pr-tone-success"
            data-testid="policy-save-success-banner"
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
              <StatusGlyph kind="check" />
              <span>{saveSuccessBanner}</span>
            </div>
          </div>
        ) : null}

        <dl className="red2pr-kv-grid" data-testid="policy-readiness-gates">
          <div className="red2pr-kv-item">
            <dt className="red2pr-kv-term">Auto-Repair Eligibility</dt>
            <dd className="red2pr-kv-detail">
              <span
                className={`red2pr-badge-pill ${
                  autoRepairEligible ? "red2pr-tone-success" : "red2pr-tone-warning"
                }`}
              >
                <StatusGlyph kind={autoRepairEligible ? "check" : "warn"} />
                <span>{autoRepairEligible ? "Eligible" : "Blocked by Safety Gate"}</span>
              </span>
            </dd>
          </div>
          <div className="red2pr-kv-item">
            <dt className="red2pr-kv-term">Isolated Z3 Worker</dt>
            <dd className="red2pr-kv-detail">
              <span
                className={`red2pr-badge-pill ${
                  gates.worker_isolation_ready ? "red2pr-tone-success" : "red2pr-tone-warning"
                }`}
              >
                <StatusGlyph kind={gates.worker_isolation_ready ? "check" : "clock"} />
                <span>{gates.worker_isolation_ready ? "Verified" : "Not Configured"}</span>
              </span>
            </dd>
          </div>
          <div className="red2pr-kv-item">
            <dt className="red2pr-kv-term">Outbound Inference Consent</dt>
            <dd className="red2pr-kv-detail">
              <span
                className={`red2pr-badge-pill ${
                  gates.inference_consent_ready ? "red2pr-tone-success" : "red2pr-tone-warning"
                }`}
              >
                <StatusGlyph kind={gates.inference_consent_ready ? "check" : "lock"} />
                <span>{gates.inference_consent_ready ? "Active Consent" : "Consent Required"}</span>
              </span>
            </dd>
          </div>
          <div className="red2pr-kv-item">
            <dt className="red2pr-kv-term">SEC-031 Workflow Hazard</dt>
            <dd className="red2pr-kv-detail">
              <span
                className={`red2pr-badge-pill ${
                  gates.workflow_hazard_blocked ? "red2pr-tone-danger" : "red2pr-tone-success"
                }`}
              >
                <StatusGlyph kind={gates.workflow_hazard_blocked ? "error" : "check"} />
                <span>{gates.workflow_hazard_blocked ? "Flagged — Auto-Repair Blocked" : "Clean"}</span>
              </span>
            </dd>
          </div>
        </dl>

        {(gates.blocking_reasons ?? []).length > 0 ? (
          <div
            className="red2pr-inline-alert red2pr-tone-warning"
            data-testid="policy-gate-blockers"
          >
            <strong>Active auto_repair safety holds:</strong>
            <ul style={{ margin: "4px 0 0 18px", padding: 0 }}>
              {(gates.blocking_reasons ?? []).map((item, idx) => (
                <li key={idx}>{sanitizeUntrustedText(item).text}</li>
              ))}
            </ul>
          </div>
        ) : null}

        <form
          className="red2pr-form-stack"
          onSubmit={(ev) => {
            ev.preventDefault();
            if (!canMutate) {
              return;
            }
            setSaveSuccessBanner(null);
            saveMutation.mutate();
          }}
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
              gap: 14,
            }}
          >
            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={modeSelectId}>
                Operating Mode ({layerLabel(fieldSources["mode"])})
              </label>
              <select
                id={modeSelectId}
                className="red2pr-control-select"
                value={mode}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setMode(ev.target.value as RepositoryMode)}
              >
                <option value="monitor">Monitor (log ingest & diagnosis only — no sandbox)</option>
                <option value="approval">Approval (verified sandbox + mandatory human approval)</option>
                <option value="auto_repair">
                  Auto-Repair (verified draft PR within safe allowlist)
                </option>
              </select>
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={requiredChecksId}>
                Required remote CI check names (exact, case-sensitive; one per line)
              </label>
              <textarea
                id={requiredChecksId}
                rows={4}
                maxLength={16000}
                className="red2pr-control-input"
                value={requiredCheckNamesText}
                disabled={!canMutate || saveMutation.isPending}
                placeholder="unit-tests&#10;Build / Linux"
                onChange={(ev) => setRequiredCheckNamesText(ev.target.value)}
                aria-describedby={`${requiredChecksId}-hint`}
              />
              <p id={`${requiredChecksId}-hint`} className="red2pr-field-hint">
                Exact provider names are limited to 128 unique entries of up to 120 characters.
                Removing a required check needs fresh step-up approval. An empty list can never
                satisfy V-08 and remains unknown.
              </p>
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={runtimeProfileIdInput}>
                Certified Runtime Profile ({layerLabel(fieldSources["runtime_profile_id"])})
              </label>
              <input
                id={runtimeProfileIdInput}
                type="text"
                className="red2pr-control-input"
                value={runtimeProfileId}
                disabled={!canMutate || saveMutation.isPending}
                placeholder={effective.runtime_profile_id}
                onChange={(ev) => setRuntimeProfileId(ev.target.value)}
              />
            </div>
          </div>

          <div className="red2pr-field">
            <label
              htmlFor={pausedCheckboxId}
              style={{ display: "inline-flex", alignItems: "center", gap: 8, fontWeight: 600 }}
            >
              <input
                id={pausedCheckboxId}
                type="checkbox"
                checked={paused}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setPaused(ev.target.checked)}
              />
              <span>
                Pause repository triggers & drain queued repair jobs (
                {layerLabel(fieldSources["paused"])})
              </span>
            </label>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
              gap: 14,
            }}
          >
            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={branchAllowId}>
                Branch Allowlist Globs (one per line)
              </label>
              <textarea
                id={branchAllowId}
                rows={3}
                className="red2pr-control-input"
                value={branchAllowText}
                disabled={!canMutate || saveMutation.isPending}
                placeholder="main&#10;release/*"
                onChange={(ev) => setBranchAllowText(ev.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={branchDenyId}>
                Branch Denylist Globs (always overrides allow)
              </label>
              <textarea
                id={branchDenyId}
                rows={3}
                className="red2pr-control-input"
                value={branchDenyText}
                disabled={!canMutate || saveMutation.isPending}
                placeholder="production/*&#10;hotfix/*"
                onChange={(ev) => setBranchDenyText(ev.target.value)}
              />
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
              gap: 14,
            }}
          >
            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={fileAllowId}>
                File Path Allowlist Globs (empty = all non-denied paths)
              </label>
              <textarea
                id={fileAllowId}
                rows={3}
                className="red2pr-control-input"
                value={fileAllowText}
                disabled={!canMutate || saveMutation.isPending}
                placeholder="src/**&#10;packages/**"
                onChange={(ev) => setFileAllowText(ev.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={fileDenyId}>
                File Path Denylist Globs (merged with hard-denied .env/.git/*.pem)
              </label>
              <textarea
                id={fileDenyId}
                rows={3}
                className="red2pr-control-input"
                value={fileDenyText}
                disabled={!canMutate || saveMutation.isPending}
                placeholder="vendor/**&#10;legacy/**"
                onChange={(ev) => setFileDenyText(ev.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={sensitiveRulesId}>
                Sensitive Path Globs (always force human approval)
              </label>
              <textarea
                id={sensitiveRulesId}
                rows={3}
                className="red2pr-control-input"
                value={sensitiveRulesText}
                disabled={!canMutate || saveMutation.isPending}
                placeholder="src/auth/**&#10;billing/**"
                onChange={(ev) => setSensitiveRulesText(ev.target.value)}
              />
              <p className="red2pr-field-hint">
                Built-in protected paths (.github/workflows/**, .gitlab-ci.yml, lockfiles,
                migrations/**, Dockerfile) always require human approval even in auto_repair.
              </p>
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
              gap: 12,
            }}
          >
            <label
              htmlFor={allowTestsId}
              style={{ display: "inline-flex", alignItems: "center", gap: 8, fontWeight: 600 }}
            >
              <input
                id={allowTestsId}
                type="checkbox"
                checked={allowTestEdits}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setAllowTestEdits(ev.target.checked)}
              />
              <span>Allow test file edits (still forces human approval; step-up gated)</span>
            </label>

            <label
              htmlFor={allowConfigsId}
              style={{ display: "inline-flex", alignItems: "center", gap: 8, fontWeight: 600 }}
            >
              <input
                id={allowConfigsId}
                type="checkbox"
                checked={allowConfigEdits}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setAllowConfigEdits(ev.target.checked)}
              />
              <span>Allow build/config file edits (still forces human approval; step-up gated)</span>
            </label>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
              gap: 12,
            }}
          >
            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={maxAttemptsId}>
                Max Attempts ({layerLabel(fieldSources["max_attempts"])})
              </label>
              <input
                id={maxAttemptsId}
                type="number"
                min={1}
                max={5}
                className="red2pr-control-input"
                value={maxAttempts}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setMaxAttempts(Number.parseInt(ev.target.value || "1", 10))}
              />
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={maxDiffLinesId}>
                Max Diff Lines ({layerLabel(fieldSources["max_diff_lines"])})
              </label>
              <input
                id={maxDiffLinesId}
                type="number"
                min={1}
                max={2000}
                className="red2pr-control-input"
                value={maxDiffLines}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setMaxDiffLines(Number.parseInt(ev.target.value || "100", 10))}
              />
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={maxCallsId}>
                Max Calls / Session
              </label>
              <input
                id={maxCallsId}
                type="number"
                min={1}
                max={100}
                className="red2pr-control-input"
                value={maxCalls}
                placeholder={String(effective.max_calls_per_session)}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setMaxCalls(ev.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={maxTokensId}>
                Max Tokens / Session
              </label>
              <input
                id={maxTokensId}
                type="number"
                min={1}
                max={1000000}
                className="red2pr-control-input"
                value={maxTokens}
                placeholder={String(effective.max_tokens_per_session)}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setMaxTokens(ev.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={maxWallId}>
                Max Wall Seconds
              </label>
              <input
                id={maxWallId}
                type="number"
                min={60}
                max={7200}
                className="red2pr-control-input"
                value={maxWallSeconds}
                placeholder={String(effective.max_wall_seconds)}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setMaxWallSeconds(ev.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={maxCostAmountId}>
                Max Session Cost
              </label>
              <input
                id={maxCostAmountId}
                type="text"
                className="red2pr-control-input"
                value={maxCostAmount}
                placeholder={effective.max_cost_per_session.amount}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setMaxCostAmount(ev.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label className="red2pr-field-label" htmlFor={maxCostCurrencyId}>
                Currency
              </label>
              <input
                id={maxCostCurrencyId}
                type="text"
                maxLength={3}
                className="red2pr-control-input"
                value={maxCostCurrency}
                disabled={!canMutate || saveMutation.isPending}
                onChange={(ev) => setMaxCostCurrency(ev.target.value)}
              />
            </div>
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={reasonInputId}>
              Audit Change Reason
            </label>
            <input
              id={reasonInputId}
              type="text"
              className="red2pr-control-input"
              value={reason}
              disabled={!canMutate || saveMutation.isPending}
              placeholder="Document why repository guardrails or mode changed..."
              onChange={(ev) => setReason(ev.target.value)}
            />
          </div>

          {canMutate ? (
            <div className="red2pr-button-row">
              <Button
                label={t("policyEditor.saveAction")}
                variant="primary"
                type="submit"
                isLoading={saveMutation.isPending}
              />
            </div>
          ) : (
            <p className="red2pr-field-hint" data-testid="policy-readonly-notice">
              Read-only view: workspace admin or granted maintainer role is required to modify
              repository policy.
            </p>
          )}
        </form>
      </section>

      <section
        className="red2pr-surface red2pr-card-section"
        aria-label="Dry-Run Policy Simulator"
        data-testid="policy-dry-run-simulator"
      >
        <div className="red2pr-card-header">
          <div>
            <h3 style={{ margin: 0, fontSize: "1.05rem" }}>
              Dry-Run Policy Simulator (Zero DB Mutations)
            </h3>
            <p className="red2pr-field-hint" style={{ marginTop: 4 }}>
              Preview candidate branch/file/diff rules against historical CI failures and active
              in-flight task jobs before saving.
            </p>
          </div>
          <Button
            label={t("policyEditor.simulateAction")}
            variant="secondary"
            isLoading={previewMutation.isPending}
            onClick={() => previewMutation.mutate()}
          />
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: 14,
          }}
        >
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={sampleBranchesId}>
              Sample Branches to Test
            </label>
            <textarea
              id={sampleBranchesId}
              rows={3}
              className="red2pr-control-input"
              value={sampleBranchesText}
              onChange={(ev) => setSampleBranchesText(ev.target.value)}
            />
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={samplePathsId}>
              Sample Changed File Paths to Test
            </label>
            <textarea
              id={samplePathsId}
              rows={3}
              className="red2pr-control-input"
              value={samplePathsText}
              onChange={(ev) => setSamplePathsText(ev.target.value)}
            />
          </div>

          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={sampleDiffLinesId}>
              Sample Patch Diff Line Count
            </label>
            <input
              id={sampleDiffLinesId}
              type="number"
              min={0}
              max={100000}
              className="red2pr-control-input"
              value={sampleDiffLines}
              onChange={(ev) => setSampleDiffLines(ev.target.value)}
            />
          </div>
        </div>

        {previewResult ? (
          <div className="red2pr-form-stack" data-testid="policy-preview-results">
            <div
              className={`red2pr-inline-alert ${
                previewResult.can_apply ? "red2pr-tone-success" : "red2pr-tone-danger"
              }`}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}>
                <StatusGlyph kind={previewResult.can_apply ? "check" : "error"} />
                <span>
                  {previewResult.can_apply
                    ? `Candidate policy can be saved as v${String(previewResult.next_revision)}.`
                    : "Candidate policy is blocked by safety or ceiling guardrails."}
                </span>
                {previewResult.requires_step_up ? (
                  <span className="red2pr-badge-pill red2pr-tone-warning">
                    <StatusGlyph kind="lock" />
                    <span>5m Step-Up MFA Required</span>
                  </span>
                ) : null}
              </div>
            </div>

            {(previewResult.denials ?? []).length > 0 ? (
              <div>
                <h4 style={{ margin: "0 0 8px", fontSize: "0.95rem" }}>Policy Denials & Warnings</h4>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {(previewResult.denials ?? []).map((denial, idx) => (
                    <li key={idx}>
                      <strong>{sanitizeUntrustedText(denial.code).text}</strong> (
                      {layerLabel(denial.source_layer)}): {sanitizeUntrustedText(denial.detail).text}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {(previewResult.changed_rules ?? []).length > 0 ? (
              <div>
                <h4 style={{ margin: "0 0 8px", fontSize: "0.95rem" }}>Rule Changes vs Active Revision</h4>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {(previewResult.changed_rules ?? []).map((chg, idx) => (
                    <li key={idx}>
                      <code>{sanitizeUntrustedText(chg.field).text}</code>:{" "}
                      {sanitizeUntrustedText(chg.impact ?? "").text}
                      {chg.requires_step_up ? " (Requires 5m step-up)" : ""}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {(previewResult.branch_evaluations ?? []).length > 0 ? (
              <div>
                <h4 style={{ margin: "0 0 8px", fontSize: "0.95rem" }}>Sample Branch Verdicts</h4>
                <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
                  {(previewResult.branch_evaluations ?? []).map((be, idx) => {
                    const app = verdictAppearance(be.verdict);
                    return (
                      <li
                        key={idx}
                        style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}
                      >
                        <span className={`red2pr-badge-pill ${app.tone}`}>
                          <StatusGlyph kind={app.glyph} />
                          <span>{app.label}</span>
                        </span>
                        <code>{sanitizeUntrustedText(be.branch).text}</code>
                        <span className="red2pr-field-hint">
                          ({layerLabel(be.source_layer)} — {sanitizeUntrustedText(be.reason).text})
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ) : null}

            {(previewResult.path_evaluations ?? []).length > 0 ? (
              <div>
                <h4 style={{ margin: "0 0 8px", fontSize: "0.95rem" }}>Sample File Path Verdicts</h4>
                <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
                  {(previewResult.path_evaluations ?? []).map((pe, idx) => {
                    const app = verdictAppearance(pe.verdict);
                    return (
                      <li
                        key={idx}
                        style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}
                      >
                        <span className={`red2pr-badge-pill ${app.tone}`}>
                          <StatusGlyph kind={app.glyph} />
                          <span>{app.label}</span>
                        </span>
                        <code>{sanitizeUntrustedText(pe.raw_path).text}</code>
                        <span className="red2pr-field-hint">
                          [{pe.category} · {layerLabel(pe.source_layer)}]{" "}
                          {sanitizeUntrustedText(pe.reason).text}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ) : null}

            {(previewResult.historical_run_simulations ?? []).length > 0 ? (
              <div>
                <h4 style={{ margin: "0 0 8px", fontSize: "0.95rem" }}>
                  Historical CI Failure Run Simulation
                </h4>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {(previewResult.historical_run_simulations ?? []).map((sim) => (
                    <li key={sim.trigger_id}>
                      <code>{sanitizeUntrustedText(sim.attempt_key).text}</code> on{" "}
                      <code>{sanitizeUntrustedText(sim.ref).text}</code> →{" "}
                      <strong>{sim.disposition}</strong> ({sanitizeUntrustedText(sim.reason).text})
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {(previewResult.affected_in_flight ?? []).length > 0 ? (
              <div>
                <h4 style={{ margin: "0 0 8px", fontSize: "0.95rem" }}>
                  Active In-Flight Jobs (Pinned to Prior Revision)
                </h4>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {(previewResult.affected_in_flight ?? []).map((job) => (
                    <li key={job.job_id}>
                      <code>{sanitizeUntrustedText(job.kind).text}</code> ({job.state}, pinned v
                      {String(job.pinned_policy_revision)}):{" "}
                      {sanitizeUntrustedText(job.impact_summary).text}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        ) : null}
      </section>

      <section
        className="red2pr-surface red2pr-card-section"
        aria-label="Immutable Policy Revision History"
      >
        <h3 style={{ margin: 0, fontSize: "1.05rem" }}>Immutable Policy Revisions</h3>
        {(state.revisions ?? []).length === 0 ? (
          <p className="red2pr-field-hint">No policy revisions recorded.</p>
        ) : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 8 }}>
            {(state.revisions ?? []).map((rev) => (
              <li key={rev.id} className="red2pr-kv-item">
                <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
                  <span className="red2pr-badge-pill red2pr-tone-info">
                    <StatusGlyph kind="lock" />
                    <span>v{String(rev.revision)}</span>
                  </span>
                  <strong>Mode: {rev.mode}</strong>
                  <span>{rev.paused ? "· Paused" : "· Active"}</span>
                  <span className="red2pr-field-hint">
                    · {formatUtcTimestamp(rev.created_at)}
                  </span>
                </div>
                {rev.change_reason ? (
                  <p className="red2pr-field-hint" style={{ marginTop: 6 }}>
                    {sanitizeUntrustedText(rev.change_reason).text}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>

      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={Boolean(me.mfa_enabled)}
        onOpenChange={(nextOpen) => {
          setStepUpOpen(nextOpen);
          if (!nextOpen) {
            pendingSaveAfterStepUpRef.current = false;
          }
        }}
        onVerified={() => {
          void queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
          if (pendingSaveAfterStepUpRef.current) {
            pendingSaveAfterStepUpRef.current = false;
            saveMutation.mutate();
          }
        }}
      />
    </div>
  );
}
