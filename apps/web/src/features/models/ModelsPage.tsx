import {
  Red2PrApiError,
  type MeResponse,
  type MetaModelId,
  type ModelAvailabilityStatus,
  type ModelPricingRate,
  type ModelUsageRecord,
  type Workspace,
  type WorkspaceModelEntry,
  type WorkspaceModelsConfigUpdateRequest,
  type WorkspaceModelsResponse,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useRef, useState } from "react";
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
import { generateClientUuidV7 } from "../queues";

export interface ModelsPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";

interface ModelRow extends Record<string, unknown> {
  readonly id: MetaModelId;
  readonly display_name: string;
  readonly tier_role: WorkspaceModelEntry["tier_role"];
  readonly enabled: boolean;
  readonly status: ModelAvailabilityStatus;
  readonly status_detail: string | null;
  readonly capabilities_summary: string;
  readonly pricing: ModelPricingRate;
}

interface UsageRow extends Record<string, unknown> {
  readonly id: string;
  readonly model_id: string;
  readonly pricing_revision: string;
  readonly status: ModelUsageRecord["status"];
  readonly tokens_text: string;
  readonly estimated_text: string;
  readonly settled_text: string;
  readonly created_at: string;
}

interface PolicyDraft {
  readonly sparkRevision: string;
  readonly sparkInput: string;
  readonly sparkOutput: string;
  readonly sparkConfigured: boolean;
  readonly wonderRevision: string;
  readonly wonderInput: string;
  readonly wonderOutput: string;
  readonly wonderConfigured: boolean;
  readonly maxCalls: string;
  readonly maxTokens: string;
  readonly maxAttempts: string;
  readonly maxWallSeconds: string;
  readonly sessionCap: string;
  readonly dailyCap: string;
  readonly currency: string;
  readonly escalationEnabled: boolean;
  readonly escalateAfterAttempts: string;
}

type EditableDraftKey = Exclude<
  keyof PolicyDraft,
  "sparkConfigured" | "wonderConfigured" | "currency" | "escalationEnabled"
>;

const MODEL_BADGE: Record<
  ModelAvailabilityStatus,
  { readonly glyph: GlyphKind; readonly tone: string; readonly label: string }
> = {
  available: { glyph: "check", tone: "red2pr-tone-success", label: "Available" },
  degraded: { glyph: "warn", tone: "red2pr-tone-warning", label: "Degraded" },
  unavailable: { glyph: "error", tone: "red2pr-tone-danger", label: "Unavailable" },
  disabled: { glyph: "offline", tone: "red2pr-tone-neutral", label: "Disabled" },
  not_probed: { glyph: "clock", tone: "red2pr-tone-info", label: "Not Probed" },
};

const USAGE_BADGE: Record<
  ModelUsageRecord["status"],
  { readonly glyph: GlyphKind; readonly tone: string; readonly label: string }
> = {
  settled: { glyph: "check", tone: "red2pr-tone-success", label: "Settled" },
  reserved: { glyph: "clock", tone: "red2pr-tone-info", label: "Reserved" },
  unknown: { glyph: "warn", tone: "red2pr-tone-warning", label: "Unknown Outcome" },
  released: { glyph: "info", tone: "red2pr-tone-neutral", label: "Released" },
  failed: { glyph: "error", tone: "red2pr-tone-danger", label: "Failed" },
};

const POLICY_FIELD_SPECS: readonly {
  readonly key: EditableDraftKey;
  readonly label: string;
  readonly type?: "text" | "number";
  readonly min?: number;
  readonly max?: number;
  readonly marksModel?: "spark" | "wonder";
}[] = [
  { key: "sparkRevision", label: "muse-spark-1.3 pricing revision", marksModel: "spark" },
  { key: "sparkInput", label: "Spark input / 1M tokens", marksModel: "spark" },
  { key: "sparkOutput", label: "Spark output / 1M tokens", marksModel: "spark" },
  { key: "wonderRevision", label: "muse-wonder-1.0 pricing revision", marksModel: "wonder" },
  { key: "wonderInput", label: "Wonder input / 1M tokens", marksModel: "wonder" },
  { key: "wonderOutput", label: "Wonder output / 1M tokens", marksModel: "wonder" },
  { key: "maxCalls", label: "Max calls / session (NFR-06)", type: "number", min: 1, max: 500 },
  { key: "maxTokens", label: "Max tokens / session", type: "number", min: 256, max: 2000000 },
  { key: "maxAttempts", label: "Max patch attempts", type: "number", min: 1, max: 10 },
  { key: "maxWallSeconds", label: "Max walltime (seconds)", type: "number", min: 60, max: 14400 },
  { key: "sessionCap", label: "Session cost cap" },
  { key: "dailyCap", label: "Daily workspace cap" },
];

function buildConfigPatch(
  partial: Partial<WorkspaceModelsConfigUpdateRequest>,
): WorkspaceModelsConfigUpdateRequest {
  return {
    clear_endpoint_registration: false,
    clear_inference_consent: false,
    clear_suspension: false,
    revoke_api_key: false,
    ...partial,
  };
}

function formatMoney(amount: string | number, currency: string): string {
  return `${currency} ${String(amount)}`;
}

function isStaleConflictError(err: unknown): boolean {
  return (
    err instanceof Red2PrApiError &&
    (err.status === 412 ||
      err.problem.code === "version_conflict" ||
      err.problem.code === "version_precondition_failed")
  );
}

function buildPolicyDraft(state: WorkspaceModelsResponse): PolicyDraft {
  const spark = state.models.find((m) => m.model_id === "muse-spark-1.3")?.pricing;
  const wonder = state.models.find((m) => m.model_id === "muse-wonder-1.0")?.pricing;
  const bp = state.budget_policy;
  return {
    sparkRevision: spark?.pricing_revision ?? "rev-1",
    sparkInput: String(spark?.input_per_1m_tokens.amount ?? "0.000000"),
    sparkOutput: String(spark?.output_per_1m_tokens.amount ?? "0.000000"),
    sparkConfigured: Boolean(spark?.configured),
    wonderRevision: wonder?.pricing_revision ?? "rev-1",
    wonderInput: String(wonder?.input_per_1m_tokens.amount ?? "0.000000"),
    wonderOutput: String(wonder?.output_per_1m_tokens.amount ?? "0.000000"),
    wonderConfigured: Boolean(wonder?.configured),
    maxCalls: String(bp.max_calls_per_session ?? 30),
    maxTokens: String(bp.max_tokens_per_session ?? 120000),
    maxAttempts: String(bp.max_patch_attempts ?? 2),
    maxWallSeconds: String(bp.max_wall_seconds ?? 1800),
    sessionCap: String(bp.max_cost_per_session.amount),
    dailyCap: String(bp.daily_workspace_cap.amount),
    currency: bp.daily_workspace_cap.currency,
    escalationEnabled: Boolean(state.escalation_policy.escalation_enabled),
    escalateAfterAttempts: String(state.escalation_policy.escalate_after_failed_attempts ?? 1),
  };
}

function LabeledField({
  label,
  value,
  onChange,
  type = "text",
  disabled = false,
  min,
  max,
  placeholder,
  autoComplete,
  required,
}: {
  readonly label: string;
  readonly value: string;
  readonly onChange: (next: string) => void;
  readonly type?: "text" | "number" | "password" | "url";
  readonly disabled?: boolean;
  readonly min?: number;
  readonly max?: number;
  readonly placeholder?: string;
  readonly autoComplete?: string;
  readonly required?: boolean;
}): React.JSX.Element {
  const inputId = useId();
  return (
    <div className="red2pr-field">
      <label htmlFor={inputId} className="red2pr-field-label">
        {label}
      </label>
      <input
        id={inputId}
        className="red2pr-control-input"
        type={type}
        value={value}
        disabled={disabled}
        min={min}
        max={max}
        placeholder={placeholder}
        autoComplete={autoComplete}
        required={required}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

export function ModelsPage({ workspace, me }: ModelsPageProps): React.JSX.Element {
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

  const consentSelectId = useId();
  const probeConsentId = useId();
  const probeFormId = useId();
  const escalationToggleId = useId();

  const [apiKeyInput, setApiKeyInput] = useState("");
  const [endpointOverride, setEndpointOverride] = useState<{
    readonly version: number;
    readonly value: string;
  } | null>(null);
  const [policyOverride, setPolicyOverride] = useState<{
    readonly version: number;
    readonly draft: PolicyDraft;
  } | null>(null);
  const [staleConflict, setStaleConflict] = useState(false);
  const [errorSummary, setErrorSummary] = useState<AuthProblemSummary | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [probeTarget, setProbeTarget] = useState<MetaModelId | null>(null);
  const [probeMaxCost, setProbeMaxCost] = useState("0.050000");
  const [probeConsentSelection, setProbeConsentSelection] = useState("");

  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingStepUpRetryRef = useRef<(() => void) | null>(null);

  const modelsQuery = useQuery({
    queryKey: ["workspace", wsSlug, "models"],
    queryFn: () => api.listWorkspaceModels(wsSlug),
  });

  const modelsState = modelsQuery.data?.data ?? null;
  const authoritativeEtag =
    modelsQuery.data?.etag ?? (modelsState !== null ? `"v${modelsState.version}"` : undefined);

  const endpointInput =
    modelsState === null
      ? ""
      : endpointOverride !== null && endpointOverride.version === modelsState.version
        ? endpointOverride.value
        : modelsState.endpoint_base_url;

  const policyDraft = useMemo<PolicyDraft | null>(() => {
    if (modelsState === null) {
      return null;
    }
    if (policyOverride !== null && policyOverride.version === modelsState.version) {
      return policyOverride.draft;
    }
    return buildPolicyDraft(modelsState);
  }, [modelsState, policyOverride]);

  const updateEndpointInput = useCallback(
    (nextValue: string) => {
      if (modelsState === null) {
        return;
      }
      setEndpointOverride({ version: modelsState.version, value: nextValue });
    },
    [modelsState],
  );

  const updatePolicyDraft = useCallback(
    (nextDraft: PolicyDraft) => {
      if (modelsState === null) {
        return;
      }
      setPolicyOverride({ version: modelsState.version, draft: nextDraft });
    },
    [modelsState],
  );

  const refreshWorkspaceModels = useCallback(async () => {
    setStaleConflict(false);
    await invalidateWorkspaceQueries(queryClient, wsSlug);
    await modelsQuery.refetch();
  }, [modelsQuery, queryClient, wsSlug]);

  const handleMutationError = useCallback(
    (err: unknown, retryCallback: () => void) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        pendingStepUpRetryRef.current = retryCallback;
        setStepUpOpen(true);
        return;
      }
      if (isStaleConflictError(err)) {
        setStaleConflict(true);
      }
      setErrorSummary(extractAuthProblemSummary(err, t("state.error.description")));
    },
    [t],
  );

  const actionMutation = useMutation({
    mutationFn: async (fn: () => Promise<void>) => fn(),
  });

  const runProtectedAction = useCallback(
    (operation: () => Promise<string>) => {
      const execute = async () => {
        setErrorSummary(null);
        setNotice(null);
        try {
          const msg = await operation();
          setStaleConflict(false);
          setNotice(msg);
          announce(msg);
          await refreshWorkspaceModels();
        } catch (err) {
          handleMutationError(err, () => {
            actionMutation.mutate(execute);
          });
        }
      };
      actionMutation.mutate(execute);
    },
    [actionMutation, announce, handleMutationError, refreshWorkspaceModels],
  );

  const runConfigPatch = useCallback(
    (partial: Partial<WorkspaceModelsConfigUpdateRequest>, msg: string) => {
      const idempotencyKey = generateClientUuidV7();
      const ifMatch = authoritativeEtag;
      const payload = buildConfigPatch(partial);
      runProtectedAction(async () => {
        await api.updateWorkspaceModelsConfig(wsSlug, payload, { idempotencyKey, ifMatch });
        return msg;
      });
    },
    [api, authoritativeEtag, runProtectedAction, wsSlug],
  );

  const handleRotateApiKey = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!isAdmin || modelsState === null) {
        return;
      }
      const trimmedKey = apiKeyInput.trim();
      const trimmedEndpoint = endpointInput.trim();
      setApiKeyInput("");
      runConfigPatch(
        {
          expected_version: modelsState.version,
          ...(trimmedKey.length > 0 ? { api_key: trimmedKey } : {}),
          ...(trimmedEndpoint.length > 0 && trimmedEndpoint !== modelsState.endpoint_base_url
            ? { endpoint_base_url: trimmedEndpoint }
            : {}),
        },
        "Meta API credential updated.",
      );
    },
    [apiKeyInput, endpointInput, isAdmin, modelsState, runConfigPatch],
  );

  const handleGrantConsent = useCallback(() => {
    if (!isAdmin || modelsState === null) {
      return;
    }
    const idempotencyKey = generateClientUuidV7();
    const destination = modelsState.endpoint_base_url;
    runProtectedAction(async () => {
      await api.grantWorkspaceInferenceConsent(
        wsSlug,
        { destination, data_classes: ["public", "workspace_internal"], policy_version: 1 },
        { idempotencyKey },
      );
      return "Workspace outbound inference consent granted.";
    });
  }, [api, isAdmin, modelsState, runProtectedAction, wsSlug]);

  const handleSavePolicy = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!isAdmin || modelsState === null || policyDraft === null) {
        return;
      }
      const currency = policyDraft.currency;
      const pricingUpdates: Record<string, ModelPricingRate> = {};
      if (
        policyDraft.sparkConfigured ||
        policyDraft.sparkRevision.trim().toLowerCase() !== "unconfigured"
      ) {
        pricingUpdates["muse-spark-1.3"] = {
          pricing_revision: policyDraft.sparkRevision.trim(),
          input_per_1m_tokens: { amount: policyDraft.sparkInput.trim(), currency },
          output_per_1m_tokens: { amount: policyDraft.sparkOutput.trim(), currency },
          configured: true,
        };
      }
      if (
        policyDraft.wonderConfigured ||
        policyDraft.wonderRevision.trim().toLowerCase() !== "unconfigured"
      ) {
        pricingUpdates["muse-wonder-1.0"] = {
          pricing_revision: policyDraft.wonderRevision.trim(),
          input_per_1m_tokens: { amount: policyDraft.wonderInput.trim(), currency },
          output_per_1m_tokens: { amount: policyDraft.wonderOutput.trim(), currency },
          configured: true,
        };
      }
      runConfigPatch(
        {
          expected_version: modelsState.version,
          ...(Object.keys(pricingUpdates).length > 0 ? { pricing_updates: pricingUpdates } : {}),
          budget_policy: {
            max_calls_per_session: Number.parseInt(policyDraft.maxCalls, 10),
            max_tokens_per_session: Number.parseInt(policyDraft.maxTokens, 10),
            max_patch_attempts: Number.parseInt(policyDraft.maxAttempts, 10),
            max_wall_seconds: Number.parseInt(policyDraft.maxWallSeconds, 10),
            max_cost_per_session: { amount: policyDraft.sessionCap.trim(), currency },
            daily_workspace_cap: { amount: policyDraft.dailyCap.trim(), currency },
            alert_threshold_percent: modelsState.budget_policy.alert_threshold_percent ?? 80,
          },
          escalation_policy: {
            escalation_enabled: policyDraft.escalationEnabled,
            escalation_model_id: "muse-wonder-1.0",
            escalate_after_failed_attempts: Number.parseInt(policyDraft.escalateAfterAttempts, 10),
            require_probed_availability: true,
            allow_non_meta_fallback: false,
          },
        },
        "Pricing, NFR-06 budgets, and escalation policy saved.",
      );
    },
    [isAdmin, modelsState, policyDraft, runConfigPatch],
  );

  const handleSubmitProbe = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!isAdmin || modelsState === null || probeTarget === null || !probeConsentSelection) {
        return;
      }
      const idempotencyKey = generateClientUuidV7();
      const currency = modelsState.budget_policy.daily_workspace_cap.currency;
      const targetModel = probeTarget;
      const maxCostAmount = probeMaxCost.trim();
      const consentId = probeConsentSelection;
      runProtectedAction(async () => {
        const res = await api.createWorkspaceModelProbe(
          wsSlug,
          {
            model_id: targetModel,
            max_cost: { amount: maxCostAmount, currency },
            consent_id: consentId,
            max_output_tokens: 64,
          },
          { idempotencyKey },
        );
        setProbeTarget(null);
        return `Capability probe recorded for ${targetModel}: ${res.data.snapshot.status}.`;
      });
    },
    [api, isAdmin, modelsState, probeConsentSelection, probeMaxCost, probeTarget, runProtectedAction, wsSlug],
  );

  const modelRows = useMemo<ModelRow[]>(() => {
    if (modelsState === null) {
      return [];
    }
    return modelsState.models.map((entry) => {
      const caps = entry.latest_snapshot?.capabilities;
      return {
        id: entry.model_id,
        display_name: sanitizeUntrustedText(entry.display_name).text,
        tier_role: entry.tier_role,
        enabled: entry.enabled,
        status: entry.status,
        status_detail: entry.latest_snapshot?.status_detail
          ? sanitizeUntrustedText(entry.latest_snapshot.status_detail).text
          : null,
        capabilities_summary: caps
          ? [
              `tools:${caps.tool_calls ?? "unknown"}`,
              `schema:${caps.structured_output ?? "unknown"}`,
              caps.context_window_tokens != null
                ? `ctx:${String(caps.context_window_tokens)}`
                : null,
            ]
              .filter(Boolean)
              .join(" · ")
          : "No probe snapshot yet",
        pricing: entry.pricing,
      };
    });
  }, [modelsState]);

  const usageRows = useMemo<UsageRow[]>(() => {
    if (modelsState === null) {
      return [];
    }
    return (modelsState.recent_usage ?? []).map((rec) => {
      const estimatedText = formatMoney(rec.estimated_cost.amount, rec.currency);
      return {
        id: rec.id,
        model_id: sanitizeUntrustedText(rec.model_id).text,
        pricing_revision: sanitizeUntrustedText(rec.pricing_revision).text,
        status: rec.status,
        tokens_text:
          rec.input_tokens != null && rec.output_tokens != null
            ? `${String(rec.input_tokens)} in / ${String(rec.output_tokens)} out`
            : "Unconfirmed (—)",
        estimated_text: estimatedText,
        settled_text:
          rec.status === "unknown"
            ? `Unconfirmed (hold ${estimatedText})`
            : rec.settled_cost != null
              ? formatMoney(rec.settled_cost.amount, rec.currency)
              : "—",
        created_at: formatUtcTimestamp(rec.created_at),
      };
    });
  }, [modelsState]);

  const modelColumns = useMemo<TableColumn<ModelRow>[]>(
    () => [
      {
        key: "id",
        header: "Model & Role",
        renderCell: (row) => (
          <div>
            <div>
              <strong>{row.display_name}</strong> <code>({row.id})</code>
            </div>
            <span className="red2pr-field-hint">
              Role: {row.tier_role} · {row.enabled ? "Enabled" : "Inactive"}
            </span>
          </div>
        ),
      },
      {
        key: "status",
        header: "Availability",
        renderCell: (row) => {
          const badge = MODEL_BADGE[row.status];
          return (
            <div>
              <span className={`red2pr-badge-pill ${badge.tone}`}>
                <StatusGlyph kind={badge.glyph} />
                <span>{badge.label}</span>
              </span>
              {row.status_detail !== null ? (
                <div className="red2pr-field-hint">{row.status_detail}</div>
              ) : null}
            </div>
          );
        },
      },
      {
        key: "capabilities_summary",
        header: "Capabilities",
        renderCell: (row) => <span>{row.capabilities_summary}</span>,
      },
      {
        key: "pricing",
        header: "Upper-Bound Pricing (/1M)",
        renderCell: (row) =>
          row.pricing.configured ? (
            <span>
              {row.pricing.pricing_revision}: {row.pricing.input_per_1m_tokens.currency}{" "}
              {String(row.pricing.input_per_1m_tokens.amount)} in /{" "}
              {String(row.pricing.output_per_1m_tokens.amount)} out
            </span>
          ) : (
            <span className="red2pr-badge-pill red2pr-tone-warning">
              <StatusGlyph kind="warn" />
              <span>Unconfigured (blocked)</span>
            </span>
          ),
      },
      {
        key: "actions",
        header: "Probe",
        renderCell: (row) => (
          <Button
            label={`Probe ${row.id}`}
            variant="secondary"
            size="sm"
            isDisabled={
              !isAdmin ||
              !modelsState?.api_key_presence.configured ||
              !modelsState?.inference_consent_active ||
              !row.pricing.configured
            }
            onClick={() => {
              const consents = modelsState?.available_inference_consents ?? [];
              setProbeConsentSelection(
                modelsState?.active_inference_consent_id ?? consents[0]?.id ?? "",
              );
              setProbeMaxCost("0.050000");
              setProbeTarget(row.id);
            }}
          />
        ),
      },
    ],
    [isAdmin, modelsState],
  );

  const usageColumns = useMemo<TableColumn<UsageRow>[]>(
    () => [
      {
        key: "model_id",
        header: "Model & Revision",
        renderCell: (row) => (
          <span>
            <code>{row.model_id}</code> ({row.pricing_revision})
          </span>
        ),
      },
      {
        key: "status",
        header: "Status",
        renderCell: (row) => {
          const badge = USAGE_BADGE[row.status];
          return (
            <span className={`red2pr-badge-pill ${badge.tone}`}>
              <StatusGlyph kind={badge.glyph} />
              <span>{badge.label}</span>
            </span>
          );
        },
      },
      { key: "tokens_text", header: "Tokens", renderCell: (row) => <span>{row.tokens_text}</span> },
      {
        key: "estimated_text",
        header: "Reserved Max",
        renderCell: (row) => <code>{row.estimated_text}</code>,
      },
      {
        key: "settled_text",
        header: "Settled Cost",
        renderCell: (row) => <code>{row.settled_text}</code>,
      },
      { key: "created_at", header: "UTC", renderCell: (row) => <span>{row.created_at}</span> },
    ],
    [],
  );

  if (modelsQuery.isPending) {
    return <StateView state="loading" />;
  }

  if (modelsQuery.isError || modelsState === null || policyDraft === null) {
    const summary = extractAuthProblemSummary(modelsQuery.error, t("state.error.description"));
    return (
      <StateView
        state={summary.status === 403 ? "forbidden" : summary.status === null ? "offline" : "error"}
        description={summary.detail}
        correlationId={summary.correlationId ?? undefined}
        primaryAction={{
          label: "Reload latest state",
          onClick: () => {
            void modelsQuery.refetch();
          },
        }}
      />
    );
  }

  const availableConsents = modelsState.available_inference_consents ?? [];
  const wonderVerified =
    modelsState.models.find((m) => m.model_id === "muse-wonder-1.0")?.status === "available";
  const wb = modelsState.workspace_budget;
  const budgetSummaryItems: readonly [string, string][] = [
    ["Daily Workspace Cap", formatMoney(wb.cost_cap.amount, wb.currency)],
    ["Settled Today", formatMoney(wb.settled_cost.amount, wb.currency)],
    ["Active Reservations", formatMoney(wb.reserved_cost.amount, wb.currency)],
    ["Unconfirmed Timeout Holds", formatMoney(wb.unknown_cost.amount, wb.currency)],
    ["Remaining Daily Headroom", formatMoney(wb.remaining_cost.amount, wb.currency)],
  ];

  return (
    <div className="red2pr-page-stack" data-testid="models-page">
      <div className="red2pr-card-header">
        <div>
          <h1 style={{ margin: 0, fontSize: "1.5rem" }}>
            Meta Muse Models, Consents &amp; Budgets
          </h1>
          <p className="red2pr-field-hint">
            Z2 Meta broker (muse-spark-1.3 primary, optional muse-wonder-1.0 escalation) and
            row-locked NFR-06 Decimal budgets.
          </p>
        </div>
        <span
          className={`red2pr-badge-pill ${
            modelsState.ready_for_repair_inference ? "red2pr-tone-success" : "red2pr-tone-warning"
          }`}
          data-testid="models-readiness-badge"
        >
          <StatusGlyph kind={modelsState.ready_for_repair_inference ? "check" : "warn"} />
          <span>
            {modelsState.ready_for_repair_inference
              ? "Repair Inference Ready"
              : "Repair Inference Blocked"}
          </span>
        </span>
      </div>

      <div className="red2pr-inline-alert red2pr-tone-info" role="note">
        <span>
          Meta Muse is a cloud dependency; repair pauses when unavailable (never offline).
        </span>
      </div>

      {!isAdmin ? (
        <div
          className="red2pr-inline-alert red2pr-tone-neutral"
          data-testid="models-readonly-banner"
        >
          <span>Read-only view: workspace admin required to modify models or budgets.</span>
        </div>
      ) : null}

      {modelsState.suspension_reason != null ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-warning"
          data-testid="models-suspension-banner"
        >
          <div>
            <strong>Inference Paused / Degraded ({modelsState.suspension_reason}):</strong>{" "}
            {modelsState.status_detail
              ? sanitizeUntrustedText(modelsState.status_detail).text
              : "Provider availability or quota check suspended automated repair calls."}
            {modelsState.retry_after_seconds != null ? (
              <span> Retry cooldown: {String(modelsState.retry_after_seconds)}s.</span>
            ) : null}
          </div>
          {isAdmin ? (
            <div className="red2pr-button-row">
              <Button
                label="Clear suspension state"
                variant="secondary"
                size="sm"
                isDisabled={actionMutation.isPending}
                onClick={() =>
                  runConfigPatch(
                    { expected_version: modelsState.version, clear_suspension: true },
                    "Workspace inference suspension cleared.",
                  )
                }
              />
            </div>
          ) : null}
        </div>
      ) : null}

      {staleConflict ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-warning"
          data-testid="models-stale-conflict-banner"
        >
          <span>
            Model configuration changed concurrently (HTTP 409/412). Reload the latest snapshot
            before saving.
          </span>
          <div className="red2pr-button-row">
            <Button
              label="Reload latest state"
              variant="secondary"
              size="sm"
              onClick={() => {
                void refreshWorkspaceModels();
              }}
            />
          </div>
        </div>
      ) : null}

      {errorSummary !== null ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-danger"
          data-testid="models-error-banner"
        >
          <span>{errorSummary.detail}</span>
        </div>
      ) : null}

      {notice !== null ? (
        <div role="status" className="red2pr-inline-alert red2pr-tone-success">
          <span>{notice}</span>
        </div>
      ) : null}

      <section className="red2pr-surface red2pr-card-section" aria-label="Meta API Credential">
        <div className="red2pr-card-header">
          <h2 style={{ margin: 0, fontSize: "1.125rem" }}>
            Z2 Meta Model API Credential &amp; Endpoint
          </h2>
          <span
            className={`red2pr-badge-pill ${
              modelsState.api_key_presence.configured
                ? "red2pr-tone-success"
                : "red2pr-tone-neutral"
            }`}
            data-testid="meta-key-presence-badge"
          >
            <StatusGlyph kind={modelsState.api_key_presence.configured ? "lock" : "warn"} />
            <span>
              {modelsState.api_key_presence.configured
                ? `Configured (v${String(modelsState.api_key_presence.secret_version ?? 1)})`
                : "Not Configured"}
            </span>
          </span>
        </div>

        <form className="red2pr-form-stack" onSubmit={handleRotateApiKey}>
          <LabeledField
            label="Allowlisted Meta Model API endpoint base URL"
            type="url"
            value={endpointInput}
            disabled={!isAdmin || actionMutation.isPending}
            onChange={updateEndpointInput}
          />
          <LabeledField
            label="Write-only Meta API key (masked after save)"
            type="password"
            autoComplete="off"
            placeholder="Paste Meta Model API key to configure or rotate..."
            value={apiKeyInput}
            disabled={!isAdmin || actionMutation.isPending}
            onChange={setApiKeyInput}
          />
          <div className="red2pr-button-row">
            <Button
              label="Save / Rotate API Key"
              variant="primary"
              type="submit"
              isLoading={actionMutation.isPending}
              isDisabled={
                !isAdmin ||
                (apiKeyInput.trim().length < 12 &&
                  endpointInput.trim() === modelsState.endpoint_base_url)
              }
            />
            {modelsState.api_key_presence.configured ? (
              <Button
                label="Revoke API Key"
                variant="destructive"
                isDisabled={!isAdmin || actionMutation.isPending}
                onClick={() => {
                  setApiKeyInput("");
                  runConfigPatch(
                    { expected_version: modelsState.version, revoke_api_key: true },
                    "Meta API credential revoked.",
                  );
                }}
              />
            ) : null}
          </div>
        </form>
      </section>

      <section
        className="red2pr-surface red2pr-card-section"
        aria-label="Outbound Inference Consent"
      >
        <div className="red2pr-card-header">
          <h2 style={{ margin: 0, fontSize: "1.125rem" }}>
            Outbound Inference Consent (SEC-018)
          </h2>
          <span
            className={`red2pr-badge-pill ${
              modelsState.inference_consent_active ? "red2pr-tone-success" : "red2pr-tone-danger"
            }`}
            data-testid="inference-consent-badge"
          >
            <StatusGlyph kind={modelsState.inference_consent_active ? "check" : "lock"} />
            <span>
              {modelsState.inference_consent_active ? "Consent Active" : "Consent Required"}
            </span>
          </span>
        </div>

        <div className="red2pr-field">
          <label htmlFor={consentSelectId} className="red2pr-field-label">
            Active inference consent record ({modelsState.endpoint_base_url})
          </label>
          <select
            id={consentSelectId}
            className="red2pr-control-select"
            disabled={!isAdmin || availableConsents.length === 0 || actionMutation.isPending}
            value={modelsState.active_inference_consent_id ?? ""}
            onChange={(event) => {
              const selected = event.target.value;
              runConfigPatch(
                selected
                  ? {
                      expected_version: modelsState.version,
                      active_inference_consent_id: selected,
                    }
                  : { expected_version: modelsState.version, clear_inference_consent: true },
                "Active inference consent updated.",
              );
            }}
          >
            <option value="">None selected</option>
            {availableConsents.map((consent) => (
              <option key={consent.id} value={consent.id}>
                {consent.id} · {consent.destination} ({consent.data_classes.join(", ")})
              </option>
            ))}
          </select>
        </div>

        <div className="red2pr-button-row">
          <Button
            label="Grant workspace inference consent"
            variant="secondary"
            isDisabled={!isAdmin || actionMutation.isPending}
            onClick={handleGrantConsent}
          />
          {modelsState.active_inference_consent_id != null ? (
            <Button
              label="Revoke active consent"
              variant="destructive"
              isDisabled={!isAdmin || actionMutation.isPending}
              onClick={() => {
                const targetId = modelsState.active_inference_consent_id;
                if (!targetId) {
                  return;
                }
                runProtectedAction(async () => {
                  await api.revokeWorkspaceInferenceConsent(wsSlug, targetId, {
                    reason: "Revoked from workspace Models & Budgets screen",
                  });
                  return "Workspace outbound inference consent revoked.";
                });
              }}
            />
          ) : null}
        </div>
      </section>

      <section className="red2pr-surface red2pr-card-section" aria-label="Meta Muse Model Registry">
        <h2 style={{ margin: 0, fontSize: "1.125rem" }}>
          Allowlisted Meta Muse Registry &amp; Capability Probes
        </h2>
        <Table
          aria-label="Allowlisted Meta Muse model registry"
          columns={modelColumns}
          data={modelRows}
        />
      </section>

      <section
        className="red2pr-surface red2pr-card-section"
        aria-label="Pricing, Atomic Budgets and Escalation Policy"
      >
        <h2 style={{ margin: 0, fontSize: "1.125rem" }}>
          Upper-Bound Token Pricing, NFR-06 Atomic Budgets &amp; Escalation
        </h2>

        <dl className="red2pr-kv-grid" data-testid="workspace-budget-summary">
          {budgetSummaryItems.map(([term, detail]) => (
            <div key={term} className="red2pr-kv-item">
              <dt className="red2pr-kv-term">{term}</dt>
              <dd className="red2pr-kv-detail">{detail}</dd>
            </div>
          ))}
        </dl>

        <form className="red2pr-form-stack" onSubmit={handleSavePolicy}>
          <div className="red2pr-kv-grid">
            {POLICY_FIELD_SPECS.map((spec) => (
              <LabeledField
                key={spec.key}
                label={spec.label}
                type={spec.type}
                min={spec.min}
                max={spec.max}
                disabled={!isAdmin}
                value={policyDraft[spec.key]}
                onChange={(v) =>
                  updatePolicyDraft({
                    ...policyDraft,
                    [spec.key]: v,
                    ...(spec.marksModel === "spark" ? { sparkConfigured: true } : {}),
                    ...(spec.marksModel === "wonder" ? { wonderConfigured: true } : {}),
                  })
                }
              />
            ))}
          </div>

          <div className="red2pr-field">
            <label htmlFor={escalationToggleId} className="red2pr-field-label">
              <input
                id={escalationToggleId}
                type="checkbox"
                checked={policyDraft.escalationEnabled}
                disabled={!isAdmin || (!wonderVerified && !policyDraft.escalationEnabled)}
                onChange={(e) =>
                  updatePolicyDraft({ ...policyDraft, escalationEnabled: e.target.checked })
                }
              />{" "}
              Enable optional escalation to muse-wonder-1.0 after failed Spark attempts
            </label>
            <p className="red2pr-field-hint">
              {wonderVerified
                ? "muse-wonder-1.0 capability probe is verified available; no non-Meta fallback is ever permitted."
                : "Escalation stays disabled until a consented capability probe verifies muse-wonder-1.0 availability."}
            </p>
          </div>

          <LabeledField
            label="Escalate after failed Spark attempts"
            type="number"
            min={1}
            max={5}
            disabled={!isAdmin}
            value={policyDraft.escalateAfterAttempts}
            onChange={(v) => updatePolicyDraft({ ...policyDraft, escalateAfterAttempts: v })}
          />

          <div className="red2pr-button-row">
            <Button
              label="Save pricing & budget policy"
              variant="primary"
              type="submit"
              isLoading={actionMutation.isPending}
              isDisabled={!isAdmin}
            />
          </div>
        </form>
      </section>

      <section className="red2pr-surface red2pr-card-section" aria-label="Model Usage Ledger">
        <h2 style={{ margin: 0, fontSize: "1.125rem" }}>Recent Model Usage Ledger (S-17)</h2>
        {usageRows.length === 0 ? (
          <StateView
            state="empty"
            title="No Meta inference calls recorded yet"
            description="Consented capability probes and autonomous repair inference reservations appear here with exact Decimal accounting."
          />
        ) : (
          <Table
            aria-label="Recent workspace model usage ledger"
            columns={usageColumns}
            data={usageRows}
          />
        )}
      </section>

      <Dialog
        isOpen={probeTarget !== null}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) {
            setProbeTarget(null);
          }
        }}
        purpose="form"
        title={`Confirm paid capability probe (${probeTarget ?? ""})`}
        subtitle="Executes a minimal Meta Model API completion bounded by max_cost and active inference consent."
        data-testid="model-probe-dialog"
        footer={
          <div className="red2pr-button-row">
            <Button
              label="Cancel"
              variant="secondary"
              isDisabled={actionMutation.isPending}
              onClick={() => setProbeTarget(null)}
            />
            <Button
              label="Confirm paid capability probe"
              variant="primary"
              type="submit"
              form={probeFormId}
              isLoading={actionMutation.isPending}
              isDisabled={!probeConsentSelection || probeMaxCost.trim().length === 0}
            />
          </div>
        }
      >
        <form id={probeFormId} className="red2pr-form-stack" onSubmit={handleSubmitProbe}>
          <LabeledField
            label={`Explicit max_cost ceiling (${policyDraft.currency})`}
            required
            value={probeMaxCost}
            onChange={setProbeMaxCost}
          />
          <div className="red2pr-field">
            <label htmlFor={probeConsentId} className="red2pr-field-label">
              Active inference consent_id
            </label>
            <select
              id={probeConsentId}
              className="red2pr-control-select"
              required
              value={probeConsentSelection}
              onChange={(event) => setProbeConsentSelection(event.target.value)}
            >
              {availableConsents.map((consent) => (
                <option key={consent.id} value={consent.id}>
                  {consent.id} ({consent.destination})
                </option>
              ))}
            </select>
          </div>
        </form>
      </Dialog>

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
