import {
  Red2PrApiError,
  type ConsentDataClass,
  type ConsentPurpose,
  type EgressAdapterKind,
  type EndpointScheme,
  type SetupReadiness,
  type SetupState,
  type SetupStepStatus,
  type SetupStepSubmitRequest,
  type SetupWizardPhase,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useId, useMemo, useRef, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import {
  StepUpDialog,
  extractAuthProblemSummary,
  isStepUpValid,
  type AuthProblemSummary,
} from "../auth";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  AppShell,
  Button,
  StateView,
  StatusGlyph,
  sanitizeUntrustedText,
  useLiveAnnouncer,
  type WorkspaceNavOption,
} from "../../shared/ui";

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";

const ORDERED_PHASES: readonly SetupWizardPhase[] = [
  "owner_claim",
  "topology_tls",
  "storage_keys",
  "workspace_admin",
  "provider_connect",
  "model_consent",
  "worker_readiness",
  "repo_policy",
  "notifications",
  "readiness_review",
];

const PHASE_LABELS: Record<SetupWizardPhase, string> = {
  owner_claim: "1. Owner Claim",
  topology_tls: "2. Topology & TLS",
  storage_keys: "3. Storage & Keys",
  workspace_admin: "4. Initial Workspace",
  provider_connect: "5. Git Provider",
  model_consent: "6. Model & Consent",
  worker_readiness: "7. Sandbox Worker",
  repo_policy: "8. Repo Guardrails",
  notifications: "9. Notifications",
  readiness_review: "10. Readiness Review",
};

const STEP_STATUS_LABELS: Record<SetupStepStatus, string> = {
  pending: "Pending",
  completed: "Completed",
  not_configured: "Not Configured",
  degraded: "Degraded",
  blocked: "Blocked",
};

function stepStatusGlyph(status: SetupStepStatus): GlyphKind {
  switch (status) {
    case "completed":
      return "check";
    case "not_configured":
      return "info";
    case "degraded":
      return "warn";
    case "blocked":
      return "error";
    case "pending":
      return "clock";
  }
}

function prereqGlyph(status: string): GlyphKind {
  if (status === "passed") {
    return "check";
  }
  if (status === "not_configured") {
    return "info";
  }
  if (status === "needs_admin" || status === "needs_restart") {
    return "warn";
  }
  return "error";
}

function readDraftString(
  draft: Readonly<Record<string, unknown>> | undefined,
  key: string,
  fallback: string,
): string {
  const val = draft?.[key];
  return typeof val === "string" && val.length > 0 ? val : fallback;
}

function readDraftNumber(
  draft: Readonly<Record<string, unknown>> | undefined,
  key: string,
  fallback: number,
): number {
  const val = draft?.[key];
  return typeof val === "number" && Number.isFinite(val) ? val : fallback;
}

function readDraftBool(
  draft: Readonly<Record<string, unknown>> | undefined,
  key: string,
  fallback: boolean,
): boolean {
  const val = draft?.[key];
  return typeof val === "boolean" ? val : fallback;
}

type PendingStepUpOp =
  | { readonly kind: "registerEndpoint" }
  | { readonly kind: "revokeEndpoint"; readonly endpointId: string }
  | null;

export function SetupWizardPage(): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const announce = useLiveAnnouncer();

  const idPrefix = useId();
  const [formError, setFormError] = useState<AuthProblemSummary | null>(null);
  const [checkpointConflict, setCheckpointConflict] = useState(false);

  // Phase 1 bootstrap claim state (held strictly in component memory)
  const [bootToken, setBootToken] = useState("");
  const [ownerDisplayName, setOwnerDisplayName] = useState("Instance Owner");
  const [ownerEmail, setOwnerEmail] = useState("");
  const [ownerPassword, setOwnerPassword] = useState("");

  // Phase 2..10 form fields
  const [deploymentMode, setDeploymentMode] = useState<"local" | "server" | "distributed">("local");
  const [publicBaseUrl, setPublicBaseUrl] = useState("http://127.0.0.1:4280");
  const [tlsMode, setTlsMode] = useState<
    "loopback_http" | "reverse_proxy_https" | "custom_ca_https"
  >("loopback_http");

  const [storageBackend, setStorageBackend] = useState<"local" | "s3_compatible">("local");
  const [backupDays, setBackupDays] = useState(30);
  const [keyCustodyConfirmed, setKeyCustodyConfirmed] = useState(true);

  const [workspaceName, setWorkspaceName] = useState("Core Engineering");
  const [workspaceSlug, setWorkspaceSlug] = useState("core-eng");

  const [providerKind, setProviderKind] = useState<"github" | "gitlab">("github");
  const [providerBaseUrl, setProviderBaseUrl] = useState("https://api.github.com");
  const [providerAuthMode, setProviderAuthMode] = useState<
    "github_app" | "signed_webhook" | "secret_token"
  >("github_app");
  const [providerEndpointId, setProviderEndpointId] = useState("");
  const [providerSecretRef, setProviderSecretRef] = useState("");

  const [primaryModel, setPrimaryModel] = useState("llama-4-maverick-17b-128e");
  const [escalationModel, setEscalationModel] = useState("llama-4-scout-17b-16e");
  const [maxCostAmount, setMaxCostAmount] = useState("2.50");
  const [maxTokens, setMaxTokens] = useState(64000);
  const [maxCalls, setMaxCalls] = useState(12);
  const [selectedInferenceConsentId, setSelectedInferenceConsentId] = useState("");

  const [sandboxBackend, setSandboxBackend] = useState<
    "docker_isolated" | "podman_rootless" | "remote_vm_worker"
  >("docker_isolated");
  const [runtimeProfileId, setRuntimeProfileId] = useState("python-3.12-linux-x86_64");
  const [workerAck, setWorkerAck] = useState(true);
  const [workerRunSelfTest, setWorkerRunSelfTest] = useState(true);

  const [defaultRepoMode, setDefaultRepoMode] = useState<"monitor" | "approval" | "auto_repair">(
    "monitor",
  );
  const [maxAttempts, setMaxAttempts] = useState(2);
  const [maxDiffLines, setMaxDiffLines] = useState(500);

  const [notifChannel, setNotifChannel] = useState<
    "in_app" | "webhook" | "slack" | "discord" | "telegram" | "email"
  >("in_app");
  const [telemetryMode, setTelemetryMode] = useState<"local_only" | "consented_export">(
    "local_only",
  );

  const [targetReadiness, setTargetReadiness] = useState<SetupReadiness>("not_ready");
  const [reviewNotes, setReviewNotes] = useState("");

  // Outbound consent form state
  const [consentPurpose, setConsentPurpose] = useState<ConsentPurpose>("inference");
  const [consentDestination, setConsentDestination] = useState("https://api.llama.com/v1");
  const [consentClasses, setConsentClasses] = useState<ConsentDataClass[]>([
    "public",
    "workspace_internal",
  ]);
  const [consentAck, setConsentAck] = useState(false);
  const [consentError, setConsentError] = useState<AuthProblemSummary | null>(null);

  // Private endpoint registration form state (ADR-037)
  const [epAdapter, setEpAdapter] = useState<EgressAdapterKind>("gitlab");
  const [epScheme, setEpScheme] = useState<EndpointScheme>("https");
  const [epHost, setEpHost] = useState("");
  const [epPort, setEpPort] = useState(443);
  const [epCidrs, setEpCidrs] = useState("10.24.0.0/16");
  const [epCaRef, setEpCaRef] = useState("");
  const [epDescription, setEpDescription] = useState("");
  const [epError, setEpError] = useState<AuthProblemSummary | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingStepUpRef = useRef<PendingStepUpOp>(null);

  const setupQuery = useQuery({
    queryKey: ["setup", "state"],
    queryFn: () => api.getSetupState(),
    retry: false,
  });

  const ownerClaimed = setupQuery.data?.data.owner_claimed === true;

  const meQuery = useQuery({
    queryKey: ["auth", "me"],
    queryFn: () => api.getMe(),
    enabled: ownerClaimed,
    retry: false,
  });

  const consentsQuery = useQuery({
    queryKey: ["setup", "consents"],
    queryFn: () => api.listSetupConsents(),
    enabled: ownerClaimed,
    retry: false,
  });

  const endpointsQuery = useQuery({
    queryKey: ["setup", "endpoints"],
    queryFn: () => api.listEndpointRegistrations(),
    enabled: ownerClaimed,
    retry: false,
  });

  const setupData: SetupState | null = setupQuery.data?.data ?? null;
  const [hydratedCheckpoint, setHydratedCheckpoint] = useState<string | null>(null);

  // Hydrate phase drafts from durable server checkpoint on load / resume (React 19 pattern)
  if (setupData !== null && setupData.checkpoint !== hydratedCheckpoint) {
    setHydratedCheckpoint(setupData.checkpoint);
    const byPhase = new Map(setupData.steps?.map((s) => [s.phase, s.redacted_draft ?? {}]) ?? []);

    const topo = byPhase.get("topology_tls");
    if (topo) {
      const dm = readDraftString(topo, "deployment_mode", "local");
      if (dm === "local" || dm === "server" || dm === "distributed") {
        setDeploymentMode(dm);
      }
      setPublicBaseUrl(readDraftString(topo, "public_base_url", "http://127.0.0.1:4280"));
      const tm = readDraftString(topo, "tls_mode", "loopback_http");
      if (tm === "loopback_http" || tm === "reverse_proxy_https" || tm === "custom_ca_https") {
        setTlsMode(tm);
      }
    }

    const stor = byPhase.get("storage_keys");
    if (stor) {
      const sb = readDraftString(stor, "storage_backend", "local");
      if (sb === "local" || sb === "s3_compatible") {
        setStorageBackend(sb);
      }
      setBackupDays(readDraftNumber(stor, "backup_retention_days", 30));
      setKeyCustodyConfirmed(readDraftBool(stor, "master_key_custody_confirmed", true));
    }

    const ws = byPhase.get("workspace_admin");
    if (ws) {
      setWorkspaceName(readDraftString(ws, "workspace_name", "Core Engineering"));
      setWorkspaceSlug(readDraftString(ws, "workspace_slug", "core-eng"));
    }

    const prov = byPhase.get("provider_connect");
    if (prov) {
      const pk = readDraftString(prov, "provider", "github");
      if (pk === "github" || pk === "gitlab") {
        setProviderKind(pk);
      }
      setProviderBaseUrl(readDraftString(prov, "provider_base_url", "https://api.github.com"));
      const am = readDraftString(prov, "auth_mode", "github_app");
      if (am === "github_app" || am === "signed_webhook" || am === "secret_token") {
        setProviderAuthMode(am);
      }
    }

    const mdl = byPhase.get("model_consent");
    if (mdl) {
      setPrimaryModel(readDraftString(mdl, "primary_model", "llama-4-maverick-17b-128e"));
      setMaxCostAmount(readDraftString(mdl, "max_cost_per_session_amount", "2.50"));
    }

    setTargetReadiness(setupData.readiness);
  }

  const claimMutation = useMutation({
    mutationFn: async () => {
      return api.claimInstanceOwner({
        bootstrap_token: bootToken.trim(),
        display_name: ownerDisplayName.trim(),
        email: ownerEmail.trim() ? ownerEmail.trim() : null,
        password: ownerPassword,
      });
    },
    onSuccess: async () => {
      setBootToken("");
      setOwnerPassword("");
      setFormError(null);
      announce("Instance owner claimed. Proceeding to Phase 2.");
      await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
      await queryClient.invalidateQueries({ queryKey: ["setup"] });
    },
    onError: (err) => {
      setFormError(extractAuthProblemSummary(err, t("auth.genericAuthErrorTitle")));
    },
  });

  const stepMutation = useMutation({
    mutationFn: async (args: {
      readonly phase: SetupWizardPhase;
      readonly body: SetupStepSubmitRequest;
    }) => {
      return api.submitSetupStep(args.phase, args.body);
    },
    onSuccess: async (envelope) => {
      setFormError(null);
      setCheckpointConflict(false);
      queryClient.setQueryData(["setup", "state"], envelope);
      announce(`Setup checkpoint updated. Active phase: ${PHASE_LABELS[envelope.data.phase]}.`);
      await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError && err.problem.code === "checkpoint_conflict") {
        setCheckpointConflict(true);
      }
      setFormError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const grantConsentMutation = useMutation({
    mutationFn: async () => {
      return api.grantSetupConsent({
        purpose: consentPurpose,
        scope: "instance",
        destination: consentDestination.trim(),
        data_classes: consentClasses,
        policy_notice_acknowledged: true,
      });
    },
    onSuccess: async (res) => {
      setConsentError(null);
      setConsentAck(false);
      if (res.data.purpose === "inference") {
        setSelectedInferenceConsentId(res.data.id);
      }
      announce(`Granted ${res.data.purpose} outbound consent.`);
      await queryClient.invalidateQueries({ queryKey: ["setup", "consents"] });
      await queryClient.invalidateQueries({ queryKey: ["setup", "state"] });
    },
    onError: (err) => {
      setConsentError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const revokeConsentMutation = useMutation({
    mutationFn: async (consentId: string) => {
      return api.revokeSetupConsent(consentId, { reason: "Revoked in setup wizard" });
    },
    onSuccess: async () => {
      setConsentError(null);
      announce("Outbound consent revoked. Readiness recomputed.");
      await queryClient.invalidateQueries({ queryKey: ["setup", "consents"] });
      await queryClient.invalidateQueries({ queryKey: ["setup", "state"] });
    },
    onError: (err) => {
      setConsentError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const registerEndpointMutation = useMutation({
    mutationFn: async () => {
      const parsedCidrs = epCidrs
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      return api.registerPrivateEndpoint({
        adapter: epAdapter,
        scheme: epScheme,
        host: epHost.trim(),
        port: epPort,
        cidrs: parsedCidrs,
        ca_ref: epCaRef.trim() ? epCaRef.trim() : null,
        description: epDescription.trim() ? epDescription.trim() : null,
      });
    },
    onSuccess: async (res) => {
      setEpError(null);
      setEpHost("");
      setEpCaRef("");
      setEpDescription("");
      if (res.data.adapter === providerKind) {
        setProviderEndpointId(res.data.id);
      }
      announce(`Registered private endpoint ${res.data.host}.`);
      await queryClient.invalidateQueries({ queryKey: ["setup", "endpoints"] });
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        pendingStepUpRef.current = { kind: "registerEndpoint" };
        setStepUpOpen(true);
        return;
      }
      setEpError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const revokeEndpointMutation = useMutation({
    mutationFn: async (endpointId: string) => {
      return api.revokePrivateEndpoint(endpointId);
    },
    onSuccess: async () => {
      setEpError(null);
      announce("Private endpoint revoked.");
      await queryClient.invalidateQueries({ queryKey: ["setup", "endpoints"] });
    },
    onError: (err, endpointId) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        pendingStepUpRef.current = { kind: "revokeEndpoint", endpointId };
        setStepUpOpen(true);
        return;
      }
      setEpError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const navOptions: WorkspaceNavOption[] = useMemo(() => {
    return (meQuery.data?.data.workspaces ?? []).map((ws) => ({
      slug: ws.slug ?? ws.id,
      name: sanitizeUntrustedText(ws.name).text,
    }));
  }, [meQuery.data?.data.workspaces]);

  if (setupQuery.isPending) {
    return (
      <main id="red2pr-main-content" className="red2pr-page-stack" style={{ padding: 24 }}>
        <StateView state="loading" />
      </main>
    );
  }

  if (setupQuery.isError || !setupData) {
    if (setupQuery.error instanceof Red2PrApiError && setupQuery.error.status === 401) {
      const nextParam = encodeURIComponent(`${location.pathname}${location.search}`);
      return <Navigate to={`/login?next=${nextParam}`} replace />;
    }
    if (setupQuery.error instanceof Red2PrApiError && setupQuery.error.status === 403) {
      return (
        <AppShell activePath="/setup" activeWorkspaceSlug="default" sseState="offline">
          <StateView state="forbidden" />
        </AppShell>
      );
    }
    const summary = extractAuthProblemSummary(setupQuery.error, t("state.error.description"));
    return (
      <main id="red2pr-main-content" className="red2pr-page-stack" style={{ padding: 24 }}>
        <StateView
          state="error"
          description={summary.detail}
          correlationId={summary.correlationId ?? undefined}
          primaryAction={{
            label: "Retry",
            onClick: () => {
              void setupQuery.refetch();
            },
          }}
        />
      </main>
    );
  }

  const activePhase = setupData.phase;
  const activePhaseIdx = ORDERED_PHASES.indexOf(activePhase);
  const currentStepSummary =
    setupData.steps?.find((s) => s.phase === activePhase) ?? null;
  const isOptionalPhase = currentStepSummary?.optional === true;
  const activeConsents = consentsQuery.data?.data.items ?? [];
  const activeEndpoints = endpointsQuery.data?.data.items ?? [];
  const inferenceConsents = activeConsents.filter(
    (c) => c.purpose === "inference" && c.status === "active",
  );
  const me = meQuery.data?.data ?? null;

  const submitCurrentPhaseSave = (): void => {
    setFormError(null);
    const ckpt = setupData.checkpoint;

    if (activePhase === "topology_tls") {
      stepMutation.mutate({
        phase: "topology_tls",
        body: {
          expected_checkpoint: ckpt,
          action: "save",
          deployment_mode: deploymentMode,
          public_base_url: publicBaseUrl.trim(),
          tls_mode: tlsMode,
        },
      });
      return;
    }

    if (activePhase === "storage_keys") {
      stepMutation.mutate({
        phase: "storage_keys",
        body: {
          expected_checkpoint: ckpt,
          action: "save",
          storage_backend: storageBackend,
          backup_retention_days: backupDays,
          master_key_custody_confirmed: keyCustodyConfirmed,
        },
      });
      return;
    }

    if (activePhase === "workspace_admin") {
      stepMutation.mutate({
        phase: "workspace_admin",
        body: {
          expected_checkpoint: ckpt,
          action: "save",
          workspace_name: workspaceName.trim(),
          workspace_slug: workspaceSlug.trim() || null,
        },
      });
      return;
    }

    if (activePhase === "provider_connect") {
      stepMutation.mutate({
        phase: "provider_connect",
        body: {
          expected_checkpoint: ckpt,
          action: "save",
          provider: providerKind,
          provider_base_url: providerBaseUrl.trim(),
          auth_mode: providerAuthMode,
          endpoint_registration_id: providerEndpointId || null,
          secret_ref: providerSecretRef.trim() || null,
        },
      });
      return;
    }

    if (activePhase === "model_consent") {
      const effectiveConsentId =
        selectedInferenceConsentId || inferenceConsents[0]?.id || null;
      stepMutation.mutate({
        phase: "model_consent",
        body: {
          expected_checkpoint: ckpt,
          action: "save",
          primary_model: primaryModel.trim(),
          escalation_model: escalationModel.trim() || null,
          inference_consent_id: effectiveConsentId,
          max_cost_per_session: {
            amount: maxCostAmount.trim() || "0",
            currency: "USD",
          },
          max_tokens_per_session: maxTokens,
          max_calls_per_session: maxCalls,
        },
      });
      return;
    }

    if (activePhase === "worker_readiness") {
      stepMutation.mutate({
        phase: "worker_readiness",
        body: {
          expected_checkpoint: ckpt,
          action: "save",
          sandbox_backend: sandboxBackend,
          runtime_profile_id: runtimeProfileId.trim(),
          host_escape_risk_acknowledged: workerAck,
          run_self_test: workerRunSelfTest,
        },
      });
      return;
    }

    if (activePhase === "repo_policy") {
      stepMutation.mutate({
        phase: "repo_policy",
        body: {
          expected_checkpoint: ckpt,
          action: "save",
          default_repo_mode: defaultRepoMode,
          require_baseline: true,
          auto_merge: false,
          max_attempts: maxAttempts,
          max_diff_lines: maxDiffLines,
          protected_branches: ["main", "release/*"],
        },
      });
      return;
    }

    if (activePhase === "notifications") {
      stepMutation.mutate({
        phase: "notifications",
        body: {
          expected_checkpoint: ckpt,
          action: "save",
          channel: notifChannel,
          telemetry_mode: telemetryMode,
        },
      });
      return;
    }

    if (activePhase === "readiness_review") {
      stepMutation.mutate({
        phase: "readiness_review",
        body: {
          expected_checkpoint: ckpt,
          action: "save",
          target_readiness: targetReadiness,
          notes: reviewNotes.trim() || null,
        },
      });
    }
  };

  const toggleConsentClass = (cls: ConsentDataClass): void => {
    setConsentClasses((prev) => {
      if (prev.includes(cls)) {
        return prev.length > 1 ? prev.filter((item) => item !== cls) : prev;
      }
      return [...prev, cls];
    });
  };

  const wizardBody = (
    <div className="red2pr-page-stack" data-testid="setup-wizard-page">
      <div
        className="red2pr-surface red2pr-card-section"
        style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", gap: 16 }}
      >
        <div>
          <h1 style={{ margin: "0 0 6px", fontSize: "1.5rem" }}>{t("setup.pageTitle")}</h1>
          <p className="red2pr-field-hint" style={{ margin: 0 }}>
            {t("setup.pageSubtitle")}
          </p>
        </div>

        <div
          data-testid="setup-readiness-banner"
          style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10 }}
        >
          <span
            data-testid="badge-ready-monitor"
            className={`red2pr-status-pill ${setupData.ready_monitor ? "red2pr-tone-success" : "red2pr-tone-neutral"}`}
            style={{ display: "inline-flex", alignItems: "center", gap: 6, fontWeight: 600 }}
          >
            <StatusGlyph kind={setupData.ready_monitor ? "check" : "info"} />
            <span>
              {setupData.ready_monitor ? t("setup.monitorReady") : t("setup.monitorNotReady")}
            </span>
          </span>

          <span
            data-testid="badge-ready-repair"
            className={`red2pr-status-pill ${setupData.ready_repair ? "red2pr-tone-success" : "red2pr-tone-warning"}`}
            style={{ display: "inline-flex", alignItems: "center", gap: 6, fontWeight: 600 }}
          >
            <StatusGlyph kind={setupData.ready_repair ? "check" : "warn"} />
            <span>
              {setupData.ready_repair ? t("setup.repairReady") : t("setup.repairNotReady")}
            </span>
          </span>
        </div>
      </div>

      <nav
        aria-label={t("setup.phasesNavLabel")}
        className="red2pr-surface red2pr-card-section"
        data-testid="setup-phase-stepper"
      >
        <ol
          style={{
            listStyle: "none",
            margin: 0,
            padding: 0,
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(185px, 1fr))",
            gap: 8,
          }}
        >
          {ORDERED_PHASES.map((phaseKey, idx) => {
            const summary = setupData.steps?.find((s) => s.phase === phaseKey);
            const st: SetupStepStatus = summary?.status ?? "pending";
            const isCurrent = phaseKey === activePhase;
            const canRevisit =
              setupData.owner_claimed &&
              phaseKey !== "owner_claim" &&
              !isCurrent &&
              (st !== "pending" || idx < activePhaseIdx);

            return (
              <li
                key={phaseKey}
                aria-current={isCurrent ? "step" : undefined}
                data-testid={`setup-step-item-${phaseKey}`}
                style={{
                  border: isCurrent
                    ? "2px solid var(--red2pr-accent, #2563eb)"
                    : "1px solid var(--red2pr-border, #cbd5e1)",
                  borderRadius: 8,
                  padding: "8px 10px",
                  display: "flex",
                  flexDirection: "column",
                  gap: 4,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
                  <strong style={{ fontSize: "0.875rem" }}>{PHASE_LABELS[phaseKey]}</strong>
                  {summary?.optional ? (
                    <span style={{ fontSize: "0.75rem" }}>({t("setup.optionalBadge")})</span>
                  ) : null}
                </div>
                <div
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    fontSize: "0.8125rem",
                  }}
                >
                  <StatusGlyph kind={stepStatusGlyph(st)} />
                  <span>{STEP_STATUS_LABELS[st]}</span>
                </div>
                {canRevisit ? (
                  <div>
                    <Button
                      label="Edit step"
                      variant="ghost"
                      size="sm"
                      type="button"
                      isDisabled={stepMutation.isPending}
                      onClick={() => {
                        stepMutation.mutate({
                          phase: phaseKey,
                          body: {
                            expected_checkpoint: setupData.checkpoint,
                            action: "back",
                          },
                        });
                      }}
                    />
                  </div>
                ) : null}
              </li>
            );
          })}
        </ol>
      </nav>

      {checkpointConflict ? (
        <div
          role="alert"
          data-testid="setup-checkpoint-conflict-banner"
          className="red2pr-inline-alert red2pr-tone-warning"
          style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12 }}
        >
          <StatusGlyph kind="warn" />
          <span>
            Setup checkpoint changed in another browser tab or operator session. Reload the latest
            checkpoint before submitting changes.
          </span>
          <Button
            label={t("setup.reloadCheckpoint")}
            variant="secondary"
            size="sm"
            type="button"
            onClick={() => {
              setCheckpointConflict(false);
              setFormError(null);
              void setupQuery.refetch();
            }}
          />
        </div>
      ) : null}

      {formError !== null ? (
        <div
          role="alert"
          data-testid="setup-step-error"
          className="red2pr-inline-alert red2pr-tone-danger"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="error" />
            <span>{formError.detail}</span>
          </div>
          {formError.correlationId ? (
            <div style={{ fontSize: "0.8125rem", marginTop: 4 }}>
              {t("state.correlationId", { correlationId: formError.correlationId })}
            </div>
          ) : null}
        </div>
      ) : null}

      {!setupData.owner_claimed ? (
        <section
          className="red2pr-surface red2pr-card-section"
          aria-labelledby={`${idPrefix}-claim-heading`}
          data-testid="setup-phase-owner_claim"
        >
          <h2 id={`${idPrefix}-claim-heading`} style={{ margin: "0 0 6px", fontSize: "1.2rem" }}>
            {PHASE_LABELS.owner_claim}
          </h2>
          <p className="red2pr-field-hint">{t("auth.bootstrapSubtitle")}</p>

          <form
            className="red2pr-form-stack"
            onSubmit={(e) => {
              e.preventDefault();
              setFormError(null);
              claimMutation.mutate();
            }}
            noValidate
          >
            <div className="red2pr-field">
              <label htmlFor={`${idPrefix}-boot-token`} className="red2pr-field-label">
                {t("auth.bootstrapTokenLabel")}
              </label>
              <input
                id={`${idPrefix}-boot-token`}
                className="red2pr-control-input"
                type="password"
                autoComplete="off"
                required
                value={bootToken}
                onChange={(e) => setBootToken(e.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label htmlFor={`${idPrefix}-owner-name`} className="red2pr-field-label">
                {t("auth.displayNameLabel")}
              </label>
              <input
                id={`${idPrefix}-owner-name`}
                className="red2pr-control-input"
                type="text"
                required
                value={ownerDisplayName}
                onChange={(e) => setOwnerDisplayName(e.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label htmlFor={`${idPrefix}-owner-email`} className="red2pr-field-label">
                {t("auth.emailOptionalLabel")}
              </label>
              <input
                id={`${idPrefix}-owner-email`}
                className="red2pr-control-input"
                type="email"
                value={ownerEmail}
                onChange={(e) => setOwnerEmail(e.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label htmlFor={`${idPrefix}-owner-pw`} className="red2pr-field-label">
                {t("auth.newOwnerPasswordLabel")}
              </label>
              <input
                id={`${idPrefix}-owner-pw`}
                className="red2pr-control-input"
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                value={ownerPassword}
                onChange={(e) => setOwnerPassword(e.target.value)}
              />
            </div>

            <div>
              <Button
                label={t("auth.bootstrapSubmit")}
                variant="primary"
                type="submit"
                isLoading={claimMutation.isPending}
                isDisabled={
                  !bootToken.trim() ||
                  !ownerDisplayName.trim() ||
                  ownerPassword.length < 12 ||
                  claimMutation.isPending
                }
              />
            </div>
          </form>
        </section>
      ) : (
        <section
          className="red2pr-surface red2pr-card-section"
          aria-labelledby={`${idPrefix}-active-phase-heading`}
          data-testid={`setup-phase-${activePhase}`}
        >
          <h2
            id={`${idPrefix}-active-phase-heading`}
            style={{ margin: "0 0 8px", fontSize: "1.2rem" }}
          >
            {PHASE_LABELS[activePhase]}
          </h2>

          {currentStepSummary?.probe_detail ? (
            <p className="red2pr-field-hint" data-testid="setup-step-probe-detail">
              {currentStepSummary.probe_detail}
            </p>
          ) : null}

          <form
            className="red2pr-form-stack"
            onSubmit={(e) => {
              e.preventDefault();
              submitCurrentPhaseSave();
            }}
            noValidate
          >
            {activePhase === "topology_tls" ? (
              <>
                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-dep-mode`} className="red2pr-field-label">
                    Deployment mode
                  </label>
                  <select
                    id={`${idPrefix}-dep-mode`}
                    className="red2pr-control-input"
                    value={deploymentMode}
                    onChange={(e) =>
                      setDeploymentMode(e.target.value as "local" | "server" | "distributed")
                    }
                  >
                    <option value="local">Local workstation (loopback HTTP or HTTPS)</option>
                    <option value="server">Single-host server (HTTPS required)</option>
                    <option value="distributed">Distributed cluster (HTTPS required)</option>
                  </select>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-base-url`} className="red2pr-field-label">
                    Public base URL
                  </label>
                  <input
                    id={`${idPrefix}-base-url`}
                    className="red2pr-control-input"
                    type="url"
                    required
                    value={publicBaseUrl}
                    onChange={(e) => setPublicBaseUrl(e.target.value)}
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-tls-mode`} className="red2pr-field-label">
                    TLS termination mode
                  </label>
                  <select
                    id={`${idPrefix}-tls-mode`}
                    className="red2pr-control-input"
                    value={tlsMode}
                    onChange={(e) =>
                      setTlsMode(
                        e.target.value as
                          | "loopback_http"
                          | "reverse_proxy_https"
                          | "custom_ca_https",
                      )
                    }
                  >
                    <option value="loopback_http">Loopback HTTP (127.0.0.1 / localhost only)</option>
                    <option value="reverse_proxy_https">Reverse proxy HTTPS</option>
                    <option value="custom_ca_https">Enterprise custom CA HTTPS</option>
                  </select>
                </div>
              </>
            ) : null}

            {activePhase === "storage_keys" ? (
              <>
                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-storage-backend`} className="red2pr-field-label">
                    Artifact storage backend
                  </label>
                  <select
                    id={`${idPrefix}-storage-backend`}
                    className="red2pr-control-input"
                    value={storageBackend}
                    onChange={(e) =>
                      setStorageBackend(e.target.value as "local" | "s3_compatible")
                    }
                  >
                    <option value="local">Local encrypted filesystem</option>
                    <option value="s3_compatible">S3-compatible object storage</option>
                  </select>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-backup-days`} className="red2pr-field-label">
                    Backup & evidence retention (days)
                  </label>
                  <input
                    id={`${idPrefix}-backup-days`}
                    className="red2pr-control-input"
                    type="number"
                    min={1}
                    max={3650}
                    value={backupDays}
                    onChange={(e) => setBackupDays(Math.max(1, Number(e.target.value) || 30))}
                  />
                </div>

                <div className="red2pr-field">
                  <label
                    htmlFor={`${idPrefix}-kek-ack`}
                    style={{ display: "flex", alignItems: "center", gap: 8 }}
                  >
                    <input
                      id={`${idPrefix}-kek-ack`}
                      type="checkbox"
                      checked={keyCustodyConfirmed}
                      onChange={(e) => setKeyCustodyConfirmed(e.target.checked)}
                    />
                    <span>
                      I have backed up the Z2 master encryption key (KEK) outside the database
                      volume.
                    </span>
                  </label>
                </div>
              </>
            ) : null}

            {activePhase === "workspace_admin" ? (
              <>
                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-ws-name`} className="red2pr-field-label">
                    Initial workspace name
                  </label>
                  <input
                    id={`${idPrefix}-ws-name`}
                    className="red2pr-control-input"
                    type="text"
                    required
                    value={workspaceName}
                    onChange={(e) => setWorkspaceName(e.target.value)}
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-ws-slug`} className="red2pr-field-label">
                    Workspace URL slug
                  </label>
                  <input
                    id={`${idPrefix}-ws-slug`}
                    className="red2pr-control-input"
                    type="text"
                    value={workspaceSlug}
                    onChange={(e) => setWorkspaceSlug(e.target.value)}
                  />
                </div>
              </>
            ) : null}

            {activePhase === "provider_connect" ? (
              <>
                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-prov-kind`} className="red2pr-field-label">
                    Git / CI provider
                  </label>
                  <select
                    id={`${idPrefix}-prov-kind`}
                    className="red2pr-control-input"
                    value={providerKind}
                    onChange={(e) => setProviderKind(e.target.value as "github" | "gitlab")}
                  >
                    <option value="github">GitHub / GitHub Enterprise</option>
                    <option value="gitlab">GitLab / Self-Managed GitLab</option>
                  </select>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-prov-url`} className="red2pr-field-label">
                    Provider API base URL
                  </label>
                  <input
                    id={`${idPrefix}-prov-url`}
                    className="red2pr-control-input"
                    type="url"
                    value={providerBaseUrl}
                    onChange={(e) => setProviderBaseUrl(e.target.value)}
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-prov-auth`} className="red2pr-field-label">
                    Authentication mode
                  </label>
                  <select
                    id={`${idPrefix}-prov-auth`}
                    className="red2pr-control-input"
                    value={providerAuthMode}
                    onChange={(e) =>
                      setProviderAuthMode(
                        e.target.value as "github_app" | "signed_webhook" | "secret_token",
                      )
                    }
                  >
                    <option value="github_app">GitHub App installation</option>
                    <option value="signed_webhook">HMAC-signed webhook</option>
                    <option value="secret_token">Scoped token via Z2 SecretBroker</option>
                  </select>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-prov-ep`} className="red2pr-field-label">
                    Private endpoint registration (optional, for self-hosted Git)
                  </label>
                  <select
                    id={`${idPrefix}-prov-ep`}
                    className="red2pr-control-input"
                    value={providerEndpointId}
                    onChange={(e) => setProviderEndpointId(e.target.value)}
                  >
                    <option value="">Public HTTPS endpoint (default)</option>
                    {activeEndpoints
                      .filter((ep) => ep.status === "active" && ep.adapter === providerKind)
                      .map((ep) => (
                        <option key={ep.id} value={ep.id}>
                          {`${ep.scheme}://${ep.host}:${String(ep.port)}`}
                        </option>
                      ))}
                  </select>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-prov-secref`} className="red2pr-field-label">
                    Opaque Z2 secret reference (optional, e.g. sec_provider_01)
                  </label>
                  <input
                    id={`${idPrefix}-prov-secref`}
                    className="red2pr-control-input"
                    type="text"
                    autoComplete="off"
                    value={providerSecretRef}
                    onChange={(e) => setProviderSecretRef(e.target.value)}
                  />
                </div>
              </>
            ) : null}

            {activePhase === "model_consent" ? (
              <>
                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-model-primary`} className="red2pr-field-label">
                    Primary Meta model identifier
                  </label>
                  <input
                    id={`${idPrefix}-model-primary`}
                    className="red2pr-control-input"
                    type="text"
                    required
                    value={primaryModel}
                    onChange={(e) => setPrimaryModel(e.target.value)}
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-model-esc`} className="red2pr-field-label">
                    Escalation model identifier (optional)
                  </label>
                  <input
                    id={`${idPrefix}-model-esc`}
                    className="red2pr-control-input"
                    type="text"
                    value={escalationModel}
                    onChange={(e) => setEscalationModel(e.target.value)}
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-model-cost`} className="red2pr-field-label">
                    Max cost per repair session (USD)
                  </label>
                  <input
                    id={`${idPrefix}-model-cost`}
                    className="red2pr-control-input"
                    type="text"
                    value={maxCostAmount}
                    onChange={(e) => setMaxCostAmount(e.target.value)}
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-model-tokens`} className="red2pr-field-label">
                    Max tokens per repair session
                  </label>
                  <input
                    id={`${idPrefix}-model-tokens`}
                    className="red2pr-control-input"
                    type="number"
                    min={1}
                    max={1000000}
                    value={maxTokens}
                    onChange={(e) => setMaxTokens(Math.max(1, Number(e.target.value) || 64000))}
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-model-calls`} className="red2pr-field-label">
                    Max model calls per repair session
                  </label>
                  <input
                    id={`${idPrefix}-model-calls`}
                    className="red2pr-control-input"
                    type="number"
                    min={1}
                    max={100}
                    value={maxCalls}
                    onChange={(e) => setMaxCalls(Math.max(1, Number(e.target.value) || 12))}
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-inf-consent`} className="red2pr-field-label">
                    Active outbound inference consent record
                  </label>
                  <select
                    id={`${idPrefix}-inf-consent`}
                    className="red2pr-control-input"
                    value={selectedInferenceConsentId || inferenceConsents[0]?.id || ""}
                    onChange={(e) => setSelectedInferenceConsentId(e.target.value)}
                  >
                    <option value="">No inference consent selected (Repair stays blocked)</option>
                    {inferenceConsents.map((c) => (
                      <option key={c.id} value={c.id}>
                        {`${c.destination} (${c.data_classes.join(", ")})`}
                      </option>
                    ))}
                  </select>
                </div>
              </>
            ) : null}

            {activePhase === "worker_readiness" ? (
              <>
                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-sandbox-kind`} className="red2pr-field-label">
                    Isolated Z3 sandbox backend
                  </label>
                  <select
                    id={`${idPrefix}-sandbox-kind`}
                    className="red2pr-control-input"
                    value={sandboxBackend}
                    onChange={(e) =>
                      setSandboxBackend(
                        e.target.value as
                          | "docker_isolated"
                          | "podman_rootless"
                          | "remote_vm_worker",
                      )
                    }
                  >
                    <option value="docker_isolated">
                      Isolated Docker container (no host socket, network default-deny)
                    </option>
                    <option value="podman_rootless">Rootless Podman container</option>
                    <option value="remote_vm_worker">Dedicated remote VM worker</option>
                  </select>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-runtime-prof`} className="red2pr-field-label">
                    Certified runtime profile ID
                  </label>
                  <input
                    id={`${idPrefix}-runtime-prof`}
                    className="red2pr-control-input"
                    type="text"
                    required
                    value={runtimeProfileId}
                    onChange={(e) => setRuntimeProfileId(e.target.value)}
                  />
                </div>

                <div className="red2pr-field">
                  <label
                    htmlFor={`${idPrefix}-worker-selftest`}
                    style={{ display: "flex", alignItems: "center", gap: 8 }}
                  >
                    <input
                      id={`${idPrefix}-worker-selftest`}
                      type="checkbox"
                      checked={workerRunSelfTest}
                      onChange={(e) => setWorkerRunSelfTest(e.target.checked)}
                    />
                    <span>Run deterministic sandbox isolation & egress-deny self-test</span>
                  </label>
                </div>

                <div className="red2pr-field">
                  <label
                    htmlFor={`${idPrefix}-worker-ack`}
                    style={{ display: "flex", alignItems: "center", gap: 8 }}
                  >
                    <input
                      id={`${idPrefix}-worker-ack`}
                      type="checkbox"
                      checked={workerAck}
                      onChange={(e) => setWorkerAck(e.target.checked)}
                    />
                    <span>
                      I confirm the worker never mounts the host Docker socket, runs non-privileged,
                      and receives zero write tokens or Meta API keys.
                    </span>
                  </label>
                </div>
              </>
            ) : null}

            {activePhase === "repo_policy" ? (
              <>
                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-repo-mode`} className="red2pr-field-label">
                    Default repository operating mode
                  </label>
                  <select
                    id={`${idPrefix}-repo-mode`}
                    className="red2pr-control-input"
                    value={defaultRepoMode}
                    onChange={(e) =>
                      setDefaultRepoMode(e.target.value as "monitor" | "approval" | "auto_repair")
                    }
                  >
                    <option value="monitor">Monitor & diagnose only (safe default)</option>
                    <option value="approval">Draft PR/MR after human approval</option>
                    <option value="auto_repair">
                      Auto-open draft PR/MR after deterministic proof (requires Repair Ready)
                    </option>
                  </select>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-max-attempts`} className="red2pr-field-label">
                    Max repair attempts per CI failure (1-5)
                  </label>
                  <input
                    id={`${idPrefix}-max-attempts`}
                    className="red2pr-control-input"
                    type="number"
                    min={1}
                    max={5}
                    value={maxAttempts}
                    onChange={(e) =>
                      setMaxAttempts(Math.min(5, Math.max(1, Number(e.target.value) || 2)))
                    }
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-max-diff`} className="red2pr-field-label">
                    Max patch diff lines (1-2000)
                  </label>
                  <input
                    id={`${idPrefix}-max-diff`}
                    className="red2pr-control-input"
                    type="number"
                    min={1}
                    max={2000}
                    value={maxDiffLines}
                    onChange={(e) =>
                      setMaxDiffLines(Math.min(2000, Math.max(1, Number(e.target.value) || 500)))
                    }
                  />
                </div>

                <p className="red2pr-field-hint">
                  Enforced invariants: Baseline failure reproduction is mandatory
                  (require_baseline=true) and autonomous PR/MR auto-merge is permanently disabled
                  (auto_merge=false).
                </p>
              </>
            ) : null}

            {activePhase === "notifications" ? (
              <>
                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-notif-chan`} className="red2pr-field-label">
                    Primary operator notification channel
                  </label>
                  <select
                    id={`${idPrefix}-notif-chan`}
                    className="red2pr-control-input"
                    value={notifChannel}
                    onChange={(e) =>
                      setNotifChannel(
                        e.target.value as
                          | "in_app"
                          | "webhook"
                          | "slack"
                          | "discord"
                          | "telegram"
                          | "email",
                      )
                    }
                  >
                    <option value="in_app">In-app workspace inbox only (local)</option>
                    <option value="webhook">Signed HTTPS webhook</option>
                    <option value="slack">Slack incoming webhook</option>
                    <option value="discord">Discord webhook</option>
                    <option value="telegram">Telegram bot</option>
                    <option value="email">SMTP email</option>
                  </select>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-telem-mode`} className="red2pr-field-label">
                    Telemetry export policy
                  </label>
                  <select
                    id={`${idPrefix}-telem-mode`}
                    className="red2pr-control-input"
                    value={telemetryMode}
                    onChange={(e) =>
                      setTelemetryMode(e.target.value as "local_only" | "consented_export")
                    }
                  >
                    <option value="local_only">Local-only metrics & audit (default)</option>
                    <option value="consented_export">
                      Consented OpenTelemetry export (requires active telemetry consent)
                    </option>
                  </select>
                </div>
              </>
            ) : null}

            {activePhase === "readiness_review" ? (
              <>
                <div data-testid="setup-prerequisites-checklist" style={{ marginBottom: 12 }}>
                  <h3 style={{ margin: "0 0 8px", fontSize: "1rem" }}>
                    Verified Readiness Gates
                  </h3>
                  <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 8 }}>
                    {setupData.prerequisites.map((item) => (
                      <li
                        key={item.id}
                        data-testid={`prereq-${item.id}`}
                        style={{
                          display: "flex",
                          alignItems: "flex-start",
                          gap: 8,
                          padding: "8px 10px",
                          borderRadius: 6,
                          border: "1px solid var(--red2pr-border, #cbd5e1)",
                        }}
                      >
                        <StatusGlyph kind={prereqGlyph(item.status)} />
                        <div>
                          <strong>{item.id}</strong> ({item.status}): {item.remediation}
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-target-readiness`} className="red2pr-field-label">
                    Target readiness certification
                  </label>
                  <select
                    id={`${idPrefix}-target-readiness`}
                    className="red2pr-control-input"
                    value={targetReadiness}
                    onChange={(e) => setTargetReadiness(e.target.value as SetupReadiness)}
                  >
                    <option value="not_ready">Save onboarding state (Not Ready)</option>
                    <option value="ready_monitor">Certify Monitor Ready</option>
                    <option value="ready_repair">Certify Repair Ready</option>
                  </select>
                </div>

                <div className="red2pr-field">
                  <label htmlFor={`${idPrefix}-review-notes`} className="red2pr-field-label">
                    Operator handoff notes (redacted before persistence)
                  </label>
                  <textarea
                    id={`${idPrefix}-review-notes`}
                    className="red2pr-control-input"
                    rows={2}
                    value={reviewNotes}
                    onChange={(e) => setReviewNotes(e.target.value)}
                  />
                </div>
              </>
            ) : null}

            <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 8 }}>
              {activePhaseIdx > 1 ? (
                <Button
                  label={t("setup.backPrevious")}
                  variant="secondary"
                  type="button"
                  isDisabled={stepMutation.isPending}
                  onClick={() => {
                    const prevPhase = ORDERED_PHASES[activePhaseIdx - 1];
                    if (prevPhase && prevPhase !== "owner_claim") {
                      stepMutation.mutate({
                        phase: prevPhase,
                        body: {
                          expected_checkpoint: setupData.checkpoint,
                          action: "back",
                        },
                      });
                    }
                  }}
                />
              ) : null}

              <Button
                label={
                  activePhase === "readiness_review"
                    ? t("setup.completeReview")
                    : t("setup.saveContinue")
                }
                variant="primary"
                type="submit"
                isLoading={stepMutation.isPending}
                isDisabled={stepMutation.isPending}
              />

              {isOptionalPhase ? (
                <Button
                  label={t("setup.skipOptional")}
                  variant="ghost"
                  type="button"
                  isDisabled={stepMutation.isPending}
                  onClick={() => {
                    stepMutation.mutate({
                      phase: activePhase,
                      body: {
                        expected_checkpoint: setupData.checkpoint,
                        action: "skip",
                      },
                    });
                  }}
                />
              ) : null}

              {setupData.completed_at && setupData.default_workspace_slug ? (
                <Button
                  label={t("setup.openWorkspace")}
                  variant="secondary"
                  type="button"
                  onClick={() => {
                    const slug = setupData.default_workspace_slug ?? "default";
                    navigate(`/w/${encodeURIComponent(slug)}/members`);
                  }}
                />
              ) : null}
            </div>
          </form>
        </section>
      )}

      {setupData.owner_claimed ? (
        <>
          <section
            className="red2pr-surface red2pr-card-section"
            aria-labelledby={`${idPrefix}-consents-heading`}
            data-testid="setup-consents-panel"
          >
            <h2 id={`${idPrefix}-consents-heading`} style={{ margin: "0 0 6px", fontSize: "1.15rem" }}>
              {t("setup.consentsTitle")}
            </h2>
            <p className="red2pr-field-hint">{t("setup.consentsSubtitle")}</p>

            {consentError !== null ? (
              <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <StatusGlyph kind="error" />
                  <span>{consentError.detail}</span>
                </div>
              </div>
            ) : null}

            <form
              className="red2pr-form-stack"
              onSubmit={(e) => {
                e.preventDefault();
                setConsentError(null);
                grantConsentMutation.mutate();
              }}
              noValidate
            >
              <div className="red2pr-field">
                <label htmlFor={`${idPrefix}-consent-purpose`} className="red2pr-field-label">
                  Consent purpose
                </label>
                <select
                  id={`${idPrefix}-consent-purpose`}
                  className="red2pr-control-input"
                  value={consentPurpose}
                  onChange={(e) => setConsentPurpose(e.target.value as ConsentPurpose)}
                >
                  <option value="inference">inference (outbound code/log context to model)</option>
                  <option value="notification">notification (outbound alert summaries)</option>
                  <option value="telemetry">telemetry (outbound OpenTelemetry metrics/traces)</option>
                  <option value="provider">provider (outbound Git/CI API calls)</option>
                </select>
              </div>

              <div className="red2pr-field">
                <label htmlFor={`${idPrefix}-consent-dest`} className="red2pr-field-label">
                  Authorized destination URL
                </label>
                <input
                  id={`${idPrefix}-consent-dest`}
                  className="red2pr-control-input"
                  type="url"
                  required
                  value={consentDestination}
                  onChange={(e) => setConsentDestination(e.target.value)}
                />
              </div>

              <fieldset
                style={{
                  border: "1px solid var(--red2pr-border, #cbd5e1)",
                  borderRadius: 6,
                  padding: "8px 12px",
                }}
              >
                <legend style={{ fontWeight: 600, fontSize: "0.875rem" }}>
                  Permitted redacted data classes (secrets always forbidden)
                </legend>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 16 }}>
                  {(["public", "workspace_internal", "restricted"] as const).map((cls) => (
                    <label
                      key={cls}
                      htmlFor={`${idPrefix}-cls-${cls}`}
                      style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
                    >
                      <input
                        id={`${idPrefix}-cls-${cls}`}
                        type="checkbox"
                        checked={consentClasses.includes(cls)}
                        onChange={() => toggleConsentClass(cls)}
                      />
                      <span>{cls}</span>
                    </label>
                  ))}
                </div>
              </fieldset>

              <div className="red2pr-field">
                <label
                  htmlFor={`${idPrefix}-consent-ack`}
                  style={{ display: "flex", alignItems: "center", gap: 8 }}
                >
                  <input
                    id={`${idPrefix}-consent-ack`}
                    type="checkbox"
                    checked={consentAck}
                    onChange={(e) => setConsentAck(e.target.checked)}
                  />
                  <span>
                    I explicitly authorize redacted outbound transmission for this specific purpose.
                  </span>
                </label>
              </div>

              <div>
                <Button
                  label={t("setup.grantConsentAction")}
                  variant="secondary"
                  type="submit"
                  isLoading={grantConsentMutation.isPending}
                  isDisabled={
                    !consentDestination.trim() || !consentAck || grantConsentMutation.isPending
                  }
                />
              </div>
            </form>

            {activeConsents.length > 0 ? (
              <ul
                data-testid="setup-consents-list"
                style={{ listStyle: "none", padding: 0, margin: "12px 0 0", display: "grid", gap: 8 }}
              >
                {activeConsents.map((item) => (
                  <li
                    key={item.id}
                    data-testid={`consent-row-${item.purpose}`}
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 10,
                      padding: "8px 10px",
                      border: "1px solid var(--red2pr-border, #cbd5e1)",
                      borderRadius: 6,
                    }}
                  >
                    <div>
                      <strong>{item.purpose}</strong> · {item.destination} (
                      {item.data_classes.join(", ")})
                    </div>
                    <Button
                      label={t("setup.revokeConsentAction")}
                      variant="destructive"
                      size="sm"
                      type="button"
                      isLoading={revokeConsentMutation.isPending}
                      onClick={() => revokeConsentMutation.mutate(item.id)}
                    />
                  </li>
                ))}
              </ul>
            ) : null}
          </section>

          <section
            className="red2pr-surface red2pr-card-section"
            aria-labelledby={`${idPrefix}-endpoints-heading`}
            data-testid="setup-endpoints-panel"
          >
            <h2
              id={`${idPrefix}-endpoints-heading`}
              style={{ margin: "0 0 6px", fontSize: "1.15rem" }}
            >
              {t("setup.endpointsTitle")}
            </h2>
            <p className="red2pr-field-hint">{t("setup.endpointsSubtitle")}</p>

            {epError !== null ? (
              <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <StatusGlyph kind="error" />
                  <span>{epError.detail}</span>
                </div>
              </div>
            ) : null}

            <form
              className="red2pr-form-stack"
              onSubmit={(e) => {
                e.preventDefault();
                setEpError(null);
                if (me && !isStepUpValid(me.step_up_valid_until)) {
                  pendingStepUpRef.current = { kind: "registerEndpoint" };
                  setStepUpOpen(true);
                  return;
                }
                registerEndpointMutation.mutate();
              }}
              noValidate
            >
              <div className="red2pr-field">
                <label htmlFor={`${idPrefix}-ep-adapter`} className="red2pr-field-label">
                  Bound outbound adapter
                </label>
                <select
                  id={`${idPrefix}-ep-adapter`}
                  className="red2pr-control-input"
                  value={epAdapter}
                  onChange={(e) => setEpAdapter(e.target.value as EgressAdapterKind)}
                >
                  <option value="gitlab">gitlab</option>
                  <option value="github">github</option>
                  <option value="meta_inference">meta_inference</option>
                  <option value="oidc">oidc</option>
                  <option value="s3_artifacts">s3_artifacts</option>
                  <option value="webhook">webhook</option>
                  <option value="slack">slack</option>
                  <option value="discord">discord</option>
                  <option value="telegram">telegram</option>
                  <option value="smtp">smtp</option>
                </select>
              </div>

              <div className="red2pr-field">
                <label htmlFor={`${idPrefix}-ep-scheme`} className="red2pr-field-label">
                  Scheme
                </label>
                <select
                  id={`${idPrefix}-ep-scheme`}
                  className="red2pr-control-input"
                  value={epScheme}
                  onChange={(e) => setEpScheme(e.target.value as EndpointScheme)}
                >
                  <option value="https">https</option>
                  <option value="http">http (private enterprise network only)</option>
                </select>
              </div>

              <div className="red2pr-field">
                <label htmlFor={`${idPrefix}-ep-host`} className="red2pr-field-label">
                  Hostname (no scheme or port)
                </label>
                <input
                  id={`${idPrefix}-ep-host`}
                  className="red2pr-control-input"
                  type="text"
                  required
                  value={epHost}
                  onChange={(e) => setEpHost(e.target.value)}
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={`${idPrefix}-ep-port`} className="red2pr-field-label">
                  Port
                </label>
                <input
                  id={`${idPrefix}-ep-port`}
                  className="red2pr-control-input"
                  type="number"
                  min={1}
                  max={65535}
                  required
                  value={epPort}
                  onChange={(e) =>
                    setEpPort(Math.min(65535, Math.max(1, Number(e.target.value) || 443)))
                  }
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={`${idPrefix}-ep-cidrs`} className="red2pr-field-label">
                  Allowed private CIDRs (comma-separated, e.g. 10.24.0.0/16)
                </label>
                <input
                  id={`${idPrefix}-ep-cidrs`}
                  className="red2pr-control-input"
                  type="text"
                  required
                  value={epCidrs}
                  onChange={(e) => setEpCidrs(e.target.value)}
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={`${idPrefix}-ep-caref`} className="red2pr-field-label">
                  Custom CA bundle reference (optional, e.g. ref:corp-root-ca)
                </label>
                <input
                  id={`${idPrefix}-ep-caref`}
                  className="red2pr-control-input"
                  type="text"
                  value={epCaRef}
                  onChange={(e) => setEpCaRef(e.target.value)}
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={`${idPrefix}-ep-desc`} className="red2pr-field-label">
                  Description (optional)
                </label>
                <input
                  id={`${idPrefix}-ep-desc`}
                  className="red2pr-control-input"
                  type="text"
                  value={epDescription}
                  onChange={(e) => setEpDescription(e.target.value)}
                />
              </div>

              <div>
                <Button
                  label={t("setup.registerEndpointAction")}
                  variant="secondary"
                  type="submit"
                  isLoading={registerEndpointMutation.isPending}
                  isDisabled={
                    !epHost.trim() || !epCidrs.trim() || registerEndpointMutation.isPending
                  }
                />
              </div>
            </form>

            {activeEndpoints.length > 0 ? (
              <ul
                data-testid="setup-endpoints-list"
                style={{ listStyle: "none", padding: 0, margin: "12px 0 0", display: "grid", gap: 8 }}
              >
                {activeEndpoints.map((ep) => (
                  <li
                    key={ep.id}
                    data-testid={`endpoint-row-${ep.host}`}
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 10,
                      padding: "8px 10px",
                      border: "1px solid var(--red2pr-border, #cbd5e1)",
                      borderRadius: 6,
                    }}
                  >
                    <div>
                      <strong>{ep.adapter}</strong> · {`${ep.scheme}://${ep.host}:${String(ep.port)}`}{" "}
                      · CIDRs: {ep.cidrs.join(", ")}
                      {ep.ca_ref ? ` · CA: ${ep.ca_ref}` : ""}
                    </div>
                    <Button
                      label={t("setup.revokeEndpointAction")}
                      variant="destructive"
                      size="sm"
                      type="button"
                      isLoading={revokeEndpointMutation.isPending}
                      onClick={() => {
                        if (me && !isStepUpValid(me.step_up_valid_until)) {
                          pendingStepUpRef.current = { kind: "revokeEndpoint", endpointId: ep.id };
                          setStepUpOpen(true);
                          return;
                        }
                        revokeEndpointMutation.mutate(ep.id);
                      }}
                    />
                  </li>
                ))}
              </ul>
            ) : null}
          </section>

          <StepUpDialog
            isOpen={stepUpOpen}
            mfaEnabled={me?.mfa_enabled ?? false}
            onOpenChange={(nextOpen) => {
              if (!nextOpen) {
                pendingStepUpRef.current = null;
              }
              setStepUpOpen(nextOpen);
            }}
            onVerified={() => {
              void queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
              const pending = pendingStepUpRef.current;
              pendingStepUpRef.current = null;
              if (pending?.kind === "registerEndpoint") {
                registerEndpointMutation.mutate();
              } else if (pending?.kind === "revokeEndpoint") {
                revokeEndpointMutation.mutate(pending.endpointId);
              }
            }}
          />
        </>
      ) : null}
    </div>
  );

  if (!setupData.owner_claimed) {
    return (
      <main id="red2pr-main-content" style={{ maxWidth: 960, margin: "0 auto", padding: 24 }}>
        {wizardBody}
      </main>
    );
  }

  const defaultSlug = setupData.default_workspace_slug ?? navOptions[0]?.slug ?? "default";
  return (
    <AppShell
      activePath="/setup"
      activeWorkspaceSlug={defaultSlug}
      workspaces={navOptions}
      onSelectWorkspace={(nextSlug) => navigate(`/w/${encodeURIComponent(nextSlug)}/members`)}
      sseState="offline"
    >
      {wizardBody}
    </AppShell>
  );
}
