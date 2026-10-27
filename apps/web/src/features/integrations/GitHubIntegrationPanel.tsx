import {
  Red2PrApiError,
  type CapabilityAvailability,
  type Connection,
  type ConnectionStatus,
  type GitHubInstallStateResponse,
  type MeResponse,
  type Repository,
  type WorkflowHazardStatus,
  type Workspace,
  type WorkspaceRole,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  Button,
  Dialog,
  StateView,
  StatusGlyph,
  Table,
  sanitizeNavigationHref,
  sanitizeUntrustedText,
  useLiveAnnouncer,
  type TableColumn,
} from "../../shared/ui";
import {
  extractAuthProblemSummary,
  formatUtcTimestamp,
  type AuthProblemSummary,
} from "../auth";
import { generateClientUuidV7 } from "../queues/QueuesPage";
import { ConnectionPollingReconcileCard } from "./ConnectionPollingReconcileCard";

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";
type RepositoryRow = Repository & Record<string, unknown>;

export interface GitHubIntegrationPanelProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

function resolveEffectiveRole(
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

function connectionStatusAppearance(status: ConnectionStatus): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (status) {
    case "ready":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Ready" };
    case "degraded":
      return { glyph: "warn", tone: "red2pr-tone-warning", label: "Degraded" };
    case "revoked":
      return { glyph: "error", tone: "red2pr-tone-danger", label: "Revoked — Suspended" };
    case "checking":
      return { glyph: "clock", tone: "red2pr-tone-info", label: "Checking" };
    case "unsupported":
      return { glyph: "warn", tone: "red2pr-tone-warning", label: "Unsupported" };
    case "not_configured":
      return { glyph: "clock", tone: "red2pr-tone-neutral", label: "Not Configured" };
  }
}

function capabilityAppearance(avail: CapabilityAvailability): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (avail) {
    case "available":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Available" };
    case "unavailable":
      return { glyph: "warn", tone: "red2pr-tone-warning", label: "Unavailable" };
    case "unknown":
      return { glyph: "clock", tone: "red2pr-tone-neutral", label: "Unknown" };
  }
}

function hazardStatusAppearance(status: WorkflowHazardStatus | undefined): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (status ?? "unscanned") {
    case "clean":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Clean Workflows" };
    case "flagged":
      return {
        glyph: "warn",
        tone: "red2pr-tone-danger",
        label: "Hazard Flagged · Auto-Repair Blocked",
      };
    case "unscanned":
      return { glyph: "clock", tone: "red2pr-tone-neutral", label: "Unscanned" };
  }
}

export function GitHubIntegrationPanel({
  workspace,
  me,
}: GitHubIntegrationPanelProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const announce = useLiveAnnouncer();
  const [searchParams, setSearchParams] = useSearchParams();

  const wsSlug = workspace.slug ?? workspace.id;
  const effectiveRole = useMemo(() => resolveEffectiveRole(workspace, me), [me, workspace]);
  const isAdmin = effectiveRole === "admin";

  // Create GitHub App connection form state (write-only secrets wiped immediately on submit)
  const [createOpen, setCreateOpen] = useState(false);
  const [createDisplayName, setCreateDisplayName] = useState("");
  const [createAppId, setCreateAppId] = useState("");
  const [createClientId, setCreateClientId] = useState("");
  const [createBaseUrl, setCreateBaseUrl] = useState("https://api.github.com");
  const [createPrivateKeyPem, setCreatePrivateKeyPem] = useState("");
  const [createWebhookSecret, setCreateWebhookSecret] = useState("");

  // Selected connection & installation binding state
  const [selectedConnectionId, setSelectedConnectionId] = useState<string | null>(null);
  const [mintedState, setMintedState] = useState<GitHubInstallStateResponse | null>(null);
  const [confirmInstallationIdOverride, setConfirmInstallationIdOverride] = useState<string | null>(
    null,
  );
  const [confirmStateNonceOverride, setConfirmStateNonceOverride] = useState<string | null>(null);

  // Callback validation state from ?state=...&installation_id=...
  const callbackStateParam = searchParams.get("state");
  const callbackInstallationParam = searchParams.get("installation_id");
  const callbackSetupActionParam = searchParams.get("setup_action");

  // Rotate / Update dialog state
  const [rotateOpen, setRotateOpen] = useState(false);
  const [rotateDisplayName, setRotateDisplayName] = useState("");
  const [rotateBaseUrl, setRotateBaseUrl] = useState("");
  const [rotatePrivateKeyPem, setRotatePrivateKeyPem] = useState("");
  const [rotateWebhookSecret, setRotateWebhookSecret] = useState("");

  // Destructive disconnect dialog state
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [revokeConfirmText, setRevokeConfirmText] = useState("");

  // Action feedback & version conflict state
  const [feedbackBanner, setFeedbackBanner] = useState<{
    readonly tone: "success" | "warning" | "danger" | "info";
    readonly glyph: GlyphKind;
    readonly text: string;
    readonly correlationId?: string | null;
  } | null>(null);
  const [versionConflictError, setVersionConflictError] = useState<AuthProblemSummary | null>(null);

  // Accessible field IDs
  const createNameId = useId();
  const createAppIdField = useId();
  const createClientIdField = useId();
  const createBaseUrlField = useId();
  const createPemField = useId();
  const createWebhookField = useId();
  const confirmInstallIdField = useId();
  const confirmStateField = useId();
  const rotateNameField = useId();
  const rotateBaseUrlField = useId();
  const rotatePemField = useId();
  const rotateWebhookField = useId();
  const revokeConfirmField = useId();

  const connectionsQuery = useQuery({
    queryKey: ["workspace", wsSlug, "integrations", "github"],
    queryFn: () => api.listConnections(wsSlug, { provider: "github", limit: 50 }),
  });

  const connections = useMemo<readonly Connection[]>(
    () => connectionsQuery.data?.data.items ?? [],
    [connectionsQuery.data],
  );

  const callbackValidationQuery = useQuery({
    queryKey: [
      "integrations",
      "github-callback",
      callbackStateParam,
      callbackInstallationParam,
      callbackSetupActionParam,
    ],
    queryFn: () =>
      api.handleGitHubCallback({
        state: callbackStateParam,
        installation_id: callbackInstallationParam,
        setup_action: callbackSetupActionParam,
      }),
    enabled: Boolean(callbackStateParam || callbackInstallationParam),
    retry: false,
  });

  const validatedCallback = callbackValidationQuery.data?.data ?? null;

  const effectiveSelectedConnectionId = useMemo<string | null>(() => {
    if (selectedConnectionId !== null && connections.some((c) => c.id === selectedConnectionId)) {
      return selectedConnectionId;
    }
    if (
      validatedCallback !== null &&
      connections.some((c) => c.id === validatedCallback.connection_id)
    ) {
      return validatedCallback.connection_id;
    }
    return connections[0]?.id ?? validatedCallback?.connection_id ?? null;
  }, [connections, selectedConnectionId, validatedCallback]);

  const effectiveConfirmInstallationId =
    confirmInstallationIdOverride ??
    validatedCallback?.installation_id ??
    callbackInstallationParam ??
    "";
  const effectiveConfirmStateNonce =
    confirmStateNonceOverride ?? (validatedCallback ? (callbackStateParam ?? "") : "");

  const detailQuery = useQuery({
    queryKey: ["workspace", wsSlug, "integrations", "detail", effectiveSelectedConnectionId],
    queryFn: () => api.getConnection(wsSlug, effectiveSelectedConnectionId ?? ""),
    enabled: effectiveSelectedConnectionId !== null,
  });

  const refreshIntegrations = useCallback(async () => {
    await invalidateWorkspaceQueries(queryClient, wsSlug);
    await connectionsQuery.refetch();
    if (effectiveSelectedConnectionId !== null) {
      await detailQuery.refetch();
    }
  }, [connectionsQuery, detailQuery, effectiveSelectedConnectionId, queryClient, wsSlug]);

  const createMutation = useMutation({
    mutationFn: async () => {
      const pem = createPrivateKeyPem.trim();
      const wh = createWebhookSecret.trim();
      // Immediately scrub plaintext secret inputs from React component state before network await
      setCreatePrivateKeyPem("");
      setCreateWebhookSecret("");
      return api.createConnection(
        wsSlug,
        {
          provider: "github",
          auth_mode: "github_app",
          display_name: createDisplayName.trim() || null,
          app_id: createAppId.trim(),
          client_id: createClientId.trim() || null,
          base_url: createBaseUrl.trim(),
          private_key_pem: pem || null,
          webhook_secret: wh || null,
        },
        { idempotencyKey: generateClientUuidV7() },
      );
    },
    onSuccess: async (res) => {
      setCreateOpen(false);
      setCreateDisplayName("");
      setCreateAppId("");
      setCreateClientId("");
      setSelectedConnectionId(res.data.id);
      setFeedbackBanner({
        tone: "success",
        glyph: "check",
        text: `GitHub App connection "${sanitizeUntrustedText(res.data.display_name ?? res.data.id).text}" created and credentials sealed in SecretBroker.`,
        correlationId: res.correlationId,
      });
      announce("GitHub App connection created.");
      await refreshIntegrations();
    },
    onError: (err) => {
      const prob = extractAuthProblemSummary(err, t("state.error.description"));
      setFeedbackBanner({
        tone: "danger",
        glyph: "error",
        text: prob.detail,
        correlationId: prob.correlationId,
      });
    },
  });

  const mintStateMutation = useMutation({
    mutationFn: async (connectionId: string) => {
      const currentOrigin =
        typeof window !== "undefined" && window.location?.origin
          ? window.location.origin
          : "http://127.0.0.1:4280";
      return api.mintGitHubInstallState(
        wsSlug,
        connectionId,
        { expected_origin: currentOrigin },
        { idempotencyKey: generateClientUuidV7() },
      );
    },
    onSuccess: (res) => {
      setMintedState(res.data);
      setConfirmStateNonceOverride(res.data.state);
      setFeedbackBanner({
        tone: "info",
        glyph: "clock",
        text: "Minted single-use 10-minute GitHub App callback state nonce. Install the App on GitHub or paste your installation ID below to confirm.",
        correlationId: res.correlationId,
      });
      announce("Single-use GitHub installation state minted.");
    },
    onError: (err) => {
      const prob = extractAuthProblemSummary(err, t("state.error.description"));
      setFeedbackBanner({
        tone: "danger",
        glyph: "error",
        text: prob.detail,
        correlationId: prob.correlationId,
      });
    },
  });

  const confirmInstallMutation = useMutation({
    mutationFn: async (connectionId: string) => {
      return api.confirmGitHubInstallation(
        wsSlug,
        connectionId,
        {
          installation_id: effectiveConfirmInstallationId.trim(),
          state: effectiveConfirmStateNonce.trim(),
        },
        { idempotencyKey: generateClientUuidV7() },
      );
    },
    onSuccess: async (res) => {
      setMintedState(null);
      setConfirmStateNonceOverride(null);
      setConfirmInstallationIdOverride(null);
      if (callbackStateParam || callbackInstallationParam) {
        setSearchParams({}, { replace: true });
      }
      const repoTotal = res.data.repositories?.length ?? 0;
      const tone = res.data.partial_sync || res.data.grant_review_required ? "warning" : "success";
      setFeedbackBanner({
        tone,
        glyph: tone === "warning" ? "warn" : "check",
        text: res.data.grant_review_required
          ? `Reconnected installation ${sanitizeUntrustedText(res.data.connection.installation_id ?? "").text} (${repoTotal} repositories reset to Monitor mode — explicit grant review required).`
          : `Confirmed GitHub App installation ${sanitizeUntrustedText(res.data.connection.installation_id ?? "").text} and discovered ${repoTotal} repositories in Monitor mode.`,
        correlationId: res.correlationId,
      });
      announce(`Confirmed GitHub App installation with ${repoTotal} repositories.`);
      await refreshIntegrations();
    },
    onError: (err) => {
      const prob = extractAuthProblemSummary(err, t("state.error.description"));
      setFeedbackBanner({
        tone: "danger",
        glyph: "error",
        text: prob.detail,
        correlationId: prob.correlationId,
      });
    },
  });

  const probeMutation = useMutation({
    mutationFn: async (connectionId: string) => {
      return api.probeConnection(wsSlug, connectionId, {
        idempotencyKey: generateClientUuidV7(),
      });
    },
    onSuccess: async (res) => {
      const st = res.data.connection.status;
      setFeedbackBanner({
        tone: st === "ready" ? "success" : st === "revoked" ? "danger" : "warning",
        glyph: st === "ready" ? "check" : st === "revoked" ? "error" : "warn",
        text: sanitizeUntrustedText(
          res.data.snapshot.detail ?? `Capability probe completed with status: ${st}.`,
        ).text,
        correlationId: res.correlationId,
      });
      announce(`Capability probe finished: ${st}.`);
      await refreshIntegrations();
    },
    onError: (err) => {
      const prob = extractAuthProblemSummary(err, t("state.error.description"));
      setFeedbackBanner({
        tone: "danger",
        glyph: "error",
        text: prob.detail,
        correlationId: prob.correlationId,
      });
    },
  });

  const syncMutation = useMutation({
    mutationFn: async (connectionId: string) => {
      return api.syncConnection(wsSlug, connectionId, {
        idempotencyKey: generateClientUuidV7(),
      });
    },
    onSuccess: async (res) => {
      setFeedbackBanner({
        tone: res.data.partial_sync ? "warning" : "success",
        glyph: res.data.partial_sync ? "warn" : "check",
        text: res.data.partial_sync
          ? `Partial repository sync preserved ${res.data.discovered_count} repositories after upstream pagination warning.`
          : `Synchronized ${res.data.discovered_count} repositories (${res.data.flagged_hazard_count ?? 0} flagged with workflow hazards).`,
        correlationId: res.correlationId,
      });
      announce(`Synchronized ${res.data.discovered_count} repositories.`);
      await refreshIntegrations();
    },
    onError: async (err) => {
      const prob = extractAuthProblemSummary(err, t("state.error.description"));
      setFeedbackBanner({
        tone: "danger",
        glyph: "error",
        text: prob.detail,
        correlationId: prob.correlationId,
      });
      await refreshIntegrations();
    },
  });

  const rotateMutation = useMutation({
    mutationFn: async (params: { readonly connection: Connection; readonly etag: string | null }) => {
      const pem = rotatePrivateKeyPem.trim();
      const wh = rotateWebhookSecret.trim();
      setRotatePrivateKeyPem("");
      setRotateWebhookSecret("");
      return api.updateConnection(
        wsSlug,
        params.connection.id,
        {
          expected_version: params.connection.version,
          display_name: rotateDisplayName.trim() || null,
          base_url: rotateBaseUrl.trim() || null,
          private_key_pem: pem || null,
          webhook_secret: wh || null,
        },
        {
          idempotencyKey: generateClientUuidV7(),
          ifMatch: params.etag ?? `"v${params.connection.version}"`,
        },
      );
    },
    onSuccess: async (res) => {
      setRotateOpen(false);
      setVersionConflictError(null);
      setFeedbackBanner({
        tone: "success",
        glyph: "check",
        text: `Updated connection "${sanitizeUntrustedText(res.data.display_name ?? res.data.id).text}" (v${res.data.version}).`,
        correlationId: res.correlationId,
      });
      announce("GitHub App connection updated.");
      await refreshIntegrations();
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError && (err.status === 409 || err.status === 412)) {
        setRotateOpen(false);
        setVersionConflictError(extractAuthProblemSummary(err, t("state.error.description")));
        return;
      }
      const prob = extractAuthProblemSummary(err, t("state.error.description"));
      setFeedbackBanner({
        tone: "danger",
        glyph: "error",
        text: prob.detail,
        correlationId: prob.correlationId,
      });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: async (connectionId: string) => {
      return api.deleteConnection(wsSlug, connectionId, {
        idempotencyKey: generateClientUuidV7(),
      });
    },
    onSuccess: async (res) => {
      setRevokeOpen(false);
      setRevokeConfirmText("");
      setFeedbackBanner({
        tone: "warning",
        glyph: "warn",
        text: "Connection disconnected: stored secrets revoked, cached JIT tokens purged, and active repository jobs suspended.",
        correlationId: res.correlationId,
      });
      announce("GitHub App connection disconnected and revoked.");
      await refreshIntegrations();
    },
    onError: (err) => {
      const prob = extractAuthProblemSummary(err, t("state.error.description"));
      setFeedbackBanner({
        tone: "danger",
        glyph: "error",
        text: prob.detail,
        correlationId: prob.correlationId,
      });
    },
  });

  const selectedDetail = detailQuery.data?.data ?? null;
  const selectedConnection: Connection | null =
    selectedDetail?.connection ??
    connections.find((c) => c.id === effectiveSelectedConnectionId) ??
    null;
  const selectedEtag = detailQuery.data?.etag ?? null;
  const discoveredRepos = useMemo<RepositoryRow[]>(
    () => (selectedDetail?.repositories ?? []).map((r) => ({ ...r })),
    [selectedDetail?.repositories],
  );

  const repoColumns = useMemo<TableColumn<RepositoryRow>[]>(
    () => [
      {
        key: "name",
        header: "Repository",
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span style={{ fontWeight: 600 }}>{sanitizeUntrustedText(row.name).text}</span>
            <span className="red2pr-field-hint">
              ext:{sanitizeUntrustedText(row.external_id).text} · branch{" "}
              <code>{sanitizeUntrustedText(row.default_branch).text}</code>
            </span>
          </div>
        ),
      },
      {
        key: "visibility",
        header: "Posture",
        renderCell: (row) => (
          <div className="red2pr-button-row" style={{ gap: 6 }}>
            <span className="red2pr-badge-pill red2pr-tone-neutral">
              <StatusGlyph kind={row.visibility === "private" ? "lock" : "info"} />
              <span>{row.visibility}</span>
            </span>
            {row.is_fork ? (
              <span className="red2pr-badge-pill red2pr-tone-warning">
                <StatusGlyph kind="warn" />
                <span>Fork</span>
              </span>
            ) : null}
            {row.archived ? (
              <span className="red2pr-badge-pill red2pr-tone-neutral">
                <StatusGlyph kind="clock" />
                <span>Archived</span>
              </span>
            ) : null}
          </div>
        ),
      },
      {
        key: "mode",
        header: "Automation Mode",
        renderCell: (row) => (
          <span className="red2pr-badge-pill red2pr-tone-info">
            <StatusGlyph kind={row.paused ? "clock" : "info"} />
            <span>{row.paused ? `${row.mode} (paused)` : row.mode}</span>
          </span>
        ),
      },
      {
        key: "hazards",
        header: "Workflow Security (SEC-031)",
        renderCell: (row) => {
          const app = hazardStatusAppearance(row.workflow_hazard_status);
          const hazards = row.workflow_hazards ?? [];
          return (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <div>
                <span className={`red2pr-badge-pill ${app.tone}`}>
                  <StatusGlyph kind={app.glyph} />
                  <span>{app.label}</span>
                </span>
              </div>
              {hazards.length > 0 ? (
                <ul
                  style={{ margin: 0, paddingLeft: 18, fontSize: "0.78rem" }}
                  aria-label={`Workflow hazards for ${sanitizeUntrustedText(row.name).text}`}
                >
                  {hazards.map((h, idx) => (
                    <li key={`${h.workflow_path}-${h.code}-${idx}`}>
                      <code>{sanitizeUntrustedText(h.code).text}</code> in{" "}
                      <code>{sanitizeUntrustedText(h.workflow_path).text}</code>:{" "}
                      {sanitizeUntrustedText(h.detail).text}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          );
        },
      },
    ],
    [],
  );

  if (connectionsQuery.isPending) {
    return <StateView state="loading" />;
  }

  if (connectionsQuery.isError) {
    const errSummary = extractAuthProblemSummary(
      connectionsQuery.error,
      t("state.error.description"),
    );
    const uxState =
      errSummary.status === null
        ? "offline"
        : errSummary.status === 403
          ? "forbidden"
          : errSummary.status === 429
            ? "rate_limited"
            : "error";
    return (
      <StateView
        state={uxState}
        description={errSummary.detail}
        correlationId={errSummary.correlationId ?? undefined}
        primaryAction={{
          label: "Retry",
          onClick: () => {
            void connectionsQuery.refetch();
          },
        }}
      />
    );
  }

  const sanitizedInstallUrl = sanitizeNavigationHref(mintedState?.install_url ?? null);

  return (
    <div className="red2pr-page-stack" data-testid="github-integration-panel">
      {!isAdmin ? (
        <div
          role="status"
          className="red2pr-inline-alert red2pr-tone-info"
          data-testid="github-readonly-rbac-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="lock" />
            <span>
              Read-only workspace access ({effectiveRole ?? "viewer"}): only Workspace
              Administrators can configure credentials, bind installations, or revoke connections.
            </span>
          </div>
        </div>
      ) : null}

      {callbackValidationQuery.isError ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-danger"
          data-testid="github-callback-error-banner"
        >
          {(() => {
            const cbErr = extractAuthProblemSummary(
              callbackValidationQuery.error,
              "GitHub installation callback validation failed.",
            );
            return (
              <>
                <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                  <StatusGlyph kind="error" />
                  <span>Callback rejected: {cbErr.detail}</span>
                </div>
                {cbErr.correlationId ? (
                  <span className="red2pr-field-hint">
                    Correlation ID: {cbErr.correlationId}
                  </span>
                ) : null}
              </>
            );
          })()}
        </div>
      ) : null}

      {callbackValidationQuery.data?.data.state_valid ? (
        <div
          role="status"
          className="red2pr-inline-alert red2pr-tone-info"
          data-testid="github-callback-verified-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="check" />
            <span>
              GitHub callback state verified (read-only). Review the installation ID below and
              confirm binding to activate Monitor discovery.
            </span>
          </div>
        </div>
      ) : null}

      {versionConflictError !== null ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-warning"
          data-testid="github-version-conflict-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="warn" />
            <span>
              Concurrent modification detected ({versionConflictError.code}):{" "}
              {versionConflictError.detail}
            </span>
          </div>
          <div className="red2pr-button-row">
            <Button
              label="Reload authoritative connection"
              variant="secondary"
              size="sm"
              onClick={() => {
                setVersionConflictError(null);
                void refreshIntegrations();
              }}
            />
          </div>
        </div>
      ) : null}

      {feedbackBanner !== null ? (
        <div
          role={feedbackBanner.tone === "danger" ? "alert" : "status"}
          className={`red2pr-inline-alert red2pr-tone-${feedbackBanner.tone}`}
          data-testid="github-feedback-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind={feedbackBanner.glyph} />
            <span>{feedbackBanner.text}</span>
          </div>
          {feedbackBanner.correlationId ? (
            <span className="red2pr-field-hint">
              Correlation ID: {feedbackBanner.correlationId}
            </span>
          ) : null}
        </div>
      ) : null}

      {/* Top Toolbar & Connection Create Form */}
      <section
        className="red2pr-surface red2pr-card-section"
        aria-labelledby="gh-connections-heading"
      >
        <div className="red2pr-card-header">
          <div>
            <h2 id="gh-connections-heading" style={{ margin: 0, fontSize: "1.125rem" }}>
              GitHub App Connections
            </h2>
            <p className="red2pr-field-hint" style={{ marginTop: 4 }}>
              RS256 App JWTs (≤10m) and JIT repository-scoped installation tokens. Plaintext keys
              are sealed into Z2 SecretBroker and never returned by APIs.
            </p>
          </div>
          {isAdmin ? (
            <Button
              label={createOpen ? "Cancel new connection" : "Add GitHub App connection"}
              variant={createOpen ? "secondary" : "primary"}
              onClick={() => setCreateOpen((prev) => !prev)}
            />
          ) : null}
        </div>

        {isAdmin && createOpen ? (
          <form
            className="red2pr-form-stack"
            data-testid="github-create-connection-form"
            onSubmit={(event) => {
              event.preventDefault();
              setFeedbackBanner(null);
              createMutation.mutate();
            }}
          >
            <div className="red2pr-kv-grid">
              <div className="red2pr-field">
                <label htmlFor={createNameId} className="red2pr-field-label">
                  Connection display name
                </label>
                <input
                  id={createNameId}
                  className="red2pr-control-input"
                  type="text"
                  maxLength={120}
                  placeholder="Acme Production GitHub App"
                  value={createDisplayName}
                  onChange={(e) => setCreateDisplayName(e.target.value)}
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={createAppIdField} className="red2pr-field-label">
                  GitHub App ID (required)
                </label>
                <input
                  id={createAppIdField}
                  className="red2pr-control-input"
                  type="text"
                  required
                  maxLength={128}
                  placeholder="340122"
                  value={createAppId}
                  onChange={(e) => setCreateAppId(e.target.value)}
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={createClientIdField} className="red2pr-field-label">
                  Client ID (optional)
                </label>
                <input
                  id={createClientIdField}
                  className="red2pr-control-input"
                  type="text"
                  maxLength={128}
                  placeholder="Iv1.acme01"
                  value={createClientId}
                  onChange={(e) => setCreateClientId(e.target.value)}
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={createBaseUrlField} className="red2pr-field-label">
                  GitHub REST API base URL
                </label>
                <input
                  id={createBaseUrlField}
                  className="red2pr-control-input"
                  type="url"
                  required
                  maxLength={2048}
                  value={createBaseUrl}
                  onChange={(e) => setCreateBaseUrl(e.target.value)}
                />
              </div>
            </div>

            <div className="red2pr-field">
              <label htmlFor={createPemField} className="red2pr-field-label">
                RSA private key PEM (write-only · sealed in Z2 SecretBroker)
              </label>
              <textarea
                id={createPemField}
                className="red2pr-control-input"
                rows={4}
                autoComplete="off"
                spellCheck={false}
                placeholder="-----BEGIN PRIVATE KEY-----..."
                value={createPrivateKeyPem}
                onChange={(e) => setCreatePrivateKeyPem(e.target.value)}
              />
              <p className="red2pr-field-hint">
                Cleared from browser memory immediately on submit; never echoed or persisted in Web
                Storage.
              </p>
            </div>

            <div className="red2pr-field">
              <label htmlFor={createWebhookField} className="red2pr-field-label">
                Webhook HMAC secret (optional · write-only)
              </label>
              <input
                id={createWebhookField}
                className="red2pr-control-input"
                type="password"
                autoComplete="new-password"
                maxLength={512}
                value={createWebhookSecret}
                onChange={(e) => setCreateWebhookSecret(e.target.value)}
              />
            </div>

            <div className="red2pr-button-row">
              <Button
                label="Seal credentials & create connection"
                variant="primary"
                type="submit"
                isLoading={createMutation.isPending}
                isDisabled={
                  createAppId.trim().length === 0 ||
                  createBaseUrl.trim().length === 0 ||
                  createMutation.isPending
                }
              />
            </div>
          </form>
        ) : null}

        {connections.length === 0 ? (
          <StateView
            state="empty"
            title="No GitHub App connections configured"
            description={
              isAdmin
                ? "Register a GitHub App connection to verify permissions and discover repositories in safe Monitor mode."
                : "No GitHub App connection has been configured for this workspace yet."
            }
            primaryAction={
              isAdmin && !createOpen
                ? {
                    label: "Add GitHub App connection",
                    onClick: () => setCreateOpen(true),
                  }
                : undefined
            }
          />
        ) : (
          <div className="red2pr-tab-strip" role="group" aria-label={t("integrations.connectionsTableLabel")}>
            {connections.map((conn) => {
              const stApp = connectionStatusAppearance(conn.status);
              const isSelected = conn.id === selectedConnection?.id;
              return (
                <button
                  key={conn.id}
                  type="button"
                  className="red2pr-tab-button"
                  aria-pressed={isSelected}
                  onClick={() => setSelectedConnectionId(conn.id)}
                >
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                    <StatusGlyph kind={stApp.glyph} />
                    <span>
                      {sanitizeUntrustedText(conn.display_name ?? `App ${conn.app_id ?? conn.id}`).text}
                    </span>
                    <span className="red2pr-field-hint">({stApp.label})</span>
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </section>

      {/* Selected Connection Detail, A-23 Binding, Capabilities & Repositories */}
      {selectedConnection !== null ? (
        <section
          className="red2pr-surface red2pr-card-section"
          aria-labelledby="gh-selected-heading"
          data-testid="github-connection-detail"
        >
          <div className="red2pr-card-header">
            <div>
              <div className="red2pr-button-row" style={{ gap: 8 }}>
                <h2 id="gh-selected-heading" style={{ margin: 0, fontSize: "1.125rem" }}>
                  {
                    sanitizeUntrustedText(
                      selectedConnection.display_name ?? `GitHub App ${selectedConnection.app_id ?? ""}`,
                    ).text
                  }
                </h2>
                {(() => {
                  const stApp = connectionStatusAppearance(selectedConnection.status);
                  return (
                    <span
                      className={`red2pr-badge-pill ${stApp.tone}`}
                      data-testid="connection-status-badge"
                    >
                      <StatusGlyph kind={stApp.glyph} />
                      <span>{stApp.label}</span>
                    </span>
                  );
                })()}
              </div>
              <p className="red2pr-field-hint" style={{ marginTop: 4 }}>
                {sanitizeUntrustedText(
                  selectedConnection.status_detail ?? "Ready for capability inspection.",
                ).text}
              </p>
            </div>

            {isAdmin ? (
              <div className="red2pr-button-row">
                <Button
                  label="Probe capabilities"
                  variant="secondary"
                  size="sm"
                  isLoading={probeMutation.isPending}
                  onClick={() => probeMutation.mutate(selectedConnection.id)}
                />
                <Button
                  label="Sync repositories"
                  variant="secondary"
                  size="sm"
                  isLoading={syncMutation.isPending}
                  isDisabled={
                    !selectedConnection.installation_id ||
                    selectedConnection.status === "revoked" ||
                    syncMutation.isPending
                  }
                  onClick={() => syncMutation.mutate(selectedConnection.id)}
                />
                <Button
                  label="Rotate / edit"
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setRotateDisplayName(selectedConnection.display_name ?? "");
                    setRotateBaseUrl(selectedConnection.base_url);
                    setRotatePrivateKeyPem("");
                    setRotateWebhookSecret("");
                    setRotateOpen(true);
                  }}
                />
                <Button
                  label="Disconnect & revoke"
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    setRevokeConfirmText("");
                    setRevokeOpen(true);
                  }}
                />
              </div>
            ) : null}
          </div>

          {selectedConnection.status === "revoked" || selectedConnection.grant_review_required ? (
            <div
              role="status"
              className="red2pr-inline-alert red2pr-tone-warning"
              data-testid="github-reconnect-review-banner"
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                <StatusGlyph kind="warn" />
                <span>
                  {selectedConnection.status === "revoked"
                    ? "Connection revoked (SEC-011): active jobs were suspended and cached JIT installation tokens purged. Mint a fresh installation state to reconnect."
                    : "Reconnected after revocation (W-02): all repositories were forced back to Monitor mode. Explicitly review repository grants and policies before re-enabling automation."}
                </span>
              </div>
            </div>
          ) : null}

          <dl className="red2pr-kv-grid">
            <div className="red2pr-kv-item">
              <dt className="red2pr-kv-term">App ID / Installation ID</dt>
              <dd className="red2pr-kv-detail">
                App {sanitizeUntrustedText(selectedConnection.app_id ?? "—").text} · Install{" "}
                {sanitizeUntrustedText(selectedConnection.installation_id ?? "Unbound").text}
              </dd>
            </div>
            <div className="red2pr-kv-item">
              <dt className="red2pr-kv-term">Account & API Version</dt>
              <dd className="red2pr-kv-detail">
                {sanitizeUntrustedText(selectedConnection.account_login ?? "Pending verification").text} ·{" "}
                <code>{sanitizeUntrustedText(selectedConnection.api_version ?? "2026-03-10").text}</code>
              </dd>
            </div>
            <div className="red2pr-kv-item">
              <dt className="red2pr-kv-term">RSA Key Presence (Z2)</dt>
              <dd className="red2pr-kv-detail">
                {selectedConnection.secret_presence.configured
                  ? `Configured (v${selectedConnection.secret_presence.secret_version ?? 1})`
                  : "Not configured / Revoked"}
              </dd>
            </div>
            <div className="red2pr-kv-item">
              <dt className="red2pr-kv-term">Webhook Secret Presence</dt>
              <dd className="red2pr-kv-detail">
                {selectedConnection.webhook_secret_presence?.configured
                  ? `Configured (v${selectedConnection.webhook_secret_presence.secret_version ?? 1})`
                  : "Not configured"}
              </dd>
            </div>
            <div className="red2pr-kv-item">
              <dt className="red2pr-kv-term">Last Checked / Synced (UTC)</dt>
              <dd className="red2pr-kv-detail">
                {selectedConnection.checked_at
                  ? formatUtcTimestamp(selectedConnection.checked_at)
                  : "Never"}
              </dd>
            </div>
            <div className="red2pr-kv-item">
              <dt className="red2pr-kv-term">Entity Version</dt>
              <dd className="red2pr-kv-detail">v{selectedConnection.version}</dd>
            </div>
          </dl>

          {/* Capability & Permission Diff Matrix */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <h3 style={{ margin: 0, fontSize: "0.95rem" }}>
              Observed Capabilities & Permission Diff
            </h3>
            <div className="red2pr-button-row">
              {Object.entries(selectedConnection.capabilities ?? {}).map(([capName, avail]) => {
                const capApp = capabilityAppearance(avail);
                return (
                  <span key={capName} className={`red2pr-badge-pill ${capApp.tone}`}>
                    <StatusGlyph kind={capApp.glyph} />
                    <span>
                      {sanitizeUntrustedText(capName).text}: {capApp.label}
                    </span>
                  </span>
                );
              })}
            </div>
            {Object.keys(selectedConnection.granted_permissions ?? {}).length > 0 ? (
              <p className="red2pr-field-hint" data-testid="github-granted-permissions">
                <strong>Granted permissions:</strong>{" "}
                {Object.entries(selectedConnection.granted_permissions ?? {})
                  .map(([k, v]) => `${sanitizeUntrustedText(k).text}:${sanitizeUntrustedText(v).text}`)
                  .join(", ")}
              </p>
            ) : null}
            {(selectedConnection.missing_permissions ?? []).length > 0 ? (
              <div
                className="red2pr-inline-alert red2pr-tone-warning"
                data-testid="github-missing-permissions"
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                  <StatusGlyph kind="warn" />
                  <span>
                    Missing permissions:{" "}
                    {(selectedConnection.missing_permissions ?? [])
                      .map((m) => sanitizeUntrustedText(m).text)
                      .join(", ")}
                  </span>
                </div>
              </div>
            ) : null}
          </div>

          {/* Two-step A-23 Installation State & Confirmation */}
          {isAdmin ? (
            <div
              className="red2pr-surface red2pr-card-section"
              style={{ backgroundColor: "var(--red2pr-bg-subtle)" }}
              data-testid="github-installation-binding-box"
            >
              <div className="red2pr-card-header">
                <div>
                  <h3 style={{ margin: 0, fontSize: "0.95rem" }}>
                    GitHub App Installation Binding (A-23 Single-Use State)
                  </h3>
                  <p className="red2pr-field-hint" style={{ marginTop: 4 }}>
                    Installation IDs on redirect URLs are never trusted without a single-use
                    10-minute state nonce bound to your session and workspace.
                  </p>
                </div>
                <Button
                  label="Mint 10m install state"
                  variant="secondary"
                  size="sm"
                  isLoading={mintStateMutation.isPending}
                  onClick={() => mintStateMutation.mutate(selectedConnection.id)}
                />
              </div>

              {mintedState !== null && mintedState.connection_id === selectedConnection.id ? (
                <div
                  className="red2pr-inline-alert red2pr-tone-info"
                  data-testid="github-minted-state-box"
                >
                  <div>
                    <strong>Active single-use state:</strong>{" "}
                    <code>{mintedState.state}</code> (expires{" "}
                    {formatUtcTimestamp(mintedState.expires_at)})
                  </div>
                  {sanitizedInstallUrl ? (
                    <div>
                      <a
                        href={sanitizedInstallUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ fontWeight: 600 }}
                      >
                        Open GitHub App installation settings in new tab
                      </a>
                    </div>
                  ) : null}
                </div>
              ) : null}

              <form
                className="red2pr-form-stack"
                onSubmit={(event) => {
                  event.preventDefault();
                  setFeedbackBanner(null);
                  confirmInstallMutation.mutate(selectedConnection.id);
                }}
              >
                <div className="red2pr-kv-grid">
                  <div className="red2pr-field">
                    <label htmlFor={confirmInstallIdField} className="red2pr-field-label">
                      GitHub Installation ID
                    </label>
                    <input
                      id={confirmInstallIdField}
                      className="red2pr-control-input"
                      type="text"
                      required
                      maxLength={128}
                      placeholder="99001"
                      value={effectiveConfirmInstallationId}
                      onChange={(e) => setConfirmInstallationIdOverride(e.target.value)}
                    />
                  </div>
                  <div className="red2pr-field">
                    <label htmlFor={confirmStateField} className="red2pr-field-label">
                      Single-use callback state nonce
                    </label>
                    <input
                      id={confirmStateField}
                      className="red2pr-control-input"
                      type="text"
                      required
                      minLength={16}
                      maxLength={256}
                      placeholder="st_..."
                      value={effectiveConfirmStateNonce}
                      onChange={(e) => setConfirmStateNonceOverride(e.target.value)}
                    />
                  </div>
                </div>
                <div className="red2pr-button-row">
                  <Button
                    label="Confirm & bind installation"
                    variant="primary"
                    size="sm"
                    type="submit"
                    isLoading={confirmInstallMutation.isPending}
                    isDisabled={
                      effectiveConfirmInstallationId.trim().length === 0 ||
                      effectiveConfirmStateNonce.trim().length < 16 ||
                      confirmInstallMutation.isPending
                    }
                  />
                </div>
              </form>
            </div>
          ) : null}

          {/* Discovered Repositories & Workflow Hazard Scanner Table */}
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <h3 style={{ margin: 0, fontSize: "0.95rem" }}>
              Discovered Repositories ({discoveredRepos.length})
            </h3>
            {detailQuery.isPending ? (
              <StateView state="loading" />
            ) : (
              <Table
                aria-label={t("integrations.reposTableLabel")}
                columns={repoColumns}
                data={discoveredRepos}
                emptyTitle="No repositories bound yet"
                emptyDescription={
                  isAdmin
                    ? "Mint an installation state and confirm your GitHub App installation to discover repositories in Monitor mode."
                    : "No repositories are currently granted to your role under this connection."
                }
              />
            )}
          </div>
        </section>
      ) : null}

      {selectedConnection !== null ? (
        <ConnectionPollingReconcileCard
          workspaceSlug={wsSlug}
          connection={selectedConnection}
          repositories={selectedDetail?.repositories ?? []}
          syncCursors={selectedDetail?.sync_cursors ?? []}
          isAdmin={isAdmin}
          onReconciled={async (result) => {
            setFeedbackBanner({
              tone: result.tone,
              glyph:
                result.tone === "success"
                  ? "check"
                  : result.tone === "danger"
                    ? "error"
                    : "warn",
              text: result.text,
              correlationId: result.correlationId,
            });
            await refreshIntegrations();
          }}
        />
      ) : null}

      {/* Rotate Credentials / Edit Connection Dialog */}
      {selectedConnection !== null ? (
        <Dialog
          isOpen={rotateOpen}
          onOpenChange={setRotateOpen}
          title="Rotate Credentials or Update Connection"
          subtitle={`Optimistic concurrency guard bound to v${selectedConnection.version}. Leave secret fields blank to preserve current sealed credentials.`}
          purpose="form"
          data-testid="github-rotate-dialog"
          footer={
            <div className="red2pr-button-row">
              <Button
                label="Cancel"
                variant="secondary"
                onClick={() => setRotateOpen(false)}
              />
              <Button
                label="Save & rotate"
                variant="primary"
                isLoading={rotateMutation.isPending}
                onClick={() =>
                  rotateMutation.mutate({
                    connection: selectedConnection,
                    etag: selectedEtag,
                  })
                }
              />
            </div>
          }
        >
          <div className="red2pr-form-stack">
            <div className="red2pr-field">
              <label htmlFor={rotateNameField} className="red2pr-field-label">
                Display name
              </label>
              <input
                id={rotateNameField}
                className="red2pr-control-input"
                type="text"
                maxLength={120}
                value={rotateDisplayName}
                onChange={(e) => setRotateDisplayName(e.target.value)}
              />
            </div>
            <div className="red2pr-field">
              <label htmlFor={rotateBaseUrlField} className="red2pr-field-label">
                GitHub REST API base URL
              </label>
              <input
                id={rotateBaseUrlField}
                className="red2pr-control-input"
                type="url"
                maxLength={2048}
                value={rotateBaseUrl}
                onChange={(e) => setRotateBaseUrl(e.target.value)}
              />
            </div>
            <div className="red2pr-field">
              <label htmlFor={rotatePemField} className="red2pr-field-label">
                Replacement RSA private key PEM (optional · write-only)
              </label>
              <textarea
                id={rotatePemField}
                className="red2pr-control-input"
                rows={4}
                autoComplete="off"
                spellCheck={false}
                value={rotatePrivateKeyPem}
                onChange={(e) => setRotatePrivateKeyPem(e.target.value)}
              />
            </div>
            <div className="red2pr-field">
              <label htmlFor={rotateWebhookField} className="red2pr-field-label">
                Replacement webhook secret (optional · write-only)
              </label>
              <input
                id={rotateWebhookField}
                className="red2pr-control-input"
                type="password"
                autoComplete="new-password"
                value={rotateWebhookSecret}
                onChange={(e) => setRotateWebhookSecret(e.target.value)}
              />
            </div>
          </div>
        </Dialog>
      ) : null}

      {/* Destructive Disconnect & Revoke Confirmation Dialog */}
      {selectedConnection !== null ? (
        <Dialog
          isOpen={revokeOpen}
          onOpenChange={setRevokeOpen}
          title="Disconnect & Revoke GitHub App Connection"
          subtitle="This immediately revokes stored SecretBroker keys, purges cached JIT installation tokens, pauses repositories in Monitor mode, and cancels/suspends active queue jobs (SEC-011)."
          purpose="form"
          data-testid="github-revoke-dialog"
          footer={
            <div className="red2pr-button-row">
              <Button
                label="Keep connection"
                variant="secondary"
                onClick={() => setRevokeOpen(false)}
              />
              <Button
                label="Confirm disconnect & revoke"
                variant="destructive"
                isLoading={revokeMutation.isPending}
                isDisabled={
                  revokeConfirmText.trim() !==
                    (selectedConnection.display_name ?? selectedConnection.id) ||
                  revokeMutation.isPending
                }
                onClick={() => revokeMutation.mutate(selectedConnection.id)}
              />
            </div>
          }
        >
          <div className="red2pr-form-stack">
            <div className="red2pr-field">
              <label htmlFor={revokeConfirmField} className="red2pr-field-label">
                Type{" "}
                <code>
                  {
                    sanitizeUntrustedText(
                      selectedConnection.display_name ?? selectedConnection.id,
                    ).text
                  }
                </code>{" "}
                to confirm revocation
              </label>
              <input
                id={revokeConfirmField}
                className="red2pr-control-input"
                type="text"
                autoComplete="off"
                value={revokeConfirmText}
                onChange={(e) => setRevokeConfirmText(e.target.value)}
              />
            </div>
          </div>
        </Dialog>
      ) : null}
    </div>
  );
}
