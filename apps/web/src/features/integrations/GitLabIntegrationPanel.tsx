import {
  Red2PrApiError,
  type CapabilityAvailability,
  type Connection,
  type ConnectionAuthMode,
  type ConnectionStatus,
  type MeResponse,
  type Repository,
  type WorkflowHazardStatus,
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
import { generateClientUuidV7 } from "../queues/QueuesPage";

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";
type RepositoryRow = Repository & Record<string, unknown>;
type GitLabPinnedAuthMode = Extract<
  ConnectionAuthMode,
  "gitlab_signed_v19" | "gitlab_legacy_token"
>;

export interface GitLabIntegrationPanelProps {
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
      return { glyph: "warn", tone: "red2pr-tone-danger", label: "Unsupported Auth Mode" };
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
      return { glyph: "check", tone: "red2pr-tone-success", label: "Clean .gitlab-ci.yml" };
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

function formatPinnedAuthBadge(authMode: ConnectionAuthMode): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
  readonly assuranceNote: string;
} {
  if (authMode === "gitlab_signed_v19" || authMode === "signed_webhook") {
    return {
      glyph: "lock",
      tone: "red2pr-tone-success",
      label: "Pinned: Signed v19 HMAC",
      assuranceNote:
        "GitLab 19.0+/19.1 Standard Webhooks HMAC (webhook-signature + 5m timestamp window). Never falls back to X-Gitlab-Token.",
    };
  }
  return {
    glyph: "warn",
    tone: "red2pr-tone-warning",
    label: "Pinned: Legacy X-Gitlab-Token (TLS)",
    assuranceNote:
      "Constant-time X-Gitlab-Token header verification over HTTPS/TLS (lower replay assurance; relies on semantic dedup & API reconciliation).",
  };
}

export function GitLabIntegrationPanel({
  workspace,
  me,
}: GitLabIntegrationPanelProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const announce = useLiveAnnouncer();

  const wsSlug = workspace.slug ?? workspace.id;
  const effectiveRole = useMemo(() => resolveEffectiveRole(workspace, me), [me, workspace]);
  const isAdmin = effectiveRole === "admin";

  // Create GitLab connection form state (write-only secrets wiped immediately before await)
  const [createOpen, setCreateOpen] = useState(false);
  const [createDisplayName, setCreateDisplayName] = useState("");
  const [createBaseUrl, setCreateBaseUrl] = useState("https://gitlab.com");
  const [createAuthMode, setCreateAuthMode] =
    useState<GitLabPinnedAuthMode>("gitlab_signed_v19");
  const [createAccessToken, setCreateAccessToken] = useState("");
  const [createWebhookSecret, setCreateWebhookSecret] = useState("");

  // Selected connection state (derived without useEffect setState)
  const [selectedConnectionId, setSelectedConnectionId] = useState<string | null>(null);

  // Rotate / Update dialog state
  const [rotateOpen, setRotateOpen] = useState(false);
  const [rotateDisplayName, setRotateDisplayName] = useState("");
  const [rotateBaseUrl, setRotateBaseUrl] = useState("");
  const [rotateAccessToken, setRotateAccessToken] = useState("");
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
  const createBaseUrlField = useId();
  const createAuthModeField = useId();
  const createTokenField = useId();
  const createWebhookField = useId();
  const rotateNameField = useId();
  const rotateBaseUrlField = useId();
  const rotateTokenField = useId();
  const rotateWebhookField = useId();
  const revokeConfirmField = useId();

  const connectionsQuery = useQuery({
    queryKey: ["workspace", wsSlug, "integrations", "gitlab"],
    queryFn: async () => {
      const res = await api.listConnections(wsSlug, { provider: "gitlab", limit: 50 });
      return res.data;
    },
  });

  const connections = useMemo<readonly Connection[]>(
    () => connectionsQuery.data?.items ?? [],
    [connectionsQuery.data],
  );

  const effectiveSelectedConnectionId = useMemo<string | null>(() => {
    if (
      selectedConnectionId !== null &&
      connections.some((item) => item.id === selectedConnectionId)
    ) {
      return selectedConnectionId;
    }
    return connections[0]?.id ?? null;
  }, [connections, selectedConnectionId]);

  const detailQuery = useQuery({
    queryKey: [
      "workspace",
      wsSlug,
      "integrations",
      "gitlab",
      "detail",
      effectiveSelectedConnectionId,
    ],
    enabled: effectiveSelectedConnectionId !== null,
    queryFn: async () => {
      const res = await api.getConnection(wsSlug, effectiveSelectedConnectionId!);
      return {
        detail: res.data,
        etag: res.etag ?? `"v${res.data.connection.version}"`,
      };
    },
  });

  const refreshIntegrations = useCallback(async () => {
    await invalidateWorkspaceQueries(queryClient, wsSlug);
    await connectionsQuery.refetch();
    if (effectiveSelectedConnectionId !== null) {
      await detailQuery.refetch();
    }
  }, [connectionsQuery, detailQuery, effectiveSelectedConnectionId, queryClient, wsSlug]);

  const handleMutationError = useCallback(
    (err: unknown, fallbackMessage: string) => {
      const summary = extractAuthProblemSummary(err, fallbackMessage);
      if (err instanceof Red2PrApiError && (err.status === 409 || err.status === 412)) {
        setVersionConflictError(summary);
      }
      setFeedbackBanner({
        tone: "danger",
        glyph: "error",
        text: summary.detail,
        correlationId: summary.correlationId,
      });
      announce(summary.detail);
    },
    [announce],
  );

  const createMutation = useMutation({
    mutationFn: async (input: {
      readonly displayName: string;
      readonly baseUrl: string;
      readonly authMode: GitLabPinnedAuthMode;
      readonly accessToken: string;
      readonly webhookSecret: string;
    }) => {
      return api.createConnection(
        wsSlug,
        {
          provider: "gitlab",
          base_url: input.baseUrl.trim(),
          auth_mode: input.authMode,
          display_name: input.displayName.trim() || undefined,
          access_token: input.accessToken.trim(),
          webhook_secret: input.webhookSecret.trim() || undefined,
        },
        { idempotencyKey: generateClientUuidV7() },
      );
    },
    onSuccess: async (res) => {
      setCreateOpen(false);
      setCreateDisplayName("");
      setCreateBaseUrl("https://gitlab.com");
      setCreateAuthMode("gitlab_signed_v19");
      setSelectedConnectionId(res.data.id);
      setFeedbackBanner({
        tone: "success",
        glyph: "check",
        text: `GitLab connection "${sanitizeUntrustedText(res.data.display_name ?? res.data.base_url).text}" sealed in Z2 vault with pinned ${res.data.auth_mode}. Run Probe capabilities to negotiate server version and token scopes.`,
        correlationId: res.correlationId,
      });
      announce("GitLab connection created and credentials sealed in Z2 vault.");
      await refreshIntegrations();
    },
    onError: (err) => handleMutationError(err, "Failed to create GitLab connection."),
  });

  const probeMutation = useMutation({
    mutationFn: async (connectionId: string) => {
      return api.probeConnection(wsSlug, connectionId, {
        idempotencyKey: generateClientUuidV7(),
      });
    },
    onSuccess: async (res) => {
      const status = res.data.connection.status;
      const ver = res.data.connection.vendor_version ?? res.data.connection.api_version ?? "v4";
      const safeDetail = sanitizeUntrustedText(
        res.data.snapshot.detail ?? `GitLab capability probe completed (${ver}: ${status}).`,
      ).text;
      setFeedbackBanner({
        tone:
          status === "ready"
            ? "success"
            : status === "revoked" || status === "unsupported"
              ? "danger"
              : "warning",
        glyph:
          status === "ready"
            ? "check"
            : status === "revoked"
              ? "error"
              : "warn",
        text: safeDetail || `GitLab capability probe completed (${status}).`,
        correlationId: res.correlationId,
      });
      announce(`GitLab capability probe finished with status ${status}.`);
      await refreshIntegrations();
    },
    onError: (err) => handleMutationError(err, "GitLab capability probe failed."),
  });

  const syncMutation = useMutation({
    mutationFn: async (connectionId: string) => {
      return api.syncConnection(wsSlug, connectionId, {
        idempotencyKey: generateClientUuidV7(),
      });
    },
    onSuccess: async (res) => {
      const partial = res.data.partial_sync;
      const hazards = res.data.flagged_hazard_count ?? 0;
      setFeedbackBanner({
        tone: partial || hazards > 0 ? "warning" : "success",
        glyph: partial || hazards > 0 ? "warn" : "check",
        text: partial
          ? `Partial project sync preserved existing catalog (${res.data.discovered_count} active projects).`
          : hazards > 0
            ? `Synchronized ${res.data.discovered_count} GitLab project(s); ${hazards} flagged for .gitlab-ci.yml deployment hazards (auto-repair blocked).`
            : `Synchronized ${res.data.discovered_count} GitLab project(s) cleanly in Monitor mode.`,
        correlationId: res.correlationId,
      });
      announce(`Synchronized ${res.data.discovered_count} GitLab projects.`);
      await refreshIntegrations();
    },
    onError: async (err) => {
      handleMutationError(err, "GitLab project synchronization failed.");
      await refreshIntegrations();
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (input: {
      readonly connection: Connection;
      readonly etag: string;
      readonly displayName: string;
      readonly baseUrl: string;
      readonly accessToken: string;
      readonly webhookSecret: string;
    }) => {
      return api.updateConnection(
        wsSlug,
        input.connection.id,
        {
          expected_version: input.connection.version,
          display_name: input.displayName.trim() || undefined,
          base_url: input.baseUrl.trim() || undefined,
          access_token: input.accessToken.trim() || undefined,
          webhook_secret: input.webhookSecret.trim() || undefined,
        },
        {
          idempotencyKey: generateClientUuidV7(),
          ifMatch: input.etag,
        },
      );
    },
    onSuccess: async (res) => {
      setRotateOpen(false);
      setVersionConflictError(null);
      setFeedbackBanner({
        tone: "success",
        glyph: "check",
        text: sanitizeUntrustedText(
          res.data.status_detail ?? "GitLab connection updated and write-only credentials rotated.",
        ).text,
        correlationId: res.correlationId,
      });
      announce("GitLab connection updated.");
      await refreshIntegrations();
    },
    onError: (err) => handleMutationError(err, "Failed to update GitLab connection."),
  });

  const deleteMutation = useMutation({
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
        text: "GitLab connection disconnected: Z2 tokens revoked, active task jobs suspended, and projects reset to Monitor.",
        correlationId: res.correlationId,
      });
      announce("GitLab connection disconnected and credentials revoked.");
      await refreshIntegrations();
    },
    onError: (err) => handleMutationError(err, "Failed to disconnect GitLab connection."),
  });

  const activeConnection: Connection | null =
    detailQuery.data?.detail.connection ??
    connections.find((c) => c.id === effectiveSelectedConnectionId) ??
    null;
  const activeSnapshot = detailQuery.data?.detail.latest_snapshot ?? null;
  const activeEtag =
    detailQuery.data?.etag ?? (activeConnection ? `"v${activeConnection.version}"` : '"v1"');

  const projectRows = useMemo<RepositoryRow[]>(
    () =>
      (detailQuery.data?.detail.repositories ?? []).map((repo) => ({
        ...repo,
      })),
    [detailQuery.data],
  );

  const projectColumns = useMemo<TableColumn<RepositoryRow>[]>(
    () => [
      {
        key: "name",
        header: "GitLab Project",
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span style={{ fontWeight: 600 }}>{sanitizeUntrustedText(row.name).text}</span>
            <span className="red2pr-field-hint">
              Project ID: <code>{sanitizeUntrustedText(row.external_id).text}</code>
              {row.is_fork ? " · Fork" : ""}
              {row.archived ? " · Archived" : ""}
            </span>
          </div>
        ),
      },
      {
        key: "visibility",
        header: "Visibility & Branch",
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <div>
              <span className="red2pr-badge-pill red2pr-tone-neutral">
                <StatusGlyph kind={row.visibility === "private" ? "lock" : "info"} />
                <span>{row.visibility}</span>
              </span>
            </div>
            <span className="red2pr-field-hint">
              Default: <code>{sanitizeUntrustedText(row.default_branch).text}</code>
            </span>
          </div>
        ),
      },
      {
        key: "mode",
        header: "Automation Mode",
        renderCell: (row) => (
          <span className="red2pr-badge-pill red2pr-tone-info">
            <StatusGlyph kind={row.paused ? "clock" : "info"} />
            <span>
              {row.paused
                ? `${row.mode} (paused)`
                : row.mode === "monitor"
                  ? "Monitor (Read-Only)"
                  : row.mode}
            </span>
          </span>
        ),
      },
      {
        key: "workflow_hazard_status",
        header: ".gitlab-ci.yml Hazard Posture",
        renderCell: (row) => {
          const badge = hazardStatusAppearance(row.workflow_hazard_status);
          const findings = row.workflow_hazards ?? [];
          return (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <div>
                <span className={`red2pr-badge-pill ${badge.tone}`}>
                  <StatusGlyph kind={badge.glyph} />
                  <span>{badge.label}</span>
                </span>
              </div>
              {findings.length > 0 ? (
                <ul
                  style={{
                    margin: 0,
                    paddingLeft: 18,
                    fontSize: "0.78rem",
                  }}
                  aria-label={`CI hazards for ${sanitizeUntrustedText(row.name).text}`}
                >
                  {findings.map((finding, idx) => (
                    <li key={`${finding.workflow_path}-${finding.code}-${idx}`}>
                      <code>{sanitizeUntrustedText(finding.workflow_path).text}</code>:{" "}
                      {sanitizeUntrustedText(finding.detail).text}
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

  const handleOpenRotateDialog = useCallback(() => {
    if (!activeConnection) {
      return;
    }
    setRotateDisplayName(activeConnection.display_name ?? "");
    setRotateBaseUrl(activeConnection.base_url);
    setRotateAccessToken("");
    setRotateWebhookSecret("");
    setRotateOpen(true);
  }, [activeConnection]);

  const handleCreateSubmit = useCallback(() => {
    const tokenCopy = createAccessToken;
    const webhookCopy = createWebhookSecret;
    // Wipe write-only secrets from component state immediately before network dispatch
    setCreateAccessToken("");
    setCreateWebhookSecret("");
    createMutation.mutate({
      displayName: createDisplayName,
      baseUrl: createBaseUrl,
      authMode: createAuthMode,
      accessToken: tokenCopy,
      webhookSecret: webhookCopy,
    });
  }, [
    createAccessToken,
    createAuthMode,
    createBaseUrl,
    createDisplayName,
    createMutation,
    createWebhookSecret,
  ]);

  const handleRotateSubmit = useCallback(() => {
    if (!activeConnection) {
      return;
    }
    const tokenCopy = rotateAccessToken;
    const webhookCopy = rotateWebhookSecret;
    setRotateAccessToken("");
    setRotateWebhookSecret("");
    updateMutation.mutate({
      connection: activeConnection,
      etag: activeEtag,
      displayName: rotateDisplayName,
      baseUrl: rotateBaseUrl,
      accessToken: tokenCopy,
      webhookSecret: webhookCopy,
    });
  }, [
    activeConnection,
    activeEtag,
    rotateAccessToken,
    rotateBaseUrl,
    rotateDisplayName,
    rotateWebhookSecret,
    updateMutation,
  ]);

  if (connectionsQuery.isPending) {
    return <StateView state="loading" />;
  }

  if (connectionsQuery.isError) {
    const summary = extractAuthProblemSummary(
      connectionsQuery.error,
      t("state.error.description"),
    );
    const uxState =
      summary.status === null
        ? "offline"
        : summary.status === 403
          ? "forbidden"
          : summary.status === 429
            ? "rate_limited"
            : "error";
    return (
      <StateView
        state={uxState}
        description={summary.detail}
        correlationId={summary.correlationId ?? undefined}
        primaryAction={{
          label: "Retry",
          onClick: () => {
            void connectionsQuery.refetch();
          },
        }}
      />
    );
  }

  const expectedRevokePhrase = activeConnection?.display_name ?? activeConnection?.id ?? "";
  const canConfirmRevoke =
    Boolean(activeConnection) &&
    revokeConfirmText.trim() === expectedRevokePhrase.trim() &&
    !deleteMutation.isPending;

  return (
    <div className="red2pr-page-stack" data-testid="gitlab-integration-panel">
      {!isAdmin ? (
        <div
          className="red2pr-inline-alert red2pr-tone-info"
          role="status"
          data-testid="gitlab-readonly-rbac-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="lock" />
            <span>
              Read-only workspace access ({effectiveRole ?? "viewer"}): only workspace admins can
              register GitLab connections, rotate write-only tokens, probe capabilities, or sync
              projects.
            </span>
          </div>
        </div>
      ) : null}

      {feedbackBanner !== null ? (
        <div
          className={`red2pr-inline-alert red2pr-tone-${feedbackBanner.tone}`}
          role={feedbackBanner.tone === "danger" ? "alert" : "status"}
          data-testid="gitlab-feedback-banner"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind={feedbackBanner.glyph} />
            <span>{feedbackBanner.text}</span>
          </div>
          {feedbackBanner.correlationId ? (
            <span className="red2pr-field-hint">
              Correlation ID: <code>{feedbackBanner.correlationId}</code>
            </span>
          ) : null}
        </div>
      ) : null}

      {versionConflictError !== null ? (
        <div
          className="red2pr-inline-alert red2pr-tone-warning"
          role="alert"
          data-testid="gitlab-version-conflict-banner"
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
              label="Reload latest connection state"
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

      {/* Header + Connection Selector */}
      <section
        className="red2pr-surface red2pr-card-section"
        aria-labelledby="gl-connections-heading"
      >
        <div className="red2pr-card-header">
          <div>
            <h2 id="gl-connections-heading" style={{ margin: 0, fontSize: "1.125rem" }}>
              {t("integrations.gitlabSectionTitle")}
            </h2>
            <p className="red2pr-field-hint" style={{ marginTop: 4 }}>
              {t("integrations.gitlabSectionSubtitle")}
            </p>
          </div>
          {isAdmin ? (
            <Button
              label={t("integrations.gitlabAddConnection")}
              variant="primary"
              onClick={() => setCreateOpen(true)}
              data-testid="open-create-gitlab-btn"
            />
          ) : null}
        </div>

        {connections.length === 0 ? (
          <StateView
            state="empty"
            title="No GitLab connection configured"
            description="Register a GitLab.com or Self-Managed GitLab connection using a least-privilege project/group access token and a pinned webhook authentication mode."
          />
        ) : (
          <div
            style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12 }}
            role="group"
            aria-label={t("integrations.gitlabConnectionsTableLabel")}
          >
            {connections.map((conn) => {
              const badge = connectionStatusAppearance(conn.status);
              const selected = conn.id === effectiveSelectedConnectionId;
              return (
                <button
                  key={conn.id}
                  type="button"
                  className="red2pr-tab-button"
                  aria-pressed={selected}
                  onClick={() => setSelectedConnectionId(conn.id)}
                  data-testid={`select-gitlab-connection-${conn.id}`}
                >
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                    <StatusGlyph kind={badge.glyph} />
                    <span>{sanitizeUntrustedText(conn.display_name ?? conn.base_url).text}</span>
                    <span className={`red2pr-badge-pill ${badge.tone}`}>{badge.label}</span>
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </section>

      {/* Active Connection Detail, Pinned Auth, Capabilities & Discovered Projects */}
      {activeConnection !== null ? (
        <>
          {activeConnection.status === "unsupported" ? (
            <div
              className="red2pr-inline-alert red2pr-tone-danger"
              role="alert"
              data-testid="gitlab-unsupported-auth-banner"
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                <StatusGlyph kind="error" />
                <span>
                  Pinned webhook auth mode unsupported by server (SEC-027):{" "}
                  {
                    sanitizeUntrustedText(
                      activeConnection.status_detail ??
                        "Target GitLab server (< 19.0) does not support Standard Webhooks signing tokens (`gitlab_signed_v19`). Red2PR never silently downgrades to legacy X-Gitlab-Token.",
                    ).text
                  }
                </span>
              </div>
            </div>
          ) : null}

          {activeConnection.grant_review_required ? (
            <div
              className="red2pr-inline-alert red2pr-tone-warning"
              role="alert"
              data-testid="gitlab-grant-review-banner"
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                <StatusGlyph kind="warn" />
                <span>
                  Grant &amp; automation review required (W-02): This GitLab connection experienced
                  a prior revocation. All synchronized projects remain in <code>Monitor</code> mode
                  until a workspace administrator explicitly reviews repository grants and policies.
                </span>
              </div>
            </div>
          ) : null}

          <section
            className="red2pr-surface red2pr-card-section"
            aria-labelledby="gl-detail-heading"
            data-testid="gitlab-connection-detail-card"
          >
            <div className="red2pr-card-header">
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                  <h2 id="gl-detail-heading" style={{ margin: 0, fontSize: "1.125rem" }}>
                    {sanitizeUntrustedText(activeConnection.display_name ?? "GitLab Connection").text}
                  </h2>
                  {(() => {
                    const st = connectionStatusAppearance(activeConnection.status);
                    return (
                      <span
                        className={`red2pr-badge-pill ${st.tone}`}
                        data-testid="gitlab-connection-status-pill"
                      >
                        <StatusGlyph kind={st.glyph} />
                        <span>{st.label}</span>
                      </span>
                    );
                  })()}
                  {(() => {
                    const authBadge = formatPinnedAuthBadge(activeConnection.auth_mode);
                    return (
                      <span
                        className={`red2pr-badge-pill ${authBadge.tone}`}
                        data-testid="gitlab-pinned-auth-pill"
                      >
                        <StatusGlyph kind={authBadge.glyph} />
                        <span>{authBadge.label}</span>
                      </span>
                    );
                  })()}
                </div>
                <p className="red2pr-field-hint" style={{ marginTop: 6 }}>
                  {sanitizeUntrustedText(activeConnection.status_detail ?? "Configured.").text}
                </p>
                <p className="red2pr-field-hint" style={{ marginTop: 4 }}>
                  {formatPinnedAuthBadge(activeConnection.auth_mode).assuranceNote}
                </p>
              </div>

              {isAdmin ? (
                <div className="red2pr-button-row">
                  <Button
                    label="Probe capabilities"
                    variant="secondary"
                    size="sm"
                    isLoading={probeMutation.isPending}
                    onClick={() => probeMutation.mutate(activeConnection.id)}
                    data-testid="probe-gitlab-btn"
                  />
                  <Button
                    label="Sync projects"
                    variant="secondary"
                    size="sm"
                    isLoading={syncMutation.isPending}
                    isDisabled={
                      activeConnection.status === "revoked" ||
                      activeConnection.status === "unsupported"
                    }
                    onClick={() => syncMutation.mutate(activeConnection.id)}
                    data-testid="sync-gitlab-btn"
                  />
                  <Button
                    label="Rotate credentials / edit"
                    variant="secondary"
                    size="sm"
                    onClick={handleOpenRotateDialog}
                    data-testid="rotate-gitlab-btn"
                  />
                  {activeConnection.status !== "revoked" ? (
                    <Button
                      label="Disconnect & revoke"
                      variant="destructive"
                      size="sm"
                      onClick={() => {
                        setRevokeConfirmText("");
                        setRevokeOpen(true);
                      }}
                      data-testid="open-revoke-gitlab-btn"
                    />
                  ) : null}
                </div>
              ) : null}
            </div>

            {/* Metadata & SecretPresence Grid (never exposes raw secrets) */}
            <dl className="red2pr-kv-grid" style={{ marginTop: 16 }}>
              <div>
                <dt className="red2pr-field-hint">GitLab Base URL &amp; Version</dt>
                <dd style={{ margin: "4px 0 0 0" }}>
                  <code>{sanitizeUntrustedText(activeConnection.base_url).text}</code>
                  <div className="red2pr-field-hint">
                    Server:{" "}
                    <code>
                      {sanitizeUntrustedText(activeConnection.vendor_version ?? "unprobed").text}
                    </code>{" "}
                    · API: <code>{activeConnection.api_version ?? "v4"}</code> · ETag{" "}
                    <code>v{activeConnection.version}</code>
                  </div>
                </dd>
              </div>
              <div>
                <dt className="red2pr-field-hint">Token Identity &amp; Edition</dt>
                <dd style={{ margin: "4px 0 0 0" }}>
                  <code>
                    {sanitizeUntrustedText(activeConnection.account_login ?? "pending-probe").text}
                  </code>
                  {activeConnection.granted_permissions?.edition ? (
                    <span style={{ marginLeft: 6 }} className="red2pr-field-hint">
                      ({sanitizeUntrustedText(activeConnection.granted_permissions.edition).text})
                    </span>
                  ) : null}
                </dd>
              </div>
              <div>
                <dt className="red2pr-field-hint">Project/Group Token (Z2 Broker)</dt>
                <dd style={{ margin: "4px 0 0 0" }} data-testid="gitlab-token-presence">
                  {activeConnection.secret_presence.configured ? (
                    <span className="red2pr-badge-pill red2pr-tone-success">
                      <StatusGlyph kind="lock" />
                      <span>
                        Configured · key v{activeConnection.secret_presence.secret_version ?? 1}
                      </span>
                    </span>
                  ) : (
                    <span className="red2pr-badge-pill red2pr-tone-warning">
                      <StatusGlyph kind="warn" />
                      <span>Not configured / Revoked</span>
                    </span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="red2pr-field-hint">Webhook Secret / Signing Key (Z2 Broker)</dt>
                <dd style={{ margin: "4px 0 0 0" }} data-testid="gitlab-webhook-presence">
                  {activeConnection.webhook_secret_presence?.configured ? (
                    <span className="red2pr-badge-pill red2pr-tone-success">
                      <StatusGlyph kind="lock" />
                      <span>
                        Configured · key v
                        {activeConnection.webhook_secret_presence.secret_version ?? 1}
                      </span>
                    </span>
                  ) : (
                    <span className="red2pr-badge-pill red2pr-tone-neutral">
                      <StatusGlyph kind="clock" />
                      <span>Not configured (polling fallback available)</span>
                    </span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="red2pr-field-hint">Last Capability Probe / Sync</dt>
                <dd style={{ margin: "4px 0 0 0" }}>
                  Probed:{" "}
                  {activeConnection.checked_at
                    ? formatUtcTimestamp(activeConnection.checked_at)
                    : "Never"}
                  <br />
                  Synced:{" "}
                  {activeConnection.last_synced_at
                    ? formatUtcTimestamp(activeConnection.last_synced_at)
                    : "Never"}
                </dd>
              </div>
            </dl>

            {/* Capability & Permission Matrix */}
            <div style={{ marginTop: 16 }}>
              <h3 style={{ margin: "0 0 8px 0", fontSize: "0.95rem" }}>
                Observed GitLab Capabilities &amp; Negotiated Scopes
              </h3>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {Object.entries(activeConnection.capabilities ?? {}).map(([capName, avail]) => {
                  const capStyle = capabilityAppearance(avail);
                  return (
                    <span key={capName} className={`red2pr-badge-pill ${capStyle.tone}`}>
                      <StatusGlyph kind={capStyle.glyph} />
                      <span>
                        {capName}: {capStyle.label}
                      </span>
                    </span>
                  );
                })}
              </div>

              {activeConnection.capabilities?.webhook_admin === "unavailable" &&
              activeConnection.capabilities?.polling_fallback === "available" ? (
                <div
                  className="red2pr-inline-alert red2pr-tone-info"
                  style={{ marginTop: 10 }}
                  data-testid="gitlab-polling-fallback-notice"
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <StatusGlyph kind="info" />
                    <span>
                      <strong>Webhook admin scope unavailable:</strong> This token is scoped for
                      read-only monitoring (<code>read_api</code>); automatic webhook registration
                      and Draft MR creation remain unavailable, and scheduled polling reconciliation
                      is available.
                    </span>
                  </div>
                </div>
              ) : null}

              {(activeConnection.missing_permissions ?? []).length > 0 ? (
                <div
                  className="red2pr-inline-alert red2pr-tone-warning"
                  style={{ marginTop: 10 }}
                  data-testid="gitlab-missing-permissions-banner"
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <StatusGlyph kind="warn" />
                    <span>
                      Missing scopes / prerequisites:{" "}
                      <code>{(activeConnection.missing_permissions ?? []).join(", ")}</code>
                    </span>
                  </div>
                </div>
              ) : null}

              {activeSnapshot ? (
                <div className="red2pr-field-hint" style={{ marginTop: 8 }}>
                  Latest capability snapshot <code>{activeSnapshot.id}</code> recorded at{" "}
                  {formatUtcTimestamp(activeSnapshot.checked_at)}.
                </div>
              ) : null}
            </div>
          </section>

          {/* Discovered GitLab Projects & .gitlab-ci.yml Hazard Table */}
          <section
            className="red2pr-surface red2pr-card-section"
            aria-labelledby="gl-projects-heading"
          >
            <div className="red2pr-card-header">
              <div>
                <h2 id="gl-projects-heading" style={{ margin: 0, fontSize: "1.125rem" }}>
                  Discovered GitLab Projects ({projectRows.length})
                </h2>
                <p className="red2pr-field-hint" style={{ marginTop: 4 }}>
                  All newly discovered GitLab projects start in <code>Monitor</code> mode. Projects
                  whose <code>.gitlab-ci.yml</code> deploys automatically to production on MR
                  pipelines are flagged and blocked from autonomous repair (<code>SEC-031</code>).
                </p>
              </div>
              {(activeConnection.flagged_hazard_repo_count ?? 0) > 0 ? (
                <span
                  className="red2pr-badge-pill red2pr-tone-danger"
                  data-testid="gitlab-hazard-summary-pill"
                >
                  <StatusGlyph kind="warn" />
                  <span>{activeConnection.flagged_hazard_repo_count} hazard-flagged</span>
                </span>
              ) : null}
            </div>

            <div style={{ marginTop: 12 }}>
              <Table
                aria-label={t("integrations.gitlabProjectsTableLabel")}
                columns={projectColumns}
                data={projectRows}
                emptyTitle="No synchronized GitLab projects visible"
                emptyDescription={
                  isAdmin
                    ? "Run Sync projects as a workspace admin to discover authorized GitLab projects and inspect .gitlab-ci.yml hazards."
                    : "No GitLab projects are currently granted to your role under this connection."
                }
              />
            </div>
          </section>
        </>
      ) : null}

      {/* Create GitLab Connection Dialog */}
      <Dialog
        isOpen={createOpen}
        onOpenChange={setCreateOpen}
        title="Register GitLab Cloud or Self-Managed Connection"
        subtitle="Write-only access tokens and webhook signing keys are encrypted inside the Z2 SecretBroker and cleared from browser memory immediately on submit."
        purpose="form"
        data-testid="gitlab-create-dialog"
        footer={
          <div className="red2pr-button-row">
            <Button
              label="Cancel"
              variant="secondary"
              type="button"
              onClick={() => setCreateOpen(false)}
            />
            <Button
              label="Seal credentials & create"
              variant="primary"
              type="button"
              isLoading={createMutation.isPending}
              isDisabled={!createAccessToken.trim() || !createBaseUrl.trim()}
              onClick={handleCreateSubmit}
            />
          </div>
        }
      >
        <div className="red2pr-form-stack">
          <div className="red2pr-inline-alert red2pr-tone-info">
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <StatusGlyph kind="info" />
              <span>
                <strong>Self-Managed GitLab (ADR-037):</strong> Public{" "}
                <code>https://gitlab.com</code> works immediately. Private/internal Self-Managed
                hosts require an active Instance Owner private endpoint registration (exact host,
                port, CIDRs &amp; custom <code>ca_ref</code>) under 5-minute step-up in Setup.
              </span>
            </div>
          </div>

          <div className="red2pr-field">
            <label htmlFor={createNameId} className="red2pr-field-label">
              Connection display name
            </label>
            <input
              id={createNameId}
              type="text"
              className="red2pr-control-input"
              value={createDisplayName}
              onChange={(e) => setCreateDisplayName(e.target.value)}
              placeholder="Acme GitLab Cloud"
              maxLength={120}
            />
          </div>

          <div className="red2pr-field">
            <label htmlFor={createBaseUrlField} className="red2pr-field-label">
              GitLab Base URL
            </label>
            <input
              id={createBaseUrlField}
              type="url"
              className="red2pr-control-input"
              required
              value={createBaseUrl}
              onChange={(e) => setCreateBaseUrl(e.target.value)}
              placeholder="https://gitlab.com"
            />
            <span className="red2pr-field-hint">
              Use <code>https://gitlab.com</code> for GitLab Cloud or your Self-Managed HTTPS root
              URL (e.g. <code>https://gitlab.internal.acme.corp:8443</code>).
            </span>
          </div>

          <div className="red2pr-field">
            <label htmlFor={createAuthModeField} className="red2pr-field-label">
              Pinned Webhook Authentication Mode (Immutable — SEC-027)
            </label>
            <select
              id={createAuthModeField}
              className="red2pr-control-input"
              value={createAuthMode}
              onChange={(e) => setCreateAuthMode(e.target.value as GitLabPinnedAuthMode)}
            >
              <option value="gitlab_signed_v19">
                GitLab 19.0+ / 19.1+ Signed Webhooks HMAC (Recommended — Standard Webhooks v1)
              </option>
              <option value="gitlab_legacy_token">
                GitLab &lt; 19.0 Legacy Secret Token (X-Gitlab-Token over HTTPS/TLS)
              </option>
            </select>
            <span className="red2pr-field-hint">
              Webhook authentication mode is pinned permanently on creation and never silently
              downgrades from signed HMAC to legacy <code>X-Gitlab-Token</code>.
            </span>
          </div>

          <div className="red2pr-field">
            <label htmlFor={createTokenField} className="red2pr-field-label">
              Project or Group Access Token (Write-Only)
            </label>
            <input
              id={createTokenField}
              type="password"
              className="red2pr-control-input"
              required
              minLength={12}
              autoComplete="new-password"
              value={createAccessToken}
              onChange={(e) => setCreateAccessToken(e.target.value)}
              placeholder="glpat-..."
            />
            <span className="red2pr-field-hint">
              Use <code>read_api</code> + <code>read_repository</code> for Monitor-only, or{" "}
              <code>api</code> + <code>write_repository</code> on a dedicated bot token for Draft MR
              publication.
            </span>
          </div>

          <div className="red2pr-field">
            <label htmlFor={createWebhookField} className="red2pr-field-label">
              {createAuthMode === "gitlab_signed_v19"
                ? "Webhook Signing Key (Write-Only, whsec_... or >=16-byte secret)"
                : "Legacy Webhook Secret Token (Write-Only, >=16 chars)"}
            </label>
            <input
              id={createWebhookField}
              type="password"
              className="red2pr-control-input"
              autoComplete="new-password"
              value={createWebhookSecret}
              onChange={(e) => setCreateWebhookSecret(e.target.value)}
              placeholder={
                createAuthMode === "gitlab_signed_v19" ? "whsec_..." : "Minimum 16 characters"
              }
            />
          </div>
        </div>
      </Dialog>

      {/* Rotate Credentials / Update Connection Dialog */}
      {activeConnection !== null ? (
        <Dialog
          isOpen={rotateOpen}
          onOpenChange={setRotateOpen}
          title="Update GitLab Connection or Rotate Credentials"
          subtitle="Optimistic concurrency is enforced via If-Match ETag. Pinned webhook auth_mode is immutable; leave write-only fields blank to keep existing Z2 secrets."
          purpose="form"
          data-testid="gitlab-rotate-dialog"
          footer={
            <div className="red2pr-button-row">
              <Button
                label="Cancel"
                variant="secondary"
                type="button"
                onClick={() => setRotateOpen(false)}
              />
              <Button
                label="Save & rotate"
                variant="primary"
                type="button"
                isLoading={updateMutation.isPending}
                onClick={handleRotateSubmit}
              />
            </div>
          }
        >
          <div className="red2pr-form-stack">
            <div className="red2pr-field">
              <label htmlFor={rotateNameField} className="red2pr-field-label">
                Connection display name
              </label>
              <input
                id={rotateNameField}
                type="text"
                className="red2pr-control-input"
                value={rotateDisplayName}
                onChange={(e) => setRotateDisplayName(e.target.value)}
                maxLength={120}
              />
            </div>

            <div className="red2pr-field">
              <label htmlFor={rotateBaseUrlField} className="red2pr-field-label">
                GitLab Base URL
              </label>
              <input
                id={rotateBaseUrlField}
                type="url"
                className="red2pr-control-input"
                value={rotateBaseUrl}
                onChange={(e) => setRotateBaseUrl(e.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label htmlFor={rotateTokenField} className="red2pr-field-label">
                New Project/Group Access Token (Write-Only — optional rotation)
              </label>
              <input
                id={rotateTokenField}
                type="password"
                className="red2pr-control-input"
                autoComplete="new-password"
                value={rotateAccessToken}
                onChange={(e) => setRotateAccessToken(e.target.value)}
                placeholder="Leave empty to retain current token"
              />
            </div>

            <div className="red2pr-field">
              <label htmlFor={rotateWebhookField} className="red2pr-field-label">
                New Webhook Signing / Secret Key (Write-Only — retains previous key for overlap)
              </label>
              <input
                id={rotateWebhookField}
                type="password"
                className="red2pr-control-input"
                autoComplete="new-password"
                value={rotateWebhookSecret}
                onChange={(e) => setRotateWebhookSecret(e.target.value)}
                placeholder="Leave empty to retain current webhook secret"
              />
            </div>
          </div>
        </Dialog>
      ) : null}

      {/* Disconnect & Revoke Destructive Confirmation Dialog */}
      {activeConnection !== null ? (
        <Dialog
          isOpen={revokeOpen}
          onOpenChange={setRevokeOpen}
          title="Disconnect GitLab Connection & Revoke Credentials"
          subtitle="Immediately revokes stored Z2 access and webhook secrets, cancels queued jobs, cooperatively cancels running jobs, and resets all projects to Monitor mode (SEC-011)."
          purpose="form"
          data-testid="gitlab-revoke-dialog"
          footer={
            <div className="red2pr-button-row">
              <Button
                label="Cancel"
                variant="secondary"
                type="button"
                onClick={() => setRevokeOpen(false)}
              />
              <Button
                label="Confirm disconnect & revoke"
                variant="destructive"
                type="button"
                isDisabled={!canConfirmRevoke}
                isLoading={deleteMutation.isPending}
                onClick={() => deleteMutation.mutate(activeConnection.id)}
                data-testid="confirm-revoke-gitlab-btn"
              />
            </div>
          }
        >
          <div className="red2pr-form-stack">
            <div className="red2pr-inline-alert red2pr-tone-danger">
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <StatusGlyph kind="error" />
                <span>
                  Type <strong>{sanitizeUntrustedText(expectedRevokePhrase).text}</strong> to
                  confirm immediate revocation and active job suspension.
                </span>
              </div>
            </div>

            <div className="red2pr-field">
              <label htmlFor={revokeConfirmField} className="red2pr-field-label">
                Confirm connection name
              </label>
              <input
                id={revokeConfirmField}
                type="text"
                className="red2pr-control-input"
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
