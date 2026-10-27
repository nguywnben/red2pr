import {
  Red2PrApiError,
  type BreakGlassGrant,
  type Invite,
  type InviteCreateResponse,
  type MeResponse,
  type Membership,
  type Workspace,
  type WorkspaceRole,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  Button,
  Dialog,
  StateView,
  StatusGlyph,
  Table,
  sanitizeUntrustedText,
  type TableColumn,
} from "../../shared/ui";
import {
  extractAuthProblemSummary,
  formatUtcTimestamp,
  type AuthProblemSummary,
} from "../auth";
import { AcceptInviteDialog } from "./AcceptInviteDialog";

const ROLE_OPTIONS: readonly WorkspaceRole[] = [
  "admin",
  "maintainer",
  "reviewer",
  "viewer",
  "auditor",
];

function parseRepositoryGrantInput(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[\s,]+/)
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0),
    ),
  );
}

interface MemberTableRow extends Record<string, unknown> {
  readonly id: string;
  readonly user_id: string;
  readonly display_name: string;
  readonly email: string | null;
  readonly role: WorkspaceRole;
  readonly repository_grants: readonly string[];
  readonly version: number;
  readonly created_at: string;
}

interface InviteTableRow extends Record<string, unknown> {
  readonly id: string;
  readonly email: string;
  readonly role: WorkspaceRole;
  readonly status: Invite["status"];
  readonly repository_grants: readonly string[];
  readonly expires_at: string;
}

interface BreakGlassTableRow extends Record<string, unknown> {
  readonly id: string;
  readonly user_id: string;
  readonly reason: string;
  readonly active: boolean;
  readonly expires_at: string;
}

function toMemberRow(item: Membership): MemberTableRow {
  return {
    id: item.id,
    user_id: item.user_id,
    display_name: item.user?.display_name
      ? sanitizeUntrustedText(item.user.display_name).text
      : sanitizeUntrustedText(item.user_id).text,
    email: item.user?.email ? sanitizeUntrustedText(item.user.email).text : null,
    role: item.role,
    repository_grants: item.repository_grants ?? [],
    version: item.version,
    created_at: item.created_at,
  };
}

function toInviteRow(item: Invite): InviteTableRow {
  return {
    id: item.id,
    email: sanitizeUntrustedText(item.email).text,
    role: item.role,
    status: item.status,
    repository_grants: item.repository_grants ?? [],
    expires_at: item.expires_at,
  };
}

function toBreakGlassRow(item: BreakGlassGrant): BreakGlassTableRow {
  return {
    id: item.id,
    user_id: item.user_id,
    reason: sanitizeUntrustedText(item.reason).text,
    active: item.active,
    expires_at: item.expires_at,
  };
}

export interface MembersPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

export function MembersPage({ workspace, me }: MembersPageProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const wsSlug = workspace.slug ?? workspace.id;

  const callerMembership = useMemo(
    () => (me.memberships ?? []).find((entry) => entry.workspace_id === workspace.id) ?? null,
    [me.memberships, workspace.id],
  );
  const effectiveRole: WorkspaceRole | "break_glass" = callerMembership?.role ?? "break_glass";
  const isAdmin = effectiveRole === "admin";
  const canInspectAuditTables =
    effectiveRole === "admin" ||
    effectiveRole === "auditor" ||
    effectiveRole === "break_glass";

  const [memberCursor, setMemberCursor] = useState<string | null>(null);
  const [actionError, setActionError] = useState<AuthProblemSummary | null>(null);

  // Invite dialog state (one-time token held strictly in memory, wiped on close)
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<WorkspaceRole>("viewer");
  const [inviteRepoInput, setInviteRepoInput] = useState("");
  const [inviteDialogError, setInviteDialogError] = useState<AuthProblemSummary | null>(null);
  const [createdInviteOnce, setCreatedInviteOnce] = useState<InviteCreateResponse | null>(null);

  // Edit member dialog state
  const [editingMember, setEditingMember] = useState<MemberTableRow | null>(null);
  const [editRole, setEditRole] = useState<WorkspaceRole>("viewer");
  const [editRepoInput, setEditRepoInput] = useState("");
  const [editDialogError, setEditDialogError] = useState<AuthProblemSummary | null>(null);

  // Remove member dialog state
  const [removingMember, setRemovingMember] = useState<MemberTableRow | null>(null);
  const [removeDialogError, setRemoveDialogError] = useState<AuthProblemSummary | null>(null);

  // Redeem invitation dialog state
  const [acceptDialogOpen, setAcceptDialogOpen] = useState(false);

  const inviteFormId = useId();
  const inviteEmailId = useId();
  const inviteRoleId = useId();
  const inviteReposId = useId();

  const editFormId = useId();
  const editRoleId = useId();
  const editReposId = useId();

  const membersQuery = useQuery({
    queryKey: ["workspace", wsSlug, "members", memberCursor ?? "first"],
    queryFn: () => api.listWorkspaceMembers(wsSlug, { cursor: memberCursor, limit: 50 }),
    retry: false,
  });

  const invitationsQuery = useQuery({
    queryKey: ["workspace", wsSlug, "invitations"],
    queryFn: () => api.listWorkspaceInvitations(wsSlug, { limit: 50 }),
    enabled: canInspectAuditTables,
    retry: false,
  });

  const breakGlassQuery = useQuery({
    queryKey: ["workspace", wsSlug, "break-glass"],
    queryFn: () => api.listBreakGlassGrants(wsSlug),
    enabled: canInspectAuditTables,
    retry: false,
  });

  const refreshAuthoritativeState = useCallback(async (): Promise<void> => {
    await invalidateWorkspaceQueries(queryClient, wsSlug);
    await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
  }, [queryClient, wsSlug]);

  const createInviteMutation = useMutation({
    mutationFn: async () => {
      return api.createWorkspaceInvitation(wsSlug, {
        email: inviteEmail.trim(),
        role: inviteRole,
        repository_grants: parseRepositoryGrantInput(inviteRepoInput),
      });
    },
    onSuccess: async (envelope) => {
      setInviteDialogError(null);
      setCreatedInviteOnce(envelope.data);
      await invalidateWorkspaceQueries(queryClient, wsSlug);
    },
    onError: (err) => {
      setInviteDialogError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const revokeInviteMutation = useMutation({
    mutationFn: async (inviteId: string) => {
      return api.revokeWorkspaceInvitation(wsSlug, inviteId);
    },
    onSuccess: async () => {
      setActionError(null);
      await invalidateWorkspaceQueries(queryClient, wsSlug);
    },
    onError: (err) => {
      setActionError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const updateMemberMutation = useMutation({
    mutationFn: async (target: MemberTableRow) => {
      return api.updateWorkspaceMember(
        wsSlug,
        target.id,
        {
          role: editRole,
          repository_grants: parseRepositoryGrantInput(editRepoInput),
          expected_version: target.version,
        },
        { ifMatch: `"v${String(target.version)}"` },
      );
    },
    onSuccess: async () => {
      setEditDialogError(null);
      setEditingMember(null);
      setActionError(null);
      await refreshAuthoritativeState();
    },
    onError: async (err, target) => {
      const summary = extractAuthProblemSummary(err, t("state.error.description"));
      setEditDialogError(summary);
      // Roll back local form state to authoritative values on conflict/rejection
      setEditRole(target.role);
      setEditRepoInput(target.repository_grants.join(", "));
      await refreshAuthoritativeState();
    },
  });

  const removeMemberMutation = useMutation({
    mutationFn: async (target: MemberTableRow) => {
      return api.removeWorkspaceMember(wsSlug, target.id);
    },
    onSuccess: async () => {
      setRemoveDialogError(null);
      setRemovingMember(null);
      setActionError(null);
      await refreshAuthoritativeState();
    },
    onError: async (err) => {
      setRemoveDialogError(extractAuthProblemSummary(err, t("state.error.description")));
      await refreshAuthoritativeState();
    },
  });

  const revokeBreakGlassMutation = useMutation({
    mutationFn: async (grantId: string) => {
      return api.revokeBreakGlassGrant(wsSlug, grantId);
    },
    onSuccess: async () => {
      setActionError(null);
      await refreshAuthoritativeState();
    },
    onError: (err) => {
      setActionError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const openEditDialog = useCallback((row: MemberTableRow): void => {
    setEditingMember(row);
    setEditRole(row.role);
    setEditRepoInput(row.repository_grants.join(", "));
    setEditDialogError(null);
  }, []);

  const closeInviteDialog = useCallback((nextOpen: boolean): void => {
    if (!nextOpen) {
      setCreatedInviteOnce(null);
      setInviteEmail("");
      setInviteRole("viewer");
      setInviteRepoInput("");
      setInviteDialogError(null);
    }
    setInviteDialogOpen(nextOpen);
  }, []);

  const memberColumns = useMemo<TableColumn<MemberTableRow>[]>(() => {
    const cols: TableColumn<MemberTableRow>[] = [
      {
        key: "display_name",
        header: t("members.colMember"),
        renderCell: (row) => (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span style={{ fontWeight: 600 }}>{row.display_name}</span>
            {row.email ? (
              <span className="red2pr-field-hint">{row.email}</span>
            ) : null}
          </div>
        ),
      },
      {
        key: "role",
        header: t("members.colRole"),
        renderCell: (row) => (
          <span
            className={`red2pr-badge-pill ${
              row.role === "admin" ? "red2pr-tone-info" : "red2pr-tone-neutral"
            }`}
          >
            <StatusGlyph kind={row.role === "admin" ? "lock" : "info"} />
            <span>{row.role}</span>
          </span>
        ),
      },
      {
        key: "repository_grants",
        header: t("members.colRepoGrants"),
        renderCell: (row) => {
          if (row.role === "admin") {
            return (
              <span className="red2pr-badge-pill red2pr-tone-success">
                <StatusGlyph kind="check" />
                <span>{t("members.allWorkspaceReposBadge")}</span>
              </span>
            );
          }
          if (row.repository_grants.length === 0) {
            return (
              <span className="red2pr-badge-pill red2pr-tone-warning">
                <StatusGlyph kind="lock" />
                <span>{t("members.noRepoGrantsBadge")}</span>
              </span>
            );
          }
          return (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {row.repository_grants.map((repoId) => (
                <code key={repoId} className="red2pr-badge-pill red2pr-tone-neutral">
                  {sanitizeUntrustedText(repoId).text}
                </code>
              ))}
            </div>
          );
        },
      },
      {
        key: "created_at",
        header: t("members.colJoined"),
        renderCell: (row) => (
          <span>{`v${String(row.version)} · ${formatUtcTimestamp(row.created_at)}`}</span>
        ),
      },
    ];

    if (isAdmin) {
      cols.push({
        key: "id",
        header: t("members.colActions"),
        renderCell: (row) => (
          <div className="red2pr-button-row">
            <Button
              label={t("members.editAccessAction")}
              variant="secondary"
              size="sm"
              onClick={() => openEditDialog(row)}
            />
            <Button
              label={t("members.removeMemberAction")}
              variant="destructive"
              size="sm"
              onClick={() => {
                setRemoveDialogError(null);
                setRemovingMember(row);
              }}
            />
          </div>
        ),
      });
    }

    return cols;
  }, [isAdmin, openEditDialog, t]);

  const inviteColumns = useMemo<TableColumn<InviteTableRow>[]>(() => {
    const cols: TableColumn<InviteTableRow>[] = [
      {
        key: "email",
        header: t("members.colInviteEmail"),
        renderCell: (row) => <code>{row.email}</code>,
      },
      {
        key: "role",
        header: t("members.colInviteRole"),
        renderCell: (row) => <span>{row.role}</span>,
      },
      {
        key: "status",
        header: t("members.colInviteStatus"),
        renderCell: (row) => (
          <span
            className={`red2pr-badge-pill ${
              row.status === "pending"
                ? "red2pr-tone-info"
                : row.status === "accepted"
                  ? "red2pr-tone-success"
                  : "red2pr-tone-neutral"
            }`}
          >
            <StatusGlyph
              kind={
                row.status === "pending"
                  ? "clock"
                  : row.status === "accepted"
                    ? "check"
                    : "info"
              }
            />
            <span>{row.status}</span>
          </span>
        ),
      },
      {
        key: "repository_grants",
        header: t("members.colInviteRepos"),
        renderCell: (row) =>
          row.repository_grants.length > 0 ? (
            <span>{row.repository_grants.join(", ")}</span>
          ) : (
            <span className="red2pr-field-hint">—</span>
          ),
      },
      {
        key: "expires_at",
        header: t("members.colInviteExpires"),
        renderCell: (row) => <span>{formatUtcTimestamp(row.expires_at)}</span>,
      },
    ];

    if (isAdmin) {
      cols.push({
        key: "id",
        header: t("members.colActions"),
        renderCell: (row) =>
          row.status === "pending" ? (
            <Button
              label={t("members.revokeInviteAction")}
              variant="destructive"
              size="sm"
              isDisabled={revokeInviteMutation.isPending}
              onClick={() => revokeInviteMutation.mutate(row.id)}
            />
          ) : (
            <span className="red2pr-field-hint">—</span>
          ),
      });
    }

    return cols;
  }, [isAdmin, revokeInviteMutation, t]);

  const breakGlassColumns = useMemo<TableColumn<BreakGlassTableRow>[]>(() => {
    const canRevoke = isAdmin || effectiveRole === "break_glass";
    const cols: TableColumn<BreakGlassTableRow>[] = [
      {
        key: "reason",
        header: t("members.colBgReason"),
        renderCell: (row) => <span>{row.reason}</span>,
      },
      {
        key: "active",
        header: t("members.colBgStatus"),
        renderCell: (row) => (
          <span
            className={`red2pr-badge-pill ${
              row.active ? "red2pr-tone-warning" : "red2pr-tone-neutral"
            }`}
          >
            <StatusGlyph kind={row.active ? "warn" : "info"} />
            <span>
              {row.active ? t("members.bgActiveBadge") : t("members.bgInactiveBadge")}
            </span>
          </span>
        ),
      },
      {
        key: "expires_at",
        header: t("members.colBgExpires"),
        renderCell: (row) => <span>{formatUtcTimestamp(row.expires_at)}</span>,
      },
    ];

    if (canRevoke) {
      cols.push({
        key: "id",
        header: t("members.colActions"),
        renderCell: (row) =>
          row.active ? (
            <Button
              label={t("members.revokeBreakGlassAction")}
              variant="destructive"
              size="sm"
              isDisabled={revokeBreakGlassMutation.isPending}
              onClick={() => revokeBreakGlassMutation.mutate(row.id)}
            />
          ) : (
            <span className="red2pr-field-hint">—</span>
          ),
      });
    }
    return cols;
  }, [effectiveRole, isAdmin, revokeBreakGlassMutation, t]);

  if (membersQuery.isPending) {
    return <StateView state="loading" />;
  }

  if (membersQuery.isError) {
    if (membersQuery.error instanceof Red2PrApiError && membersQuery.error.status === 410) {
      return (
        <StateView
          state="reconciling"
          correlationId={membersQuery.error.problem.correlation_id}
          primaryAction={{
            label: t("members.resetFirstPage"),
            onClick: () => {
              setMemberCursor(null);
              void membersQuery.refetch();
            },
          }}
        />
      );
    }
    if (
      membersQuery.error instanceof Red2PrApiError &&
      (membersQuery.error.status === 403 || membersQuery.error.status === 404)
    ) {
      return (
        <StateView
          state="forbidden"
          title={t("workspaceGuard.revokedTitle")}
          description={t("workspaceGuard.revokedDesc")}
          correlationId={membersQuery.error.problem.correlation_id}
          primaryAction={{
            label: t("workspaceGuard.goToAccount"),
            onClick: () => navigate("/account"),
          }}
        />
      );
    }
    const errSummary = extractAuthProblemSummary(
      membersQuery.error,
      t("state.error.description"),
    );
    return (
      <StateView
        state={errSummary.status === null ? "offline" : "error"}
        description={errSummary.detail}
        correlationId={errSummary.correlationId ?? undefined}
        primaryAction={{
          label: "Retry",
          onClick: () => {
            void membersQuery.refetch();
          },
        }}
      />
    );
  }

  const memberRows = membersQuery.data.data.items.map(toMemberRow);
  const nextMemberCursor = membersQuery.data.data.next_cursor ?? null;
  const inviteRows = (invitationsQuery.data?.data.items ?? []).map(toInviteRow);
  const breakGlassRows = (breakGlassQuery.data?.data.items ?? []).map(toBreakGlassRow);

  return (
    <div className="red2pr-page-stack" data-testid="members-page">
      <div className="red2pr-card-header">
        <div>
          <h1 style={{ margin: "0 0 6px", fontSize: "1.5rem" }}>{t("members.pageTitle")}</h1>
          <p className="red2pr-field-hint">{t("members.pageSubtitle")}</p>
        </div>
        <div className="red2pr-button-row" style={{ alignItems: "center" }}>
          <span
            data-testid="effective-role-badge"
            className={`red2pr-badge-pill ${
              isAdmin
                ? "red2pr-tone-info"
                : effectiveRole === "break_glass"
                  ? "red2pr-tone-warning"
                  : "red2pr-tone-neutral"
            }`}
          >
            <StatusGlyph
              kind={isAdmin ? "lock" : effectiveRole === "break_glass" ? "warn" : "info"}
            />
            <span>{t("members.effectiveRoleLabel", { role: effectiveRole })}</span>
          </span>
          <Button
            label={t("members.redeemInviteAction")}
            variant="secondary"
            onClick={() => setAcceptDialogOpen(true)}
          />
          {isAdmin ? (
            <Button
              label={t("members.inviteMemberAction")}
              variant="primary"
              onClick={() => closeInviteDialog(true)}
            />
          ) : null}
        </div>
      </div>

      {effectiveRole === "break_glass" ? (
        <div
          role="status"
          data-testid="break-glass-active-banner"
          className="red2pr-inline-alert red2pr-tone-warning"
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind="warn" />
            <span>{t("members.breakGlassReadOnlyBanner")}</span>
          </div>
        </div>
      ) : !isAdmin ? (
        <p className="red2pr-field-hint" data-testid="members-readonly-notice">
          {t("members.readOnlyNotice")}
        </p>
      ) : null}

      {actionError !== null ? (
        <div
          role="alert"
          data-testid="members-error-banner"
          className={`red2pr-inline-alert ${
            actionError.status === 429 ? "red2pr-tone-warning" : "red2pr-tone-danger"
          }`}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind={actionError.status === 429 ? "clock" : "error"} />
            <span>{actionError.detail}</span>
          </div>
          {actionError.correlationId ? (
            <div>
              <code>{t("state.correlationId", { correlationId: actionError.correlationId })}</code>
            </div>
          ) : null}
        </div>
      ) : null}

      <section
        className="red2pr-surface red2pr-card-section"
        aria-labelledby="workspace-members-heading"
      >
        <div className="red2pr-card-header">
          <div>
            <h2 id="workspace-members-heading" style={{ margin: "0 0 4px", fontSize: "1.125rem" }}>
              {t("members.membersSectionTitle")}
            </h2>
            <p className="red2pr-field-hint">{t("members.membersSectionSubtitle")}</p>
          </div>
          <div className="red2pr-button-row">
            {memberCursor !== null ? (
              <Button
                label={t("members.resetFirstPage")}
                variant="secondary"
                size="sm"
                onClick={() => setMemberCursor(null)}
              />
            ) : null}
            {nextMemberCursor !== null ? (
              <Button
                label={t("members.loadNextPage")}
                variant="secondary"
                size="sm"
                onClick={() => setMemberCursor(nextMemberCursor)}
              />
            ) : null}
          </div>
        </div>

        <Table<MemberTableRow>
          aria-label={t("members.membersTableLabel")}
          data={memberRows}
          columns={memberColumns}
        />
      </section>

      {canInspectAuditTables ? (
        <section
          className="red2pr-surface red2pr-card-section"
          aria-labelledby="workspace-invitations-heading"
        >
          <div className="red2pr-card-header">
            <div>
              <h2
                id="workspace-invitations-heading"
                style={{ margin: "0 0 4px", fontSize: "1.125rem" }}
              >
                {t("members.invitationsSectionTitle")}
              </h2>
              <p className="red2pr-field-hint">{t("members.invitationsSectionSubtitle")}</p>
            </div>
          </div>

          <Table<InviteTableRow>
            aria-label={t("members.invitationsTableLabel")}
            data={inviteRows}
            columns={inviteColumns}
          />
        </section>
      ) : null}

      {canInspectAuditTables && breakGlassRows.length > 0 ? (
        <section
          className="red2pr-surface red2pr-card-section"
          aria-labelledby="workspace-break-glass-heading"
        >
          <div className="red2pr-card-header">
            <div>
              <h2
                id="workspace-break-glass-heading"
                style={{ margin: "0 0 4px", fontSize: "1.125rem" }}
              >
                {t("members.breakGlassSectionTitle")}
              </h2>
              <p className="red2pr-field-hint">{t("members.breakGlassSectionSubtitle")}</p>
            </div>
          </div>

          <Table<BreakGlassTableRow>
            aria-label={t("members.breakGlassTableLabel")}
            data={breakGlassRows}
            columns={breakGlassColumns}
          />
        </section>
      ) : null}

      {/* Create Single-Use Invitation Dialog (Admin only) */}
      <Dialog
        isOpen={inviteDialogOpen}
        onOpenChange={closeInviteDialog}
        purpose="form"
        title={t("members.inviteDialogTitle")}
        subtitle={t("members.inviteDialogSubtitle")}
        correlationId={inviteDialogError?.correlationId ?? undefined}
        data-testid="invite-member-dialog"
        footer={
          createdInviteOnce !== null ? (
            <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
              <Button
                label={t("members.inviteAcknowledgeAction")}
                variant="primary"
                onClick={() => closeInviteDialog(false)}
              />
            </div>
          ) : (
            <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
              <Button
                label={t("members.cancelAction")}
                variant="secondary"
                isDisabled={createInviteMutation.isPending}
                onClick={() => closeInviteDialog(false)}
              />
              <Button
                label={t("members.inviteSubmitAction")}
                variant="primary"
                type="submit"
                form={inviteFormId}
                isLoading={createInviteMutation.isPending}
                isDisabled={inviteEmail.trim().length < 3 || createInviteMutation.isPending}
              />
            </div>
          )
        }
      >
        {createdInviteOnce !== null ? (
          <div className="red2pr-form-stack" data-testid="invite-once-token-panel">
            <div role="alert" className="red2pr-inline-alert red2pr-tone-warning">
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                <StatusGlyph kind="warn" />
                <span>{t("members.inviteOnceWarning")}</span>
              </div>
            </div>
            <div className="red2pr-field">
              <span className="red2pr-field-label">{t("members.inviteOnceTokenLabel")}</span>
              <code
                data-testid="invite-once-token-value"
                style={{
                  display: "block",
                  padding: "10px 12px",
                  borderRadius: 6,
                  wordBreak: "break-all",
                  border: "1px solid currentColor",
                }}
              >
                {createdInviteOnce.invite_token}
              </code>
            </div>
          </div>
        ) : (
          <form
            id={inviteFormId}
            className="red2pr-form-stack"
            onSubmit={(event) => {
              event.preventDefault();
              setInviteDialogError(null);
              createInviteMutation.mutate();
            }}
            noValidate
          >
            {inviteDialogError !== null ? (
              <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">
                <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                  <StatusGlyph kind="error" />
                  <span>{inviteDialogError.detail}</span>
                </div>
              </div>
            ) : null}

            <div className="red2pr-field">
              <label htmlFor={inviteEmailId} className="red2pr-field-label">
                {t("members.inviteEmailLabel")}
              </label>
              <input
                id={inviteEmailId}
                className="red2pr-control-input"
                type="email"
                autoComplete="off"
                required
                value={inviteEmail}
                onChange={(event) => setInviteEmail(event.target.value)}
              />
            </div>

            <div className="red2pr-field">
              <label htmlFor={inviteRoleId} className="red2pr-field-label">
                {t("members.inviteRoleLabel")}
              </label>
              <select
                id={inviteRoleId}
                className="red2pr-control-select"
                value={inviteRole}
                onChange={(event) => setInviteRole(event.target.value as WorkspaceRole)}
              >
                {ROLE_OPTIONS.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt}
                  </option>
                ))}
              </select>
            </div>

            <div className="red2pr-field">
              <label htmlFor={inviteReposId} className="red2pr-field-label">
                {t("members.repoGrantsFieldLabel")}
              </label>
              <textarea
                id={inviteReposId}
                className="red2pr-control-input"
                rows={3}
                value={inviteRepoInput}
                onChange={(event) => setInviteRepoInput(event.target.value)}
              />
              <span className="red2pr-field-hint">{t("members.repoGrantsFieldHint")}</span>
            </div>
          </form>
        )}
      </Dialog>

      {/* Edit Member Role & Repo Grants Dialog */}
      <Dialog
        isOpen={editingMember !== null}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) {
            setEditingMember(null);
            setEditDialogError(null);
          }
        }}
        purpose="form"
        title={t("members.editDialogTitle")}
        subtitle={t("members.editDialogSubtitle")}
        correlationId={editDialogError?.correlationId ?? undefined}
        data-testid="edit-member-dialog"
        footer={
          <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
            <Button
              label={t("members.cancelAction")}
              variant="secondary"
              isDisabled={updateMemberMutation.isPending}
              onClick={() => {
                setEditingMember(null);
                setEditDialogError(null);
              }}
            />
            <Button
              label={t("members.saveMemberAction")}
              variant="primary"
              type="submit"
              form={editFormId}
              isLoading={updateMemberMutation.isPending}
              isDisabled={updateMemberMutation.isPending || editingMember === null}
            />
          </div>
        }
      >
        <form
          id={editFormId}
          className="red2pr-form-stack"
          onSubmit={(event) => {
            event.preventDefault();
            if (editingMember !== null) {
              setEditDialogError(null);
              updateMemberMutation.mutate(editingMember);
            }
          }}
          noValidate
        >
          {editDialogError !== null ? (
            <div
              role="alert"
              data-testid="edit-member-error"
              className="red2pr-inline-alert red2pr-tone-danger"
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                <StatusGlyph kind="error" />
                <span>{editDialogError.detail}</span>
              </div>
            </div>
          ) : null}

          <div className="red2pr-field">
            <label htmlFor={editRoleId} className="red2pr-field-label">
              {t("members.roleFieldLabel")}
            </label>
            <select
              id={editRoleId}
              className="red2pr-control-select"
              value={editRole}
              onChange={(event) => setEditRole(event.target.value as WorkspaceRole)}
            >
              {ROLE_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>

          <div className="red2pr-field">
            <label htmlFor={editReposId} className="red2pr-field-label">
              {t("members.repoGrantsFieldLabel")}
            </label>
            <textarea
              id={editReposId}
              className="red2pr-control-input"
              rows={3}
              value={editRepoInput}
              onChange={(event) => setEditRepoInput(event.target.value)}
            />
            <span className="red2pr-field-hint">{t("members.repoGrantsFieldHint")}</span>
          </div>
        </form>
      </Dialog>

      {/* Remove Member Confirmation Dialog */}
      <Dialog
        isOpen={removingMember !== null}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) {
            setRemovingMember(null);
            setRemoveDialogError(null);
          }
        }}
        purpose="form"
        title={t("members.removeDialogTitle")}
        subtitle={t("members.removeDialogSubtitle")}
        correlationId={removeDialogError?.correlationId ?? undefined}
        data-testid="remove-member-dialog"
        footer={
          <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
            <Button
              label={t("members.cancelAction")}
              variant="secondary"
              isDisabled={removeMemberMutation.isPending}
              onClick={() => {
                setRemovingMember(null);
                setRemoveDialogError(null);
              }}
            />
            <Button
              label={t("members.confirmRemoveAction")}
              variant="destructive"
              isLoading={removeMemberMutation.isPending}
              isDisabled={removeMemberMutation.isPending || removingMember === null}
              onClick={() => {
                if (removingMember !== null) {
                  setRemoveDialogError(null);
                  removeMemberMutation.mutate(removingMember);
                }
              }}
            />
          </div>
        }
      >
        <div className="red2pr-form-stack">
          {removeDialogError !== null ? (
            <div
              role="alert"
              data-testid="remove-member-error"
              className="red2pr-inline-alert red2pr-tone-danger"
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                <StatusGlyph kind="error" />
                <span>{removeDialogError.detail}</span>
              </div>
            </div>
          ) : null}
          {removingMember !== null ? (
            <p style={{ margin: 0 }}>
              {t("members.removeConfirmBody", {
                memberLabel: removingMember.display_name,
                role: removingMember.role,
              })}
            </p>
          ) : null}
        </div>
      </Dialog>

      {/* Accept Invitation Dialog */}
      <AcceptInviteDialog
        isOpen={acceptDialogOpen}
        onOpenChange={setAcceptDialogOpen}
        onAccepted={(membership) => {
          navigate(`/w/${encodeURIComponent(membership.workspace_id)}/members`);
        }}
      />
    </div>
  );
}
