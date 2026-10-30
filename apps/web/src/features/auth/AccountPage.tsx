import { Red2PrApiError, type MfaEnrollResponse, type SessionListItem } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useRef, useState } from "react";
import { Navigate, useNavigate } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  Button,
  StateView,
  StatusGlyph,
  Table,
  sanitizeUntrustedText,
  type TableColumn,
} from "../../shared/ui";
import {
  extractAuthProblemSummary,
  formatUtcTimestamp,
  isStepUpValid,
  type AuthProblemSummary,
} from "./authHelpers";
import { StepUpDialog } from "./StepUpDialog";
import { TelegramLinkCard } from "./TelegramLinkCard";

interface SessionTableRow extends Record<string, unknown> {
  readonly id: string;
  readonly is_current: boolean;
  readonly auth_strength: string;
  readonly client_ip: string | null;
  readonly user_agent_summary: string | null;
  readonly last_seen_at: string;
  readonly expires_at: string;
}

function toSessionRow(item: SessionListItem): SessionTableRow {
  return {
    id: item.id,
    is_current: item.is_current,
    auth_strength: item.auth_strength,
    client_ip: item.client_ip ?? null,
    user_agent_summary: item.user_agent_summary ?? null,
    last_seen_at: item.last_seen_at,
    expires_at: item.expires_at,
  };
}

export function AccountPage(): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const mfaConfirmOtpId = useId();
  const mfaDisableCodeId = useId();

  const [stepUpDialogOpen, setStepUpDialogOpen] = useState(false);
  const pendingStepUpActionRef = useRef<(() => void) | null>(null);

  const [pendingEnrollment, setPendingEnrollment] = useState<MfaEnrollResponse | null>(null);
  const [confirmOtp, setConfirmOtp] = useState("");
  const [onceRecoveryCodes, setOnceRecoveryCodes] = useState<readonly string[] | null>(null);
  const [disableRecoveryCode, setDisableRecoveryCode] = useState("");
  const [actionError, setActionError] = useState<AuthProblemSummary | null>(null);

  const meQuery = useQuery({
    queryKey: ["me", "profile"],
    queryFn: () => api.getMe(),
    retry: false,
  });

  const sessionsQuery = useQuery({
    queryKey: ["me", "sessions"],
    queryFn: () => api.listMySessions(),
    enabled: meQuery.isSuccess,
    retry: false,
  });

  const requireStepUpThen = useCallback(
    (stepUpValidUntil: string | null | undefined, action: () => void): void => {
      if (isStepUpValid(stepUpValidUntil)) {
        action();
        return;
      }
      pendingStepUpActionRef.current = action;
      setStepUpDialogOpen(true);
    },
    [],
  );

  const handleStepUpVerified = useCallback((): void => {
    void queryClient.invalidateQueries({ queryKey: ["me"] });
    const nextAction = pendingStepUpActionRef.current;
    pendingStepUpActionRef.current = null;
    if (nextAction !== null) {
      nextAction();
    }
  }, [queryClient]);

  const logoutMutation = useMutation({
    mutationFn: () => api.logout(),
    onSuccess: () => {
      queryClient.clear();
      void navigate("/login", { replace: true });
    },
    onError: (err) => {
      setActionError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const startEnrollMutation = useMutation({
    mutationFn: () => api.enrollMyMfa({}),
    onSuccess: (envelope) => {
      setActionError(null);
      setConfirmOtp("");
      setPendingEnrollment(envelope.data);
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        pendingStepUpActionRef.current = () => {
          startEnrollMutation.mutate();
        };
        setStepUpDialogOpen(true);
        return;
      }
      setActionError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const confirmEnrollMutation = useMutation({
    mutationFn: async () => {
      if (!pendingEnrollment?.challenge_id) {
        throw new Error("Missing active MFA enrollment challenge.");
      }
      return api.enrollMyMfa({
        challenge_id: pendingEnrollment.challenge_id,
        otp: confirmOtp.trim(),
      });
    },
    onSuccess: async (envelope) => {
      setActionError(null);
      setPendingEnrollment(null);
      setConfirmOtp("");
      setOnceRecoveryCodes(envelope.data.recovery_codes ?? []);
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        pendingStepUpActionRef.current = () => {
          confirmEnrollMutation.mutate();
        };
        setStepUpDialogOpen(true);
        return;
      }
      setActionError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const disableMfaMutation = useMutation({
    mutationFn: () =>
      api.deleteMyMfa({
        recovery_authorization: disableRecoveryCode.trim(),
      }),
    onSuccess: async () => {
      setActionError(null);
      setDisableRecoveryCode("");
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        pendingStepUpActionRef.current = () => {
          disableMfaMutation.mutate();
        };
        setStepUpDialogOpen(true);
        return;
      }
      setActionError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const revokeSessionMutation = useMutation({
    mutationFn: async (row: SessionTableRow) => {
      await api.revokeMySession(row.id);
      return row;
    },
    onSuccess: async (revokedRow) => {
      setActionError(null);
      if (revokedRow.is_current) {
        queryClient.clear();
        void navigate("/login", { replace: true });
        return;
      }
      await queryClient.invalidateQueries({ queryKey: ["me", "sessions"] });
    },
    onError: (err) => {
      setActionError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const sessionRows = useMemo<SessionTableRow[]>(
    () => (sessionsQuery.data?.data.items ?? []).map(toSessionRow),
    [sessionsQuery.data],
  );

  const sessionColumns = useMemo<TableColumn<SessionTableRow>[]>(
    () => [
      {
        key: "user_agent_summary",
        header: t("account.colSessionDevice"),
        renderCell: (row) => {
          const safeUa = row.user_agent_summary
            ? sanitizeUntrustedText(row.user_agent_summary).text
            : t("account.unknownDevice");
          return (
            <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
              <span>{safeUa}</span>
              {row.is_current ? (
                <span className="red2pr-badge-pill red2pr-tone-success">
                  <StatusGlyph kind="check" />
                  <span>{t("account.currentSessionBadge")}</span>
                </span>
              ) : null}
            </div>
          );
        },
      },
      {
        key: "auth_strength",
        header: t("account.colSessionStrength"),
        renderCell: (row) => (
          <span
            className={`red2pr-badge-pill ${
              row.auth_strength === "mfa" ? "red2pr-tone-success" : "red2pr-tone-neutral"
            }`}
          >
            {row.auth_strength.toUpperCase()}
          </span>
        ),
      },
      {
        key: "client_ip",
        header: t("account.colSessionIp"),
        renderCell: (row) => (
          <code>{row.client_ip ? sanitizeUntrustedText(row.client_ip).text : "—"}</code>
        ),
      },
      {
        key: "last_seen_at",
        header: t("account.colSessionLastSeen"),
        renderCell: (row) => <span>{formatUtcTimestamp(row.last_seen_at)}</span>,
      },
      {
        key: "expires_at",
        header: t("account.colSessionExpires"),
        renderCell: (row) => <span>{formatUtcTimestamp(row.expires_at)}</span>,
      },
      {
        key: "id",
        header: t("account.colSessionAction"),
        renderCell: (row) => (
          <Button
            label={t("account.revokeSessionAction")}
            variant={row.is_current ? "secondary" : "destructive"}
            size="sm"
            isDisabled={revokeSessionMutation.isPending}
            onClick={() => revokeSessionMutation.mutate(row)}
          />
        ),
      },
    ],
    [revokeSessionMutation, t],
  );

  if (meQuery.isPending) {
    return <StateView state="loading" />;
  }

  if (meQuery.isError) {
    if (meQuery.error instanceof Red2PrApiError && meQuery.error.status === 401) {
      return <Navigate to="/login?next=%2Faccount" replace />;
    }
    const errSummary = extractAuthProblemSummary(meQuery.error, t("state.error.description"));
    return (
      <StateView
        state={errSummary.status === null ? "offline" : "error"}
        description={errSummary.detail}
        correlationId={errSummary.correlationId ?? undefined}
        primaryAction={{
          label: "Retry",
          onClick: () => {
            void meQuery.refetch();
          },
        }}
      />
    );
  }

  const me = meQuery.data.data;
  const stepUpActive = isStepUpValid(me.step_up_valid_until);

  return (
    <div className="red2pr-page-stack">
      <div className="red2pr-card-header">
        <div>
          <h1 style={{ margin: "0 0 6px", fontSize: "1.5rem" }}>{t("account.pageTitle")}</h1>
          <p className="red2pr-field-hint">{t("account.pageSubtitle")}</p>
        </div>
        <div className="red2pr-button-row">
          <Button
            label={t("account.verifyStepUpAction")}
            variant="secondary"
            onClick={() => {
              pendingStepUpActionRef.current = null;
              setStepUpDialogOpen(true);
            }}
          />
          <Button
            label={t("account.signOut")}
            variant="secondary"
            isLoading={logoutMutation.isPending}
            onClick={() => logoutMutation.mutate()}
          />
        </div>
      </div>

      {actionError !== null ? (
        <div
          role="alert"
          data-testid="account-error-banner"
          className={`red2pr-inline-alert ${
            actionError.status === 429 ? "red2pr-tone-warning" : "red2pr-tone-danger"
          }`}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
            <StatusGlyph kind={actionError.status === 429 ? "clock" : "error"} />
            <span>
              {actionError.status === 429 && actionError.retryAfterSeconds !== null
                ? t("auth.rateLimitedNotice", { seconds: actionError.retryAfterSeconds })
                : actionError.detail}
            </span>
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
        aria-labelledby="account-profile-heading"
      >
        <div className="red2pr-card-header">
          <h2 id="account-profile-heading" style={{ margin: 0, fontSize: "1.125rem" }}>
            {t("account.profileTitle")}
          </h2>
          <span
            className={`red2pr-badge-pill ${
              me.is_instance_owner ? "red2pr-tone-info" : "red2pr-tone-neutral"
            }`}
          >
            <StatusGlyph kind={me.is_instance_owner ? "lock" : "info"} />
            <span>{me.is_instance_owner ? t("account.roleOwner") : t("account.roleMember")}</span>
          </span>
        </div>

        <dl className="red2pr-kv-grid">
          <div className="red2pr-kv-item">
            <dt className="red2pr-kv-term">{t("account.fieldDisplayName")}</dt>
            <dd className="red2pr-kv-detail">
              {sanitizeUntrustedText(me.user.display_name).text}
            </dd>
          </div>
          <div className="red2pr-kv-item">
            <dt className="red2pr-kv-term">{t("account.fieldEmail")}</dt>
            <dd className="red2pr-kv-detail">
              {me.user.email
                ? sanitizeUntrustedText(me.user.email).text
                : t("account.fieldEmailUnset")}
            </dd>
          </div>
          <div className="red2pr-kv-item">
            <dt className="red2pr-kv-term">{t("account.fieldStatus")}</dt>
            <dd className="red2pr-kv-detail">{me.user.status}</dd>
          </div>
          <div className="red2pr-kv-item">
            <dt className="red2pr-kv-term">{t("account.fieldAuthStrength")}</dt>
            <dd className="red2pr-kv-detail">{me.session.auth_strength.toUpperCase()}</dd>
          </div>
          <div className="red2pr-kv-item">
            <dt className="red2pr-kv-term">{t("account.fieldStepUp")}</dt>
            <dd className="red2pr-kv-detail">
              {stepUpActive && me.step_up_valid_until
                ? t("account.stepUpActive", { until: formatUtcTimestamp(me.step_up_valid_until) })
                : t("account.stepUpInactive")}
            </dd>
          </div>
        </dl>

        <div>
          <h3 style={{ margin: "0 0 6px", fontSize: "0.9375rem" }}>
            {t("account.grantsHeading")}
          </h3>
          {(me.memberships ?? []).length === 0 ? (
            <p className="red2pr-field-hint">{t("account.grantsEmpty")}</p>
          ) : (
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              {(me.memberships ?? []).map((membership) => (
                <li key={membership.id}>
                  <code>{membership.workspace_id}</code> — {membership.role}
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section
        className="red2pr-surface red2pr-card-section"
        aria-labelledby="account-mfa-heading"
      >
        <div className="red2pr-card-header">
          <h2 id="account-mfa-heading" style={{ margin: 0, fontSize: "1.125rem" }}>
            {t("account.mfaTitle")}
          </h2>
          <span
            data-testid="mfa-status-badge"
            className={`red2pr-badge-pill ${
              me.mfa_enabled ? "red2pr-tone-success" : "red2pr-tone-warning"
            }`}
          >
            <StatusGlyph kind={me.mfa_enabled ? "check" : "warn"} />
            <span>
              {me.mfa_enabled ? t("account.mfaEnabledBadge") : t("account.mfaDisabledBadge")}
            </span>
          </span>
        </div>

        {me.mfa_required_for_privileged ? (
          <div className="red2pr-inline-alert red2pr-tone-info">
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <StatusGlyph kind="lock" />
              <span>{t("account.mfaMandatoryNotice")}</span>
            </div>
          </div>
        ) : null}

        {onceRecoveryCodes !== null ? (
          <div
            data-testid="mfa-recovery-codes-panel"
            className="red2pr-inline-alert red2pr-tone-warning"
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
              <StatusGlyph kind="warn" />
              <span>{t("account.mfaRecoveryOnceWarning")}</span>
            </div>
            <ul className="red2pr-code-grid" style={{ marginTop: 8 }}>
              {onceRecoveryCodes.map((code) => (
                <li key={code} className="red2pr-code-chip">
                  {code}
                </li>
              ))}
            </ul>
            <div className="red2pr-button-row" style={{ marginTop: 10 }}>
              <Button
                label={t("account.mfaAcknowledgeCodes")}
                variant="primary"
                onClick={() => setOnceRecoveryCodes(null)}
              />
            </div>
          </div>
        ) : null}

        {pendingEnrollment !== null ? (
          <form
            className="red2pr-form-stack"
            data-testid="mfa-enrollment-confirm-form"
            onSubmit={(event) => {
              event.preventDefault();
              setActionError(null);
              confirmEnrollMutation.mutate();
            }}
            noValidate
          >
            <div className="red2pr-inline-alert red2pr-tone-warning">
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                <StatusGlyph kind="warn" />
                <span>{t("account.mfaSecretOnceWarning")}</span>
              </div>
            </div>

            <div className="red2pr-field">
              <span className="red2pr-field-label">{t("account.mfaSecretLabel")}</span>
              <div
                data-testid="mfa-secret-once"
                className="red2pr-code-viewport"
                style={{ padding: "8px 12px", wordBreak: "break-all" }}
              >
                {pendingEnrollment.secret_base32}
              </div>
            </div>

            {pendingEnrollment.otpauth_uri ? (
              <div className="red2pr-field">
                <span className="red2pr-field-label">{t("account.mfaUriLabel")}</span>
                <div
                  className="red2pr-code-viewport"
                  style={{ padding: "8px 12px", wordBreak: "break-all" }}
                >
                  {pendingEnrollment.otpauth_uri}
                </div>
              </div>
            ) : null}

            <div className="red2pr-field">
              <label htmlFor={mfaConfirmOtpId} className="red2pr-field-label">
                {t("account.mfaConfirmOtpLabel")}
              </label>
              <input
                id={mfaConfirmOtpId}
                className="red2pr-control-input"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
                required
                value={confirmOtp}
                onChange={(event) => setConfirmOtp(event.target.value)}
              />
            </div>

            <div className="red2pr-button-row">
              <Button
                label={t("account.mfaConfirmAction")}
                variant="primary"
                type="submit"
                isLoading={confirmEnrollMutation.isPending}
                isDisabled={confirmOtp.trim().length < 6 || confirmEnrollMutation.isPending}
              />
              <Button
                label={t("account.mfaCancelSetup")}
                variant="secondary"
                isDisabled={confirmEnrollMutation.isPending}
                onClick={() => {
                  setPendingEnrollment(null);
                  setConfirmOtp("");
                }}
              />
            </div>
          </form>
        ) : (
          <div className="red2pr-button-row">
            <Button
              label={me.mfa_enabled ? t("account.mfaRotateEnroll") : t("account.mfaStartEnroll")}
              variant="primary"
              isLoading={startEnrollMutation.isPending}
              onClick={() => {
                setActionError(null);
                requireStepUpThen(me.step_up_valid_until, () => {
                  startEnrollMutation.mutate();
                });
              }}
            />
          </div>
        )}

        {me.mfa_enabled && pendingEnrollment === null ? (
          <form
            className="red2pr-form-stack"
            style={{
              borderTop: "1px solid var(--red2pr-border-subtle)",
              paddingTop: 14,
            }}
            onSubmit={(event) => {
              event.preventDefault();
              setActionError(null);
              requireStepUpThen(me.step_up_valid_until, () => {
                disableMfaMutation.mutate();
              });
            }}
            noValidate
          >
            <div>
              <h3 style={{ margin: "0 0 4px", fontSize: "0.9375rem" }}>
                {t("account.mfaDisableHeading")}
              </h3>
              <p className="red2pr-field-hint">{t("account.mfaDisableDesc")}</p>
            </div>

            <div className="red2pr-field">
              <label htmlFor={mfaDisableCodeId} className="red2pr-field-label">
                {t("account.mfaDisableCodeLabel")}
              </label>
              <input
                id={mfaDisableCodeId}
                className="red2pr-control-input"
                type="text"
                autoComplete="off"
                required
                value={disableRecoveryCode}
                onChange={(event) => setDisableRecoveryCode(event.target.value)}
              />
            </div>

            <div className="red2pr-button-row">
              <Button
                label={t("account.mfaDisableAction")}
                variant="destructive"
                type="submit"
                isLoading={disableMfaMutation.isPending}
                isDisabled={
                  disableRecoveryCode.trim().length < 10 || disableMfaMutation.isPending
                }
              />
            </div>
          </form>
        ) : null}
      </section>

      <TelegramLinkCard
        link={me.telegram_link ?? { status: "not_configured" }}
        requireStepUpThen={(action) => requireStepUpThen(me.step_up_valid_until, action)}
      />

      <section
        className="red2pr-surface red2pr-card-section"
        aria-labelledby="account-sessions-heading"
      >
        <div>
          <h2 id="account-sessions-heading" style={{ margin: "0 0 4px", fontSize: "1.125rem" }}>
            {t("account.sessionsTitle")}
          </h2>
          <p className="red2pr-field-hint">{t("account.sessionsSubtitle")}</p>
        </div>

        <Table<SessionTableRow>
          aria-label={t("account.sessionsTableLabel")}
          data={sessionRows}
          columns={sessionColumns}
          idKey="id"
          density="compact"
        />
      </section>

      <StepUpDialog
        isOpen={stepUpDialogOpen}
        mfaEnabled={me.mfa_enabled}
        onOpenChange={(nextOpen) => {
          setStepUpDialogOpen(nextOpen);
          if (!nextOpen) {
            pendingStepUpActionRef.current = null;
          }
        }}
        onVerified={handleStepUpVerified}
      />
    </div>
  );
}
