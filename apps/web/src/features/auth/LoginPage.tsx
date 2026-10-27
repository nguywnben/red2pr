import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import { useRed2PrTheme, type ThemeMode } from "../../shared/theme";
import { Button, StatusGlyph } from "../../shared/ui";
import {
  extractAuthProblemSummary,
  resolveSafePostLoginPath,
  type AuthProblemSummary,
} from "./authHelpers";

type AuthFlowTab = "login" | "claim" | "recovery";

export function LoginPage(): React.JSX.Element {
  const { t } = useI18n();
  const { mode, setMode } = useRed2PrTheme();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();

  const themeSelectId = useId();
  const identifierId = useId();
  const identifierHintId = useId();
  const passwordId = useId();
  const otpId = useId();
  const otpHintId = useId();
  const bootstrapTokenId = useId();
  const bootstrapTokenHintId = useId();
  const displayNameId = useId();
  const claimEmailId = useId();
  const claimPasswordId = useId();
  const claimPasswordHintId = useId();
  const recoveryCodeId = useId();
  const recoveryCodeHintId = useId();
  const recoveryIdentifierId = useId();
  const recoveryPasswordId = useId();
  const recoveryPasswordHintId = useId();

  const [explicitTab, setExplicitTab] = useState<AuthFlowTab | null>(null);
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [pendingChallengeId, setPendingChallengeId] = useState<string | null>(null);
  const [otp, setOtp] = useState("");

  const [bootstrapToken, setBootstrapToken] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [claimEmail, setClaimEmail] = useState("");
  const [claimPassword, setClaimPassword] = useState("");

  const [recoveryCode, setRecoveryCode] = useState("");
  const [recoveryIdentifier, setRecoveryIdentifier] = useState("");
  const [recoveryNewPassword, setRecoveryNewPassword] = useState("");

  const [errorSummary, setErrorSummary] = useState<AuthProblemSummary | null>(null);

  const csrfQuery = useQuery({
    queryKey: ["auth", "csrf"],
    queryFn: () => api.getAuthCsrf(),
    retry: false,
  });

  const bootstrapClaimRequired = csrfQuery.data?.data.bootstrap_claim_required === true;
  const activeTab: AuthFlowTab =
    explicitTab ?? (bootstrapClaimRequired ? "claim" : "login");

  const postLoginTarget = resolveSafePostLoginPath(location.search, "/account");

  const completeSignInNavigation = useCallback(
    async (targetPath: string): Promise<void> => {
      await queryClient.invalidateQueries({ queryKey: ["me"] });
      await queryClient.invalidateQueries({ queryKey: ["auth", "csrf"] });
      void navigate(targetPath, { replace: true });
    },
    [navigate, queryClient],
  );

  const switchTab = useCallback((nextTab: AuthFlowTab): void => {
    setExplicitTab(nextTab);
    setPendingChallengeId(null);
    setPassword("");
    setOtp("");
    setErrorSummary(null);
  }, []);

  const handleThemeChange = useCallback(
    (event: React.ChangeEvent<HTMLSelectElement>): void => {
      const value = event.target.value;
      if (value === "light" || value === "dark" || value === "system") {
        setMode(value as ThemeMode);
      }
    },
    [setMode],
  );

  const loginPasswordMutation = useMutation({
    mutationFn: async () =>
      api.login({
        identifier: identifier.trim(),
        password,
      }),
    onSuccess: async (envelope) => {
      setErrorSummary(null);
      if (envelope.data.status === "mfa_required" && envelope.data.mfa_challenge_id) {
        setOtp("");
        setPendingChallengeId(envelope.data.mfa_challenge_id);
        return;
      }
      setPassword("");
      await completeSignInNavigation(postLoginTarget);
    },
    onError: (err) => {
      setErrorSummary(extractAuthProblemSummary(err, t("auth.genericAuthErrorTitle")));
    },
  });

  const loginMfaMutation = useMutation({
    mutationFn: async () =>
      api.login({
        identifier: identifier.trim(),
        password,
        mfa_challenge_id: pendingChallengeId,
        otp: otp.trim(),
      }),
    onSuccess: async () => {
      setErrorSummary(null);
      setPassword("");
      setOtp("");
      setPendingChallengeId(null);
      await completeSignInNavigation(postLoginTarget);
    },
    onError: (err) => {
      setErrorSummary(extractAuthProblemSummary(err, t("auth.genericAuthErrorTitle")));
    },
  });

  const bootstrapMutation = useMutation({
    mutationFn: async () =>
      api.claimInstanceOwner({
        bootstrap_token: bootstrapToken.trim(),
        display_name: displayName.trim(),
        email: claimEmail.trim().length > 0 ? claimEmail.trim() : null,
        password: claimPassword,
      }),
    onSuccess: async () => {
      setErrorSummary(null);
      setBootstrapToken("");
      setClaimPassword("");
      await completeSignInNavigation("/account");
    },
    onError: (err) => {
      setErrorSummary(extractAuthProblemSummary(err, t("auth.genericAuthErrorTitle")));
    },
  });

  const recoveryMutation = useMutation({
    mutationFn: async () =>
      api.recoverAccount({
        single_use_code: recoveryCode.trim(),
        identifier: recoveryIdentifier.trim().length > 0 ? recoveryIdentifier.trim() : null,
        new_password: recoveryNewPassword,
      }),
    onSuccess: async (envelope) => {
      setErrorSummary(null);
      setRecoveryCode("");
      setRecoveryNewPassword("");
      const destination = envelope.data.mfa_re_enrollment_required
        ? "/account"
        : postLoginTarget;
      await completeSignInNavigation(destination);
    },
    onError: (err) => {
      setErrorSummary(extractAuthProblemSummary(err, t("auth.genericAuthErrorTitle")));
    },
  });

  const isBusy =
    loginPasswordMutation.isPending ||
    loginMfaMutation.isPending ||
    bootstrapMutation.isPending ||
    recoveryMutation.isPending;

  return (
    <div className="red2pr-auth-shell">
      <a href="#red2pr-auth-main" className="red2pr-badge-pill red2pr-tone-neutral" style={{ alignSelf: "flex-start", margin: "8px 20px 0" }}>
        {t("app.skipToMain")}
      </a>

      <header className="red2pr-auth-topbar">
        <div>
          <strong style={{ fontSize: "1.0625rem" }}>{t("app.brand")}</strong>
          <span style={{ marginLeft: 10, fontSize: "0.875rem", color: "var(--red2pr-text-secondary)" }}>
            {t("app.tagline")}
          </span>
        </div>
        <div style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          <label htmlFor={themeSelectId} style={{ fontSize: "0.8125rem", fontWeight: 600 }}>
            {t("app.theme.label")}
          </label>
          <select
            id={themeSelectId}
            className="red2pr-control-select"
            value={mode}
            onChange={handleThemeChange}
          >
            <option value="light">{t("app.theme.light")}</option>
            <option value="dark">{t("app.theme.dark")}</option>
            <option value="system">{t("app.theme.system")}</option>
          </select>
        </div>
      </header>

      <main id="red2pr-auth-main" className="red2pr-auth-main">
        <section className="red2pr-surface red2pr-auth-card" aria-labelledby="red2pr-auth-heading">
          {bootstrapClaimRequired ? (
            <div className="red2pr-inline-alert red2pr-tone-info" style={{ marginBottom: 16 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                <StatusGlyph kind="info" />
                <span>{t("auth.bootstrapBanner")}</span>
              </div>
            </div>
          ) : null}

          <nav className="red2pr-tab-strip" aria-label={t("auth.modeLabel")} style={{ marginBottom: 18 }}>
            <button
              type="button"
              className="red2pr-tab-button"
              aria-pressed={activeTab === "login"}
              onClick={() => switchTab("login")}
            >
              {t("auth.modeSignIn")}
            </button>
            <button
              type="button"
              className="red2pr-tab-button"
              aria-pressed={activeTab === "claim"}
              onClick={() => switchTab("claim")}
            >
              {t("auth.modeBootstrap")}
            </button>
            <button
              type="button"
              className="red2pr-tab-button"
              aria-pressed={activeTab === "recovery"}
              onClick={() => switchTab("recovery")}
            >
              {t("auth.modeRecovery")}
            </button>
          </nav>

          {errorSummary !== null ? (
            <div
              role="alert"
              data-testid="auth-error-banner"
              className={`red2pr-inline-alert ${
                errorSummary.status === 429 ? "red2pr-tone-warning" : "red2pr-tone-danger"
              }`}
              style={{ marginBottom: 16 }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                <StatusGlyph kind={errorSummary.status === 429 ? "clock" : "error"} />
                <span>
                  {errorSummary.status === 429 && errorSummary.retryAfterSeconds !== null
                    ? t("auth.rateLimitedNotice", { seconds: errorSummary.retryAfterSeconds })
                    : errorSummary.detail}
                </span>
              </div>
              {errorSummary.correlationId ? (
                <div>
                  <code>
                    {t("state.correlationId", { correlationId: errorSummary.correlationId })}
                  </code>
                </div>
              ) : null}
            </div>
          ) : null}

          {activeTab === "login" && pendingChallengeId === null ? (
            <form
              className="red2pr-form-stack"
              onSubmit={(event) => {
                event.preventDefault();
                setErrorSummary(null);
                loginPasswordMutation.mutate();
              }}
              noValidate
            >
              <div>
                <h1 id="red2pr-auth-heading" style={{ margin: "0 0 6px", fontSize: "1.375rem" }}>
                  {t("auth.signInTitle")}
                </h1>
                <p className="red2pr-field-hint">{t("auth.signInSubtitle")}</p>
              </div>

              <div className="red2pr-field">
                <label htmlFor={identifierId} className="red2pr-field-label">
                  {t("auth.identifierLabel")}
                </label>
                <input
                  id={identifierId}
                  className="red2pr-control-input"
                  type="text"
                  autoComplete="username"
                  aria-describedby={identifierHintId}
                  required
                  value={identifier}
                  onChange={(event) => setIdentifier(event.target.value)}
                />
                <p id={identifierHintId} className="red2pr-field-hint">
                  {t("auth.identifierHint")}
                </p>
              </div>

              <div className="red2pr-field">
                <label htmlFor={passwordId} className="red2pr-field-label">
                  {t("auth.passwordLabel")}
                </label>
                <input
                  id={passwordId}
                  className="red2pr-control-input"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </div>

              <div className="red2pr-button-row" style={{ marginTop: 4 }}>
                <Button
                  label={t("auth.signInSubmit")}
                  variant="primary"
                  type="submit"
                  isLoading={loginPasswordMutation.isPending}
                  isDisabled={identifier.trim().length === 0 || password.length === 0 || isBusy}
                />
              </div>
            </form>
          ) : null}

          {activeTab === "login" && pendingChallengeId !== null ? (
            <form
              className="red2pr-form-stack"
              data-testid="mfa-challenge-form"
              onSubmit={(event) => {
                event.preventDefault();
                setErrorSummary(null);
                loginMfaMutation.mutate();
              }}
              noValidate
            >
              <div>
                <h1 id="red2pr-auth-heading" style={{ margin: "0 0 6px", fontSize: "1.375rem" }}>
                  {t("auth.mfaTitle")}
                </h1>
                <p className="red2pr-field-hint">{t("auth.mfaSubtitle")}</p>
              </div>

              <div className="red2pr-field">
                <label htmlFor={otpId} className="red2pr-field-label">
                  {t("auth.otpLabel")}
                </label>
                <input
                  id={otpId}
                  className="red2pr-control-input"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={8}
                  aria-describedby={otpHintId}
                  required
                  value={otp}
                  onChange={(event) => setOtp(event.target.value)}
                />
                <p id={otpHintId} className="red2pr-field-hint">
                  {t("auth.otpHint")}
                </p>
              </div>

              <div className="red2pr-button-row" style={{ marginTop: 4 }}>
                <Button
                  label={t("auth.mfaSubmit")}
                  variant="primary"
                  type="submit"
                  isLoading={loginMfaMutation.isPending}
                  isDisabled={otp.trim().length < 6 || isBusy}
                />
                <Button
                  label={t("auth.mfaBack")}
                  variant="secondary"
                  isDisabled={isBusy}
                  onClick={() => {
                    setPendingChallengeId(null);
                    setPassword("");
                    setOtp("");
                    setErrorSummary(null);
                  }}
                />
              </div>

              <div>
                <Button
                  label={t("auth.mfaUseRecovery")}
                  variant="ghost"
                  size="sm"
                  isDisabled={isBusy}
                  onClick={() => {
                    if (identifier.trim().length > 0 && recoveryIdentifier.length === 0) {
                      setRecoveryIdentifier(identifier.trim());
                    }
                    switchTab("recovery");
                  }}
                />
              </div>
            </form>
          ) : null}

          {activeTab === "claim" ? (
            <form
              className="red2pr-form-stack"
              data-testid="bootstrap-claim-form"
              onSubmit={(event) => {
                event.preventDefault();
                setErrorSummary(null);
                bootstrapMutation.mutate();
              }}
              noValidate
            >
              <div>
                <h1 id="red2pr-auth-heading" style={{ margin: "0 0 6px", fontSize: "1.375rem" }}>
                  {t("auth.bootstrapTitle")}
                </h1>
                <p className="red2pr-field-hint">{t("auth.bootstrapSubtitle")}</p>
              </div>

              <div className="red2pr-field">
                <label htmlFor={bootstrapTokenId} className="red2pr-field-label">
                  {t("auth.bootstrapTokenLabel")}
                </label>
                <input
                  id={bootstrapTokenId}
                  className="red2pr-control-input"
                  type="password"
                  autoComplete="off"
                  aria-describedby={bootstrapTokenHintId}
                  required
                  value={bootstrapToken}
                  onChange={(event) => setBootstrapToken(event.target.value)}
                />
                <p id={bootstrapTokenHintId} className="red2pr-field-hint">
                  {t("auth.bootstrapTokenHint")}
                </p>
              </div>

              <div className="red2pr-field">
                <label htmlFor={displayNameId} className="red2pr-field-label">
                  {t("auth.displayNameLabel")}
                </label>
                <input
                  id={displayNameId}
                  className="red2pr-control-input"
                  type="text"
                  autoComplete="name"
                  required
                  value={displayName}
                  onChange={(event) => setDisplayName(event.target.value)}
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={claimEmailId} className="red2pr-field-label">
                  {t("auth.emailOptionalLabel")}
                </label>
                <input
                  id={claimEmailId}
                  className="red2pr-control-input"
                  type="email"
                  autoComplete="email"
                  value={claimEmail}
                  onChange={(event) => setClaimEmail(event.target.value)}
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={claimPasswordId} className="red2pr-field-label">
                  {t("auth.newOwnerPasswordLabel")}
                </label>
                <input
                  id={claimPasswordId}
                  className="red2pr-control-input"
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  aria-describedby={claimPasswordHintId}
                  required
                  value={claimPassword}
                  onChange={(event) => setClaimPassword(event.target.value)}
                />
                <p id={claimPasswordHintId} className="red2pr-field-hint">
                  {t("auth.passwordPolicyHint")}
                </p>
              </div>

              <div className="red2pr-button-row" style={{ marginTop: 4 }}>
                <Button
                  label={t("auth.bootstrapSubmit")}
                  variant="primary"
                  type="submit"
                  isLoading={bootstrapMutation.isPending}
                  isDisabled={
                    bootstrapToken.trim().length < 16 ||
                    displayName.trim().length === 0 ||
                    claimPassword.length < 12 ||
                    isBusy
                  }
                />
              </div>
            </form>
          ) : null}

          {activeTab === "recovery" ? (
            <form
              className="red2pr-form-stack"
              data-testid="recovery-reset-form"
              onSubmit={(event) => {
                event.preventDefault();
                setErrorSummary(null);
                recoveryMutation.mutate();
              }}
              noValidate
            >
              <div>
                <h1 id="red2pr-auth-heading" style={{ margin: "0 0 6px", fontSize: "1.375rem" }}>
                  {t("auth.recoveryTitle")}
                </h1>
                <p className="red2pr-field-hint">{t("auth.recoverySubtitle")}</p>
              </div>

              <div className="red2pr-field">
                <label htmlFor={recoveryCodeId} className="red2pr-field-label">
                  {t("auth.recoveryCodeLabel")}
                </label>
                <input
                  id={recoveryCodeId}
                  className="red2pr-control-input"
                  type="text"
                  autoComplete="off"
                  aria-describedby={recoveryCodeHintId}
                  required
                  value={recoveryCode}
                  onChange={(event) => setRecoveryCode(event.target.value)}
                />
                <p id={recoveryCodeHintId} className="red2pr-field-hint">
                  {t("auth.recoveryCodeHint")}
                </p>
              </div>

              <div className="red2pr-field">
                <label htmlFor={recoveryIdentifierId} className="red2pr-field-label">
                  {t("auth.recoveryIdentifierLabel")}
                </label>
                <input
                  id={recoveryIdentifierId}
                  className="red2pr-control-input"
                  type="text"
                  autoComplete="username"
                  value={recoveryIdentifier}
                  onChange={(event) => setRecoveryIdentifier(event.target.value)}
                />
              </div>

              <div className="red2pr-field">
                <label htmlFor={recoveryPasswordId} className="red2pr-field-label">
                  {t("auth.newPasswordLabel")}
                </label>
                <input
                  id={recoveryPasswordId}
                  className="red2pr-control-input"
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  aria-describedby={recoveryPasswordHintId}
                  required
                  value={recoveryNewPassword}
                  onChange={(event) => setRecoveryNewPassword(event.target.value)}
                />
                <p id={recoveryPasswordHintId} className="red2pr-field-hint">
                  {t("auth.passwordPolicyHint")}
                </p>
              </div>

              <div className="red2pr-button-row" style={{ marginTop: 4 }}>
                <Button
                  label={t("auth.recoverySubmit")}
                  variant="primary"
                  type="submit"
                  isLoading={recoveryMutation.isPending}
                  isDisabled={
                    recoveryCode.trim().length < 10 || recoveryNewPassword.length < 12 || isBusy
                  }
                />
              </div>
            </form>
          ) : null}
        </section>
      </main>
    </div>
  );
}
