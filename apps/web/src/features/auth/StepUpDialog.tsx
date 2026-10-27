import type { StepUpResponse } from "@red2pr/ts-client";
import { useMutation } from "@tanstack/react-query";
import React, { useCallback, useId, useState } from "react";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import { Button, Dialog, StatusGlyph } from "../../shared/ui";
import { extractAuthProblemSummary, type AuthProblemSummary } from "./authHelpers";

export interface StepUpDialogProps {
  readonly isOpen: boolean;
  readonly mfaEnabled: boolean;
  readonly onOpenChange: (nextOpen: boolean) => void;
  readonly onVerified: (result: StepUpResponse) => void;
}

export function StepUpDialog({
  isOpen,
  mfaEnabled,
  onOpenChange,
  onVerified,
}: StepUpDialogProps): React.JSX.Element | null {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const passwordInputId = useId();
  const otpInputId = useId();
  const formId = useId();

  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [errorSummary, setErrorSummary] = useState<AuthProblemSummary | null>(null);

  const resetForm = useCallback((): void => {
    setPassword("");
    setOtp("");
    setErrorSummary(null);
  }, []);

  const handleOpenChange = useCallback(
    (nextOpen: boolean): void => {
      if (!nextOpen) {
        resetForm();
      }
      onOpenChange(nextOpen);
    },
    [onOpenChange, resetForm],
  );

  const stepUpMutation = useMutation({
    mutationFn: async () => {
      return api.stepUp({
        password,
        otp: mfaEnabled ? otp.trim() : null,
      });
    },
    onSuccess: (envelope) => {
      resetForm();
      onVerified(envelope.data);
      onOpenChange(false);
    },
    onError: (err) => {
      setErrorSummary(extractAuthProblemSummary(err, t("auth.genericAuthErrorTitle")));
    },
  });

  const handleSubmit = useCallback(
    (event: React.FormEvent<HTMLFormElement>): void => {
      event.preventDefault();
      setErrorSummary(null);
      stepUpMutation.mutate();
    },
    [stepUpMutation],
  );

  const canSubmit =
    password.length > 0 && (!mfaEnabled || otp.trim().length >= 6) && !stepUpMutation.isPending;

  return (
    <Dialog
      isOpen={isOpen}
      onOpenChange={handleOpenChange}
      purpose="form"
      title={t("stepUp.dialogTitle")}
      subtitle={t("stepUp.dialogSubtitle")}
      correlationId={errorSummary?.correlationId ?? undefined}
      data-testid="step-up-dialog"
      footer={
        <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
          <Button
            label={t("stepUp.cancel")}
            variant="secondary"
            isDisabled={stepUpMutation.isPending}
            onClick={() => handleOpenChange(false)}
          />
          <Button
            label={t("stepUp.submit")}
            variant="primary"
            type="submit"
            form={formId}
            isLoading={stepUpMutation.isPending}
            isDisabled={!canSubmit}
          />
        </div>
      }
    >
      <form id={formId} className="red2pr-form-stack" onSubmit={handleSubmit} noValidate>
        {errorSummary !== null ? (
          <div
            role="alert"
            className={`red2pr-inline-alert ${
              errorSummary.status === 429 ? "red2pr-tone-warning" : "red2pr-tone-danger"
            }`}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
              <StatusGlyph kind={errorSummary.status === 429 ? "clock" : "error"} />
              <span>
                {errorSummary.status === 429 && errorSummary.retryAfterSeconds !== null
                  ? t("auth.rateLimitedNotice", { seconds: errorSummary.retryAfterSeconds })
                  : errorSummary.detail}
              </span>
            </div>
          </div>
        ) : null}

        <div className="red2pr-field">
          <label htmlFor={passwordInputId} className="red2pr-field-label">
            {t("stepUp.passwordLabel")}
          </label>
          <input
            id={passwordInputId}
            className="red2pr-control-input"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>

        {mfaEnabled ? (
          <div className="red2pr-field">
            <label htmlFor={otpInputId} className="red2pr-field-label">
              {t("stepUp.otpLabel")}
            </label>
            <input
              id={otpInputId}
              className="red2pr-control-input"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={8}
              required
              value={otp}
              onChange={(event) => setOtp(event.target.value)}
            />
          </div>
        ) : null}
      </form>
    </Dialog>
  );
}
