import type { Membership } from "@red2pr/ts-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useState } from "react";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import { Button, Dialog, StatusGlyph } from "../../shared/ui";
import { extractAuthProblemSummary, type AuthProblemSummary } from "../auth";

export interface AcceptInviteDialogProps {
  readonly isOpen: boolean;
  readonly onOpenChange: (nextOpen: boolean) => void;
  readonly onAccepted?: (membership: Membership) => void;
}

export function AcceptInviteDialog({
  isOpen,
  onOpenChange,
  onAccepted,
}: AcceptInviteDialogProps): React.JSX.Element | null {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const tokenInputId = useId();
  const formId = useId();

  const [token, setToken] = useState("");
  const [errorSummary, setErrorSummary] = useState<AuthProblemSummary | null>(null);

  const resetForm = useCallback((): void => {
    setToken("");
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

  const acceptMutation = useMutation({
    mutationFn: async () => {
      return api.acceptWorkspaceInvitation({ token: token.trim() });
    },
    onSuccess: async (envelope) => {
      resetForm();
      await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
      await queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      onAccepted?.(envelope.data);
      onOpenChange(false);
    },
    onError: (err) => {
      setErrorSummary(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const handleSubmit = useCallback(
    (event: React.FormEvent<HTMLFormElement>): void => {
      event.preventDefault();
      setErrorSummary(null);
      acceptMutation.mutate();
    },
    [acceptMutation],
  );

  const canSubmit = token.trim().length >= 16 && !acceptMutation.isPending;

  return (
    <Dialog
      isOpen={isOpen}
      onOpenChange={handleOpenChange}
      purpose="form"
      title={t("members.acceptDialogTitle")}
      subtitle={t("members.acceptDialogSubtitle")}
      correlationId={errorSummary?.correlationId ?? undefined}
      data-testid="accept-invite-dialog"
      footer={
        <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
          <Button
            label={t("members.cancelAction")}
            variant="secondary"
            isDisabled={acceptMutation.isPending}
            onClick={() => handleOpenChange(false)}
          />
          <Button
            label={t("members.acceptSubmitAction")}
            variant="primary"
            type="submit"
            form={formId}
            isLoading={acceptMutation.isPending}
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
          <label htmlFor={tokenInputId} className="red2pr-field-label">
            {t("members.acceptTokenLabel")}
          </label>
          <input
            id={tokenInputId}
            className="red2pr-control-input"
            type="password"
            autoComplete="off"
            required
            value={token}
            onChange={(event) => setToken(event.target.value)}
          />
        </div>
      </form>
    </Dialog>
  );
}
