import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import { Banner, Button, Card, Center, Heading, Link, Text, TextInput, VStack } from "../../shared/ui";
import { extractAuthProblemSummary, resolveSafePostLoginPath, type AuthProblemSummary } from "./authHelpers";

export function AccountRecoveryPage(): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const [code, setCode] = useState("");
  const [identifier, setIdentifier] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState<AuthProblemSummary | null>(null);
  const csrfQuery = useQuery({ queryKey: ["auth", "csrf"], queryFn: () => api.getAuthCsrf(), retry: false });

  const recoveryMutation = useMutation({
    mutationFn: () => api.recoverAccount({
      single_use_code: code.trim(),
      identifier: identifier.trim().length === 0 ? null : identifier.trim(),
      new_password: newPassword,
    }),
    onSuccess: async (response) => {
      setError(null);
      setCode("");
      setNewPassword("");
      await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
      await queryClient.invalidateQueries({ queryKey: ["auth", "csrf"] });
      navigate(
        response.data.mfa_re_enrollment_required
          ? "/account"
          : resolveSafePostLoginPath(location.search, "/account"),
        { replace: true },
      );
    },
    onError: (cause) => setError(extractAuthProblemSummary(cause, t("auth.genericAuthErrorTitle"))),
  });

  const visibleError = error ?? (csrfQuery.isError
    ? extractAuthProblemSummary(csrfQuery.error, t("auth.genericAuthErrorTitle"))
    : null);
  const recoveryCodeError = visibleError?.code === "invalid_recovery_code" ? visibleError : null;
  const formError = visibleError !== null && recoveryCodeError === null ? visibleError : null;

  return (
    <main>
      <Center minHeight="100vh" padding={6}>
        <VStack gap={4} width="100%" maxWidth={440}>
          <Card width="100%" maxWidth={440}>
            <VStack gap={4}>
              <VStack gap={1}>
                <Heading level={1}>Recover your account</Heading>
                <Text type="supporting" as="p">Use a single-use recovery code issued for this account.</Text>
              </VStack>
              {formError !== null ? (
                <Banner
                  status={formError.status === 429 ? "warning" : "error"}
                  title={formError.status === 429 && formError.retryAfterSeconds !== null
                    ? t("auth.rateLimitedNotice", { seconds: formError.retryAfterSeconds })
                    : formError.detail}
                  description={formError.correlationId
                    ? t("state.correlationId", { correlationId: formError.correlationId })
                    : undefined}
                  container="section"
                  collapsible={false}
                />
              ) : null}
              <VStack
                as="form"
                data-testid="recovery-reset-form"
                gap={3}
                onSubmit={(event) => {
                  event.preventDefault();
                  setError(null);
                  recoveryMutation.mutate();
                }}
              >
                <TextInput
                  label={t("auth.recoveryCodeLabel")}
                  value={code}
                  onChange={setCode}
                  autoComplete="off"
                  isRequired
                  description={t("auth.recoveryCodeHint")}
                  isDisabled={recoveryMutation.isPending}
                  status={recoveryCodeError === null ? undefined : { type: "error", message: recoveryCodeError.detail }}
                />
                <TextInput
                  label={t("auth.recoveryIdentifierLabel")}
                  value={identifier}
                  onChange={setIdentifier}
                  autoComplete="username"
                  isDisabled={recoveryMutation.isPending}
                  isOptional
                />
                <TextInput
                  label={t("auth.newPasswordLabel")}
                  type="password"
                  value={newPassword}
                  onChange={setNewPassword}
                  autoComplete="new-password"
                  isRequired
                  isDisabled={recoveryMutation.isPending}
                  description={t("auth.passwordPolicyHint")}
                />
                <Button
                  label={t("auth.recoverySubmit")}
                  type="submit"
                  variant="primary"
                  isLoading={recoveryMutation.isPending}
                  isDisabled={csrfQuery.isPending || code.trim().length < 10 || newPassword.length < 12}
                />
              </VStack>
              <Link href="/login">Back to sign in</Link>
            </VStack>
          </Card>
        </VStack>
      </Center>
    </main>
  );
}
