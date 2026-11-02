import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { useRed2PrApi, useRed2PrTransportConfig } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import { Banner, Button, Card, Center, Heading, HStack, Link, Text, TextInput, VStack } from "../../shared/ui";
import { extractAuthProblemSummary, resolveSafePostLoginPath, type AuthProblemSummary } from "./authHelpers";

async function readOidcProviderIds(fetchImpl: typeof fetch, baseUrl: string): Promise<string[]> {
  try {
    const response = await fetchImpl(`${baseUrl.replace(/\/$/, "")}/api/v1/system/capabilities`, {
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return [];
    const body: unknown = await response.json();
    if (typeof body !== "object" || body === null || !("oidc_providers" in body)) return [];
    const providers = body.oidc_providers;
    return Array.isArray(providers)
      ? providers.filter((provider): provider is string => typeof provider === "string")
      : [];
  } catch {
    return [];
  }
}

export function LoginPage(): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const transport = useRed2PrTransportConfig();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [mfaChallengeId, setMfaChallengeId] = useState<string | null>(null);
  const [error, setError] = useState<AuthProblemSummary | null>(null);

  const csrfQuery = useQuery({
    queryKey: ["auth", "csrf"],
    queryFn: () => api.getAuthCsrf(),
    retry: false,
  });
  const oidcProvidersQuery = useQuery({
    queryKey: ["system", "capabilities", "oidc"],
    queryFn: () => readOidcProviderIds(transport.fetchImpl ?? fetch, transport.baseUrl),
    retry: false,
    staleTime: 60_000,
  });

  const completeSignIn = async (path: string): Promise<void> => {
    setPassword("");
    setOtp("");
    setMfaChallengeId(null);
    await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
    await queryClient.invalidateQueries({ queryKey: ["auth", "csrf"] });
    navigate(path, { replace: true });
  };

  const signInMutation = useMutation({
    mutationFn: () =>
      api.login({
        identifier: identifier.trim(),
        password,
        ...(mfaChallengeId === null ? {} : { mfa_challenge_id: mfaChallengeId, otp: otp.trim() }),
      }),
    onSuccess: async (response) => {
      setError(null);
      if (response.data.status === "mfa_required" && response.data.mfa_challenge_id) {
        setOtp("");
        setMfaChallengeId(response.data.mfa_challenge_id);
        return;
      }
      await completeSignIn(resolveSafePostLoginPath(location.search, "/account"));
    },
    onError: (cause) => {
      setError(extractAuthProblemSummary(cause, t("auth.genericAuthErrorTitle")));
    },
  });

  const csrfError = csrfQuery.isError
    ? extractAuthProblemSummary(csrfQuery.error, t("auth.genericAuthErrorTitle"))
    : null;
  const visibleError = error ?? csrfError;
  const otpError = mfaChallengeId !== null && visibleError?.code === "invalid_totp"
    ? visibleError
    : null;
  const formError = visibleError !== null && otpError === null ? visibleError : null;
  const submitting = signInMutation.isPending || csrfQuery.isPending;
  const bootstrapClaimRequired = csrfQuery.data?.data.bootstrap_claim_required === true;

  return (
    <main>
      <Center minHeight="100vh" padding={6}>
        <VStack gap={4} width="100%" maxWidth={440}>
          <Card width="100%" maxWidth={440}>
            <VStack gap={4}>
              <VStack gap={1}>
                <Heading level={1}>{t("auth.signInTitle")}</Heading>
              </VStack>

              {bootstrapClaimRequired ? (
                <Banner
                  status="info"
                  title={t("auth.setupRequiredTitle")}
                  description={t("auth.setupRequiredDescription")}
                  container="section"
                  collapsible={false}
                  endContent={<Link href="/setup">{t("auth.setupLink")}</Link>}
                />
              ) : null}

              {formError !== null ? (
                <Card data-testid="auth-error-banner">
                  <VStack gap={1}>
                    <Text as="p" role="alert" type="label" weight="semibold">
                      {formError.status === 429 && formError.retryAfterSeconds !== null
                        ? t("auth.rateLimitedNotice", { seconds: formError.retryAfterSeconds })
                        : formError.detail}
                    </Text>
                    {formError.correlationId ? (
                      <Text as="p" type="supporting">
                        {t("state.correlationId", { correlationId: formError.correlationId })}
                      </Text>
                    ) : null}
                  </VStack>
                </Card>
              ) : null}

              <VStack
                as="form"
                data-testid={mfaChallengeId === null ? "login-form" : "mfa-challenge-form"}
                gap={3}
                onSubmit={(event) => {
                  event.preventDefault();
                  setError(null);
                  signInMutation.mutate();
                }}
              >
                {mfaChallengeId !== null ? <Heading level={2}>{t("auth.mfaTitle")}</Heading> : null}
                <TextInput
                  label={t("auth.identifierLabel")}
                  value={identifier}
                  onChange={setIdentifier}
                  autoComplete="username"
                  isRequired
                  isDisabled={mfaChallengeId !== null || signInMutation.isPending}
                  description={mfaChallengeId === null ? t("auth.identifierHint") : undefined}
                />
                {mfaChallengeId === null ? (
                  <TextInput
                    label={t("auth.passwordLabel")}
                    type="password"
                    value={password}
                    onChange={setPassword}
                    autoComplete="current-password"
                    isRequired
                    isDisabled={signInMutation.isPending}
                  />
                ) : (
                  <TextInput
                    label={t("auth.otpLabel")}
                    value={otp}
                    onChange={setOtp}
                    autoComplete="one-time-code"
                    isRequired
                    isDisabled={signInMutation.isPending}
                    description={t("auth.otpHint")}
                    hasAutoFocus
                    status={otpError === null ? undefined : { type: "error", message: otpError.detail }}
                  />
                )}
                <Button
                  label={mfaChallengeId === null ? t("auth.signInSubmit") : t("auth.mfaSubmit")}
                  type="submit"
                  variant="primary"
                  isLoading={submitting}
                  isDisabled={
                    submitting || identifier.trim().length === 0 ||
                    (mfaChallengeId === null ? password.length === 0 : otp.trim().length === 0)
                  }
                />
              </VStack>

              {mfaChallengeId !== null ? (
                <Button
                  label={t("auth.mfaBack")}
                  variant="ghost"
                  isDisabled={signInMutation.isPending}
                  onClick={() => {
                    setMfaChallengeId(null);
                    setOtp("");
                    setError(null);
                  }}
                />
              ) : null}

              {mfaChallengeId === null && oidcProvidersQuery.data?.length ? (
                <VStack gap={2}>
                  <Text type="supporting" as="p">Continue with your identity provider</Text>
                  {oidcProvidersQuery.data.map((providerId) => (
                    <Button
                      key={providerId}
                      label={t("auth.oidcSignIn", { provider: providerId })}
                      variant="secondary"
                      isDisabled={submitting}
                      onClick={() => {
                        window.location.assign(
                          `${transport.baseUrl.replace(/\/$/, "")}/api/v1/auth/oidc/${encodeURIComponent(providerId)}/authorize`,
                        );
                      }}
                    />
                  ))}
                </VStack>
              ) : null}

              {mfaChallengeId === null ? (
                <HStack gap={0}>
                  <Link href="/login/recovery">{t("auth.recoveryLink")}</Link>
                </HStack>
              ) : null}
            </VStack>
          </Card>
        </VStack>
      </Center>
    </main>
  );
}
