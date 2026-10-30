import { Red2PrApiError } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { Button, StateView } from "../../shared/ui";
import { StepUpDialog, extractAuthProblemSummary } from "../auth";

const TOKEN_RE = /^[A-Za-z0-9_-]{32,64}$/;

export function TelegramIntentConfirmPage(): React.JSX.Element {
  const api = useRed2PrApi();
  const location = useLocation();
  const queryClient = useQueryClient();
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const idempotencyKey = useRef<string | null>(null);
  const candidate = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  const token = useMemo(() => (TOKEN_RE.test(candidate) ? candidate : null), [candidate]);

  useEffect(() => {
    // Remove the one-use bearer token from browser history before any API request.
    window.history.replaceState(window.history.state, "", location.pathname);
  }, [location.hash, location.pathname]);

  const meQuery = useQuery({ queryKey: ["auth", "me"], queryFn: () => api.getMe(), retry: false });
  const intentQuery = useQuery({
    queryKey: ["telegram-intent", token],
    queryFn: () => api.previewTelegramIntent({ token: token ?? "" }),
    enabled: token !== null && meQuery.isSuccess,
    retry: false,
  });
  const confirmMutation = useMutation({
    mutationFn: () => {
      if (token === null) throw new Error("Confirmation token is unavailable.");
      idempotencyKey.current ??= crypto.randomUUID();
      return api.confirmTelegramIntent(
        { token, confirmed: true },
        { idempotencyKey: idempotencyKey.current },
      );
    },
    onSuccess: async () => {
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    onError: (cause) => {
      if (cause instanceof Red2PrApiError && cause.problem.code === "step_up_required") {
        setStepUpOpen(true);
        return;
      }
      setError(extractAuthProblemSummary(cause, "The Telegram action could not be confirmed.").detail);
    },
  });

  if (meQuery.isError && meQuery.error instanceof Red2PrApiError && meQuery.error.status === 401) {
    return (
      <main className="red2pr-page-stack" data-testid="telegram-intent-sign-in-required">
        <h1>Sign in to review this Telegram action</h1>
        <p>
          This link has not changed anything. Sign in, then reopen the original confirmation link
          from your Telegram message to review and confirm it.
        </p>
        <a href="/login?next=%2Faccount">Sign in to Red2PR</a>
      </main>
    );
  }
  if (meQuery.isPending || (token !== null && intentQuery.isPending)) return <StateView state="loading" />;
  if (meQuery.isError) return <StateView state="error" title="Sign-in status unavailable" description="Sign in to review this Telegram action." />;

  const intent = intentQuery.data?.data;
  const confirmed = confirmMutation.isSuccess;
  return (
    <main className="red2pr-page-stack" data-testid="telegram-intent-confirm-page">
      <header className="red2pr-page-header">
        <div><h1>Confirm Telegram action</h1><p>Review the requested change in your authenticated Red2PR session.</p></div>
      </header>
      {error ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">{error}</div> : null}
      {token === null && !error ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">This Telegram confirmation link is missing or malformed.</div> : null}
      {intentQuery.isError ? <StateView state="error" title="Confirmation unavailable" description="The action is invalid, expired, already used, or outside your current access." /> : null}
      {intent ? (
        <section className="red2pr-surface red2pr-card-section" aria-labelledby="telegram-intent-heading">
          <h2 id="telegram-intent-heading">/{intent.action}</h2>
          <p>{intent.scope_description}</p>
          <p>Expires: <time dateTime={intent.expires_at}>{new Date(intent.expires_at).toLocaleString()}</time></p>
          {intent.already_confirmed || confirmed ? (
            <p role="status">This action has already been confirmed.</p>
          ) : (
            <Button label={`Confirm /${intent.action}`} variant="primary" isLoading={confirmMutation.isPending} isDisabled={confirmMutation.isPending} onClick={() => confirmMutation.mutate()} />
          )}
          {confirmMutation.data?.data.status_url ? <p><a href={confirmMutation.data.data.status_url}>View affected item</a></p> : null}
        </section>
      ) : null}
      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={meQuery.data?.data.mfa_enabled ?? false}
        onOpenChange={setStepUpOpen}
        onVerified={() => confirmMutation.mutate()}
      />
    </main>
  );
}
