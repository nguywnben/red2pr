import { Red2PrApiError } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { BrandLogo, Button, StateView } from "../../shared/ui";
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
      <main className="red2pr-auth-shell" data-testid="telegram-intent-sign-in-required">
        <div className="red2pr-surface red2pr-card-section red2pr-auth-card">
          <BrandLogo style={{ height: 28, width: "auto" }} decorative />
          <h1>Sign in to review this Telegram action</h1>
          <p className="red2pr-field-hint">
            This link has not changed anything. Sign in, then reopen the original confirmation link
            from your Telegram message to review and confirm it.
          </p>
          <Link className="red2pr-inline-link" to="/login?next=%2Faccount">Sign in to Red2PR</Link>
        </div>
      </main>
    );
  }
  if (meQuery.isPending || (token !== null && intentQuery.isPending)) {
    return (
      <main className="red2pr-auth-shell" data-testid="telegram-intent-confirm-page">
        <div className="red2pr-page-stack red2pr-auth-card">
          <BrandLogo style={{ height: 28, width: "auto" }} decorative />
          <header className="red2pr-page-header">
            <div><h1>Confirm Telegram action</h1><p>Review the requested change in your authenticated Red2PR session.</p></div>
          </header>
          <StateView state="loading" skeletonVariant="detail" />
        </div>
      </main>
    );
  }
  if (meQuery.isError) {
    return (
      <main className="red2pr-auth-shell">
        <div className="red2pr-page-stack red2pr-auth-card">
          <StateView state="error" title="Sign-in status unavailable" description="Sign in to review this Telegram action." />
        </div>
      </main>
    );
  }

  const intent = intentQuery.data?.data;
  const confirmed = confirmMutation.isSuccess;
  return (
    <main className="red2pr-auth-shell" data-testid="telegram-intent-confirm-page">
      <div className="red2pr-page-stack red2pr-auth-card">
        <BrandLogo style={{ height: 28, width: "auto" }} decorative />
        <header className="red2pr-page-header">
          <div><h1>Confirm Telegram action</h1><p>Review the requested change in your authenticated Red2PR session.</p></div>
        </header>
        {error ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">{error}</div> : null}
        {token === null && !error ? (
          <section className="red2pr-surface red2pr-card-section" role="alert">
            <h2>Telegram confirmation link required</h2>
            <p className="red2pr-field-hint">This Telegram confirmation link is missing or malformed. Open the latest link directly from your Telegram message, or return to your account settings.</p>
            <div className="red2pr-button-row"><Link className="red2pr-inline-link" to="/account">Go to Account →</Link></div>
          </section>
        ) : null}
        {intentQuery.isError ? <StateView state="error" title="Confirmation unavailable" description="The action is invalid, expired, already used, or outside your current access." /> : null}
        {intent ? (
          <section className="red2pr-surface red2pr-card-section" aria-labelledby="telegram-intent-heading">
            <h2 id="telegram-intent-heading">/{intent.action}</h2>
            <p>{intent.scope_description}</p>
            <p className="red2pr-field-hint">Expires: <time dateTime={intent.expires_at}>{new Date(intent.expires_at).toLocaleString()}</time></p>
            {intent.already_confirmed || confirmed ? (
              <p role="status">This action has already been confirmed.</p>
            ) : (
              <Button label={`Confirm /${intent.action}`} variant="primary" isLoading={confirmMutation.isPending} isDisabled={confirmMutation.isPending} onClick={() => confirmMutation.mutate()} />
            )}
            {confirmMutation.data?.data.status_url ? <p><a href={confirmMutation.data.data.status_url}>View affected item</a></p> : null}
          </section>
        ) : null}
      </div>
      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={meQuery.data?.data.mfa_enabled ?? false}
        onOpenChange={setStepUpOpen}
        onVerified={() => confirmMutation.mutate()}
      />
    </main>
  );
}
