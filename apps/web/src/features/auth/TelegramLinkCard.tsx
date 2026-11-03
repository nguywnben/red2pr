import type { TelegramLinkSummary } from "@red2pr/ts-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import React, { useState } from "react";
import { useRed2PrApi } from "../../shared/api";
import { ConfirmActionButton, Button } from "../../shared/ui";
import { extractAuthProblemSummary, type AuthProblemSummary } from "./authHelpers";

export interface TelegramLinkCardProps {
  readonly link: TelegramLinkSummary;
  readonly requireStepUpThen: (action: () => void) => void;
}

export function TelegramLinkCard({
  link,
  requireStepUpThen,
}: TelegramLinkCardProps): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const [error, setError] = useState<AuthProblemSummary | null>(null);
  const [deepLink, setDeepLink] = useState<string | null>(null);
  const createMutation = useMutation({
    mutationFn: () => api.createMyTelegramLinkChallenge(),
    onSuccess: async (result) => {
      setError(null);
      setDeepLink(result.data.deep_link);
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    onError: (cause) => setError(extractAuthProblemSummary(cause, "Telegram link could not be created.")),
  });
  const unlinkMutation = useMutation({
    mutationFn: () => api.deleteMyTelegramLink(),
    onSuccess: async () => {
      setError(null);
      setDeepLink(null);
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    onError: (cause) => setError(extractAuthProblemSummary(cause, "Telegram could not be unlinked.")),
  });
  const busy = createMutation.isPending || unlinkMutation.isPending;

  return (
    <section className="red2pr-surface red2pr-card-section" aria-labelledby="account-telegram-heading">
      <div className="red2pr-card-header">
        <h2 id="account-telegram-heading" >
          Personal Telegram pairing
        </h2>
        {link.status !== "not_configured" ? (
          <span className="red2pr-badge-pill red2pr-tone-neutral" data-testid="telegram-link-status">
            {link.status === "linked" ? "Linked" : "Pending"}
          </span>
        ) : null}
      </div>
      <p className="red2pr-field-hint">
        Link a private chat for scoped read commands. Telegram actions always require signed-in web confirmation.
      </p>
      {link.status === "linked" && link.linked_at ? (
        <p>Linked since <time dateTime={link.linked_at}>{new Date(link.linked_at).toLocaleString()}</time>.</p>
      ) : null}
      {link.status !== "linked" ? (
        <Button
          label="Create one-time Telegram link"
          variant="primary"
          isLoading={createMutation.isPending}
          isDisabled={busy}
          onClick={() => createMutation.mutate()}
        />
      ) : (
        <ConfirmActionButton
          label="Unlink Telegram"
          variant="destructive"
          isDisabled={busy}
          confirmationTitle="Unlink this Telegram account?"
          confirmationDescription="Telegram will no longer be able to provide scoped read commands for this account."
          confirmationActionLabel="Unlink Telegram"
          onConfirm={() => requireStepUpThen(() => unlinkMutation.mutate())}
        />
      )}
      {deepLink ? (
        <p role="status" data-testid="telegram-link-created">
          Link expires shortly. Open it in Telegram, then send <code>/start</code> in the private chat. {" "}
          <a href={deepLink} target="_blank" rel="noreferrer">Open Telegram</a>
        </p>
      ) : null}
      {deepLink && link.status !== "linked" ? (
        <Button
          label="Refresh pairing status"
          variant="secondary"
          isDisabled={busy}
          onClick={() => void queryClient.invalidateQueries({ queryKey: ["me"] })}
        />
      ) : null}
      {error ? <p role="alert">{error.detail}</p> : null}
    </section>
  );
}
