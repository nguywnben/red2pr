import { InputControl } from "../../shared/ui";
import { SelectorControl } from "../../shared/ui";
import { Red2PrApiError, type Connection, type MeResponse, type Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useId, useMemo, useState } from "react";
import { useRed2PrApi } from "../../shared/api";
import { Button, StateView } from "../../shared/ui";
import { StepUpDialog } from "../auth";
import { generateClientUuidV7 } from "../queues";

export interface RelayConfigCardProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

export function RelayConfigCard({ workspace, me }: RelayConfigCardProps): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const ws = workspace.slug ?? workspace.id;
  const endpointId = useId();
  const consentId = useId();
  const secretId = useId();
  const certificateId = useId();
  const privateKeyId = useId();
  const enabledId = useId();
  const [connectionId, setConnectionId] = useState("");
  const [endpointRegistrationId, setEndpointRegistrationId] = useState("");
  const [consentRecordId, setConsentRecordId] = useState("");
  const [relaySecret, setRelaySecret] = useState("");
  const [clientCertificate, setClientCertificate] = useState("");
  const [clientPrivateKey, setClientPrivateKey] = useState("");
  const [enabledOverride, setEnabledOverride] = useState<boolean | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [retryAfterStepUp, setRetryAfterStepUp] = useState<(() => void) | null>(null);

  const isAdmin = (me.memberships ?? []).some(
    (membership) => membership.workspace_id === workspace.id && membership.role === "admin",
  );
  const connectionsQuery = useQuery({
    queryKey: ["workspace", ws, "integrations", "relay-connections"],
    queryFn: () => api.listConnections(ws, { limit: 50 }),
  });
  const connections = useMemo(
    () => (connectionsQuery.data?.data.items ?? []).filter((item) => item.status === "ready"),
    [connectionsQuery.data],
  );
  const selectedConnectionId = connections.some((item) => item.id === connectionId)
    ? connectionId
    : (connections[0]?.id ?? "");
  const relayQuery = useQuery({
    queryKey: ["workspace", ws, "integrations", selectedConnectionId, "relay"],
    queryFn: () => api.getRelaySubscription(ws, selectedConnectionId),
    enabled: selectedConnectionId.length > 0,
  });
  const current = relayQuery.data?.data ?? null;
  const enabled = enabledOverride ?? current?.enabled ?? false;
  const credentialValues = [relaySecret, clientCertificate, clientPrivateKey];
  const credentialCount = credentialValues.filter((value) => value.length > 0).length;
  const credentialsValid =
    (current !== null && credentialCount === 0) ||
    (credentialCount === 3 &&
      relaySecret.length >= 32 &&
      clientCertificate.length >= 64 &&
      clientPrivateKey.length >= 64);

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!selectedConnectionId) {
        throw new Error("Choose a ready GitHub or GitLab connection.");
      }
      const body = {
        provider_connection_id: selectedConnectionId,
        endpoint_registration_id: (endpointRegistrationId || current?.endpoint_registration_id || "").trim(),
        consent_id: (consentRecordId || current?.consent_id || "").trim(),
        enabled,
        ...(credentialCount === 3
          ? {
              relay_hmac_secret: relaySecret,
              client_certificate_pem: clientCertificate,
              client_private_key_pem: clientPrivateKey,
            }
          : {}),
        ...(current ? { expected_version: current.version } : {}),
      };
      return api.putRelaySubscription(ws, selectedConnectionId, body, {
        idempotencyKey: generateClientUuidV7(),
        ...(relayQuery.data?.etag ? { ifMatch: relayQuery.data.etag } : {}),
      });
    },
    onSuccess: async ({ data }) => {
      setRelaySecret("");
      setClientCertificate("");
      setClientPrivateKey("");
      setFeedback(data.enabled ? "Customer relay enabled." : "Customer relay configuration saved disabled.");
      setError(null);
      await queryClient.invalidateQueries({
        queryKey: ["workspace", ws, "integrations", selectedConnectionId, "relay"],
      });
    },
    onError: (cause) => {
      if (cause instanceof Red2PrApiError && cause.problem.code === "step_up_required") {
        setRetryAfterStepUp(() => () => saveMutation.mutate());
        setStepUpOpen(true);
        return;
      }
      setError(cause instanceof Error ? cause.message : "Relay configuration failed.");
    },
  });
  const pullMutation = useMutation({
    mutationFn: () =>
      api.pullRelaySubscription(ws, selectedConnectionId, {
        idempotencyKey: generateClientUuidV7(),
      }),
    onSuccess: async ({ data }) => {
      setFeedback(
        data.status === "gap_detected"
          ? "Relay cursor gap detected; local polling recovery is required."
          : `Relay pull status: ${data.status}.`,
      );
      await queryClient.invalidateQueries({
        queryKey: ["workspace", ws, "integrations", selectedConnectionId, "relay"],
      });
    },
    onError: (cause) => {
      if (cause instanceof Red2PrApiError && cause.problem.code === "step_up_required") {
        setRetryAfterStepUp(() => () => pullMutation.mutate());
        setStepUpOpen(true);
        return;
      }
      setError(cause instanceof Error ? cause.message : "Relay pull failed.");
    },
  });

  return (
    <section className="red2pr-surface red2pr-card-section" aria-label="Customer-operated webhook relay">
      <h2 >Customer-operated webhook relay</h2>
      <p className="red2pr-field-hint">
        Optional outbound WSS/mTLS relay. Register the endpoint and grant provider consent first.
        Relay credentials are write-only and Red2PR does not host relay infrastructure.
      </p>
      {connectionsQuery.isLoading ? (
        <StateView state="loading" skeletonVariant="form" />
      ) : connections.length === 0 ? (
        <StateView state="empty" title="No ready provider connection" description="Connect GitHub or GitLab before configuring a relay." />
      ) : (
        <div className="red2pr-form-stack">
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={`${endpointId}-connection`}>Provider connection</label>
            <SelectorControl
              id={`${endpointId}-connection`}
              className="red2pr-control-select"
              value={selectedConnectionId}
              onChange={(event) => {
                setConnectionId(event.target.value);
                setEndpointRegistrationId("");
                setConsentRecordId("");
                setRelaySecret("");
                setClientCertificate("");
                setClientPrivateKey("");
                setEnabledOverride(null);
                setFeedback(null);
                setError(null);
              }}
            >
              {connections.map((connection: Connection) => (
                <option key={connection.id} value={connection.id}>
                  {connection.provider} · {connection.display_name}
                </option>
              ))}
            </SelectorControl>
          </div>
          {current ? (
            <dl className="red2pr-kv-grid" data-testid="relay-status">
              <div className="red2pr-kv-item"><dt className="red2pr-kv-term">Status</dt><dd className="red2pr-kv-detail">{current.status}</dd></div>
              <div className="red2pr-kv-item"><dt className="red2pr-kv-term">Last cursor</dt><dd className="red2pr-kv-detail">{current.last_relay_seq}</dd></div>
            </dl>
          ) : null}
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={endpointId}>Registered endpoint ID</label>
            <InputControl id={endpointId} className="red2pr-control-input" value={endpointRegistrationId || current?.endpoint_registration_id || ""} onChange={(event) => setEndpointRegistrationId(event.target.value)} autoComplete="off" />
          </div>
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={consentId}>Provider consent ID</label>
            <InputControl id={consentId} className="red2pr-control-input" value={consentRecordId || current?.consent_id || ""} onChange={(event) => setConsentRecordId(event.target.value)} autoComplete="off" />
          </div>
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={secretId}>Relay frame HMAC secret</label>
            <InputControl id={secretId} className="red2pr-control-input" type="password" value={relaySecret} onChange={(event) => setRelaySecret(event.target.value)} autoComplete="new-password" />
          </div>
          {current ? (
            <p className="red2pr-field-hint">
              Stored credentials are write-only. Leave all three credential fields blank to keep
              the current identity, or provide all three to rotate it.
            </p>
          ) : null}
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={certificateId}>Client certificate PEM</label>
            <textarea id={certificateId} className="red2pr-control-input" value={clientCertificate} onChange={(event) => setClientCertificate(event.target.value)} autoComplete="off" rows={4} />
          </div>
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={privateKeyId}>Client private key PEM</label>
            <textarea id={privateKeyId} className="red2pr-control-input" value={clientPrivateKey} onChange={(event) => setClientPrivateKey(event.target.value)} autoComplete="off" rows={4} />
          </div>
          <label className="red2pr-field-label" htmlFor={enabledId}>
            <input id={enabledId} type="checkbox" checked={enabled} onChange={(event) => setEnabledOverride(event.target.checked)} /> Enable relay (off by default)
          </label>
          {feedback ? <p role="status">{feedback}</p> : null}
          {error ? <p role="alert">{error}</p> : null}
          <div className="red2pr-button-row">
            <Button label="Save relay configuration" variant="primary" isLoading={saveMutation.isPending} isDisabled={!isAdmin || saveMutation.isPending || !credentialsValid || !(endpointRegistrationId || current?.endpoint_registration_id) || !(consentRecordId || current?.consent_id)} onClick={() => saveMutation.mutate()} />
            <Button label="Pull one relay frame" variant="secondary" isLoading={pullMutation.isPending} isDisabled={!isAdmin || !current?.enabled || pullMutation.isPending} onClick={() => pullMutation.mutate()} />
          </div>
        </div>
      )}
      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={Boolean(me.mfa_enabled)}
        onOpenChange={setStepUpOpen}
        onVerified={() => {
          const retry = retryAfterStepUp;
          setRetryAfterStepUp(null);
          retry?.();
        }}
      />
    </section>
  );
}
