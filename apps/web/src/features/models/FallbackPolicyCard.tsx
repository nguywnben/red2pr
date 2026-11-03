import {
  Red2PrApiError,
  type ConsentRecord,
  type MeResponse,
  type Repository,
  type Workspace,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useId, useMemo, useState } from "react";
import { useRed2PrApi } from "../../shared/api";
import { Button, Selector, StateView } from "../../shared/ui";
import { StepUpDialog } from "../auth";
import { generateClientUuidV7 } from "../queues";

export interface FallbackPolicyCardProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
  readonly consents: readonly ConsentRecord[];
  readonly isAdmin: boolean;
}

export function FallbackPolicyCard({
  workspace,
  me,
  consents,
  isAdmin,
}: FallbackPolicyCardProps): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const ws = workspace.slug ?? workspace.id;
  const repositorySelectId = useId();
  const primarySelectId = useId();
  const secondarySelectId = useId();
  const consentSelectId = useId();
  const enabledId = useId();
  const [repositoryId, setRepositoryId] = useState("");
  const [primaryProfileOverride, setPrimaryProfileOverride] = useState<string | null>(null);
  const [secondaryProfileOverride, setSecondaryProfileOverride] = useState<string | null>(null);
  const [consentId, setConsentId] = useState("");
  const [enabledOverride, setEnabledOverride] = useState<boolean | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [retryAfterStepUp, setRetryAfterStepUp] = useState<(() => void) | null>(null);

  const repositoriesQuery = useQuery({
    queryKey: ["workspace", ws, "repositories", "fallback-policy"],
    queryFn: () => api.listRepositories(ws, { limit: 100 }),
  });
  const profilesQuery = useQuery({
    queryKey: ["workspace", ws, "agent-profiles", "fallback-policy"],
    queryFn: () => api.listWorkspaceAgentProfiles(ws),
  });
  const repositories = useMemo<readonly Repository[]>(
    () => (repositoriesQuery.data?.data.items ?? []) as readonly Repository[],
    [repositoriesQuery.data],
  );
  const selectedRepositoryId = repositories.some((repo) => repo.id === repositoryId)
    ? repositoryId
    : (repositories[0]?.id ?? "");
  const policyQuery = useQuery({
    queryKey: ["workspace", ws, "repository", selectedRepositoryId, "model-fallback"],
    queryFn: () => api.getRepositoryModelFallback(ws, selectedRepositoryId),
    enabled: selectedRepositoryId.length > 0,
  });
  const current = policyQuery.data?.data ?? null;
  const profiles = (profilesQuery.data?.data.profiles ?? []).filter((profile) => profile.enabled);
  const primaryProfileId =
    primaryProfileOverride ?? current?.primary_model_profile_id ?? profiles[0]?.id ?? "";
  const primaryProfile = profiles.find((profile) => profile.id === primaryProfileId);
  const secondaryProfileId =
    secondaryProfileOverride ??
    current?.secondary_model_profile_id ??
    profiles.find(
      (profile) =>
        profile.id !== primaryProfileId && profile.model_id !== primaryProfile?.model_id,
    )?.id ??
    "";
  const secondaryProfile = profiles.find((profile) => profile.id === secondaryProfileId);
  const activeConsents = consents.filter(
    (consent) =>
      consent.purpose === "inference" &&
      consent.scope === "repository" &&
      consent.repository_id === selectedRepositoryId &&
      consent.status === "active" &&
      consent.revoked_at === null,
  );
  const selectedConsentId = activeConsents.some((item) => item.id === consentId)
    ? consentId
    : (current?.consent_id ?? activeConsents[0]?.id ?? "");
  const enabled = enabledOverride ?? current?.enabled ?? false;

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!selectedRepositoryId) {
        throw new Error("Choose a repository before saving fallback policy.");
      }
      return api.putRepositoryModelFallback(
        ws,
        selectedRepositoryId,
        {
          primary_model_profile_id: primaryProfileId,
          secondary_model_profile_id: secondaryProfileId,
          consent_id: selectedConsentId,
          enabled,
          ...(current ? { expected_version: current.version } : {}),
        },
        {
          idempotencyKey: generateClientUuidV7(),
          ...(policyQuery.data?.etag ? { ifMatch: policyQuery.data.etag } : {}),
        },
      );
    },
    onSuccess: async ({ data }) => {
      setFeedback(data.enabled ? "Repository model fallback enabled." : "Fallback policy saved disabled.");
      setError(null);
      await queryClient.invalidateQueries({
        queryKey: ["workspace", ws, "repository", selectedRepositoryId, "model-fallback"],
      });
    },
    onError: (cause) => {
      if (cause instanceof Red2PrApiError && cause.problem.code === "step_up_required") {
        setRetryAfterStepUp(() => () => saveMutation.mutate());
        setStepUpOpen(true);
        return;
      }
      setError(cause instanceof Error ? cause.message : "Model fallback policy could not be saved.");
    },
  });

  const saveDisabled =
    !isAdmin ||
    saveMutation.isPending ||
    !selectedConsentId ||
    !primaryProfile ||
    !secondaryProfile ||
    primaryProfileId === secondaryProfileId ||
    primaryProfile.model_id === secondaryProfile.model_id ||
    (enabled && !activeConsents.some((item) => item.id === selectedConsentId));

  return (
    <section className="red2pr-surface red2pr-card-section" aria-label="Repository model fallback policy">
      <h2 >Consented model fallback</h2>
      <p className="red2pr-field-hint">
        Disabled by default. Fallback remains within the same Meta vendor, repository consent,
        tool schema, redaction policy, and repair session budget account.
      </p>
      {repositoriesQuery.isLoading || profilesQuery.isLoading ? (
        <StateView state="loading" skeletonVariant="form" />
      ) : profilesQuery.isError ? (
        <StateView state="error" title="Model profiles unavailable" description="Fallback policies require the current workspace profile list." />
      ) : repositories.length === 0 ? (
        <StateView state="empty" title="No repositories available" description="Sync a repository before configuring model fallback." />
      ) : profiles.length < 2 ? (
        <StateView state="empty" title="Two enabled profiles required" description="Enable two workspace model profiles with different probed Meta models before configuring fallback." />
      ) : (
        <div className="red2pr-form-stack">
          {current ? (
            <dl className="red2pr-kv-grid" data-testid="model-fallback-status">
              <div className="red2pr-kv-item"><dt className="red2pr-kv-term">Status</dt><dd className="red2pr-kv-detail">{current.enabled ? "enabled" : "disabled"}</dd></div>
              <div className="red2pr-kv-item"><dt className="red2pr-kv-term">Last fallback</dt><dd className="red2pr-kv-detail">{current.last_fallback_reason ?? "not used"}</dd></div>
            </dl>
          ) : null}
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={repositorySelectId}>Repository</label>
            <Selector id={repositorySelectId} label="Repository" isLabelHidden variant="input" size="md" presentation="popover"
              options={repositories.map((repo) => ({ value: repo.id, label: repo.organization ? `${repo.organization}/${repo.name}` : repo.name }))}
              value={selectedRepositoryId} onChange={setRepositoryId} />
          </div>
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={primarySelectId}>Primary model profile</label>
            <Selector id={primarySelectId} label="Primary model profile" isLabelHidden variant="input" size="md" presentation="popover"
              options={profiles.map((profile) => ({ value: profile.id, label: `${profile.display_name} · ${profile.model_id}` }))}
              value={primaryProfileId} onChange={setPrimaryProfileOverride} />
          </div>
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={secondarySelectId}>Fallback model profile</label>
            <Selector id={secondarySelectId} label="Fallback model profile" isLabelHidden variant="input" size="md" presentation="popover"
              options={profiles.map((profile) => ({ value: profile.id, label: `${profile.display_name} · ${profile.model_id}` }))}
              value={secondaryProfileId} onChange={setSecondaryProfileOverride} />
          </div>
          <div className="red2pr-field">
            <label className="red2pr-field-label" htmlFor={consentSelectId}>Active repository inference consent</label>
            <Selector id={consentSelectId} label="Active repository inference consent" isLabelHidden isRequired variant="input" size="md" presentation="popover"
              options={[{ value: "", label: "No eligible consent" }, ...activeConsents.map((item) => ({ value: item.id, label: `${item.id} · ${item.destination}` }))]}
              value={selectedConsentId} onChange={setConsentId} />
          </div>
          <label className="red2pr-field-label" htmlFor={enabledId}>
            <input id={enabledId} type="checkbox" checked={enabled} onChange={(event) => setEnabledOverride(event.target.checked)} /> Enable fallback (off by default)
          </label>
          <p className="red2pr-field-hint">Allowed triggers are HTTP 429, HTTP 503, or an unavailable probed primary capability. Network errors, timeouts, authentication failures, and other vendors never trigger fallback.</p>
          {feedback ? <p role="status">{feedback}</p> : null}
          {error ? <p role="alert">{error}</p> : null}
          <Button label="Save repository fallback policy" variant="primary" isLoading={saveMutation.isPending} isDisabled={saveDisabled} onClick={() => saveMutation.mutate()} />
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
