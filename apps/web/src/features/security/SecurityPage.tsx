import type { ApiTokenCreateRequest, Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useId, useRef, useState } from "react";
import { useRed2PrApi } from "../../shared/api";
import { Button, StateView, sanitizeUntrustedText } from "../../shared/ui";
import { isStepUpValid } from "../auth/authHelpers";
import { StepUpDialog } from "../auth/StepUpDialog";

export interface SecurityPageProps {
  readonly workspace: Workspace;
}

const TOKEN_SCOPES: ApiTokenCreateRequest["scopes"] = [
  "notifications:read",
  "notifications:write",
  "repairs:read",
  "repairs:write",
  "integrations:read",
  "integrations:write",
  "events:read",
];

export function SecurityPage({ workspace }: SecurityPageProps): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const ws = workspace.slug ?? workspace.id;
  const nameId = useId();
  const scopeId = useId();
  const repositoriesId = useId();
  const actionId = useId();
  const correlationId = useId();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<ApiTokenCreateRequest["scopes"]>(["repairs:read"]);
  const [repositoryIds, setRepositoryIds] = useState<string[]>([]);
  const [action, setAction] = useState("");
  const [auditCorrelation, setAuditCorrelation] = useState("");
  const [findingRef, setFindingRef] = useState("");
  const [artifactDigest, setArtifactDigest] = useState("");
  const [reviewerUserId, setReviewerUserId] = useState("");
  const [mitigation, setMitigation] = useState("");
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<{ id: string; name: string } | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingStepUpRetryRef = useRef<(() => void) | null>(null);

  const me = useQuery({ queryKey: ["me", "profile"], queryFn: () => api.getMe(), retry: false });

  const tokens = useQuery({
    queryKey: ["workspace", ws, "security", "tokens"],
    queryFn: ({ signal }) => api.listApiTokens(ws, { limit: 100 }, { signal }),
    retry: false,
  });
  const repositories = useQuery({
    queryKey: ["workspace", ws, "security", "repositories"],
    queryFn: ({ signal }) => api.listRepositories(ws, { limit: 100 }, { signal }),
    retry: false,
  });
  const audit = useQuery({
    queryKey: ["workspace", ws, "security", "audit", action, auditCorrelation],
    queryFn: ({ signal }) => api.listWorkspaceAudit(
      ws,
      {
        limit: 50,
        action: action.trim() || undefined,
        correlation_id: auditCorrelation.trim() || undefined,
      },
      { signal },
    ),
    retry: false,
  });
  const members = useQuery({
    queryKey: ["workspace", ws, "security", "members"],
    queryFn: ({ signal }) => api.listWorkspaceMembers(ws, { limit: 100 }, { signal }),
    retry: false,
  });
  const modelSecurity = useQuery({
    queryKey: ["workspace", ws, "security", "inference-consent"],
    queryFn: ({ signal }) => api.listWorkspaceModels(ws, { signal }),
    retry: false,
  });
  const exceptions = useQuery({
    queryKey: ["workspace", ws, "security", "release-exceptions"],
    queryFn: ({ signal }) => api.listWorkspaceReleaseExceptions(ws, { signal }),
    retry: false,
  });
  const secretMetadata = useQuery({
    queryKey: ["workspace", ws, "security", "secrets"],
    queryFn: ({ signal }) => api.listWorkspaceSecretMetadata(ws, { signal }),
    retry: false,
  });
  const rotateSecretKeys = useMutation({
    mutationFn: () => api.rotateWorkspaceSecretKeys(ws),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["workspace", ws, "security", "secrets"] });
      await queryClient.invalidateQueries({ queryKey: ["workspace", ws, "security", "audit"] });
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
  });
  const createToken = useMutation({
    mutationFn: async () => {
      const expiry = new Date(Date.now() + 90 * 86400000).toISOString();
      return api.createApiToken(ws, { name: name.trim(), scopes, repository_ids: repositoryIds, expires_at: expiry });
    },
    onSuccess: async (result) => {
      setRevealedToken(result.data.token);
      setName("");
      await queryClient.invalidateQueries({ queryKey: ["workspace", ws, "security", "tokens"] });
    },
  });
  const revokeToken = useMutation({
    mutationFn: (tokenId: string) => api.revokeApiToken(ws, tokenId),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ["workspace", ws, "security", "tokens"] }),
  });
  const createException = useMutation({
    mutationFn: () => api.createWorkspaceReleaseException(ws, {
      finding_ref: findingRef.trim(),
      artifact_digest: artifactDigest.trim(),
      security_reviewer_user_id: reviewerUserId,
      mitigation: mitigation.trim(),
      expires_at: new Date(Date.now() + 14 * 86400000).toISOString(),
    }),
    onSuccess: async () => {
      setFindingRef("");
      setArtifactDigest("");
      setReviewerUserId("");
      setMitigation("");
      await queryClient.invalidateQueries({ queryKey: ["workspace", ws, "security", "release-exceptions"] });
      await queryClient.invalidateQueries({ queryKey: ["workspace", ws, "security", "audit"] });
    },
  });
  const revokeException = useMutation({
    mutationFn: (exceptionId: string) => api.revokeWorkspaceReleaseException(ws, exceptionId),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ["workspace", ws, "security", "release-exceptions"] }),
  });

  const requestKeyRotation = (): void => {
    if (!me.data?.data.is_instance_owner) return;
    if (!isStepUpValid(me.data.data.step_up_valid_until)) {
      pendingStepUpRetryRef.current = () => rotateSecretKeys.mutate();
      setStepUpOpen(true);
      return;
    }
    rotateSecretKeys.mutate();
  };

  return (
    <main className="red2pr-page-stack" data-testid="security-page">
      <header>
        <h1>Security and audit</h1>
        <p>Review verified workspace audit events, scoped API tokens, and retention policy.</p>
      </header>

      <section className="red2pr-surface red2pr-card-section" aria-labelledby="security-grants-title">
        <h2 id="security-grants-title">Workspace grants and consent</h2>
        {members.isPending ? <StateView state="loading" title="Loading workspace grants" /> : null}
        {members.isError ? <StateView state="error" title="Workspace grants unavailable" description="Your current role cannot read workspace membership and repository grants." primaryAction={{ label: "Retry", onClick: () => { void members.refetch(); } }} /> : null}
        {members.data ? <ul aria-label="Workspace member grants">
          {members.data.data.items.map((member) => <li key={member.id}>
            {sanitizeUntrustedText(member.user?.display_name ?? member.user_id).text}: {member.role}; {member.repository_grants?.length ?? 0} repository grants.
          </li>)}
        </ul> : null}
        {modelSecurity.isPending ? <StateView state="loading" title="Loading inference consent" /> : null}
        {modelSecurity.isError ? <p role="status">Inference consent status is unavailable to this role.</p> : null}
        {modelSecurity.data ? <p role="status">
          Outbound inference consent: {modelSecurity.data.data.inference_consent_active ? "active" : "not active"}
          {modelSecurity.data.data.active_inference_consent_id
            ? ` · record ${modelSecurity.data.data.active_inference_consent_id}`
            : ""}.
        </p> : null}
        <nav aria-label="Manage workspace grants and consent">
          <ul>
            <li><a href={`/w/${encodeURIComponent(ws)}/members`}>Manage workspace roles and repository grants</a></li>
            <li><a href={`/w/${encodeURIComponent(ws)}/models`}>Manage outbound inference consent</a></li>
          </ul>
        </nav>
      </section>

      <section className="red2pr-surface red2pr-card-section" aria-labelledby="security-audit-title">
        <h2 id="security-audit-title">Verified audit search</h2>
        <p>Audit results are shown only after the signed external checkpoint and hash chain verify.</p>
        <form className="red2pr-form-stack" onSubmit={(event) => { event.preventDefault(); void audit.refetch(); }}>
          <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={actionId}>Action</label><input id={actionId} className="red2pr-control-input" value={action} maxLength={120} onChange={(event) => setAction(event.target.value)} /></div>
          <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={correlationId}>Correlation ID</label><input id={correlationId} className="red2pr-control-input" value={auditCorrelation} maxLength={120} onChange={(event) => setAuditCorrelation(event.target.value)} /></div>
          <Button label="Search audit" variant="secondary" type="submit" isDisabled={audit.isFetching} />
        </form>
        {audit.isPending ? <StateView state="loading" title="Verifying audit chain" /> : null}
        {audit.isError ? <StateView state="error" title="Verified audit unavailable" description="The audit chain or signed checkpoint could not be verified with current access." primaryAction={{ label: "Retry", onClick: () => { void audit.refetch(); } }} /> : null}
        {audit.data?.data.items.length === 0 ? <p role="status">No matching audit events.</p> : null}
        {audit.data?.data.items.length ? <ul aria-label="Verified audit events">
          {audit.data.data.items.map((entry) => <li key={entry.id}>
            <strong>{sanitizeUntrustedText(entry.action).text}</strong>
            <span> · {new Date(entry.created_at).toLocaleString()}</span>
            <p>{sanitizeUntrustedText(entry.target).text}</p>
            <small>Decision: {entry.decision}; correlation: {sanitizeUntrustedText(entry.correlation_id).text}</small>
          </li>)}
        </ul> : null}
      </section>

      <section className="red2pr-surface red2pr-card-section" aria-labelledby="security-token-title">
        <h2 id="security-token-title">Scoped API tokens</h2>
        <p>Tokens are limited to selected repositories and scopes. Newly issued token material is shown once.</p>
        {tokens.isPending ? <StateView state="loading" title="Loading token metadata" /> : null}
        {tokens.isError ? <StateView state="error" title="Token metadata unavailable" description="Your current role cannot read this token list." primaryAction={{ label: "Retry", onClick: () => { void tokens.refetch(); } }} /> : null}
        {tokens.data?.data.items.length === 0 ? <p role="status">No API tokens are visible in this workspace.</p> : null}
        {tokens.data?.data.items.map((token) => <article key={token.id}>
          <h3>{sanitizeUntrustedText(token.name).text}</h3>
          <p>Scopes: {token.scopes.join(", ")}; expires {new Date(token.expires_at).toLocaleDateString()}.</p>
          <p>{token.revoked_at ? "Revoked" : "Active"}{token.last_used_at ? ` · last used ${new Date(token.last_used_at).toLocaleString()}` : " · never used"}</p>
          {!token.revoked_at ? <Button label={`Revoke ${token.name}`} variant="secondary" isDisabled={revokeToken.isPending} onClick={() => setRevokeTarget({ id: token.id, name: token.name })} /> : null}
        </article>)}
        <form className="red2pr-form-stack" onSubmit={(event) => { event.preventDefault(); createToken.mutate(); }}>
          <h3>Issue a 90-day token</h3>
          <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={nameId}>Token name</label><input id={nameId} className="red2pr-control-input" required minLength={1} maxLength={64} value={name} onChange={(event) => setName(event.target.value)} /></div>
          <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={scopeId}>Scopes</label><select id={scopeId} className="red2pr-control-input" multiple value={scopes} onChange={(event) => setScopes(Array.from(event.target.selectedOptions, (option) => option.value as ApiTokenCreateRequest["scopes"][number]))}>{TOKEN_SCOPES.map((scope) => <option key={scope} value={scope}>{scope}</option>)}</select></div>
          <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={repositoriesId}>Repository access</label><select id={repositoriesId} className="red2pr-control-input" multiple value={repositoryIds} onChange={(event) => setRepositoryIds(Array.from(event.target.selectedOptions, (option) => option.value))}>{(repositories.data?.data.items ?? []).map((repository) => <option key={repository.id} value={repository.id}>{sanitizeUntrustedText(repository.name).text}</option>)}</select></div>
          {repositories.isError ? <p role="alert">Repository grants could not be loaded, so token issuance is disabled.</p> : null}
          <Button label="Issue scoped token" variant="primary" type="submit" isDisabled={createToken.isPending || !name.trim() || scopes.length === 0 || repositoryIds.length === 0 || repositories.isError} isLoading={createToken.isPending} />
          {createToken.isError ? <p role="alert">Token issuance failed. Check your role and selected scopes.</p> : null}
        </form>
        {revealedToken ? <div role="status"><p>Copy this token now. It will not be shown again.</p><code>{revealedToken}</code><Button label="Hide token" variant="secondary" type="button" onClick={() => setRevealedToken(null)} /></div> : null}
        {revokeTarget ? <div role="dialog" aria-modal="true" aria-labelledby="revoke-token-title">
          <h3 id="revoke-token-title">Revoke {sanitizeUntrustedText(revokeTarget.name).text}?</h3>
          <p>Requests using this token will be denied immediately.</p>
          <Button label="Confirm revoke" variant="primary" isDisabled={revokeToken.isPending} onClick={() => revokeToken.mutate(revokeTarget.id, { onSuccess: () => setRevokeTarget(null) })} />
          <Button label="Cancel" variant="secondary" onClick={() => setRevokeTarget(null)} />
        </div> : null}
      </section>

      <section className="red2pr-surface red2pr-card-section" aria-labelledby="security-exceptions-title">
        <h2 id="security-exceptions-title">High finding exceptions</h2>
        <p>Each exception is bound to one artifact digest, requires two different workspace admins, and expires within 30 days.</p>
        {exceptions.isPending ? <StateView state="loading" title="Loading release exceptions" /> : null}
        {exceptions.isError ? <StateView state="error" title="Release exceptions unavailable" description="Your current role cannot read the exception ledger." primaryAction={{ label: "Retry", onClick: () => { void exceptions.refetch(); } }} /> : null}
        {exceptions.data?.data.items.length === 0 ? <p role="status">No release exceptions are recorded.</p> : null}
        {exceptions.data?.data.items.map((exception) => <article key={exception.id}>
          <h3>{sanitizeUntrustedText(exception.finding_ref).text} · High</h3>
          <p>Artifact digest: <code>{exception.artifact_digest}</code></p>
          <p>{sanitizeUntrustedText(exception.mitigation).text}</p>
          <p>Owner: {exception.owner_user_id}; reviewer: {exception.security_reviewer_user_id}; expires {new Date(exception.expires_at).toLocaleString()}.</p>
          {exception.revoked_at ? <p>Revoked {new Date(exception.revoked_at).toLocaleString()}.</p> : <Button label={`Revoke exception ${exception.finding_ref}`} variant="secondary" isDisabled={revokeException.isPending} onClick={() => revokeException.mutate(exception.id)} />}
        </article>)}
        <form className="red2pr-form-stack" onSubmit={(event) => { event.preventDefault(); createException.mutate(); }}>
          <h3>Record a High finding exception</h3>
          <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={`${nameId}-finding`}>Finding reference</label><input id={`${nameId}-finding`} className="red2pr-control-input" required maxLength={128} value={findingRef} onChange={(event) => setFindingRef(event.target.value)} /></div>
          <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={`${nameId}-digest`}>Artifact SHA-256 digest</label><input id={`${nameId}-digest`} className="red2pr-control-input" required minLength={64} maxLength={64} pattern="[0-9a-f]{64}" value={artifactDigest} onChange={(event) => setArtifactDigest(event.target.value)} /></div>
          <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={`${nameId}-reviewer`}>Independent security reviewer</label><select id={`${nameId}-reviewer`} className="red2pr-control-input" required value={reviewerUserId} onChange={(event) => setReviewerUserId(event.target.value)}><option value="">Select an admin</option>{(members.data?.data.items ?? []).filter((member) => member.role === "admin").map((member) => <option key={member.user_id} value={member.user_id}>{member.user_id}</option>)}</select></div>
          <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={`${nameId}-mitigation`}>Mitigation</label><textarea id={`${nameId}-mitigation`} className="red2pr-control-input" required minLength={20} maxLength={2000} value={mitigation} onChange={(event) => setMitigation(event.target.value)} /></div>
          {members.isError ? <p role="alert">Admin reviewer list could not be loaded, so exception creation is disabled.</p> : null}
          <Button label="Record 14-day High exception" variant="primary" type="submit" isDisabled={createException.isPending || members.isError || !findingRef.trim() || !/^[0-9a-f]{64}$/.test(artifactDigest) || !reviewerUserId || mitigation.trim().length < 20} isLoading={createException.isPending} />
          {createException.isError ? <p role="alert">Exception creation failed. Confirm your admin role, recent MFA step-up, independent reviewer, digest and expiry.</p> : null}
          {revokeException.isError ? <p role="alert">Exception revocation failed. Confirm your admin role and recent MFA step-up.</p> : null}
        </form>
      </section>

      <section className="red2pr-surface red2pr-card-section" aria-labelledby="security-retention-title">
        <h2 id="security-retention-title">Retention and secret handling</h2>
        <p>Baseline retention; deployment configuration may extend these windows within storage budgets.</p>
        <ul>
          <li>Raw provider logs: 7 days.</li>
          <li>Encrypted evidence artifacts: 30 days unless an approved retention policy extends them.</li>
          <li>Delivery and replay tombstones: 90 days.</li>
          <li>Pseudonymous audit proofs: at least 365 days.</li>
        </ul>
        <p>Secret values are never displayed here. Key material remains in the configured external key ring; token revocation takes effect immediately.</p>
        <h3>Secret key metadata</h3>
        {secretMetadata.isPending ? <StateView state="loading" title="Loading key metadata" /> : null}
        {secretMetadata.isError ? <StateView state="error" title="Key metadata unavailable" description="Secret metadata requires workspace admin or auditor access." primaryAction={{ label: "Retry", onClick: () => { void secretMetadata.refetch(); } }} /> : null}
        {secretMetadata.data ? <>
          <p>Active master key version: {secretMetadata.data.data.active_kek_version}. Secret values and references are never returned.</p>
          {secretMetadata.data.data.items.length === 0 ? <p role="status">No workspace secrets are configured.</p> : <ul aria-label="Secret key metadata">
            {secretMetadata.data.data.items.map((item) => <li key={item.id}>
              {item.purpose}: {item.configured ? "configured" : "revoked"}; KEK v{item.kek_version}; last rotated {item.rotated_at ? new Date(item.rotated_at).toLocaleString() : "not recorded"}.
            </li>)}
          </ul>}
        </> : null}
        <div className="red2pr-button-row">
          <Button label="Re-encrypt all secrets with active master key" variant="secondary" isDisabled={!me.data?.data.is_instance_owner || rotateSecretKeys.isPending || secretMetadata.isError} isLoading={rotateSecretKeys.isPending} onClick={requestKeyRotation} />
        </div>
        {rotateSecretKeys.data ? <p role="status">Re-encrypted {rotateSecretKeys.data.data.rotated_count} secret entries with KEK v{rotateSecretKeys.data.data.active_kek_version}.</p> : null}
        {rotateSecretKeys.isError ? <p role="alert">Key rotation failed. Confirm the shared external key file contains the active key and all currently used key versions, and that the current web session has a fresh step-up.</p> : null}
        <nav aria-label="Related security controls">
          <ul>
            <li><a href={`/w/${encodeURIComponent(ws)}/members`}>Review workspace members and repository grants</a></li>
            <li><a href={`/w/${encodeURIComponent(ws)}/integrations`}>Review provider credentials and grants</a></li>
            <li><a href={`/w/${encodeURIComponent(ws)}/notifications`}>Rotate notification signing keys</a></li>
            <li><a href={`/w/${encodeURIComponent(ws)}/models`}>Review and revoke inference consent</a></li>
          </ul>
        </nav>
      </section>
      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={Boolean(me.data?.data.mfa_enabled)}
        onOpenChange={(nextOpen) => {
          setStepUpOpen(nextOpen);
          if (!nextOpen) pendingStepUpRetryRef.current = null;
        }}
        onVerified={() => {
          const retry = pendingStepUpRetryRef.current;
          pendingStepUpRetryRef.current = null;
          retry?.();
        }}
      />
    </main>
  );
}
