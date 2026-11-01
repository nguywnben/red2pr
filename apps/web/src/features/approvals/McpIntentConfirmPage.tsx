import { Red2PrApiError } from "@red2pr/ts-client";
import { useMutation, useQuery } from "@tanstack/react-query";
import React, { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router";
import { useRed2PrApi, useRed2PrTransportConfig } from "../../shared/api";
import { Button, StateView } from "../../shared/ui";
import { StepUpDialog, extractAuthProblemSummary } from "../auth";

const TOKEN_RE = /^[A-Za-z0-9_-]{32,64}$/;
const WORKSPACE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function McpIntentConfirmPage(): React.JSX.Element {
  const api = useRed2PrApi();
  const transport = useRed2PrTransportConfig();
  const location = useLocation();
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const candidate = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  const token = useMemo(() => (TOKEN_RE.test(candidate) ? candidate : null), [candidate]);
  const workspaceCandidate = new URLSearchParams(location.search).get("workspace_id") ?? "";
  const workspaceId = useMemo(
    () => (WORKSPACE_ID_RE.test(workspaceCandidate) ? workspaceCandidate : null),
    [workspaceCandidate],
  );

  useEffect(() => {
    window.history.replaceState(window.history.state, "", `${location.pathname}${location.search}`);
  }, [location.hash, location.pathname, location.search]);

  const meQuery = useQuery({ queryKey: ["auth", "me"], queryFn: () => api.getMe(), retry: false });
  const previewQuery = useQuery({
    queryKey: ["mcp-approval-preview", workspaceId, token],
    enabled: token !== null && workspaceId !== null && meQuery.isSuccess,
    retry: false,
    queryFn: async () => {
      const csrf = await api.getAuthCsrf();
      const url = new URL("/api/v1/extensions/mcp/approval/preview", transport.baseUrl || window.location.origin);
      const response = await (transport.fetchImpl ?? fetch)(url, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf.data.csrf_token },
        body: JSON.stringify({ token, workspace_id: workspaceId }),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error("This approval link is invalid, expired, or outside your current access.");
      return payload as { intent_id: string; repair_id: string; reason: string; expires_at: string };
    },
  });
  const confirmMutation = useMutation({
    mutationFn: async () => {
      if (token === null) throw new Error("The approval token is unavailable.");
      if (workspaceId === null) throw new Error("The approval workspace is unavailable.");
      const csrf = await api.getAuthCsrf();
      const url = new URL("/api/v1/extensions/mcp/approval/confirm", transport.baseUrl || window.location.origin);
      const response = await (transport.fetchImpl ?? fetch)(url, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf.data.csrf_token,
        },
        body: JSON.stringify({ token, workspace_id: workspaceId }),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        const problem = payload && typeof payload === "object" ? payload as { detail?: unknown; code?: unknown } : {};
        const failure = new Error(typeof problem.detail === "string" ? problem.detail : "Approval could not be confirmed.") as Error & { code?: string; status?: number };
        failure.code = typeof problem.code === "string" ? problem.code : undefined;
        failure.status = response.status;
        throw failure;
      }
      return payload as { state: string; repair_id: string };
    },
    onError: (cause) => {
      if ((cause instanceof Red2PrApiError && cause.problem.code === "step_up_required") || (cause instanceof Error && "code" in cause && cause.code === "step_up_required")) {
        setStepUpOpen(true);
        return;
      }
      setError(extractAuthProblemSummary(cause, "The MCP action could not be confirmed.").detail);
    },
  });

  if (meQuery.isError && meQuery.error instanceof Red2PrApiError && meQuery.error.status === 401) {
    return (
      <main className="red2pr-page-stack" data-testid="mcp-intent-sign-in-required">
        <h1>Sign in to review this MCP action</h1>
        <p>This link has not changed anything. Sign in, then reopen the original approval link.</p>
        <a href="/login?next=%2Faccount">Sign in to Red2PR</a>
      </main>
    );
  }
  if (meQuery.isPending) return <StateView state="loading" />;
  if (meQuery.isError) return <StateView state="error" title="Sign-in status unavailable" description="Sign in to review this action." />;

  return (
    <main className="red2pr-page-stack" data-testid="mcp-intent-confirm-page">
      <header className="red2pr-page-header">
        <div>
          <h1>Confirm repair recheck</h1>
          <p>Confirming creates a new repair session. Red2PR rechecks your access and policy before it starts.</p>
        </div>
      </header>
      {error ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">{error}</div> : null}
      {(token === null || workspaceId === null) && !error ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">This approval link is missing or malformed.</div> : null}
      {confirmMutation.isSuccess ? (
        <section className="red2pr-surface red2pr-card-section" role="status">
          <h2>Recheck requested</h2>
          <p>A new repair session was created: {confirmMutation.data.repair_id}</p>
        </section>
      ) : (
        <section className="red2pr-surface red2pr-card-section">
          {previewQuery.isPending ? <p>Loading the requested action…</p> : null}
          {previewQuery.isError ? <p role="alert">This approval link is invalid, expired, or outside your current access.</p> : null}
          {previewQuery.data ? <>
            <p><strong>Repair:</strong> {previewQuery.data.repair_id}</p>
            <p><strong>Reason:</strong> {previewQuery.data.reason}</p>
            <p>Expires: <time dateTime={previewQuery.data.expires_at}>{new Date(previewQuery.data.expires_at).toLocaleString()}</time></p>
          </> : null}
          <Button label="Approve and create recheck" variant="primary" isLoading={confirmMutation.isPending} isDisabled={token === null || workspaceId === null || confirmMutation.isPending} onClick={() => confirmMutation.mutate()} />
        </section>
      )}
      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={meQuery.data?.data.mfa_enabled ?? false}
        onOpenChange={setStepUpOpen}
        onVerified={() => confirmMutation.mutate()}
      />
    </main>
  );
}
