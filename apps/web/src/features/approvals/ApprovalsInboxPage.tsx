import { Red2PrApiError, type ApprovalDecisionRequest, type ApprovalInboxEntry, type MeResponse, type Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useMemo, useRef, useState } from "react";
import { Link } from "react-router";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { Button, StateView, StatusGlyph } from "../../shared/ui";
import { StepUpDialog, extractAuthProblemSummary, formatUtcTimestamp } from "../auth";
import { generateClientUuidV7 } from "../queues";

export interface ApprovalsInboxPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

interface DecisionAttempt {
  readonly entry: ApprovalInboxEntry;
  readonly decision: "approve" | "reject";
  readonly key: string;
}

export function ApprovalsInboxPage({ workspace, me }: ApprovalsInboxPageProps): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const ws = workspace.slug ?? workspace.id;
  const membership = (me.memberships ?? []).find((item) => item.workspace_id === workspace.id);
  const mayDecide = membership?.role === "admin" || membership?.role === "maintainer" || membership?.role === "reviewer";
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [cursorHistory, setCursorHistory] = useState<readonly (string | null)[]>([]);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const retryAfterStepUp = useRef<DecisionAttempt | null>(null);
  const approvalQuery = useQuery({
    queryKey: ["workspace", ws, "approvals", "pending", cursor],
    queryFn: () => api.listWorkspaceApprovals(ws, { status: "pending", limit: 25, ...(cursor ? { cursor } : {}) }),
  });
  const decisionMutation = useMutation({
    mutationFn: async ({ entry, decision, key }: DecisionAttempt) => {
      const approval = entry.approval;
      const body: ApprovalDecisionRequest = {
        decision,
        reason: null,
        expected_patch_digest: approval.patch_digest,
        expected_policy_revision: approval.policy_revision,
      };
      return api.decideWorkspaceApproval(ws, approval.id, body, { idempotencyKey: key });
    },
    onSuccess: async () => {
      setApprovalError(null);
      await invalidateWorkspaceQueries(queryClient, ws);
      await approvalQuery.refetch();
    },
    onError: (error, variables) => {
      if (error instanceof Red2PrApiError && error.problem.code === "step_up_required") {
        retryAfterStepUp.current = variables;
        setStepUpOpen(true);
        return;
      }
      setApprovalError(extractAuthProblemSummary(error, "Approval could not be recorded.").detail);
    },
  });
  const entries = useMemo(() => approvalQuery.data?.data.items ?? [], [approvalQuery.data]);
  const decide = useCallback((entry: ApprovalInboxEntry, decision: "approve" | "reject") => {
    if (!me.mfa_enabled) {
      setApprovalError("MFA must be enabled before deciding an approval.");
      return;
    }
    setApprovalError(null);
    decisionMutation.mutate({ entry, decision, key: generateClientUuidV7() });
  }, [decisionMutation, me.mfa_enabled]);

  return <div className="red2pr-page-stack" data-testid="approvals-inbox-page">
    <header className="red2pr-page-header"><div><h1>Approvals</h1><p>Each decision applies to one verified patch, base SHA, target, policy revision, and expiry.</p></div></header>
    {approvalError ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">{approvalError}</div> : null}
    {!me.mfa_enabled ? <div role="status" className="red2pr-inline-alert red2pr-tone-warning">Enable MFA in Account before you can decide approvals.</div> : null}
    {approvalQuery.isPending ? <StateView state="loading" /> : approvalQuery.isError ? <StateView state={approvalQuery.error instanceof Red2PrApiError && approvalQuery.error.status === 403 ? "forbidden" : "error"} title="Approvals could not be loaded" description={approvalQuery.error instanceof Error ? approvalQuery.error.message : "The approval inbox is unavailable."} primaryAction={{ label: "Retry", onClick: () => void approvalQuery.refetch() }} /> : entries.length === 0 ? <StateView state="empty" title="No pending approvals" description="A request appears after a locally verified patch enters a repository with approval policy." /> : <div className="red2pr-page-stack">
      {entries.map((entry) => {
        const approval = entry.approval;
        const busy = decisionMutation.isPending && decisionMutation.variables?.entry.approval.id === approval.id;
        return <article key={approval.id} className="red2pr-surface red2pr-card-section" data-testid={`approval-${approval.id}`}>
          <header className="red2pr-card-header"><div><h2>{entry.scope_description}</h2><p>Repair <Link to={`/w/${ws}/repairs/${approval.repair_id}`}>{approval.repair_id.slice(0, 8)}</Link> · {entry.risk_level} risk</p></div><span className="red2pr-badge-pill red2pr-tone-warning"><StatusGlyph kind="clock" />Pending</span></header>
          <dl className="red2pr-definition-grid">
            <div><dt>Repository</dt><dd><code>{approval.repository_id}</code></dd></div>
            <div><dt>Base SHA</dt><dd><code>{approval.base_sha}</code></dd></div>
            <div><dt>Patch digest</dt><dd><code>{approval.patch_digest}</code></dd></div>
            <div><dt>Target</dt><dd><code>{approval.target_ref}</code></dd></div>
            <div><dt>Policy revision</dt><dd>{approval.policy_revision}</dd></div>
            <div><dt>Expires</dt><dd><time dateTime={approval.expires_at}>{formatUtcTimestamp(approval.expires_at)}</time></dd></div>
          </dl>
          {entry.sensitive_change ? <p role="note" className="red2pr-tone-warning">Sensitive test/configuration change: the requester cannot approve this request.</p> : null}
          {mayDecide ? <div className="red2pr-button-row"><Button label="Approve" variant="primary" isLoading={busy && decisionMutation.variables?.decision === "approve"} isDisabled={decisionMutation.isPending || !me.mfa_enabled} onClick={() => decide(entry, "approve")} /><Button label="Reject" variant="secondary" isLoading={busy && decisionMutation.variables?.decision === "reject"} isDisabled={decisionMutation.isPending || !me.mfa_enabled} onClick={() => decide(entry, "reject")} /></div> : <p role="note">Your current workspace role cannot decide this approval.</p>}
        </article>;
      })}
    </div>}
    {entries.length > 0 ? <nav className="red2pr-button-row" aria-label="Approval pages"><Button label="Previous page" variant="secondary" isDisabled={cursorHistory.length === 0} onClick={() => { const previous = cursorHistory.at(-1) ?? null; setCursorHistory((items) => items.slice(0, -1)); setCursor(previous); }} /><span>Snapshot {formatUtcTimestamp(approvalQuery.data?.data.snapshot_at ?? new Date().toISOString())}</span><Button label="Next page" variant="secondary" isDisabled={!approvalQuery.data?.data.next_cursor} onClick={() => { const next = approvalQuery.data?.data.next_cursor; if (next) { setCursorHistory((items) => [...items, cursor]); setCursor(next); } }} /></nav> : null}
    <StepUpDialog isOpen={stepUpOpen} mfaEnabled={me.mfa_enabled} onOpenChange={(open) => { setStepUpOpen(open); if (!open) retryAfterStepUp.current = null; }} onVerified={() => {
      const attempt = retryAfterStepUp.current;
      retryAfterStepUp.current = null;
      if (attempt) decisionMutation.mutate(attempt);
    }} />
  </div>;
}
