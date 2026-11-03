import { InputControl } from "../../shared/ui";
import { Red2PrApiError, type MeResponse, type Publication, type Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useMemo, useState } from "react";
import { Link } from "react-router";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { Button, StateView, StatusGlyph, Table, proportional, type TableColumn } from "../../shared/ui";
import { extractAuthProblemSummary, formatUtcTimestamp } from "../auth";
import { generateClientUuidV7 } from "../queues";

const RECONCILABLE_PUBLICATION_STATUSES = [
  "published",
  "reconciling",
  "pushing",
  "creating",
  "intent",
] as const;

export interface PullRequestsPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

export function PullRequestsPage({ workspace, me }: PullRequestsPageProps): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const ws = workspace.slug ?? workspace.id;
  const membership = me.memberships?.find((item) => item.workspace_id === workspace.id);
  const canReconcile = membership?.role === "admin" || membership?.role === "maintainer" || membership?.role === "reviewer";
  const [selected, setSelected] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const query = useQuery({
    queryKey: ["workspace", ws, "publications"],
    queryFn: () => api.listWorkspacePublications(ws),
  });
  const detail = useQuery({
    queryKey: ["workspace", ws, "publications", selected],
    queryFn: () => api.getWorkspacePublication(ws, selected ?? ""),
    enabled: selected !== null,
  });
  const reconcile = useMutation({
    mutationFn: () => api.reconcileWorkspacePublication(ws, selected ?? "", { reason: reason.trim() }, { idempotencyKey: generateClientUuidV7() }),
    onSuccess: async () => {
      setReason("");
      await invalidateWorkspaceQueries(queryClient, ws);
      await detail.refetch();
    },
  });
  const rows = useMemo(() => query.data?.data.items ?? [], [query.data]);
  const selectedRow = useMemo(
    () => rows.find((item) => item.id === selected) ?? null,
    [rows, selected],
  );
  const requiredCheckResults = useMemo(() => {
    const remote = detail.data?.data.remote_check;
    if (!remote) return [];
    return (remote.required_check_names ?? []).map((name) => {
      const matches = (remote.observations ?? []).filter((check) => check.check_name === name);
      const exact = matches.filter((check) => check.head_sha === remote.head_sha);
      const successful = exact.some(
        (check) => check.conclusion === "success" && check.status === "completed",
      );
      const failed = exact.some(
        (check) =>
          !["queued", "in_progress", "pending", "running"].includes(check.status) &&
          (check.status !== "success" && check.status !== "completed" ||
            check.conclusion !== "success"),
      );
      return {
        name,
        status: successful
          ? "passed on exact SHA"
          : failed
            ? "failed on exact SHA"
            : exact.length
              ? "pending on exact SHA"
              : matches.length
                ? "wrong SHA"
                : "missing",
      };
    });
  }, [detail.data]);
  const columns: TableColumn<Publication>[] = [
    { key: "state", header: "Publication", width: proportional(1.3, { minWidth: 117 }), renderCell: (row) => <Button label={`${row.status} · ${row.id.slice(0, 8)}`} variant="secondary" size="sm" onClick={() => setSelected(row.id)} /> },
    { key: "branch", header: "Branch", width: proportional(1.8, { minWidth: 162 }), renderCell: (row) => <code>{row.branch}</code> },
    { key: "sha", header: "Published SHA", width: proportional(1, { minWidth: 90 }), renderCell: (row) => row.expected_commit_sha ? <code>{row.expected_commit_sha.slice(0, 12)}</code> : "Pending" },
    { key: "review", header: "Draft review", width: proportional(0.9, { minWidth: 81 }), renderCell: (row) => row.url ? <a href={row.url} target="_blank" rel="noreferrer">Open draft</a> : "Not created" },
    { key: "time", header: "Updated", width: proportional(1.15, { minWidth: 103 }), renderCell: (row) => <time dateTime={row.updated_at}>{formatUtcTimestamp(row.updated_at)}</time> },
  ];
  const resolvedRepairId = detail.data?.data.publication.repair_id ?? selectedRow?.repair_id ?? null;
  const remoteCheck = detail.data?.data.remote_check ?? null;
  return <div className="red2pr-page-stack" data-testid="pull-requests-page">
    <header className="red2pr-page-header"><div><h1>Pull requests</h1><p>Draft publications and remote CI proof tied to the exact published commit.</p></div></header>
    {query.isPending ? <StateView state="loading" skeletonVariant="table" /> : query.isError ? <StateView state={query.error instanceof Red2PrApiError && query.error.status === 403 ? "forbidden" : "error"} title="Publications could not be loaded" description={query.error instanceof Error ? query.error.message : "The publication list is unavailable."} primaryAction={{ label: "Retry", onClick: () => void query.refetch() }} /> : rows.length === 0 ? <StateView state="empty" title="No draft publications" description="A draft appears after a locally verified repair receives approval and the publisher confirms the provider state." /> : <div className="red2pr-surface red2pr-table-scroll"><Table aria-label="Draft publications" columns={columns} data={rows} /></div>}
    {selected ? <section className="red2pr-surface red2pr-card-section" aria-labelledby="publication-detail-title" data-testid="publication-detail">
      <header className="red2pr-card-header"><div><h2 id="publication-detail-title">Publication details</h2>{resolvedRepairId ? <p className="red2pr-field-hint">Repair <Link to={`/w/${ws}/repairs/${resolvedRepairId}`}>{resolvedRepairId.slice(0, 8)}</Link></p> : null}</div><Button label="Close" variant="secondary" size="sm" onClick={() => setSelected(null)} /></header>
      {detail.isPending ? <StateView state="loading" skeletonVariant="detail" /> : detail.isError ? <StateView state="error" title="Publication detail unavailable" description={extractAuthProblemSummary(detail.error, "Publication detail unavailable.").detail} primaryAction={{ label: "Retry", onClick: () => void detail.refetch() }} /> : <>
        <dl className="red2pr-kv-grid">
          <div className="red2pr-kv-item"><dt className="red2pr-kv-term">State</dt><dd className="red2pr-kv-detail">{detail.data.data.publication.status}</dd></div>
          <div className="red2pr-kv-item"><dt className="red2pr-kv-term">Branch</dt><dd className="red2pr-kv-detail"><code>{detail.data.data.publication.branch}</code></dd></div>
          <div className="red2pr-kv-item"><dt className="red2pr-kv-term">Exact head SHA</dt><dd className="red2pr-kv-detail"><code>{detail.data.data.publication.expected_commit_sha ?? "Not confirmed"}</code></dd></div>
          <div className="red2pr-kv-item"><dt className="red2pr-kv-term">Remote V-08</dt><dd className="red2pr-kv-detail"><span className={`red2pr-badge-pill ${remoteCheck?.outcome === "passed" ? "red2pr-tone-success" : remoteCheck?.outcome === "failed" ? "red2pr-tone-danger" : "red2pr-tone-warning"}`}><StatusGlyph kind={remoteCheck?.outcome === "passed" ? "check" : remoteCheck?.outcome === "failed" ? "error" : "clock"} />{remoteCheck?.outcome ?? "pending"}</span></dd></div>
          <div className="red2pr-kv-item"><dt className="red2pr-kv-term">Required set digest</dt><dd className="red2pr-kv-detail"><code>{remoteCheck?.expected_check_set_digest ?? "Not observed"}</code></dd></div>
        </dl>
        <h3>Observed checks</h3>
        {requiredCheckResults.length ? (
          <ul aria-label="Required remote checks">{requiredCheckResults.map((check) => <li key={check.name}><strong>{check.name}</strong>: {check.status}</li>)}</ul>
        ) : remoteCheck === null || remoteCheck.outcome === "unknown" ? (
          <p role="note" className="red2pr-field-hint">No required remote checks are configured; V-08 remains unknown.</p>
        ) : null}
        {detail.data.data.remote_check?.observations?.length ? <ul>{detail.data.data.remote_check.observations.map((check) => <li key={`${check.external_id}-${check.check_name}`}><strong>{check.check_name}</strong>: {check.status}{check.conclusion ? ` · ${check.conclusion}` : ""}</li>)}</ul> : <p>No remote check observations are available.</p>}
        {canReconcile ? <div className="red2pr-button-row" style={{ alignItems: "flex-end" }}><div className="red2pr-field" style={{ flex: "1 1 240px" }}><span className="red2pr-field-label">Refresh reason</span><InputControl aria-label="Refresh reason" value={reason} placeholder="Reason to reconcile provider CI checks..." maxLength={1000} onChange={(event) => setReason(event.target.value)} /></div><Button label="Reconcile remote CI" isLoading={reconcile.isPending} isDisabled={reason.trim().length === 0 || !(RECONCILABLE_PUBLICATION_STATUSES as readonly string[]).includes(detail.data.data.publication.status)} onClick={() => reconcile.mutate()} /></div> : <p role="note">Your current workspace role cannot request a provider refresh.</p>}
        {reconcile.error ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">{extractAuthProblemSummary(reconcile.error, "Provider reconciliation failed.").detail}</div> : null}
      </>}
    </section> : null}
    <p role="note" className="red2pr-field-hint">Draft reviews are never merged automatically. Remote verification requires every configured required check to pass on the exact published SHA.</p>
  </div>;
}
