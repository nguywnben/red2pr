import { Red2PrApiError, type MeResponse, type Publication, type Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useMemo, useState } from "react";
import { Link } from "react-router";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { Button, StateView, StatusGlyph, Table, type TableColumn } from "../../shared/ui";
import { formatUtcTimestamp } from "../auth";
import { generateClientUuidV7 } from "../queues";

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
    { key: "state", header: "Publication", renderCell: (row) => <Button label={`${row.status} · ${row.id.slice(0, 8)}`} variant="secondary" onClick={() => setSelected(row.id)} /> },
    { key: "branch", header: "Branch", renderCell: (row) => <code>{row.branch}</code> },
    { key: "sha", header: "Published SHA", renderCell: (row) => row.expected_commit_sha ? <code>{row.expected_commit_sha.slice(0, 12)}</code> : "Pending" },
    { key: "review", header: "Draft review", renderCell: (row) => row.url ? <a href={row.url} target="_blank" rel="noreferrer">Open draft</a> : "Not created" },
    { key: "time", header: "Updated", renderCell: (row) => <time dateTime={row.updated_at}>{formatUtcTimestamp(row.updated_at)}</time> },
  ];
  return <div className="red2pr-page-stack" data-testid="pull-requests-page">
    <header className="red2pr-page-header"><div><h1>Pull requests</h1><p>Draft publications and remote CI proof tied to the exact published commit.</p></div></header>
    {query.isPending ? <StateView state="loading" /> : query.isError ? <StateView state={query.error instanceof Red2PrApiError && query.error.status === 403 ? "forbidden" : "error"} title="Publications could not be loaded" description={query.error instanceof Error ? query.error.message : "The publication list is unavailable."} primaryAction={{ label: "Retry", onClick: () => void query.refetch() }} /> : rows.length === 0 ? <StateView state="empty" title="No draft publications" description="A draft appears after a locally verified repair receives approval and the publisher confirms the provider state." /> : <Table aria-label="Draft publications" columns={columns} data={rows} />}
    {selected ? <section className="red2pr-surface red2pr-card-section" aria-labelledby="publication-detail-title" data-testid="publication-detail">
      <header className="red2pr-card-header"><div><h2 id="publication-detail-title">Publication details</h2><p>Repair <Link to={`/w/${ws}/repairs/${detail.data?.data.publication.repair_id ?? ""}`}>{detail.data?.data.publication.repair_id.slice(0, 8) ?? selected.slice(0, 8)}</Link></p></div><Button label="Close" variant="secondary" onClick={() => setSelected(null)} /></header>
      {detail.isPending ? <StateView state="loading" /> : detail.isError ? <StateView state="error" title="Publication detail unavailable" description={String(detail.error)} primaryAction={{ label: "Retry", onClick: () => void detail.refetch() }} /> : <>
        <dl className="red2pr-definition-grid">
          <div><dt>State</dt><dd>{detail.data.data.publication.status}</dd></div>
          <div><dt>Branch</dt><dd><code>{detail.data.data.publication.branch}</code></dd></div>
          <div><dt>Exact head SHA</dt><dd><code>{detail.data.data.publication.expected_commit_sha ?? "Not confirmed"}</code></dd></div>
          <div><dt>Remote V-08</dt><dd><span className={`red2pr-badge-pill ${detail.data.data.remote_check?.outcome === "passed" ? "red2pr-tone-success" : detail.data.data.remote_check?.outcome === "failed" ? "red2pr-tone-danger" : "red2pr-tone-warning"}`}><StatusGlyph kind="clock" />{detail.data.data.remote_check?.outcome ?? "pending"}</span></dd></div>
          <div><dt>Required set digest</dt><dd><code>{detail.data.data.remote_check?.expected_check_set_digest ?? "Not observed"}</code></dd></div>
        </dl>
        <h3>Observed checks</h3>
        {requiredCheckResults.length ? <ul aria-label="Required remote checks">{requiredCheckResults.map((check) => <li key={check.name}><strong>{check.name}</strong>: {check.status}</li>)}</ul> : <p role="note">No required remote checks are configured; V-08 remains unknown.</p>}
        {detail.data.data.remote_check?.observations?.length ? <ul>{detail.data.data.remote_check.observations.map((check) => <li key={`${check.external_id}-${check.check_name}`}><strong>{check.check_name}</strong>: {check.status}{check.conclusion ? ` · ${check.conclusion}` : ""}</li>)}</ul> : <p>No remote check observations are available.</p>}
        {canReconcile ? <div className="red2pr-button-row"><label>Refresh reason <input value={reason} maxLength={1000} onChange={(event) => setReason(event.target.value)} /></label><Button label="Reconcile remote CI" isLoading={reconcile.isPending} isDisabled={reason.trim().length === 0 || detail.data.data.publication.status !== "published"} onClick={() => reconcile.mutate()} /></div> : <p role="note">Your current workspace role cannot request a provider refresh.</p>}
        {reconcile.error ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">{String(reconcile.error)}</div> : null}
      </>}
    </section> : null}
    <p role="note">Draft reviews are never merged automatically. Remote verification requires every configured required check to pass on the exact published SHA.</p>
  </div>;
}
