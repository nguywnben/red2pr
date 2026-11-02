import { InputControl } from "../../shared/ui";
import type { CiRun, Repair, MeResponse, Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { Button, Selector, StateView, StatusGlyph, Table, type TableColumn } from "../../shared/ui";
import { formatUtcTimestamp } from "../auth";
import { generateClientUuidV7 } from "../queues";

export interface RepairsListPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

function ProofBadge({ repair }: { readonly repair: Repair }): React.JSX.Element {
  const proofTone = repair.proof_grade === "locally_verified" || repair.proof_grade === "remotely_verified"
    ? "red2pr-tone-success"
    : repair.proof_grade === "baseline_confirmed" ? "red2pr-tone-info" : "red2pr-tone-neutral";
  const remoteTone = repair.remote_status === "passed" ? "red2pr-tone-success"
    : repair.remote_status === "failed" ? "red2pr-tone-danger"
      : repair.remote_status === "unknown" ? "red2pr-tone-warning" : "red2pr-tone-neutral";
  return <span className="red2pr-button-row">
    <span className={`red2pr-badge-pill ${proofTone}`}><StatusGlyph kind="info" />Proof: {repair.proof_grade.replaceAll("_", " ")}</span>
    <span className={`red2pr-badge-pill ${remoteTone}`}><StatusGlyph kind="clock" />Remote: {repair.remote_status.replaceAll("_", " ")}</span>
  </span>;
}

export function RepairsListPage({ workspace, me }: RepairsListPageProps): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [stateFilter, setStateFilter] = useState("all");
  const [proofFilter, setProofFilter] = useState("all");
  const [remoteFilter, setRemoteFilter] = useState("all");
  const [cursor, setCursor] = useState<string | null>(null);
  const [cursorHistory, setCursorHistory] = useState<readonly (string | null)[]>([]);
  const [selectedRunId, setSelectedRunId] = useState("");
  const [mode, setMode] = useState<"approval" | "auto_repair">("approval");
  const [reason, setReason] = useState("");
  const ws = workspace.slug ?? workspace.id;
  const membership = me.memberships?.find((item) => item.workspace_id === workspace.id);
  const canManage = membership?.role === "admin" || membership?.role === "maintainer";
  const runsQuery = useQuery({
    queryKey: ["workspace", ws, "runs", "repairable"],
    queryFn: () => api.listRuns(ws, { limit: 100, conclusion: "failure" }),
    enabled: canManage,
  });
  const repairsQuery = useQuery({
    queryKey: ["workspace", ws, "repairs", stateFilter, proofFilter, remoteFilter, cursor],
    queryFn: () => api.listWorkspaceRepairs(workspace.slug ?? workspace.id, {
      ...(stateFilter !== "all" ? { state: stateFilter } : {}),
      ...(proofFilter !== "all" ? { proof_grade: proofFilter } : {}),
      ...(remoteFilter !== "all" ? { remote_status: remoteFilter } : {}),
      limit: 100,
      ...(cursor ? { cursor } : {}),
    }),
  });
  const createMutation = useMutation({
    mutationFn: () => api.createWorkspaceRepair(ws, { run_id: selectedRunId, mode, reason: reason.trim() }, { idempotencyKey: generateClientUuidV7() }),
    onSuccess: async (response) => {
      setReason("");
      await queryClient.invalidateQueries({ queryKey: ["workspace", ws] });
      navigate(`/w/${ws}/repairs/${response.data.resource_id}`);
    },
  });
  const rows = useMemo(() => (repairsQuery.data?.data.items ?? []) as Repair[], [repairsQuery.data]);
  const columns: TableColumn<Repair>[] = [
    { key: "repair", header: "Repair", renderCell: (row) => <Button label={`${row.state} · ${row.id.slice(0, 8)}`} variant="secondary" onClick={() => navigate(`/w/${workspace.slug ?? workspace.id}/repairs/${row.id}`)} /> },
    { key: "proof", header: "Proof and remote status", renderCell: (row) => <ProofBadge repair={row} /> },
    { key: "base", header: "Base SHA", renderCell: (row) => <code>{row.base_sha.slice(0, 12)}</code> },
    { key: "target", header: "Target", renderCell: (row) => <code>{row.target_ref}</code> },
    { key: "updated", header: "Updated", renderCell: (row) => <time dateTime={row.updated_at}>{formatUtcTimestamp(row.updated_at)}</time> },
  ];

  const failedRuns = (runsQuery.data?.data.items ?? []).filter((run: CiRun) => ["failure", "timed_out", "action_required"].includes(run.conclusion ?? ""));
  return <div className="red2pr-page-stack" data-testid="repairs-list-page">
    <header className="red2pr-page-header"><div><h1>Repairs</h1><p>Repair sessions, evidence quality, and remote outcomes.</p></div></header>
    <div className="red2pr-toolbar" aria-label="Repair filters">
      <Selector label="Phase" isLabelHidden value={stateFilter} onChange={(value) => { setCursor(null); setCursorHistory([]); setStateFilter(value); }} options={[{ value: "all", label: "All phases" }, ...["received", "collecting", "triaging", "repro_unconfirmed", "verifying", "policy_gate", "awaiting_approval", "needs_human", "blocked", "cancelled", "remote_verified", "remote_failed"].map((item) => ({ value: item, label: item.replaceAll("_", " ") }))]} hasClear={false} hasSearch={false} placeholder="Select..." size="md" variant="input" presentation="popover" />
      <Selector label="Proof" isLabelHidden value={proofFilter} onChange={(value) => { setCursor(null); setCursorHistory([]); setProofFilter(value); }} options={[{ value: "all", label: "All proof grades" }, ...["none", "baseline_confirmed", "locally_verified", "remotely_verified"].map((item) => ({ value: item, label: item.replaceAll("_", " ") }))]} hasClear={false} hasSearch={false} placeholder="Select..." size="md" variant="input" presentation="popover" />
      <Selector label="Remote status" isLabelHidden value={remoteFilter} onChange={(value) => { setCursor(null); setCursorHistory([]); setRemoteFilter(value); }} options={[{ value: "all", label: "All remote states" }, ...["not_published", "pending", "passed", "failed", "unknown"].map((item) => ({ value: item, label: item.replaceAll("_", " ") }))]} hasClear={false} hasSearch={false} placeholder="Select..." size="md" variant="input" presentation="popover" />
    </div>
    {canManage ? <section className="red2pr-surface red2pr-card-section" aria-labelledby="start-repair-title"><h2 id="start-repair-title">Start a repair</h2>
      {runsQuery.isError ? <StateView state="error" title="Failed runs unavailable" description="Refresh pipelines and retry after run ingestion completes." primaryAction={{ label: "Retry", onClick: () => void runsQuery.refetch() }} /> : <>
        <div className="red2pr-field"><span className="red2pr-field-label">Failed CI run</span><Selector label="Failed CI run" isLabelHidden value={selectedRunId} onChange={setSelectedRunId} options={[{ value: "", label: "Select a failed run" }, ...failedRuns.map((run) => ({ value: run.id, label: `Run ${run.id.slice(0, 8)} · ${run.head_sha.slice(0, 12)} · ${run.conclusion}` }))]} hasClear={false} hasSearch={false} placeholder="Select..." size="md" variant="input" presentation="popover" /></div>
        <div className="red2pr-field"><span className="red2pr-field-label">Repair mode</span><Selector label="Repair mode" isLabelHidden value={mode} onChange={(value) => setMode(value as "approval" | "auto_repair")} options={[{ value: "approval", label: "Approval required" }, { value: "auto_repair", label: "Automatic repair" }]} hasClear={false} hasSearch={false} placeholder="Select..." size="md" variant="input" presentation="popover" /></div>
        <div className="red2pr-field"><span className="red2pr-field-label">Reason</span><InputControl aria-label="Reason" value={reason} maxLength={1000} onChange={(event) => setReason(event.target.value)} /></div>
        {createMutation.error ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">{String(createMutation.error)}</div> : null}
        <Button label="Start repair" isLoading={createMutation.isPending} isDisabled={!selectedRunId || reason.trim().length === 0} onClick={() => createMutation.mutate()} />
      </>}</section> : null}
    {repairsQuery.isPending ? <StateView state="loading" /> : repairsQuery.isError ? <StateView state="error" title="Repairs could not be loaded" description={String(repairsQuery.error)} primaryAction={{ label: "Retry", onClick: () => void repairsQuery.refetch() }} /> : rows.length === 0 ? <StateView state="empty" title="No repair sessions" description="No repair session matches these filters." /> : <Table aria-label="Repair sessions" columns={columns} data={rows} />}
    {rows.length > 0 ? <nav className="red2pr-button-row" aria-label="Repair pages"><Button label="Previous page" variant="secondary" isDisabled={cursorHistory.length === 0} onClick={() => { const previous = cursorHistory.at(-1) ?? null; setCursorHistory((items) => items.slice(0, -1)); setCursor(previous); }} /><span>Snapshot {formatUtcTimestamp(repairsQuery.data?.data.snapshot_at ?? new Date().toISOString())}</span><Button label="Next page" variant="secondary" isDisabled={!repairsQuery.data?.data.next_cursor} onClick={() => { const next = repairsQuery.data?.data.next_cursor; if (next) { setCursorHistory((items) => [...items, cursor]); setCursor(next); } }} /></nav> : null}
  </div>;
}
