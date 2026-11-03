import type { CiRun, Repair, MeResponse, Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useId, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { Button, ConfirmActionButton, InputControl, SelectorControl, StateView, StatusGlyph, Table, proportional, type TableColumn } from "../../shared/ui";
import { extractAuthProblemSummary, formatUtcTimestamp } from "../auth";
import { generateClientUuidV7 } from "../queues";

const CANONICAL_REPAIR_STATES = [
  "received",
  "authorized",
  "collecting",
  "triaging",
  "diagnosed_only",
  "unsupported",
  "reproducing",
  "repro_confirmed",
  "repro_unconfirmed",
  "blocked",
  "patching",
  "verifying",
  "rejected",
  "policy_gate",
  "awaiting_approval",
  "expired",
  "publishing",
  "publish_reconcile",
  "needs_human",
  "remote_validating",
  "remote_verified",
  "remote_failed",
  "remote_unknown",
  "cancel_requested",
  "cancelled",
] as const;

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
  const phaseFilterId = useId();
  const proofFilterId = useId();
  const remoteFilterId = useId();
  const runSelectId = useId();
  const modeSelectId = useId();
  const reasonInputId = useId();
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
    queryFn: () => api.listRuns(ws, { limit: 100 }),
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
    { key: "repair", header: "Repair", width: proportional(1.6, { minWidth: 128 }), renderCell: (row) => <Button label={`${row.state.replaceAll("_", " ")} · ${row.id.slice(0, 8)}`} variant="secondary" size="sm" onClick={() => navigate(`/w/${workspace.slug ?? workspace.id}/repairs/${row.id}`)} /> },
    { key: "proof", header: "Proof and remote status", width: proportional(2.1, { minWidth: 168 }), renderCell: (row) => <ProofBadge repair={row} /> },
    { key: "base", header: "Base SHA", width: proportional(0.95, { minWidth: 76 }), renderCell: (row) => <code>{row.base_sha.slice(0, 12)}</code> },
    { key: "target", header: "Target", width: proportional(1.15, { minWidth: 92 }), renderCell: (row) => <code>{row.target_ref}</code> },
    { key: "updated", header: "Updated", width: proportional(1.25, { minWidth: 100 }), renderCell: (row) => <time dateTime={row.updated_at}>{formatUtcTimestamp(row.updated_at)}</time> },
  ];

  const failedRuns = (runsQuery.data?.data.items ?? []).filter((run: CiRun) => ["failure", "timed_out", "action_required"].includes(run.conclusion ?? ""));
  const nextCursor = repairsQuery.data?.data.next_cursor ?? null;
  const showPagination = rows.length > 0 && (cursorHistory.length > 0 || Boolean(nextCursor));
  return <div className="red2pr-page-stack" data-testid="repairs-list-page">
    <header className="red2pr-page-header"><div><h1>Repairs</h1><p>Repair sessions, evidence quality, and remote outcomes.</p></div></header>
    <div className="red2pr-filter-panel" aria-label="Repair filters">
      <div className="red2pr-field">
        <label htmlFor={phaseFilterId} className="red2pr-field-label">Phase</label>
        <SelectorControl id={phaseFilterId} value={stateFilter} onChange={(event) => { setCursor(null); setCursorHistory([]); setStateFilter(event.target.value); }}>
          <option value="all">All phases</option>
          {CANONICAL_REPAIR_STATES.map((item) => (
            <option key={item} value={item}>{item.replaceAll("_", " ")}</option>
          ))}
        </SelectorControl>
      </div>
      <div className="red2pr-field">
        <label htmlFor={proofFilterId} className="red2pr-field-label">Proof grade</label>
        <SelectorControl id={proofFilterId} value={proofFilter} onChange={(event) => { setCursor(null); setCursorHistory([]); setProofFilter(event.target.value); }}>
          <option value="all">All proof grades</option>
          {["none", "baseline_confirmed", "locally_verified", "remotely_verified"].map((item) => (
            <option key={item} value={item}>{item.replaceAll("_", " ")}</option>
          ))}
        </SelectorControl>
      </div>
      <div className="red2pr-field">
        <label htmlFor={remoteFilterId} className="red2pr-field-label">Remote status</label>
        <SelectorControl id={remoteFilterId} value={remoteFilter} onChange={(event) => { setCursor(null); setCursorHistory([]); setRemoteFilter(event.target.value); }}>
          <option value="all">All remote states</option>
          {["not_published", "pending", "passed", "failed", "unknown"].map((item) => (
            <option key={item} value={item}>{item.replaceAll("_", " ")}</option>
          ))}
        </SelectorControl>
      </div>
    </div>
    {canManage ? <section className="red2pr-surface red2pr-card-section" aria-labelledby="start-repair-title"><h2 id="start-repair-title">Start a repair</h2>
      {runsQuery.isError ? <StateView state="error" title="Failed runs unavailable" description="Refresh pipelines and retry after run ingestion completes." primaryAction={{ label: "Retry", onClick: () => void runsQuery.refetch() }} /> : <>
        <div className="red2pr-form-grid-3">
          <div className="red2pr-field">
            <label htmlFor={runSelectId} className="red2pr-field-label">Failed CI run</label>
            <SelectorControl id={runSelectId} value={selectedRunId} onChange={(event) => setSelectedRunId(event.target.value)}>
              <option value="">Select a failed run</option>
              {failedRuns.map((run) => (
                <option key={run.id} value={run.id}>{`Run ${run.id.slice(0, 8)} · ${run.head_sha.slice(0, 12)} · ${run.conclusion}`}</option>
              ))}
            </SelectorControl>
          </div>
          <div className="red2pr-field">
            <label htmlFor={modeSelectId} className="red2pr-field-label">Repair mode</label>
            <SelectorControl id={modeSelectId} value={mode} onChange={(event) => setMode(event.target.value as "approval" | "auto_repair")}>
              <option value="approval">Approval required</option>
              <option value="auto_repair">Automatic repair</option>
            </SelectorControl>
          </div>
          <div className="red2pr-field">
            <label htmlFor={reasonInputId} className="red2pr-field-label">Reason</label>
            <InputControl id={reasonInputId} value={reason} placeholder="Describe why this run needs repair..." maxLength={1000} onChange={(event) => setReason(event.target.value)} />
          </div>
        </div>
        {createMutation.error ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">{extractAuthProblemSummary(createMutation.error, "The repair request failed.").detail}</div> : null}
        <div className="red2pr-button-row">
          <ConfirmActionButton label="Start repair" isDisabled={createMutation.isPending || !selectedRunId || reason.trim().length === 0} confirmationTitle="Start this repair?" confirmationDescription="Red2PR will create a repair session for the selected failed run. The selected mode controls whether changes require approval or can be applied automatically, and configured model or worker budget may be used." confirmationActionLabel="Start repair" confirmationActionVariant="primary" onConfirm={async () => { await createMutation.mutateAsync(); }} />
        </div>
      </>}</section> : null}
    {repairsQuery.isPending ? <StateView state="loading" skeletonVariant="table" /> : repairsQuery.isError ? <StateView state="error" title="Repairs could not be loaded" description={extractAuthProblemSummary(repairsQuery.error, "Repairs could not be loaded.").detail} primaryAction={{ label: "Retry", onClick: () => void repairsQuery.refetch() }} /> : rows.length === 0 ? <StateView state="empty" title="No repair sessions" description="No repair session matches these filters." /> : <div className="red2pr-surface red2pr-table-scroll"><Table aria-label="Repair sessions" columns={columns} data={rows} /></div>}
    {showPagination ? <nav className="red2pr-button-row" aria-label="Repair pages"><Button label="Previous page" variant="secondary" isDisabled={cursorHistory.length === 0} onClick={() => { const previous = cursorHistory.at(-1) ?? null; setCursorHistory((items) => items.slice(0, -1)); setCursor(previous); }} /><span className="red2pr-field-hint">Snapshot {formatUtcTimestamp(repairsQuery.data?.data.snapshot_at ?? new Date().toISOString())}</span><Button label="Next page" variant="secondary" isDisabled={!nextCursor} onClick={() => { if (nextCursor) { setCursorHistory((items) => [...items, cursor]); setCursor(nextCursor); } }} /></nav> : null}
  </div>;
}
