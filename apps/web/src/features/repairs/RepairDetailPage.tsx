import { SelectorControl } from "../../shared/ui";
import { Red2PrApiError, type MeResponse, type Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { Button, ConfirmActionButton, SafeDiffViewer, SafeLogViewer, StateView, StatusGlyph } from "../../shared/ui";
import { extractAuthProblemSummary, formatUtcTimestamp } from "../auth";
import { generateClientUuidV7 } from "../queues";

export interface RepairDetailPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

type TabName = "Cause" | "Repro" | "Diff" | "Verification" | "PR" | "Logs" | "Audit";
type EvidenceRow = Record<string, unknown> & { readonly id?: string; readonly summary?: string; readonly changed_paths?: readonly string[] };
const TABS: readonly TabName[] = ["Cause", "Repro", "Diff", "Verification", "PR", "Logs", "Audit"];

export function RepairDetailPage({ workspace, me }: RepairDetailPageProps): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const params = useParams<{ repairId?: string }>();
  const repairId = params.repairId ?? "";
  const ws = workspace.slug ?? workspace.id;
  const [activeTab, setActiveTab] = useState<TabName>("Cause");
  const [diffText, setDiffText] = useState("");
  const [errorText, setErrorText] = useState<string | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [logOffset, setLogOffset] = useState(0);
  const [jobLog, setJobLog] = useState<Awaited<ReturnType<typeof api.getJobLog>> | null>(null);
  const [jobLogError, setJobLogError] = useState<unknown>(null);
  const [jobLogLoading, setJobLogLoading] = useState(false);
  const [runJobs, setRunJobs] = useState<Awaited<ReturnType<typeof api.listRunJobs>> | null>(null);
  const [runJobsError, setRunJobsError] = useState<unknown>(null);
  const [runJobsLoading, setRunJobsLoading] = useState(false);
  const logRequest = useRef<AbortController | null>(null);

  const repairQuery = useQuery({ queryKey: ["workspace", ws, "repair", repairId], queryFn: () => api.getWorkspaceRepair(ws, repairId), enabled: repairId.length > 0 });
  const diagnosisQuery = useQuery({ queryKey: ["workspace", ws, "repair", repairId, "diagnosis"], queryFn: () => api.getWorkspaceRepairEvidence(ws, repairId, "diagnosis"), enabled: repairId.length > 0 });
  const patchQuery = useQuery({ queryKey: ["workspace", ws, "repair", repairId, "patches"], queryFn: () => api.getWorkspaceRepairEvidence(ws, repairId, "patches"), enabled: repairId.length > 0 });
  const verificationQuery = useQuery({ queryKey: ["workspace", ws, "repair", repairId, "verification"], queryFn: () => api.getWorkspaceRepairEvidence(ws, repairId, "verification"), enabled: repairId.length > 0 });
  const timelineQuery = useQuery({ queryKey: ["workspace", ws, "repair", repairId, "timeline"], queryFn: () => api.getWorkspaceRepairTimeline(ws, repairId), enabled: repairId.length > 0 });
  const sourceRunId = repairQuery.data?.data.run_id ?? "";
  const repair = repairQuery.data?.data ?? null;
  const publicationsQuery = useQuery({
    queryKey: ["workspace", ws, "publications", "for-repair", repairId],
    queryFn: async () => {
      try {
        return await api.listWorkspacePublications(ws);
      } catch {
        return null;
      }
    },
    enabled: activeTab === "PR" && repair !== null && repair.remote_status !== "not_published",
    retry: false,
  });
  const loadJobLog = useCallback(async (jobId: string, offset: number): Promise<void> => {
    logRequest.current?.abort();
    const controller = new AbortController();
    logRequest.current = controller;
    setJobLog(null);
    setJobLogError(null);
    setJobLogLoading(true);
    try {
      const result = await api.getJobLog(ws, jobId, { start_offset: offset, max_bytes: 65536 });
      if (!controller.signal.aborted) setJobLog(result);
    } catch (error: unknown) {
      if (!controller.signal.aborted) setJobLogError(error);
    } finally {
      if (!controller.signal.aborted) setJobLogLoading(false);
    }
  }, [api, ws]);
  const loadRunJobs = useCallback(async (): Promise<void> => {
    if (!sourceRunId) return;
    setRunJobsLoading(true);
    setRunJobsError(null);
    try {
      const result = await api.listRunJobs(ws, sourceRunId);
      setRunJobs(result);
      const firstJobId = result.data.items?.[0]?.id;
      if (firstJobId) { setSelectedJobId(firstJobId); void loadJobLog(firstJobId, 0); }
    }
    catch (error: unknown) { setRunJobsError(error); }
    finally { setRunJobsLoading(false); }
  }, [api, loadJobLog, sourceRunId, ws]);
  const diagnoses = (diagnosisQuery.data?.data.items ?? []) as readonly EvidenceRow[];
  const patches = (patchQuery.data?.data.items ?? []) as readonly EvidenceRow[];
  const verifications = (verificationQuery.data?.data.items ?? []) as readonly EvidenceRow[];
  const reproductions = (verificationQuery.data?.data.reproductions ?? []) as readonly EvidenceRow[];
  const events = useMemo(() => (timelineQuery.data?.data.items ?? []) as readonly EvidenceRow[], [timelineQuery.data]);
  const membership = (me.memberships ?? []).find((item) => item.workspace_id === workspace.id);
  const canManage = membership?.role === "admin" || membership?.role === "maintainer";

  const actionMutation = useMutation({
    mutationFn: (action: "pause" | "resume" | "cancel" | "retry") => {
      if (!repair) throw new Error("Repair is not loaded");
      return api.performRepairAction(ws, repair.id, { action, reason: `Requested from repair detail: ${action}`, expected_version: repair.version }, { idempotencyKey: generateClientUuidV7() });
    },
    onSuccess: async () => { setErrorText(null); await invalidateWorkspaceQueries(queryClient, ws); await repairQuery.refetch(); },
    onError: (error) => setErrorText(extractAuthProblemSummary(error, "The repair action failed.").detail),
  });

  const downloadDiff = useCallback(async (artifactId: string): Promise<void> => {
    try {
      const result = await api.downloadArtifact(ws, artifactId);
      setDiffText(new TextDecoder("utf-8", { fatal: false }).decode(result.data.bytes));
      setErrorText(null);
    } catch (error) {
      setErrorText(extractAuthProblemSummary(error, "Diff evidence could not be loaded.").detail);
    }
  }, [api, ws]);

  const firstDiagnosis = diagnoses[0];
  const latestPatch = patches.at(-1);
  const latestVerification = verifications.at(-1);
  const matchedPublication = useMemo(
    () => (publicationsQuery.data?.data.items ?? []).find((pub) => pub.repair_id === repairId) ?? null,
    [publicationsQuery.data, repairId],
  );
  const jobs = runJobs?.data.items ?? [];
  const activeJobId = selectedJobId ?? jobs[0]?.id ?? null;
  useEffect(() => () => logRequest.current?.abort(), []);
  const patchArtifactId = typeof latestPatch?.diff_artifact_id === "string" ? latestPatch.diff_artifact_id : null;
  const stepRows = useMemo(() => events.map((event) => ({
    id: String(event.id ?? `${String(event.source)}-${String(event.type)}-${String(event.at)}`),
    at: String(event.at ?? ""),
    source: String(event.source ?? ""),
    type: String(event.type ?? ""),
    reason: String(event.reason_code ?? ""),
  })), [events]);

  if (repairQuery.isError) return <div className="red2pr-page-stack"><StateView state={repairQuery.error instanceof Red2PrApiError && repairQuery.error.status === 403 ? "forbidden" : "error"} title="Repair detail unavailable" description={repairQuery.error instanceof Error ? repairQuery.error.message : "The repair could not be loaded."} primaryAction={{ label: "Back to repairs", onClick: () => navigate(`/w/${ws}/repairs`) }} /></div>;

  const isTerminalState = repair !== null && ["remote_verified", "cancelled", "failed", "repro_unconfirmed", "rejected", "expired", "diagnosed_only", "unsupported"].includes(repair.state);
  const proofTone = repair?.proof_grade === "locally_verified" || repair?.proof_grade === "remotely_verified"
    ? "red2pr-tone-success"
    : repair?.proof_grade === "baseline_confirmed"
      ? "red2pr-tone-info"
      : "red2pr-tone-neutral";
  const remoteTone = repair?.remote_status === "passed"
    ? "red2pr-tone-success"
    : repair?.remote_status === "failed"
      ? "red2pr-tone-danger"
      : repair?.remote_status === "unknown" || repair?.remote_status === "pending"
        ? "red2pr-tone-warning"
        : "red2pr-tone-neutral";

  return <div className="red2pr-page-stack" data-testid="repair-detail-page" data-run-id={repair?.run_id}>
    <header className="red2pr-page-header">
      <div>
        <div style={{ marginBottom: 8 }}>
          <Button label="← Repairs" variant="secondary" size="sm" onClick={() => navigate(`/w/${ws}/repairs`)} />
        </div>
        <h1>Repair {(repair?.id ?? repairId ?? "").slice(0, 8)}</h1>
        {repair ? <p>Created {formatUtcTimestamp(repair.created_at)} · target <code>{repair.target_ref}</code> · base <code>{repair.base_sha.slice(0, 12)}</code></p> : null}
      </div>
    </header>
    {repair === null ? <StateView state="loading" skeletonVariant="detail" /> : <>
    <section aria-label="Independent repair status" className="red2pr-button-row">
      <span className={`red2pr-badge-pill ${proofTone}`}><StatusGlyph kind={proofTone === "red2pr-tone-success" ? "check" : "info"} />Proof grade: {repair.proof_grade.replaceAll("_", " ")}</span>
      <span className={`red2pr-badge-pill ${remoteTone}`}><StatusGlyph kind={repair.remote_status === "passed" ? "check" : repair.remote_status === "failed" ? "error" : "clock"} />Remote status: {repair.remote_status.replaceAll("_", " ")}</span>
      <span className="red2pr-badge-pill red2pr-tone-neutral">Phase: {repair.state.replaceAll("_", " ")}</span>
    </section>
    {canManage ? <div className="red2pr-button-row" aria-label="Repair actions">
      {repair.suspension ? <Button label="Resume" variant="secondary" isLoading={actionMutation.isPending} onClick={() => actionMutation.mutate("resume")} /> : <Button label="Pause" variant="secondary" isDisabled={actionMutation.isPending || isTerminalState} onClick={() => actionMutation.mutate("pause")} />}
      <ConfirmActionButton label="Cancel" variant="secondary" isDisabled={actionMutation.isPending || isTerminalState} confirmationTitle="Cancel this repair?" confirmationDescription="The repair session will stop and cannot be resumed. You can start a new repair from a failed CI run." confirmationActionLabel="Cancel repair" onConfirm={async () => { await actionMutation.mutateAsync("cancel"); }} />
      { ["blocked", "rejected", "needs_human", "cancelled", "remote_failed", "remote_unknown", "diagnosed_only", "unsupported", "repro_unconfirmed"].includes(repair.state) ? <ConfirmActionButton label="Retry" variant="primary" isDisabled={actionMutation.isPending} confirmationTitle="Retry this repair?" confirmationDescription="Red2PR will enqueue another repair attempt using the current evidence and configured model or worker budget." confirmationActionLabel="Retry repair" confirmationActionVariant="primary" onConfirm={async () => { await actionMutation.mutateAsync("retry"); }} /> : null }
    </div> : null}
    {errorText ? <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">{errorText}</div> : null}
    <div role="tablist" tabIndex={0} aria-label="Repair evidence" className="red2pr-tab-strip" onKeyDown={(event) => {
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
      event.preventDefault();
      const direction = event.key === "ArrowRight" ? 1 : -1;
      const current = TABS.indexOf(activeTab);
      const next = TABS[(current + direction + TABS.length) % TABS.length];
      if (next) { setActiveTab(next); document.getElementById(`repair-tab-${next}`)?.focus(); }
    }}>
      {TABS.map((tab) => <button key={tab} id={`repair-tab-${tab}`} type="button" role="tab" className="red2pr-tab-button" aria-selected={activeTab === tab} aria-controls="repair-tabpanel" tabIndex={activeTab === tab ? 0 : -1} onClick={() => { setActiveTab(tab); if (tab === "Logs") { if (runJobs === null) void loadRunJobs(); else if (activeJobId) void loadJobLog(activeJobId, logOffset); } }}>{tab}</button>)}
    </div>
    <section id="repair-tabpanel" role="tabpanel" aria-labelledby={`repair-tab-${activeTab}`} className="red2pr-surface red2pr-card-section">
      {activeTab === "Cause" ? <>{firstDiagnosis ? <><h2>{String(firstDiagnosis.class ?? "Diagnosis").replaceAll("_", " ")}</h2><p>{String(firstDiagnosis.summary ?? "No summary recorded.")}</p><h3>Uncertainties</h3>{Array.isArray(firstDiagnosis.uncertainties) && firstDiagnosis.uncertainties.length > 0 ? <ul>{firstDiagnosis.uncertainties.map((item) => <li key={String(item)}>{String(item)}</li>)}</ul> : <p className="red2pr-field-hint">No open uncertainties recorded for this diagnosis.</p>}</> : <StateView state="partial_evidence" title="Diagnosis evidence is unavailable" description="No diagnosis record is linked to this session." />}</> : null}
      {activeTab === "Repro" ? <><h2>Reproduction evidence</h2><p>Repair base SHA: <code>{repair.base_sha}</code></p>{reproductions.length > 0 ? <ol>{reproductions.map((run) => <li key={String(run.id)}><strong>{String(run.phase)} · {String(run.status)}</strong> · fidelity {String(run.fidelity_grade)} · tests {String(run.executed_tests_count)} run / {String(run.passed_tests_count)} passed / {String(run.failed_tests_count)} failed / {String(run.skipped_tests_count)} skipped · exit {String(run.exit_code ?? "not reported")}<p>Source SHA: <code>{String(run.base_sha)}</code>{typeof run.patch_digest === "string" ? <> · patch <code>{run.patch_digest}</code></> : null}</p>{typeof run.failure_reason_code === "string" ? <p>Failure reason: {run.failure_reason_code}</p> : null}</li>)}</ol> : <StateView state="partial_evidence" title="No sandbox reproduction runs linked" description="No baseline or patched Sandbox A/B evidence is persisted for this repair." />}{diagnosisQuery.isError || verificationQuery.isError ? <StateView state="partial_evidence" title="Reproduction evidence is incomplete" description="Some evidence could not be loaded. Retry to resynchronize the snapshot." primaryAction={{ label: "Retry", onClick: () => { void diagnosisQuery.refetch(); void verificationQuery.refetch(); } }} /> : null}</> : null}
      {activeTab === "Diff" ? <><h2>Patch diff</h2>{latestPatch ? <><p>Patch digest: <code>{String(latestPatch.patch_digest)}</code> · based on <code>{String(latestPatch.base_sha)}</code></p><p>Changed paths: {(latestPatch.changed_paths ?? []).map(String).join(", ") || "none recorded"}</p>{patchArtifactId ? <><Button label="Load verified diff artifact" isLoading={false} onClick={() => void downloadDiff(patchArtifactId)} />{diffText ? <SafeDiffViewer rawDiff={diffText} title="Verified patch diff" /> : null}</> : <StateView state="partial_evidence" title="Diff artifact is not linked" description="Patch metadata exists, but no diff artifact reference was recorded." />}</> : <StateView state="empty" title="No patch proposed" description="No candidate patch diff has been recorded for this repair session." />}</> : null}
      {activeTab === "Verification" ? <><h2>Deterministic verification</h2>{latestVerification ? <><p>Status: <strong>{String(latestVerification.status)}</strong> · proof: <strong>{String(latestVerification.proof_grade)}</strong></p><p>Patch digest: <code>{String(latestVerification.patch_digest)}</code></p><ul>{(Array.isArray(latestVerification.gates) ? latestVerification.gates : []).map((gate) => { const item = gate as Record<string, unknown>; const count = Array.isArray(item.evidence_ids) ? item.evidence_ids.length : null; return <li key={String(item.id)}>{String(item.id)}: {String(item.outcome)}{count !== null ? ` · ${count === 1 ? "1 evidence item" : `${count} evidence items`}` : ""}</li>; })}</ul></> : <StateView state="partial_evidence" title="Verification evidence is unavailable" description="No deterministic V-01..V-07 result is linked to this repair." />}</> : null}
      {activeTab === "PR" ? <><h2>Publication</h2>{repair.remote_status === "not_published" ? <StateView state="approval_required" title="No draft PR published yet" description="A draft pull request is published only after local sandbox verification passes and any required human approval is recorded." /> : publicationsQuery.isPending ? <StateView state="loading" skeletonVariant="detail" /> : matchedPublication ? <div className="red2pr-form-stack"><dl className="red2pr-kv-grid"><div className="red2pr-kv-item"><dt className="red2pr-kv-term">Publication state</dt><dd className="red2pr-kv-detail">{matchedPublication.status}</dd></div><div className="red2pr-kv-item"><dt className="red2pr-kv-term">Branch</dt><dd className="red2pr-kv-detail"><code>{matchedPublication.branch}</code></dd></div><div className="red2pr-kv-item"><dt className="red2pr-kv-term">Published commit SHA</dt><dd className="red2pr-kv-detail"><code>{matchedPublication.expected_commit_sha ?? "Pending"}</code></dd></div><div className="red2pr-kv-item"><dt className="red2pr-kv-term">Remote CI outcome</dt><dd className="red2pr-kv-detail"><span className={`red2pr-badge-pill ${remoteTone}`}><StatusGlyph kind={repair.remote_status === "passed" ? "check" : "clock"} />{repair.remote_status.replaceAll("_", " ")}</span></dd></div></dl><div className="red2pr-button-row">{matchedPublication.url ? <a href={matchedPublication.url} target="_blank" rel="noreferrer">Open draft pull request</a> : null}<Link to={`/w/${ws}/prs`}>Inspect remote CI reconciliation →</Link></div></div> : <StateView state="partial_evidence" title="Publication record not found in current view" description="Open Pull requests to inspect draft publication status and remote check reconciliation." primaryAction={{ label: "Open Pull requests", onClick: () => navigate(`/w/${ws}/prs`) }} />}</> : null}
      {activeTab === "Logs" ? <><h2>Sanitized CI logs</h2>{runJobsLoading ? <StateView state="loading" skeletonVariant="list" /> : runJobsError ? <StateView state="offline" title="CI job list unavailable" description={extractAuthProblemSummary(runJobsError, "The CI job list could not be loaded.").detail} primaryAction={{ label: "Retry", onClick: () => void loadRunJobs() }} /> : jobs.length === 0 ? <StateView state="partial_evidence" title="No CI jobs linked" description="The repair source run has no retained CI job records." /> : <>
        <div className="red2pr-field" style={{ maxWidth: 420 }}><label className="red2pr-field-label">CI job <SelectorControl value={activeJobId ?? ""} onChange={(event) => { setSelectedJobId(event.target.value); setLogOffset(0); if (event.target.value) void loadJobLog(event.target.value, 0); }} aria-label="CI job"><option value="">Select a CI job</option>{jobs.map((job) => <option key={job.id} value={job.id}>{job.name} · {job.conclusion ?? job.status}</option>)}</SelectorControl></label></div>
        {jobLogLoading ? <StateView state="loading" skeletonVariant="code" /> : jobLogError ? <StateView state="partial_evidence" title={jobLogError instanceof Red2PrApiError && jobLogError.status === 410 ? "CI log expired" : "CI log unavailable"} description={extractAuthProblemSummary(jobLogError, "This log could not be loaded.").detail} primaryAction={{ label: "Retry", onClick: () => { if (activeJobId) void loadJobLog(activeJobId, logOffset); } }} /> : jobLog ? <>
          <SafeLogViewer rawText={jobLog.data.content} title="Redacted CI log chunk" />
          <p className="red2pr-field-hint">Offset {jobLog.data.start_offset} · {jobLog.data.returned_bytes} bytes · redaction {jobLog.data.redaction_version}{jobLog.data.incomplete_marker ? ` · ${jobLog.data.incomplete_marker}` : ""}</p>
          {jobLog.data.has_more ? <Button label="Load next log chunk" variant="secondary" onClick={() => { const next = jobLog.data.next_offset ?? logOffset; setLogOffset(next); if (activeJobId) void loadJobLog(activeJobId, next); }} /> : null}
        </> : null}
      </>}</> : null}
      {activeTab === "Audit" ? <><h2>Timeline and audit</h2>{timelineQuery.isPending ? <StateView state="loading" skeletonVariant="list" /> : timelineQuery.isError ? <StateView state="offline" title="Timeline resynchronization failed" description="The live stream can reconnect; REST snapshot refresh remains available." primaryAction={{ label: "Retry snapshot", onClick: () => void timelineQuery.refetch() }} /> : stepRows.length === 0 ? <StateView state="empty" title="No timeline events" /> : <ol>{stepRows.map((event) => <li key={event.id}><time>{formatUtcTimestamp(event.at)}</time> · <strong>{event.type}</strong> · {event.source} {event.reason ? `· ${event.reason}` : ""}</li>)}</ol>}</> : null}
    </section>
    <footer className="red2pr-field-hint"><small>Version {repair.version} · Policy revision {repair.policy_revision} · session <code>{repair.id}</code></small></footer>
    </>}
  </div>;
}
