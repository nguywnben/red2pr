import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useRef, useState } from "react";
import { useRed2PrApi } from "../../shared/api";
import { Button, StateView } from "../../shared/ui";
import { StepUpDialog } from "../auth/StepUpDialog";

const SUPPORT_FILES = ["health_summary", "doctor_report", "migration_status", "worker_status", "telemetry_snapshot", "recent_redacted_logs"] as const;

export function SystemPage(): React.JSX.Element {
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const status = useQuery({ queryKey: ["system", "status"], queryFn: () => api.getSystemStatus(), retry: false });
  const doctor = useQuery({ queryKey: ["system", "doctor"], queryFn: () => api.getSystemDoctor(), retry: false });
  const me = useQuery({ queryKey: ["auth", "me"], queryFn: () => api.getMe(), retry: false });
  const [maintenanceReason, setMaintenanceReason] = useState("");
  const [selectedFiles, setSelectedFiles] = useState<typeof SUPPORT_FILES[number][]>(["health_summary", "doctor_report", "migration_status", "worker_status"]);
  const [previewDigest, setPreviewDigest] = useState<string | null>(null);
  const [restoreBackupId, setRestoreBackupId] = useState("");
  const [reconciliationConfirmed, setReconciliationConfirmed] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingAction = useRef<(() => void) | null>(null);

  const maintenance = useMutation({
    mutationFn: (enabled: boolean) => api.setSystemMaintenance({ enabled, reason: enabled ? maintenanceReason.trim() : "Maintenance disabled by owner.", reconciliation_confirmed: !enabled && reconciliationConfirmed }),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ["system"] }),
  });
  const backup = useMutation({
    mutationFn: () => api.createSystemBackup({ label: "System screen backup" }),
  });
  const restoreDryRun = useMutation({
    mutationFn: () => api.dryRunSystemRestore({ backup_id: restoreBackupId.trim() }),
  });
  const restore = useMutation({
    mutationFn: () => {
      const plan = restoreDryRun.data?.data;
      if (!plan || !plan.compatible || !status.data?.data.maintenance_enabled) throw new Error("A compatible plan and maintenance mode are required.");
      return api.restoreSystemBackup({ backup_id: plan.backup_id, manifest_digest: plan.manifest_digest, plan_digest: plan.plan_digest });
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["system"] });
      await queryClient.invalidateQueries({ queryKey: ["auth"] });
    },
  });
  const preview = useMutation({
    mutationFn: () => api.previewSystemSupportBundle(selectedFiles),
    onSuccess: (result) => setPreviewDigest(result.data.manifest_digest),
  });
  const exportBundle = useMutation({
    mutationFn: () => {
      if (!previewDigest) throw new Error("Review the support bundle preview first.");
      return api.createSystemSupportBundle({ manifest_digest: previewDigest, file_ids: selectedFiles, confirm_export: true });
    },
  });

  const runAfterStepUp = (action: () => void): void => {
    pendingAction.current = action;
    setStepUpOpen(true);
  };

  if (status.isPending || me.isPending) return <main className="red2pr-page-stack"><StateView state="loading" title="Loading system status" /></main>;
  if (status.isError || me.isError) return <main className="red2pr-page-stack"><StateView state="error" title="System status unavailable" description="Sign in as an instance owner and retry." primaryAction={{ label: "Retry", onClick: () => { void status.refetch(); void me.refetch(); } }} /></main>;

  const current = status.data.data;
  return (
    <main className="red2pr-page-stack" data-testid="system-page">
      <header><h1>System operations</h1><p>Inspect this Red2PR instance, maintenance state, upgrade compatibility, and redacted support diagnostics.</p></header>
      <section className="red2pr-surface red2pr-card-section" aria-labelledby="system-status-title">
        <h2 id="system-status-title">Instance status</h2>
        <p role="status">State: {current.state}; schema: {current.schema_revision}; recovery epoch: {current.recovery_epoch}; PostgreSQL: {current.database_version ?? "unknown"}.</p>
        <ul aria-label="System health checks">{current.checks.map((check) => <li key={check.check_id}>{check.check_id}: {check.state} — {check.summary}</li>)}</ul>
        <Button label="Refresh diagnostics" onClick={() => { void status.refetch(); void doctor.refetch(); }} />
      </section>
      <section className="red2pr-surface red2pr-card-section" aria-labelledby="system-doctor-title">
        <h2 id="system-doctor-title">Doctor diagnostics</h2>
        {doctor.isPending ? <StateView state="loading" title="Running diagnostics" /> : null}
        {doctor.isError ? <p role="status">Doctor diagnostics could not be loaded.</p> : null}
        {doctor.data ? <ul>{doctor.data.data.checks.map((check) => <li key={check.check_id}>{check.check_id}: {check.state} — {check.summary}</li>)}</ul> : null}
      </section>
      <section className="red2pr-surface red2pr-card-section" aria-labelledby="system-maintenance-title">
        <h2 id="system-maintenance-title">Maintenance mode</h2>
        {current.maintenance_enabled && current.maintenance_reason ? <p role="status">Current maintenance reason: {current.maintenance_reason}</p> : null}
        <label htmlFor="system-maintenance-reason">Reason for enabling maintenance</label>
        <input id="system-maintenance-reason" minLength={8} maxLength={500} value={maintenanceReason} onChange={(event) => setMaintenanceReason(event.target.value)} />
        {current.maintenance_enabled && current.maintenance_reason?.startsWith("Restore completed;") ? <label><input type="checkbox" checked={reconciliationConfirmed} onChange={(event) => setReconciliationConfirmed(event.target.checked)} /> I have reconciled ambiguous task, publication, and notification effects before resuming writes.</label> : null}
        <Button label={current.maintenance_enabled ? "Disable maintenance" : "Enable maintenance"} isDisabled={maintenance.isPending || (!current.maintenance_enabled && maintenanceReason.trim().length < 8) || (current.maintenance_enabled && current.maintenance_reason?.startsWith("Restore completed;") && !reconciliationConfirmed)} onClick={() => runAfterStepUp(() => maintenance.mutate(!current.maintenance_enabled))} />
        {maintenance.isError ? <p role="alert">Maintenance change failed; current server state was not assumed to change.</p> : null}
      </section>
      <section className="red2pr-surface red2pr-card-section" aria-labelledby="system-backup-title">
        <h2 id="system-backup-title">Backups and restore</h2>
        <p>Backups bind a PostgreSQL snapshot to encrypted artifacts and externally trusted signing keys. Restore always starts with a read-only integrity preflight.</p>
        <Button label="Create signed backup" isDisabled={backup.isPending} onClick={() => runAfterStepUp(() => backup.mutate())} />
        {backup.isError ? <p role="alert">Backup could not be created. Check database dump, artifact store, signer, trust and backup-directory configuration.</p> : null}
        {backup.data ? <p role="status">Backup {backup.data.data.id} verified and stored; manifest digest {backup.data.data.manifest_digest}; {backup.data.data.object_count} encrypted objects.</p> : null}
        <label htmlFor="restore-backup-id">Backup ID for restore preflight</label>
        <input id="restore-backup-id" value={restoreBackupId} onChange={(event) => setRestoreBackupId(event.target.value)} autoComplete="off" />
        <Button label="Verify restore preflight" isDisabled={restoreDryRun.isPending || restoreBackupId.trim().length === 0} onClick={() => restoreDryRun.mutate()} />
        {restoreDryRun.data ? <div role="status"><p>Preflight {restoreDryRun.data.data.compatible ? "passed" : "blocked"}; target schema {restoreDryRun.data.data.target_schema_revision}; plan digest <code>{restoreDryRun.data.data.plan_digest}</code>.</p>
          {restoreDryRun.data.data.blockers.length ? <ul aria-label="Restore blockers">{restoreDryRun.data.data.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}</ul> : null}
          <p>Maintenance mode, recovery epoch rotation, tombstone reapplication and remote reconciliation are required for a restore.</p>
          <Button label="Restore verified backup" isDisabled={!restoreDryRun.data.data.compatible || !current.maintenance_enabled || restore.isPending} onClick={() => runAfterStepUp(() => restore.mutate())} />
        </div> : null}
        {restoreDryRun.isError ? <p role="alert">Restore preflight failed integrity, key availability, or schema compatibility checks.</p> : null}
        {restore.isError ? <p role="alert">Restore did not complete. Keep maintenance enabled and inspect System Doctor before retrying.</p> : null}
        {restore.data ? <p role="status">Restore completed at recovery epoch {restore.data.data.recovery_epoch}. Maintenance remains enabled until external effects are reconciled.</p> : null}
      </section>
      <section className="red2pr-surface red2pr-card-section" aria-labelledby="system-support-title">
        <h2 id="system-support-title">Support bundle</h2>
        <p>Preview the exact allowlisted files. Secrets and repository source are excluded. Export requires fresh owner step-up.</p>
        <fieldset><legend>Diagnostic files</legend>{SUPPORT_FILES.map((fileId) => <label key={fileId}>
          <input type="checkbox" checked={selectedFiles.includes(fileId)} onChange={(event) => {
            setPreviewDigest(null);
            setSelectedFiles((currentFiles) => event.target.checked ? [...currentFiles, fileId] : currentFiles.filter((item) => item !== fileId));
          }} /> {fileId.replaceAll("_", " ")}
        </label>)}</fieldset>
        <Button label="Preview bundle" isDisabled={preview.isPending || selectedFiles.length === 0} onClick={() => preview.mutate()} />
        {preview.data ? <div role="status"><p>Preview digest: <code>{preview.data.data.manifest_digest}</code></p><p>{preview.data.data.redacted_file_count} files; secrets and repository source excluded.</p>
          <Button label="Create support bundle" isDisabled={exportBundle.isPending} onClick={() => runAfterStepUp(() => exportBundle.mutate())} />
        </div> : null}
        {preview.isError || exportBundle.isError ? <p role="alert">Support bundle operation failed. Review the current diagnostics and retry.</p> : null}
        {exportBundle.data ? <p role="status">Bundle ready until {new Date(exportBundle.data.data.expires_at).toLocaleString()}. <a href={exportBundle.data.data.download_url}>Download bundle</a></p> : null}
      </section>
      <StepUpDialog isOpen={stepUpOpen} mfaEnabled={Boolean(me.data.data.mfa_enabled)} onOpenChange={(open) => { setStepUpOpen(open); if (!open) pendingAction.current = null; }} onVerified={() => { const action = pendingAction.current; pendingAction.current = null; action?.(); }} />
    </main>
  );
}

export default SystemPage;
