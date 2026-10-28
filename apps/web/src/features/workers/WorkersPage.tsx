import {
  Red2PrApiError,
  type MeResponse,
  type SandboxLeaseStatus,
  type Worker,
  type WorkerAction,
  type WorkerEnrollmentCreateResponse,
  type WorkerIsolationMode,
  type WorkerSelfTestResponse,
  type WorkerStatus,
  type Workspace,
  type WorkspaceSandboxLeaseSummary,
} from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useCallback, useId, useMemo, useRef, useState } from "react";
import { invalidateWorkspaceQueries, useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import {
  Button,
  Dialog,
  StateView,
  StatusGlyph,
  Table,
  sanitizeUntrustedText,
  useLiveAnnouncer,
  type TableColumn,
} from "../../shared/ui";
import {
  StepUpDialog,
  extractAuthProblemSummary,
  formatUtcTimestamp,
  type AuthProblemSummary,
} from "../auth";
import { generateClientUuidV7 } from "../queues";

export interface WorkersPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

type GlyphKind = "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";

const STATUS_OPTIONS: readonly ("all" | WorkerStatus)[] = [
  "all",
  "online",
  "draining",
  "quarantined",
  "offline",
];

const ISOLATION_OPTIONS: readonly ("all" | WorkerIsolationMode)[] = [
  "all",
  "vm_isolated",
  "oci_rootless",
  "oci_trusted_local",
];

function workerStatusAppearance(status: WorkerStatus): {
  readonly glyph: GlyphKind;
  readonly tone: string;
  readonly label: string;
} {
  switch (status) {
    case "online":
      return { glyph: "check", tone: "red2pr-tone-success", label: "Online" };
    case "draining":
      return { glyph: "clock", tone: "red2pr-tone-warning", label: "Draining" };
    case "quarantined":
      return { glyph: "error", tone: "red2pr-tone-danger", label: "Quarantined" };
    case "offline":
      return { glyph: "offline", tone: "red2pr-tone-neutral", label: "Offline" };
  }
}

function isolationLabel(mode: WorkerIsolationMode | undefined): string {
  switch (mode) {
    case "vm_isolated":
      return "MicroVM Isolated";
    case "oci_trusted_local":
      return "OCI Trusted Local (Risk Ack)";
    case "oci_rootless":
    default:
      return "OCI Rootless";
  }
}

function leaseStatusAppearance(status: SandboxLeaseStatus): {
  readonly glyph: GlyphKind;
  readonly tone: string;
} {
  switch (status) {
    case "leased":
    case "running":
      return { glyph: "clock", tone: "red2pr-tone-info" };
    case "cancel_requested":
      return { glyph: "warn", tone: "red2pr-tone-warning" };
    case "completed":
      return { glyph: "check", tone: "red2pr-tone-success" };
    case "quarantined":
    case "expired":
      return { glyph: "error", tone: "red2pr-tone-danger" };
    case "cancelled":
      return { glyph: "info", tone: "red2pr-tone-neutral" };
  }
}

interface LeaseRow extends Record<string, unknown> {
  readonly id: string;
  readonly job_id: string;
  readonly repository_id: string;
  readonly profile_id: string;
  readonly status: SandboxLeaseStatus;
  readonly lease_epoch: number;
  readonly lease_expires_at: string;
}

interface WorkerRow extends Record<string, unknown> {
  readonly id: string;
  readonly version: number;
  readonly spiffe_id: string;
  readonly status: WorkerStatus;
  readonly isolation_mode: WorkerIsolationMode;
  readonly runtime_name: string;
  readonly profiles: string;
  readonly signer_key_id: string;
  readonly heartbeat_at: string;
  readonly mtls_cert_expires_at: string | null;
  readonly active_leases: number;
  readonly host_escape_warning: boolean;
  readonly reason_note: string | null;
}

function toLeaseRow(item: WorkspaceSandboxLeaseSummary): LeaseRow {
  return {
    id: item.id,
    job_id: sanitizeUntrustedText(item.job_id).text,
    repository_id: sanitizeUntrustedText(item.repository_id).text,
    profile_id: sanitizeUntrustedText(item.profile_id).text,
    status: item.status,
    lease_epoch: item.lease_epoch,
    lease_expires_at: item.lease_expires_at,
  };
}

function toWorkerRow(w: Worker): WorkerRow {
  const mode: WorkerIsolationMode = w.isolation_mode ?? "oci_rootless";
  const note = w.quarantine_reason ?? w.drain_reason ?? null;
  const domain = sanitizeUntrustedText(w.trust_domain).text;
  return {
    id: w.id,
    version: w.version,
    spiffe_id: `spiffe://${domain}/ns/sandbox/worker/${w.id}`,
    status: w.status,
    isolation_mode: mode,
    runtime_name: w.runtime_name ? sanitizeUntrustedText(w.runtime_name).text : "—",
    profiles: (w.profile_ids ?? []).map((p) => sanitizeUntrustedText(p).text).join(", ") || "—",
    signer_key_id: w.signer_key_id ? sanitizeUntrustedText(w.signer_key_id).text : "—",
    heartbeat_at: w.heartbeat_at,
    mtls_cert_expires_at: w.mtls_cert_expires_at ?? null,
    active_leases: w.active_leases ?? 0,
    host_escape_warning: Boolean(w.host_escape_warning || mode === "oci_trusted_local"),
    reason_note: note ? sanitizeUntrustedText(note).text : null,
  };
}

export function WorkersPage({ workspace, me }: WorkersPageProps): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const queryClient = useQueryClient();
  const announce = useLiveAnnouncer();

  const wsSlug = workspace.slug ?? workspace.id;
  const isInstanceOwner = Boolean(me.is_instance_owner);

  const statusSelectId = useId();
  const isolationSelectId = useId();
  const trustDomainInputId = useId();
  const profilesInputId = useId();
  const enrollModeSelectId = useId();
  const ttlInputId = useId();
  const ackRiskCheckId = useId();
  const actionReasonInputId = useId();

  const [statusFilter, setStatusFilter] = useState<"all" | WorkerStatus>("all");
  const [isolationFilter, setIsolationFilter] = useState<"all" | WorkerIsolationMode>("all");

  // Enrollment modal state
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [trustDomain, setTrustDomain] = useState("red2pr.internal");
  const [profileCsv, setProfileCsv] = useState("python-3.12-node-22");
  const [enrollMode, setEnrollMode] = useState<WorkerIsolationMode>("vm_isolated");
  const [ttlMinutes, setTtlMinutes] = useState(15);
  const [riskAck, setRiskAck] = useState(false);
  const [enrollResult, setEnrollResult] = useState<WorkerEnrollmentCreateResponse | null>(null);
  const [enrollError, setEnrollError] = useState<AuthProblemSummary | null>(null);

  // Worker action modal state
  const [pendingAction, setPendingAction] = useState<{
    readonly worker: WorkerRow;
    readonly action: WorkerAction;
    readonly idempotencyKey: string;
  } | null>(null);
  const [actionReason, setActionReason] = useState("");
  const [actionError, setActionError] = useState<AuthProblemSummary | null>(null);
  const [staleConflict, setStaleConflict] = useState(false);

  // Self-test modal state
  const [selfTestOpen, setSelfTestOpen] = useState(false);
  const [selfTestResult, setSelfTestResult] = useState<WorkerSelfTestResponse | null>(null);
  const [selfTestError, setSelfTestError] = useState<AuthProblemSummary | null>(null);

  // Step-up retry coordination
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const retryAfterStepUpRef = useRef<"enroll" | "action" | null>(null);

  const readinessQuery = useQuery({
    queryKey: ["workspace", wsSlug, "workers", "readiness"],
    queryFn: () => api.getWorkspaceWorkerReadiness(wsSlug),
  });

  const fleetQuery = useQuery({
    queryKey: ["system", "workers", statusFilter, isolationFilter],
    queryFn: () =>
      api.listSystemWorkers({
        status: statusFilter === "all" ? undefined : statusFilter,
        isolation_mode: isolationFilter === "all" ? undefined : isolationFilter,
        limit: 50,
      }),
    enabled: isInstanceOwner,
  });

  const refreshAll = useCallback(async () => {
    await invalidateWorkspaceQueries(queryClient, wsSlug);
    if (isInstanceOwner) {
      await queryClient.invalidateQueries({ queryKey: ["system", "workers"] });
    }
  }, [isInstanceOwner, queryClient, wsSlug]);

  const parsedProfiles = useMemo(
    () =>
      profileCsv
        .split(",")
        .map((p) => p.trim())
        .filter((p) => p.length > 0),
    [profileCsv],
  );

  const enrollMutation = useMutation({
    mutationFn: async () => {
      return api.createWorkerEnrollment({
        trust_domain: trustDomain.trim(),
        profile_ids: parsedProfiles,
        isolation_mode: enrollMode,
        ttl_minutes: ttlMinutes,
        host_escape_risk_acknowledged: enrollMode === "oci_trusted_local" ? riskAck : false,
      });
    },
    onSuccess: async (envelope) => {
      setEnrollError(null);
      setEnrollResult(envelope.data);
      announce("Minted one-time worker mTLS enrollment token.");
      await refreshAll();
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        retryAfterStepUpRef.current = "enroll";
        setStepUpOpen(true);
        return;
      }
      setEnrollError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const actionMutation = useMutation({
    mutationFn: async (ctx: {
      readonly worker: WorkerRow;
      readonly action: WorkerAction;
      readonly idempotencyKey: string;
      readonly reason: string;
    }) => {
      return api.performWorkerAction(
        ctx.worker.id,
        {
          action: ctx.action,
          reason: ctx.reason.trim(),
          expected_version: ctx.worker.version,
        },
        {
          idempotencyKey: ctx.idempotencyKey,
          ifMatch: `"v${String(ctx.worker.version)}"`,
        },
      );
    },
    onSuccess: async (_env, vars) => {
      setActionError(null);
      setStaleConflict(false);
      setPendingAction(null);
      setActionReason("");
      announce(`Worker ${vars.action} action succeeded.`);
      await refreshAll();
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        retryAfterStepUpRef.current = "action";
        setStepUpOpen(true);
        return;
      }
      if (err instanceof Red2PrApiError && (err.status === 409 || err.status === 412)) {
        setStaleConflict(true);
      }
      setActionError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const selfTestMutation = useMutation({
    mutationFn: async (workerId: string) => api.runWorkerSelfTest(workerId),
    onSuccess: (envelope) => {
      setSelfTestError(null);
      setSelfTestResult(envelope.data);
    },
    onError: (err) => {
      setSelfTestResult(null);
      setSelfTestError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const openActionModal = useCallback((worker: WorkerRow, action: WorkerAction) => {
    setActionError(null);
    setStaleConflict(false);
    setActionReason("");
    setPendingAction({
      worker,
      action,
      idempotencyKey: generateClientUuidV7(),
    });
  }, []);

  const openSelfTestModal = useCallback(
    (workerId: string) => {
      setSelfTestResult(null);
      setSelfTestError(null);
      setSelfTestOpen(true);
      selfTestMutation.mutate(workerId);
    },
    [selfTestMutation],
  );

  const leaseColumns = useMemo<TableColumn<LeaseRow>[]>(
    () => [
      {
        key: "job_id",
        header: "Job ID",
        renderCell: (row) => <code>{row.job_id}</code>,
      },
      {
        key: "repository_id",
        header: "Repository",
        renderCell: (row) => <code>{row.repository_id.slice(0, 12)}</code>,
      },
      {
        key: "profile_id",
        header: "Profile",
        renderCell: (row) => <span>{row.profile_id}</span>,
      },
      {
        key: "status",
        header: "Lease Status",
        renderCell: (row) => {
          const app = leaseStatusAppearance(row.status);
          return (
            <span className={`red2pr-badge-pill ${app.tone}`}>
              <StatusGlyph kind={app.glyph} />
              <span>{row.status}</span>
            </span>
          );
        },
      },
      {
        key: "lease_epoch",
        header: "Epoch",
        renderCell: (row) => <span>e{String(row.lease_epoch)}</span>,
      },
      {
        key: "lease_expires_at",
        header: "Expires",
        renderCell: (row) => <span>{formatUtcTimestamp(row.lease_expires_at)}</span>,
      },
    ],
    [],
  );

  const workerColumns = useMemo<TableColumn<WorkerRow>[]>(
    () => [
      {
        key: "spiffe_id",
        header: "SPIFFE Identity",
        renderCell: (row) => (
          <div>
            <code style={{ fontSize: "0.8rem" }}>{row.spiffe_id}</code>
            {row.reason_note !== null ? (
              <div style={{ fontSize: "0.78rem", opacity: 0.85, marginTop: 2 }}>
                Reason: {row.reason_note}
              </div>
            ) : null}
          </div>
        ),
      },
      {
        key: "status",
        header: "Status",
        renderCell: (row) => {
          const app = workerStatusAppearance(row.status);
          return (
            <span className={`red2pr-badge-pill ${app.tone}`}>
              <StatusGlyph kind={app.glyph} />
              <span>{app.label}</span>
            </span>
          );
        },
      },
      {
        key: "isolation_mode",
        header: "Isolation & Signer",
        renderCell: (row) => (
          <div>
            <div>
              {isolationLabel(row.isolation_mode)}{" "}
              {row.host_escape_warning ? (
                <span className="red2pr-badge-pill red2pr-tone-warning">
                  <StatusGlyph kind="warn" />
                  <span>ADR-016 Risk</span>
                </span>
              ) : null}
            </div>
            <div style={{ fontSize: "0.78rem", opacity: 0.8 }}>
              Runtime: {row.runtime_name} · Signer: <code>{row.signer_key_id}</code>
            </div>
          </div>
        ),
      },
      {
        key: "profiles",
        header: "Profiles",
        renderCell: (row) => <span>{row.profiles}</span>,
      },
      {
        key: "heartbeat",
        header: "Last Heartbeat / Cert",
        renderCell: (row) => (
          <div style={{ fontSize: "0.8rem" }}>
            <div>HB: {formatUtcTimestamp(row.heartbeat_at)}</div>
            <div>
              Cert: {row.mtls_cert_expires_at ? formatUtcTimestamp(row.mtls_cert_expires_at) : "—"}
            </div>
          </div>
        ),
      },
      {
        key: "active_leases",
        header: "Leases",
        renderCell: (row) => <span>{String(row.active_leases)}</span>,
      },
      {
        key: "actions",
        header: "Actions",
        renderCell: (row) => (
          <div className="red2pr-button-row" style={{ flexWrap: "wrap", gap: 6 }}>
            <Button
              label="Self-test"
              variant="secondary"
              size="sm"
              onClick={() => openSelfTestModal(row.id)}
            />
            {row.status === "online" ? (
              <Button
                label="Drain"
                variant="secondary"
                size="sm"
                onClick={() => openActionModal(row, "drain")}
              />
            ) : null}
            {row.status === "draining" || row.status === "quarantined" ? (
              <Button
                label="Resume"
                variant="secondary"
                size="sm"
                onClick={() => openActionModal(row, "resume")}
              />
            ) : null}
            {row.status !== "quarantined" ? (
              <Button
                label="Quarantine"
                variant="secondary"
                size="sm"
                onClick={() => openActionModal(row, "quarantine")}
              />
            ) : null}
            <Button
              label="Revoke"
              variant="secondary"
              size="sm"
              onClick={() => openActionModal(row, "revoke")}
            />
          </div>
        ),
      },
    ],
    [openActionModal, openSelfTestModal],
  );

  if (readinessQuery.isPending || (isInstanceOwner && fleetQuery.isPending)) {
    return <StateView state="loading" />;
  }

  if (readinessQuery.isError) {
    const summary = extractAuthProblemSummary(readinessQuery.error, t("state.error.description"));
    return (
      <StateView
        state="error"
        description={summary.detail}
        correlationId={summary.correlationId ?? undefined}
        primaryAction={{
          label: "Retry",
          onClick: () => {
            void readinessQuery.refetch();
          },
        }}
      />
    );
  }

  const readiness = readinessQuery.data.data;
  const leaseRows = (readiness.active_workspace_leases ?? []).map(toLeaseRow);
  const fleetSummary = fleetQuery.data?.data.summary ?? null;
  const workerRows = (fleetQuery.data?.data.items ?? []).map(toWorkerRow);
  const showTrustedLocalWarning =
    Boolean(readiness.trusted_local_warning) ||
    (fleetSummary !== null && fleetSummary.trusted_local_warning_count > 0);

  const canSubmitEnroll =
    trustDomain.trim().length > 0 &&
    parsedProfiles.length > 0 &&
    (enrollMode !== "oci_trusted_local" || riskAck) &&
    !enrollMutation.isPending;

  return (
    <div className="red2pr-page-stack" data-testid="workers-page">
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 16,
          flexWrap: "wrap",
        }}
      >
        <div>
          <h1 style={{ margin: 0, fontSize: "1.5rem" }}>{t("workers.title")}</h1>
          <p style={{ margin: "4px 0 0", opacity: 0.85 }}>{t("workers.subtitle")}</p>
        </div>
        {isInstanceOwner ? (
          <Button
            label={t("workers.enrollAction")}
            variant="primary"
            data-testid="workers-enroll-open"
            onClick={() => {
              setEnrollError(null);
              setEnrollResult(null);
              setEnrollOpen(true);
            }}
          />
        ) : null}
      </div>

      {showTrustedLocalWarning ? (
        <div
          role="alert"
          className="red2pr-inline-alert red2pr-tone-warning"
          data-testid="workers-trusted-local-warning"
        >
          <StatusGlyph kind="warn" /> <strong>ADR-016 Warning:</strong>{" "}
          {t("workers.trustedLocalWarning")}
        </div>
      ) : null}

      {!readiness.ready && readiness.degraded_reason ? (
        <div
          role="status"
          className="red2pr-inline-alert red2pr-tone-warning"
          data-testid="workers-degraded-banner"
        >
          <StatusGlyph kind="warn" />{" "}
          <span>{sanitizeUntrustedText(readiness.degraded_reason).text}</span>
        </div>
      ) : null}

      <section
        aria-label="Workspace sandbox readiness summary"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
          gap: 12,
        }}
      >
        <div className="red2pr-card" data-testid="workers-readiness-card">
          <div style={{ fontSize: "0.8rem", opacity: 0.8 }}>Workspace Sandbox</div>
          <div style={{ fontWeight: 700, marginTop: 4 }}>
            <StatusGlyph kind={readiness.ready ? "check" : "warn"} />{" "}
            {readiness.ready ? "Ready" : "Degraded"} ({String(readiness.eligible_online_workers)}{" "}
            online)
          </div>
        </div>
        <div className="red2pr-card">
          <div style={{ fontSize: "0.8rem", opacity: 0.8 }}>Hypervisor / VM Isolation</div>
          <div style={{ fontWeight: 700, marginTop: 4 }}>
            <StatusGlyph kind={readiness.vm_isolation_available ? "check" : "info"} />{" "}
            {readiness.vm_isolation_available ? "VM Available" : "Rootless OCI Only"}
          </div>
        </div>
        <div className="red2pr-card">
          <div style={{ fontSize: "0.8rem", opacity: 0.8 }}>Available Runtime Profiles</div>
          <div style={{ fontWeight: 600, marginTop: 4, fontSize: "0.88rem" }}>
            {(readiness.available_profiles ?? [])
              .map((p: string) => sanitizeUntrustedText(p).text)
              .join(", ") || "None"}
          </div>
        </div>
        <div className="red2pr-card">
          <div style={{ fontSize: "0.8rem", opacity: 0.8 }}>Active Workspace Leases</div>
          <div style={{ fontWeight: 700, marginTop: 4 }}>{String(leaseRows.length)}</div>
        </div>
      </section>

      <section aria-label={t("workers.leasesTableLabel")}>
        <h2 style={{ fontSize: "1.1rem", marginBottom: 8 }}>{t("workers.leasesTableLabel")}</h2>
        {leaseRows.length === 0 ? (
          <StateView
            state="empty"
            title={t("workers.leasesEmptyTitle")}
            description={t("workers.leasesEmptyDesc")}
          />
        ) : (
          <Table
            aria-label={t("workers.leasesTableLabel")}
            columns={leaseColumns}
            data={leaseRows}
          />
        )}
      </section>

      {!isInstanceOwner ? (
        <section
          aria-label="Global worker fleet access boundary"
          className="red2pr-inline-alert red2pr-tone-info"
          data-testid="workers-owner-boundary-notice"
        >
          <StatusGlyph kind="lock" /> <span>{t("workers.ownerBoundaryNotice")}</span>
        </section>
      ) : (
        <section aria-label={t("workers.fleetTableLabel")} className="red2pr-page-stack">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "flex-end",
              gap: 12,
              flexWrap: "wrap",
            }}
          >
            <div>
              <h2 style={{ fontSize: "1.15rem", margin: 0 }}>{t("workers.fleetTableLabel")}</h2>
              {fleetSummary !== null ? (
                <div style={{ fontSize: "0.84rem", opacity: 0.85, marginTop: 4 }}>
                  Total: {String(fleetSummary.total_count)} · Online:{" "}
                  {String(fleetSummary.online_count)} · Draining:{" "}
                  {String(fleetSummary.draining_count)} · Quarantined:{" "}
                  {String(fleetSummary.quarantined_count)} · Offline:{" "}
                  {String(fleetSummary.offline_count)} · VM:{" "}
                  {String(fleetSummary.vm_isolated_count)}
                </div>
              ) : null}
            </div>

            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <label
                htmlFor={statusSelectId}
                style={{ display: "grid", gap: 4, fontSize: "0.85rem" }}
              >
                <span>Status</span>
                <select
                  id={statusSelectId}
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value as "all" | WorkerStatus)}
                >
                  {STATUS_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>
                      {opt}
                    </option>
                  ))}
                </select>
              </label>
              <label
                htmlFor={isolationSelectId}
                style={{ display: "grid", gap: 4, fontSize: "0.85rem" }}
              >
                <span>Isolation Mode</span>
                <select
                  id={isolationSelectId}
                  value={isolationFilter}
                  onChange={(e) =>
                    setIsolationFilter(e.target.value as "all" | WorkerIsolationMode)
                  }
                >
                  {ISOLATION_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>
                      {opt}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          </div>

          {fleetQuery.isError ? (
            <StateView
              state="error"
              description={
                extractAuthProblemSummary(fleetQuery.error, t("state.error.description")).detail
              }
              primaryAction={{
                label: "Retry",
                onClick: () => {
                  void fleetQuery.refetch();
                },
              }}
            />
          ) : workerRows.length === 0 ? (
            <StateView
              state="empty"
              title={t("workers.fleetEmptyTitle")}
              description={t("workers.fleetEmptyDesc")}
            />
          ) : (
            <Table
              aria-label={t("workers.fleetTableLabel")}
              columns={workerColumns}
              data={workerRows}
            />
          )}
        </section>
      )}

      {/* One-time mTLS Worker Enrollment Dialog */}
      <Dialog
        isOpen={enrollOpen}
        onOpenChange={(open) => {
          setEnrollOpen(open);
          if (!open) {
            setEnrollResult(null);
            setEnrollError(null);
          }
        }}
        purpose="form"
        title="Enroll Isolated Sandbox Worker"
        subtitle="Mint a short-lived single-use mTLS CSR bootstrap token (instance owner + 5m step-up)."
        correlationId={enrollError?.correlationId ?? undefined}
        data-testid="workers-enroll-dialog"
        footer={
          <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
            <Button
              label="Close"
              variant="secondary"
              onClick={() => {
                setEnrollOpen(false);
                setEnrollResult(null);
              }}
            />
            {enrollResult === null ? (
              <Button
                label="Mint enrollment token"
                variant="primary"
                isLoading={enrollMutation.isPending}
                isDisabled={!canSubmitEnroll}
                onClick={() => enrollMutation.mutate()}
              />
            ) : null}
          </div>
        }
      >
        <div className="red2pr-form-stack">
          {enrollError !== null ? (
            <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">
              <StatusGlyph kind="error" /> <span>{enrollError.detail}</span>
            </div>
          ) : null}

          {enrollResult !== null ? (
            <div className="red2pr-form-stack" data-testid="workers-enrolled-token-box">
              <div role="alert" className="red2pr-inline-alert red2pr-tone-warning">
                <StatusGlyph kind="warn" />{" "}
                <span>
                  Copy this enrollment token now. Only its SHA-256 digest is stored; it will never
                  be shown again.
                </span>
              </div>
              <div>
                <div style={{ fontWeight: 600, fontSize: "0.85rem" }}>
                  One-time Enrollment Token
                </div>
                <pre style={{ overflowX: "auto", padding: 8 }}>
                  <code>{enrollResult.enrollment_token}</code>
                </pre>
              </div>
              <div>
                <div style={{ fontWeight: 600, fontSize: "0.85rem" }}>Pinned Worker CA PEM</div>
                <pre style={{ overflowX: "auto", maxHeight: 140, padding: 8 }}>
                  <code>{enrollResult.ca_cert_pem}</code>
                </pre>
              </div>
            </div>
          ) : (
            <>
              <label htmlFor={trustDomainInputId} className="red2pr-field">
                <span>SPIFFE Trust Domain</span>
                <input
                  id={trustDomainInputId}
                  type="text"
                  value={trustDomain}
                  onChange={(e) => setTrustDomain(e.target.value)}
                />
              </label>
              <label htmlFor={profilesInputId} className="red2pr-field">
                <span>Reviewed Runtime Profiles (comma-separated)</span>
                <input
                  id={profilesInputId}
                  type="text"
                  value={profileCsv}
                  onChange={(e) => setProfileCsv(e.target.value)}
                />
              </label>
              <label htmlFor={enrollModeSelectId} className="red2pr-field">
                <span>Sandbox Isolation Backend</span>
                <select
                  id={enrollModeSelectId}
                  value={enrollMode}
                  onChange={(e) => {
                    const next = e.target.value as WorkerIsolationMode;
                    setEnrollMode(next);
                    if (next !== "oci_trusted_local") {
                      setRiskAck(false);
                    }
                  }}
                >
                  <option value="vm_isolated">vm_isolated (MicroVM / Firecracker / Kata)</option>
                  <option value="oci_rootless">oci_rootless (Rootless Podman / Docker)</option>
                  <option value="oci_trusted_local">
                    oci_trusted_local (Single-host Trusted Local Docker — ADR-016)
                  </option>
                </select>
              </label>
              <label htmlFor={ttlInputId} className="red2pr-field">
                <span>Token TTL (minutes, 5–120)</span>
                <input
                  id={ttlInputId}
                  type="number"
                  min={5}
                  max={120}
                  value={ttlMinutes}
                  onChange={(e) => setTtlMinutes(Number(e.target.value) || 15)}
                />
              </label>
              {enrollMode === "oci_trusted_local" ? (
                <label
                  htmlFor={ackRiskCheckId}
                  className="red2pr-inline-alert red2pr-tone-warning"
                  style={{ display: "flex", gap: 8, alignItems: "flex-start" }}
                >
                  <input
                    id={ackRiskCheckId}
                    type="checkbox"
                    checked={riskAck}
                    onChange={(e) => setRiskAck(e.target.checked)}
                  />
                  <span>
                    I acknowledge the ADR-016 shared-kernel escape risk and confirm this worker
                    runs only trusted single-workspace workloads.
                  </span>
                </label>
              ) : null}
            </>
          )}
        </div>
      </Dialog>

      {/* Worker Drain / Quarantine / Revoke / Resume Confirmation Dialog */}
      <Dialog
        isOpen={pendingAction !== null}
        onOpenChange={(open) => {
          if (!open) {
            setPendingAction(null);
            setActionError(null);
            setStaleConflict(false);
          }
        }}
        purpose="form"
        title={pendingAction ? `Confirm worker ${pendingAction.action}` : "Confirm worker action"}
        subtitle={
          pendingAction
            ? `Target: ${pendingAction.worker.spiffe_id} (v${String(pendingAction.worker.version)})`
            : undefined
        }
        correlationId={actionError?.correlationId ?? undefined}
        data-testid="workers-action-dialog"
        footer={
          <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
            <Button label="Cancel" variant="secondary" onClick={() => setPendingAction(null)} />
            {staleConflict ? (
              <Button
                label="Reload fleet"
                variant="primary"
                onClick={() => {
                  setPendingAction(null);
                  setStaleConflict(false);
                  void refreshAll();
                }}
              />
            ) : (
              <Button
                label={pendingAction ? `Confirm ${pendingAction.action}` : "Confirm"}
                variant="primary"
                isLoading={actionMutation.isPending}
                isDisabled={actionReason.trim().length < 3 || pendingAction === null}
                onClick={() => {
                  if (pendingAction !== null) {
                    actionMutation.mutate({
                      worker: pendingAction.worker,
                      action: pendingAction.action,
                      idempotencyKey: pendingAction.idempotencyKey,
                      reason: actionReason,
                    });
                  }
                }}
              />
            )}
          </div>
        }
      >
        <div className="red2pr-form-stack">
          {staleConflict ? (
            <div
              role="alert"
              className="red2pr-inline-alert red2pr-tone-warning"
              data-testid="workers-stale-conflict-banner"
            >
              <StatusGlyph kind="warn" /> <span>{t("workers.staleConflictBanner")}</span>
            </div>
          ) : null}
          {actionError !== null ? (
            <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">
              <StatusGlyph kind="error" /> <span>{actionError.detail}</span>
            </div>
          ) : null}
          <label htmlFor={actionReasonInputId} className="red2pr-field">
            <span>Audit Reason</span>
            <input
              id={actionReasonInputId}
              type="text"
              placeholder="Explain why this worker state change is required..."
              value={actionReason}
              onChange={(e) => setActionReason(e.target.value)}
            />
          </label>
        </div>
      </Dialog>

      {/* Worker Isolation Self-Test Dialog */}
      <Dialog
        isOpen={selfTestOpen}
        onOpenChange={setSelfTestOpen}
        title="Worker Isolation & mTLS Self-Test"
        subtitle="Control-plane verification of X.509 mTLS identity, external Ed25519 signer, and confinement posture."
        data-testid="workers-selftest-dialog"
        footer={
          <div className="red2pr-button-row" style={{ justifyContent: "flex-end" }}>
            <Button label="Close" variant="secondary" onClick={() => setSelfTestOpen(false)} />
          </div>
        }
      >
        {selfTestMutation.isPending ? (
          <StateView state="loading" />
        ) : selfTestError !== null ? (
          <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">
            <StatusGlyph kind="error" /> <span>{selfTestError.detail}</span>
          </div>
        ) : selfTestResult !== null ? (
          <div className="red2pr-form-stack">
            <div
              className={`red2pr-inline-alert ${
                selfTestResult.passed ? "red2pr-tone-success" : "red2pr-tone-danger"
              }`}
            >
              <StatusGlyph kind={selfTestResult.passed ? "check" : "error"} />{" "}
              <strong>
                {selfTestResult.passed ? "All Self-Test Checks Passed" : "Self-Test Failed"}
              </strong>
              <div>{sanitizeUntrustedText(selfTestResult.detail).text}</div>
            </div>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {(selfTestResult.checks ?? []).map((chk) => (
                <li key={chk.check_id} style={{ marginBottom: 6 }}>
                  <StatusGlyph kind={chk.passed ? "check" : "error"} />{" "}
                  <strong>{sanitizeUntrustedText(chk.check_id).text}:</strong>{" "}
                  {chk.detail ? sanitizeUntrustedText(chk.detail).text : "OK"}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </Dialog>

      <StepUpDialog
        isOpen={stepUpOpen}
        mfaEnabled={Boolean(me.mfa_enabled)}
        onOpenChange={(open) => {
          setStepUpOpen(open);
          if (!open) {
            retryAfterStepUpRef.current = null;
          }
        }}
        onVerified={() => {
          const pendingKind = retryAfterStepUpRef.current;
          retryAfterStepUpRef.current = null;
          if (pendingKind === "enroll") {
            enrollMutation.mutate();
          } else if (pendingKind === "action" && pendingAction !== null) {
            actionMutation.mutate({
              worker: pendingAction.worker,
              action: pendingAction.action,
              idempotencyKey: pendingAction.idempotencyKey,
              reason: actionReason,
            });
          }
        }}
      />
    </div>
  );
}
