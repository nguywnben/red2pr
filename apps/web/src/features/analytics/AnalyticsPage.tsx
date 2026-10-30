import type { MeResponse, ReportExportRequest, Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery } from "@tanstack/react-query";
import React, { useId, useMemo, useState } from "react";
import { useRed2PrApi } from "../../shared/api";
import { Button, StateView } from "../../shared/ui";
import { generateClientUuidV7 } from "../queues/QueuesPage";
import { AnalyticsFunnel, AnalyticsSummary } from "./analyticsShared";

export interface AnalyticsPageProps { readonly workspace: Workspace; readonly me: MeResponse; }
function dayValue(date: Date): string { return date.toISOString().slice(0, 10); }

export function AnalyticsPage({ workspace }: AnalyticsPageProps): React.JSX.Element {
  const api = useRed2PrApi();
  const ws = workspace.slug ?? workspace.id;
  const ids = { from: useId(), to: useId(), kind: useId(), format: useId() };
  const [rangeStart, setRangeStart] = useState(() => dayValue(new Date(Date.now() - 30 * 86400000)));
  const [rangeEnd, setRangeEnd] = useState(() => dayValue(new Date()));
  const [kind, setKind] = useState<ReportExportRequest["kind"]>("funnel");
  const [format, setFormat] = useState<ReportExportRequest["format"]>("csv");
  const [exportLink, setExportLink] = useState<{ href: string; filename: string } | null>(null);
  const queryRange = useMemo(() => ({ range_start: `${rangeStart}T00:00:00Z`, range_end: `${rangeEnd}T23:59:59Z` }), [rangeStart, rangeEnd]);
  const query = useQuery({ queryKey: ["workspace", ws, "analytics", queryRange], queryFn: ({ signal }) => api.getWorkspaceAnalytics(ws, queryRange, { signal }), enabled: rangeEnd >= rangeStart, retry: false });
  const exportMutation = useMutation({
    mutationFn: async () => {
      const body: ReportExportRequest = { kind, format, range_start: queryRange.range_start, range_end: queryRange.range_end, filters: {} };
      const created = await api.createWorkspaceReportExport(ws, body, { idempotencyKey: generateClientUuidV7() });
      const downloaded = await api.downloadWorkspaceReportExport(ws, created.data.export_id);
      return { href: URL.createObjectURL(downloaded.blob), filename: downloaded.filename ?? `red2pr-${kind}.${format}` };
    },
    onSuccess: (link) => setExportLink(link),
    onError: () => setExportLink(null),
  });
  return (
    <main className="red2pr-page-stack" data-testid="analytics-page">
      <header><h1>Analytics and cost ledger</h1><p>Bounded repair funnel, explicit denominators, unknown outcomes and exact currency totals.</p></header>
      <form className="red2pr-form-stack" onSubmit={(event) => { event.preventDefault(); void query.refetch(); }}>
        <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={ids.from}>From date (UTC)</label><input id={ids.from} className="red2pr-control-input" type="date" value={rangeStart} onChange={(event) => setRangeStart(event.target.value)} /></div>
        <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={ids.to}>To date (UTC)</label><input id={ids.to} className="red2pr-control-input" type="date" value={rangeEnd} onChange={(event) => setRangeEnd(event.target.value)} /></div>
        <Button label="Apply range (maximum 366 days)" variant="secondary" type="submit" isDisabled={rangeEnd < rangeStart} />
      </form>
      {rangeEnd < rangeStart ? <p role="alert">The end date must be on or after the start date.</p> : null}
      {query.isPending ? <StateView state="loading" title="Loading analytics" /> : null}
      {query.isError ? <StateView state="error" title="Analytics unavailable" description="The scoped analytics request failed." primaryAction={{ label: "Retry", onClick: () => { void query.refetch(); } }} /> : null}
      {query.data ? <><AnalyticsFunnel data={query.data.data} /><AnalyticsSummary data={query.data.data} /></> : null}
      <section className="red2pr-surface red2pr-card-section" aria-labelledby="report-export-title">
        <h2 id="report-export-title">Safe report export</h2>
        <p>Exports expire after 24 hours, are encrypted at rest, and use the repository access you have now. Proof reports contain artifact digests, never raw CI logs.</p>
        <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={ids.kind}>Report type</label><select id={ids.kind} className="red2pr-control-input" value={kind} onChange={(event) => setKind(event.target.value as ReportExportRequest["kind"])}><option value="funnel">Repair funnel</option><option value="usage">Usage ledger</option><option value="proof_summary">Proof report</option></select></div>
        <div className="red2pr-field"><label className="red2pr-field-label" htmlFor={ids.format}>Format</label><select id={ids.format} className="red2pr-control-input" value={format} onChange={(event) => setFormat(event.target.value as ReportExportRequest["format"])}><option value="csv">CSV</option><option value="json">JSON</option></select></div>
        <Button label="Create and download export" variant="primary" type="button" isDisabled={exportMutation.isPending || rangeEnd < rangeStart} isLoading={exportMutation.isPending} onClick={() => exportMutation.mutate()} />
        {exportMutation.isError ? <p role="alert">Export could not be created or downloaded with your current access.</p> : null}
        {exportLink ? <p role="status"><a href={exportLink.href} download={exportLink.filename}>Download {exportLink.filename}</a></p> : null}
      </section>
    </main>
  );
}
