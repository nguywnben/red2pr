import type { MeResponse, Workspace } from "@red2pr/ts-client";
import { useQuery } from "@tanstack/react-query";
import React, { useMemo } from "react";
import { Link } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { StateView } from "../../shared/ui";
import { AnalyticsFunnel, AnalyticsSummary } from "../analytics/analyticsShared";

export interface OverviewPageProps { readonly workspace: Workspace; readonly me: MeResponse; }

function defaultRange(): { range_start: string; range_end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
  return { range_start: start.toISOString(), range_end: end.toISOString() };
}

export function OverviewPage({ workspace }: OverviewPageProps): React.JSX.Element {
  const api = useRed2PrApi();
  const ws = workspace.slug ?? workspace.id;
  const range = useMemo(() => defaultRange(), []);
  const query = useQuery({
    queryKey: ["workspace", ws, "analytics", range],
    queryFn: ({ signal }) => api.getWorkspaceAnalytics(ws, range, { signal }),
    retry: false,
  });
  return (
    <main className="red2pr-page-stack" data-testid="overview-page">
      <header><h1>Workspace overview</h1><p>Repair outcomes and spend across repositories currently visible to you.</p><Link to={`/w/${encodeURIComponent(ws)}/analytics`}>Open analytics and exports</Link></header>
      {query.isPending ? <StateView state="loading" title="Loading overview" /> : null}
      {query.isError ? <StateView state="error" title="Overview unavailable" description="Analytics could not be loaded. Your workspace data remains protected." primaryAction={{ label: "Retry", onClick: () => { void query.refetch(); } }} /> : null}
      {query.data ? <><p>Showing {query.data.data.repository_count} currently authorized repositories from {query.data.data.range_start} to {query.data.data.range_end}.</p><AnalyticsFunnel data={query.data.data} /><AnalyticsSummary data={query.data.data} /></> : null}
    </main>
  );
}
