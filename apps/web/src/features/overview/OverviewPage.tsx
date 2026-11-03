import type { MeResponse, Workspace } from "@red2pr/ts-client";
import { useQuery } from "@tanstack/react-query";
import React, { useMemo } from "react";
import { Link } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import { StateView } from "../../shared/ui";
import { AnalyticsFunnel, AnalyticsSummary, isWorkspaceAnalyticsResponse } from "../analytics/analyticsShared";

export interface OverviewPageProps { readonly workspace: Workspace; readonly me: MeResponse; }

function defaultRange(): { range_start: string; range_end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
  return { range_start: start.toISOString(), range_end: end.toISOString() };
}

export function OverviewPage({ workspace }: OverviewPageProps): React.JSX.Element {
  const api = useRed2PrApi();
  const { formatDisplayTimestamp } = useI18n();
  const ws = workspace.slug ?? workspace.id;
  const range = useMemo(() => defaultRange(), []);
  const query = useQuery({
    queryKey: ["workspace", ws, "analytics", range],
    queryFn: ({ signal }) => api.getWorkspaceAnalytics(ws, range, { signal }),
    retry: false,
  });
  const analytics = query.data?.data;
  const hasValidAnalytics = isWorkspaceAnalyticsResponse(analytics);
  return (
    <section className="red2pr-page-stack" data-testid="overview-page">
      <header><h1>Workspace overview</h1><p>Repair outcomes and spend across repositories currently visible to you.</p><Link to={`/w/${encodeURIComponent(ws)}/analytics`}>Open analytics and exports</Link></header>
      {query.isPending ? <StateView state="loading" skeletonVariant="metrics" /> : null}
      {query.isError ? <StateView state="error" title="Overview unavailable" description="Analytics could not be loaded. Your workspace data remains protected." primaryAction={{ label: "Retry", onClick: () => { void query.refetch(); } }} /> : null}
      {query.data && !hasValidAnalytics ? <StateView state="error" title="Overview data unavailable" description="The analytics response was incomplete, so it could not be displayed safely." primaryAction={{ label: "Reload data", onClick: () => { void query.refetch(); } }} /> : null}
      {hasValidAnalytics ? <>
        <p>
          Showing {analytics.repository_count} currently authorized repositories from{" "}
          <time dateTime={analytics.range_start}>{formatDisplayTimestamp(analytics.range_start).localText}</time>{" "}
          to <time dateTime={analytics.range_end}>{formatDisplayTimestamp(analytics.range_end).localText}</time> local time.
          <small className="red2pr-projection-watermark">Projection updated {formatDisplayTimestamp(analytics.watermark).localText}.</small>
        </p>
        <AnalyticsFunnel data={analytics} />
        <AnalyticsSummary data={analytics} />
      </> : null}
    </section>
  );
}
