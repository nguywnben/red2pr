import type { WorkspaceAnalyticsResponse } from "@red2pr/ts-client";
import React from "react";
import "./analytics.css";

export function AnalyticsFunnel({ data }: { readonly data: WorkspaceAnalyticsResponse }): React.JSX.Element {
  return (
    <section className="red2pr-surface red2pr-card-section" aria-labelledby="repair-funnel-title">
      <h2 id="repair-funnel-title">Repair funnel</h2>
      <ol aria-label="Repair funnel chart" className="analytics-funnel-bars">
        {data.funnel.map((stage) => (
          <li key={stage.key}>
            <span>{stage.key.replaceAll("_", " ")}</span>
            <span className="analytics-funnel-bar" style={{ width: `${data.funnel[0]?.value ? Math.max(2, (stage.value / data.funnel[0].value) * 100) : 0}%` }} />
            <strong>{stage.value}</strong>
          </li>
        ))}
      </ol>
      <table className="red2pr-table" aria-label="Repair funnel values and denominators">
        <thead><tr><th scope="col">Stage</th><th scope="col">Count</th><th scope="col">Numerator</th><th scope="col">Denominator</th></tr></thead>
        <tbody>{data.funnel.map((stage) => <tr key={stage.key}><th scope="row">{stage.key.replaceAll("_", " ")}</th><td>{stage.value}</td><td>{stage.numerator ?? "—"}</td><td>{stage.denominator ?? "—"}</td></tr>)}</tbody>
      </table>
    </section>
  );
}

export function AnalyticsSummary({ data }: { readonly data: WorkspaceAnalyticsResponse }): React.JSX.Element {
  return (
    <section className="red2pr-surface red2pr-card-section" aria-labelledby="analytics-cost-title">
      <h2 id="analytics-cost-title">Cost ledger and outcomes</h2>
      <dl className="analytics-summary-grid">
        <div><dt>Local success</dt><dd>{data.local_success_count}</dd></div>
        <div><dt>Remote success</dt><dd>{data.remote_success_count}</dd></div>
        <div><dt>Unknown outcomes</dt><dd>{data.unknown_count}</dd></div>
        <div><dt>Pending outcomes</dt><dd>{data.pending_count}</dd></div>
        <div><dt>Abstained outcomes</dt><dd>{data.abstained_count}</dd></div>
      </dl>
      {data.costs.length === 0 ? <p>No usage ledger entries in this range.</p> : (
        <table className="red2pr-table" aria-label="Cost ledger by currency">
          <thead><tr><th scope="col">Currency</th><th scope="col">Settled</th><th scope="col">Estimated unsettled</th><th scope="col">Total</th><th scope="col">Unknown billing rows</th><th scope="col">Usage rows</th></tr></thead>
          <tbody>{data.costs.map((cost) => <tr key={cost.currency}><th scope="row">{cost.currency}</th><td>{cost.settled}</td><td>{cost.estimated_unsettled}</td><td>{cost.total}</td><td>{cost.unknown_rows}</td><td>{cost.usage_rows}</td></tr>)}</tbody>
        </table>
      )}
      <p>Projection watermark: <time dateTime={data.watermark}>{data.watermark}</time></p>
    </section>
  );
}
