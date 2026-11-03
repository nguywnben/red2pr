import type { WorkspaceAnalyticsResponse } from "@red2pr/ts-client";
import React from "react";
import { Table, Text, proportional, type TableColumn } from "../../shared/ui";
import "./analytics.css";

interface FunnelRow extends Record<string, unknown> {
  key: string;
  stage: string;
  count: number;
  numerator: number | "—";
  denominator: number | "—";
}

interface CostRow extends Record<string, unknown> {
  currency: string;
  settled: string;
  estimated: string;
  total: string;
  unknownRows: number;
  usageRows: number;
}

export function isWorkspaceAnalyticsResponse(value: unknown): value is WorkspaceAnalyticsResponse {
  const isRecord = (candidate: unknown): candidate is Record<string, unknown> =>
    typeof candidate === "object" && candidate !== null;
  if (!isRecord(value)) return false;
  const data = value;
  const isCount = (candidate: unknown): candidate is number =>
    typeof candidate === "number" && Number.isFinite(candidate);
  return (
    typeof data.workspace_id === "string" &&
    typeof data.range_start === "string" &&
    typeof data.range_end === "string" &&
    typeof data.watermark === "string" &&
    ["repository_count", "local_success_count", "remote_success_count", "unknown_count", "pending_count", "abstained_count"]
      .every((key) => isCount(data[key])) &&
    Array.isArray(data.funnel) &&
    data.funnel.every((stage) => isRecord(stage) && typeof stage.key === "string" && isCount(stage.value)) &&
    Array.isArray(data.costs) &&
    data.costs.every((cost) => isRecord(cost) &&
      typeof cost.currency === "string" &&
      typeof cost.settled === "string" &&
      typeof cost.estimated_unsettled === "string" &&
      typeof cost.total === "string" &&
      isCount(cost.unknown_rows) && isCount(cost.usage_rows)
    )
  );
}

export function AnalyticsFunnel({ data }: { readonly data: WorkspaceAnalyticsResponse }): React.JSX.Element {
  const rows: FunnelRow[] = data.funnel.map((stage) => ({
    key: stage.key,
    stage: stage.key.replaceAll("_", " "),
    count: stage.value,
    numerator: stage.numerator ?? "—",
    denominator: stage.denominator ?? "—",
  }));
  const columns: TableColumn<FunnelRow>[] = [
    { key: "stage", header: "Stage", width: proportional(2, { minWidth: 160 }) },
    { key: "count", header: "Count", width: proportional(1, { minWidth: 80 }) },
    { key: "numerator", header: "Numerator", width: proportional(1, { minWidth: 80 }) },
    { key: "denominator", header: "Denominator", width: proportional(1, { minWidth: 80 }) },
  ];

  return (
    <section className="red2pr-surface red2pr-card-section analytics-funnel-section" aria-labelledby="repair-funnel-title">
      <h2 id="repair-funnel-title">Repair funnel</h2>
      <ol aria-label="Repair funnel chart" className="analytics-funnel-bars">
        {data.funnel.map((stage) => (
          <li key={stage.key}>
            <span className="analytics-funnel-stage-label">{stage.key.replaceAll("_", " ")}</span>
            <span className="analytics-funnel-track">
              <span
                className="analytics-funnel-bar"
                style={{
                  width: `${
                    stage.value > 0 && data.funnel[0]?.value
                      ? Math.min(100, Math.max(4, (stage.value / data.funnel[0].value) * 100))
                      : 0
                  }%`,
                }}
              />
            </span>
            <strong>{stage.value}</strong>
          </li>
        ))}
      </ol>
      <Table
        aria-label="Repair funnel values and denominators"
        data={rows}
        columns={columns}
        idKey="key"
        density="compact"
        dividers="rows"
        textOverflow="wrap"
      />
      <Text type="supporting" className="analytics-table-scroll-note">
        Scroll horizontally to view all funnel columns.
      </Text>
    </section>
  );
}

export function AnalyticsSummary({ data }: { readonly data: WorkspaceAnalyticsResponse }): React.JSX.Element {
  const rows: CostRow[] = data.costs.map((cost) => ({
    currency: cost.currency,
    settled: cost.settled,
    estimated: cost.estimated_unsettled,
    total: cost.total,
    unknownRows: cost.unknown_rows,
    usageRows: cost.usage_rows,
  }));
  const columns: TableColumn<CostRow>[] = [
    { key: "currency", header: "Currency", width: proportional(1, { minWidth: 72 }) },
    { key: "settled", header: "Settled", width: proportional(1, { minWidth: 72 }) },
    { key: "estimated", header: "Estimated unsettled", width: proportional(1.8, { minWidth: 130 }) },
    { key: "total", header: "Total", width: proportional(1, { minWidth: 72 }) },
    { key: "unknownRows", header: "Unknown billing rows", width: proportional(1.8, { minWidth: 130 }) },
    { key: "usageRows", header: "Usage rows", width: proportional(1, { minWidth: 72 }) },
  ];

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
      {rows.length === 0 ? <p>No usage ledger entries in this range.</p> : (
        <>
          <Table
            aria-label="Cost ledger by currency"
            data={rows}
            columns={columns}
            idKey="currency"
            density="compact"
            dividers="rows"
            textOverflow="wrap"
          />
          <Text type="supporting" className="analytics-table-scroll-note">
            Scroll horizontally to view all ledger columns.
          </Text>
        </>
      )}
      <p className="red2pr-field-hint" style={{ margin: 0 }}>Projection watermark: <time dateTime={data.watermark}>{data.watermark}</time></p>
    </section>
  );
}
