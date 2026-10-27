import { Card } from "@astryxdesign/core/Card";
import React, { useMemo, useState } from "react";
import { useI18n } from "../i18n";
import { Button } from "./Button";
import { Table, type TableColumn } from "./Table";

export interface ChartDatum {
  readonly id: string;
  readonly label: string;
  readonly value: number;
}

export interface ChartWithTableFallbackProps {
  readonly title: string;
  readonly subtitle?: string;
  readonly series: readonly ChartDatum[];
  readonly denominator: number;
  readonly denominatorUnit: string;
  readonly windowStartUtc: string;
  readonly windowEndUtc: string;
  readonly defaultView?: "chart" | "table";
}

interface ChartTableRow extends Record<string, unknown> {
  id: string;
  label: string;
  value: number;
  shareText: string;
}

function formatShare(value: number, denominator: number): string {
  if (denominator <= 0) {
    return "0.0%";
  }
  const pct = Math.max(0, Math.min(100, (value / denominator) * 100));
  return `${pct.toFixed(1)}%`;
}

export function ChartWithTableFallback({
  title,
  subtitle,
  series,
  denominator,
  denominatorUnit,
  windowStartUtc,
  windowEndUtc,
  defaultView = "chart",
}: ChartWithTableFallbackProps): React.JSX.Element {
  const { t, formatUtcExportTimestamp } = useI18n();
  const [view, setView] = useState<"chart" | "table">(defaultView);

  const startUtcLabel = formatUtcExportTimestamp(windowStartUtc);
  const endUtcLabel = formatUtcExportTimestamp(windowEndUtc);

  const tableRows = useMemo<ChartTableRow[]>(
    () =>
      series.map((datum) => ({
        id: datum.id,
        label: datum.label,
        value: datum.value,
        shareText: formatShare(datum.value, denominator),
      })),
    [denominator, series],
  );

  const columns = useMemo<TableColumn<ChartTableRow>[]>(
    () => [
      { key: "label", header: t("chart.colStage") },
      { key: "value", header: t("chart.colValue"), align: "end" },
      { key: "shareText", header: t("chart.colShare"), align: "end" },
    ],
    [t],
  );

  return (
    <Card>
      <section aria-label={title} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 8,
          }}
        >
          <div>
            <h3 style={{ margin: 0 }}>{title}</h3>
            {subtitle ? <p style={{ margin: "4px 0 0 0" }}>{subtitle}</p> : null}
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: 8,
                marginTop: 6,
                fontSize: "0.8125rem",
              }}
            >
              <span className="red2pr-badge-pill red2pr-tone-neutral">
                {t("chart.denominator", { denominator, unit: denominatorUnit })}
              </span>
              <span className="red2pr-badge-pill red2pr-tone-neutral">
                {t("chart.dateRange", { startUtc: startUtcLabel, endUtc: endUtcLabel })}
              </span>
            </div>
          </div>

          <div role="group" aria-label={title} style={{ display: "flex", gap: 6 }}>
            <Button
              size="sm"
              variant={view === "chart" ? "primary" : "secondary"}
              aria-pressed={view === "chart"}
              label={t("chart.viewChart")}
              onClick={() => setView("chart")}
            />
            <Button
              size="sm"
              variant={view === "table" ? "primary" : "secondary"}
              aria-pressed={view === "table"}
              label={t("chart.viewTable")}
              onClick={() => setView("table")}
            />
          </div>
        </div>

        {view === "chart" ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {series.map((datum) => {
              const ratio =
                denominator > 0 ? Math.max(0, Math.min(1, datum.value / denominator)) : 0;
              const shareText = formatShare(datum.value, denominator);
              return (
                <div
                  key={datum.id}
                  style={{ display: "flex", flexDirection: "column", gap: 4 }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      fontSize: "0.875rem",
                    }}
                  >
                    <span>{datum.label}</span>
                    <strong>
                      {datum.value} ({shareText})
                    </strong>
                  </div>
                  <svg
                    width="100%"
                    height="12"
                    viewBox="0 0 100 6"
                    preserveAspectRatio="none"
                    role="img"
                    aria-label={`${datum.label}: ${datum.value} (${shareText})`}
                  >
                    <rect
                      x="0"
                      y="0"
                      width="100"
                      height="6"
                      rx="2"
                      fill="var(--red2pr-chart-bar-track)"
                    />
                    <rect
                      x="0"
                      y="0"
                      width={String(Math.round(ratio * 1000) / 10)}
                      height="6"
                      rx="2"
                      fill="var(--red2pr-chart-bar-primary)"
                    />
                  </svg>
                </div>
              );
            })}
          </div>
        ) : (
          <Table<ChartTableRow>
            aria-label={title}
            data={tableRows}
            columns={columns}
            idKey="id"
            density="compact"
          />
        )}
      </section>
    </Card>
  );
}
