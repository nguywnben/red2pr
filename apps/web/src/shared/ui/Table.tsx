import {
  EmptyState as AstryxEmptyState,
} from "@astryxdesign/core/EmptyState";
import {
  Table as AstryxTable,
  paginateData,
  pixel,
  proportional,
  useTablePagination,
  useTableSortable,
  type TableColumn,
  type TableDensity,
  type TableDividers,
  type TablePlugin,
  type TableProps as AstryxTableProps,
  type TableSortDirection,
  type TableSortEntry,
  type TableSortState,
} from "@astryxdesign/core/Table";
import React, { useMemo } from "react";
import { useI18n } from "../i18n";

export {
  paginateData,
  pixel,
  proportional,
  useTablePagination,
  useTableSortable,
  type TableColumn,
  type TableDensity,
  type TableDividers,
  type TablePlugin,
  type TableSortDirection,
  type TableSortEntry,
  type TableSortState,
};

export interface Red2PrTablePaginationConfig {
  readonly page: number;
  readonly pageSize: number;
  readonly totalItems?: number;
  readonly totalPages?: number;
  readonly hasMore?: boolean;
  readonly pageSizeOptions?: number[];
  readonly onPageChange: (page: number) => void;
  readonly onPageSizeChange?: (pageSize: number) => void;
  /** When true, slices `data` client-side using Astryx `paginateData`. */
  readonly sliceClientData?: boolean;
}

export interface Red2PrTableProps<T extends Record<string, unknown>>
  extends Omit<AstryxTableProps<T>, "xstyle" | "emptyState"> {
  readonly sort?: TableSortState;
  readonly onSortChange?: (next: TableSortState) => void;
  readonly pagination?: Red2PrTablePaginationConfig;
  readonly emptyTitle?: string;
  readonly emptyDescription?: string;
}

function compareValues(left: unknown, right: unknown): number {
  if (left === right) {
    return 0;
  }
  if (left === null || left === undefined) {
    return 1;
  }
  if (right === null || right === undefined) {
    return -1;
  }
  if (typeof left === "number" && typeof right === "number") {
    return left - right;
  }
  return String(left).localeCompare(String(right));
}

export function Table<T extends Record<string, unknown>>({
  data = [],
  columns,
  plugins,
  sort,
  onSortChange,
  pagination,
  emptyTitle,
  emptyDescription,
  rowIndexStart,
  rowCount,
  ...rest
}: Red2PrTableProps<T>): React.JSX.Element {
  const { t } = useI18n();

  const effectiveSort = sort ?? [];
  const noopSortChange = useMemo(() => (_next: TableSortState) => undefined, []);
  const sortablePlugin = useTableSortable<T>({
    sort: effectiveSort,
    onSortChange: onSortChange ?? noopSortChange,
  });

  const paginationPlugin = useTablePagination<T>({
    page: pagination?.page ?? 1,
    pageSize: pagination?.pageSize ?? 20,
    totalItems: pagination?.totalItems ?? data.length,
    totalPages: pagination?.totalPages,
    hasMore: pagination?.hasMore,
    pageSizeOptions: pagination?.pageSizeOptions,
    onPageChange: pagination?.onPageChange ?? (() => undefined),
    onPageSizeChange: pagination?.onPageSizeChange,
    label: t("table.paginationLabel"),
  });

  const sortedData = useMemo(() => {
    if (!sort || sort.length === 0) {
      return data;
    }
    const copy = [...data];
    copy.sort((a, b) => {
      for (const entry of sort) {
        const cmp = compareValues(a[entry.sortKey], b[entry.sortKey]);
        if (cmp !== 0) {
          return entry.direction === "ascending" ? cmp : -cmp;
        }
      }
      return 0;
    });
    return copy;
  }, [data, sort]);

  const visibleData = useMemo(() => {
    if (!pagination?.sliceClientData) {
      return sortedData;
    }
    return paginateData(sortedData, pagination.page, pagination.pageSize);
  }, [pagination, sortedData]);

  const mergedPlugins = useMemo<Record<string, TablePlugin<T>>>(() => {
    const record: Record<string, TablePlugin<T>> = {};
    if (onSortChange !== undefined || (sort !== undefined && sort.length > 0)) {
      record.sort = sortablePlugin;
    }
    if (pagination !== undefined) {
      record.pagination = paginationPlugin;
    }
    if (plugins !== undefined) {
      Object.assign(record, plugins);
    }
    return record;
  }, [onSortChange, pagination, paginationPlugin, plugins, sort, sortablePlugin]);

  const computedRowIndexStart =
    rowIndexStart ??
    (pagination !== undefined ? (pagination.page - 1) * pagination.pageSize + 1 : undefined);
  const computedRowCount = rowCount ?? pagination?.totalItems;

  return (
    <AstryxTable<T>
      {...rest}
      data={visibleData}
      columns={columns}
      plugins={mergedPlugins}
      rowIndexStart={computedRowIndexStart}
      rowCount={computedRowCount}
      emptyState={
        <AstryxEmptyState
          isCompact
          title={emptyTitle ?? t("table.emptyTitle")}
          description={emptyDescription ?? t("table.emptyDescription")}
        />
      }
    />
  );
}
