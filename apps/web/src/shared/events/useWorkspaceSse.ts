import type { EventEnvelope } from "@red2pr/ts-client";
import { useEffect, useRef, useState } from "react";
import * as z from "zod/v4-mini";
import type { SseConnectionStatus } from "../ui/AppShell";

const S19_EVENT_TYPES = [
  "provider.connection.created",
  "provider.run.failed",
  "provider.run.retried",
  "repair.session.created",
  "repair.diagnosed",
  "repair.reproduction.completed",
  "repair.patch.proposed",
  "repair.verification.completed",
  "repair.approval.requested",
  "repair.approval.decided",
  "repair.publication.created",
  "repair.remote_ci.completed",
  "repair.blocked",
  "repair.cancelled",
  "worker.offline",
  "worker.quarantined",
  "integration.disconnected",
  "usage.budget.exceeded",
  "security.policy.denied",
  "backup.failed",
  "release.update_available",
  "identity.permission_revoked",
  "notification.delivery.failed",
  "operations.restore.completed",
] as const;

export const EventEnvelopeRuntimeSchema = z.object({
  schema_version: z._default(z.literal(1), 1),
  event_id: z.string().check(z.minLength(1)),
  type: z.enum(S19_EVENT_TYPES),
  occurred_at: z.string().check(z.minLength(1)),
  workspace_id: z._default(z.nullable(z.string()), null),
  repository_id: z._default(z.nullable(z.string()), null),
  session_id: z._default(z.nullable(z.string()), null),
  aggregate_id: z.string().check(z.minLength(1)),
  aggregate_version: z.int().check(z.minimum(1)),
  correlation_id: z.string().check(z.minLength(1), z.maxLength(120)),
  causation_id: z._default(z.nullable(z.string()), null),
  payload: z.record(z.string(), z.unknown()),
});

export type SnapshotRefreshReason =
  | "cursor_expired_410"
  | "heartbeat_timeout"
  | "version_gap"
  | "reconnect";

export interface SnapshotRefreshContext {
  readonly reason: SnapshotRefreshReason;
  readonly workspaceSlug: string;
  readonly aggregateId?: string;
  readonly expectedVersion?: number;
  readonly receivedVersion?: number;
}

export interface SnapshotRefreshResult {
  readonly cursor?: string | null;
}

export interface UseWorkspaceSseOptions {
  readonly workspaceSlug: string | null | undefined;
  readonly expectedWorkspaceId?: string | null;
  readonly baseUrl?: string;
  readonly initialCursor?: string | null;
  readonly heartbeatTimeoutMs?: number;
  readonly reconnectBaseDelayMs?: number;
  readonly maxReconnectDelayMs?: number;
  readonly enabled?: boolean;
  readonly fetchImpl?: typeof fetch;
  readonly onEvent?: (envelope: EventEnvelope) => void;
  readonly onSnapshotRefresh?: (
    context: SnapshotRefreshContext,
  ) => Promise<SnapshotRefreshResult | void>;
}

export interface UseWorkspaceSseResult {
  readonly state: SseConnectionStatus;
  readonly lastEventId: string | null;
  readonly reconnectCount: number;
}

interface ParsedSseFrame {
  readonly isCommentOnly: boolean;
  readonly id: string | null;
  readonly event: string | null;
  readonly data: string | null;
}

export function parseSseFrameBlock(rawBlock: string): ParsedSseFrame | null {
  if (rawBlock.length === 0) {
    return null;
  }
  const lines = rawBlock.split("\n");
  let id: string | null = null;
  let event: string | null = null;
  const dataLines: string[] = [];
  let sawComment = false;

  for (const line of lines) {
    if (line.length === 0) {
      continue;
    }
    if (line.startsWith(":")) {
      sawComment = true;
      continue;
    }
    const colonIdx = line.indexOf(":");
    const field = colonIdx === -1 ? line : line.slice(0, colonIdx);
    let value = colonIdx === -1 ? "" : line.slice(colonIdx + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }
    if (field === "id" && !value.includes("\u0000")) {
      id = value;
    } else if (field === "event") {
      event = value;
    } else if (field === "data") {
      dataLines.push(value);
    }
  }

  if (dataLines.length === 0 && id === null && event === null) {
    return sawComment ? { isCommentOnly: true, id: null, event: null, data: null } : null;
  }

  return {
    isCommentOnly: false,
    id,
    event,
    data: dataLines.length > 0 ? dataLines.join("\n") : null,
  };
}

const MAX_DEDUP_IDS = 2048;

interface WorkspaceStreamSnapshot {
  readonly streamKey: string;
  readonly state: SseConnectionStatus;
  readonly lastEventId: string | null;
  readonly reconnectCount: number;
}

export function useWorkspaceSse({
  workspaceSlug,
  expectedWorkspaceId,
  baseUrl = "",
  initialCursor = null,
  heartbeatTimeoutMs = 15_000,
  reconnectBaseDelayMs = 500,
  maxReconnectDelayMs = 15_000,
  enabled = true,
  fetchImpl,
  onEvent,
  onSnapshotRefresh,
}: UseWorkspaceSseOptions): UseWorkspaceSseResult {
  const activeStreamKey = enabled && workspaceSlug ? workspaceSlug : "";
  const [snapshot, setSnapshot] = useState<WorkspaceStreamSnapshot>(() => ({
    streamKey: activeStreamKey,
    state: activeStreamKey ? "connecting" : "offline",
    lastEventId: activeStreamKey ? initialCursor : null,
    reconnectCount: 0,
  }));

  const onEventRef = useRef(onEvent);
  const onSnapshotRefreshRef = useRef(onSnapshotRefresh);
  const fetchRef = useRef(fetchImpl);

  useEffect(() => {
    onEventRef.current = onEvent;
    onSnapshotRefreshRef.current = onSnapshotRefresh;
    fetchRef.current = fetchImpl;
  });

  useEffect(() => {
    if (!enabled || !workspaceSlug) {
      return undefined;
    }

    let disposed = false;
    let activeAbort: AbortController | null = null;
    let activeReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    let heartbeatTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;

    // Strictly scoped per-workspace state; purged automatically on workspaceSlug change (SEC-032)
    let cursor: string | null = initialCursor ?? null;
    const seenEventIds = new Set<string>();
    const aggregateVersions = new Map<string, number>();

    const updateSnapshot = (
      patch: Partial<Omit<WorkspaceStreamSnapshot, "streamKey">>,
    ): void => {
      if (disposed) {
        return;
      }
      setSnapshot((prev) => {
        const base: WorkspaceStreamSnapshot =
          prev.streamKey === workspaceSlug
            ? prev
            : {
                streamKey: workspaceSlug,
                state: "connecting",
                lastEventId: initialCursor ?? null,
                reconnectCount: 0,
              };
        return {
          ...base,
          ...patch,
        };
      });
    };

    const clearHeartbeat = (): void => {
      if (heartbeatTimer !== null) {
        clearTimeout(heartbeatTimer);
        heartbeatTimer = null;
      }
    };

    const clearReconnect = (): void => {
      if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    const purgeWorkspaceStreamState = (): void => {
      cursor = null;
      seenEventIds.clear();
      aggregateVersions.clear();
      updateSnapshot({ lastEventId: null });
    };

    const rememberEventId = (eventId: string): boolean => {
      if (seenEventIds.has(eventId)) {
        return false;
      }
      if (seenEventIds.size >= MAX_DEDUP_IDS) {
        const oldest = seenEventIds.values().next().value;
        if (typeof oldest === "string") {
          seenEventIds.delete(oldest);
        }
      }
      seenEventIds.add(eventId);
      return true;
    };

    const scheduleReconnect = (delayMs: number): void => {
      if (disposed) {
        return;
      }
      clearReconnect();
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        if (!disposed) {
          setSnapshot((prev) => {
            const base: WorkspaceStreamSnapshot =
              prev.streamKey === workspaceSlug
                ? prev
                : {
                    streamKey: workspaceSlug,
                    state: "connecting",
                    lastEventId: cursor,
                    reconnectCount: 0,
                  };
            return {
              ...base,
              reconnectCount: base.reconnectCount + 1,
            };
          });
          void openStream();
        }
      }, delayMs);
    };

    const computeBackoffMs = (retryIndex: number): number => {
      const exp = reconnectBaseDelayMs * Math.pow(2, Math.min(retryIndex, 6));
      return Math.min(maxReconnectDelayMs, exp);
    };

    const openStream = async (): Promise<void> => {
      if (disposed) {
        return;
      }
      clearHeartbeat();
      clearReconnect();

      const controller = new AbortController();
      activeAbort = controller;
      let heartbeatExpired = false;

      const armHeartbeat = (): void => {
        clearHeartbeat();
        heartbeatTimer = setTimeout(() => {
          if (disposed) {
            return;
          }
          heartbeatExpired = true;
          updateSnapshot({ state: "stale" });
          controller.abort();
          if (activeReader !== null) {
            void activeReader.cancel().catch(() => undefined);
          }
        }, heartbeatTimeoutMs);
      };

      const headers: Record<string, string> = {
        Accept: "text/event-stream",
      };
      if (cursor !== null && cursor.length > 0) {
        headers["Last-Event-ID"] = cursor;
      }

      const url = `${baseUrl}/api/v1/workspaces/${encodeURIComponent(workspaceSlug)}/events`;
      const effectiveFetch = fetchRef.current ?? globalThis.fetch;

      try {
        const response = await effectiveFetch(url, {
          method: "GET",
          credentials: "same-origin",
          headers,
          signal: controller.signal,
        });

        if (disposed) {
          return;
        }

        if (response.status === 401) {
          purgeWorkspaceStreamState();
          updateSnapshot({ state: "unauthorized", lastEventId: null });
          return;
        }

        if (response.status === 403) {
          purgeWorkspaceStreamState();
          updateSnapshot({ state: "forbidden", lastEventId: null });
          return;
        }

        if (response.status === 410) {
          purgeWorkspaceStreamState();
          updateSnapshot({ state: "reconciling", lastEventId: null });
          const refreshResult = await onSnapshotRefreshRef.current?.({
            reason: "cursor_expired_410",
            workspaceSlug,
          });
          if (disposed) {
            return;
          }
          if (refreshResult && refreshResult.cursor !== undefined) {
            cursor = refreshResult.cursor;
            updateSnapshot({ lastEventId: cursor });
          }
          scheduleReconnect(reconnectBaseDelayMs);
          return;
        }

        if (!response.ok || response.body === null) {
          attempt += 1;
          updateSnapshot({ state: "offline" });
          scheduleReconnect(computeBackoffMs(attempt));
          return;
        }

        attempt = 0;
        updateSnapshot({ state: "connected", lastEventId: cursor });
        armHeartbeat();

        const reader = response.body.getReader();
        activeReader = reader;
        const decoder = new TextDecoder();
        let buffer = "";

        while (!disposed && !heartbeatExpired) {
          const { done, value } = await reader.read();
          if (disposed || heartbeatExpired) {
            break;
          }
          if (done) {
            break;
          }

          armHeartbeat();
          buffer += decoder.decode(value, { stream: true }).replace(/\r\n?/g, "\n");

          let boundaryIdx = buffer.indexOf("\n\n");
          while (boundaryIdx !== -1) {
            const rawBlock = buffer.slice(0, boundaryIdx);
            buffer = buffer.slice(boundaryIdx + 2);
            boundaryIdx = buffer.indexOf("\n\n");

            const frame = parseSseFrameBlock(rawBlock);
            if (!frame || frame.isCommentOnly || frame.data === null) {
              continue;
            }

            let parsedJson: unknown;
            try {
              parsedJson = JSON.parse(frame.data);
            } catch {
              continue;
            }

            const validated = EventEnvelopeRuntimeSchema.safeParse(parsedJson);
            if (!validated.success) {
              continue;
            }
            const envelope = validated.data as unknown as EventEnvelope;

            // Enforce strict workspace isolation (SEC-032)
            if (
              expectedWorkspaceId !== undefined &&
              expectedWorkspaceId !== null &&
              envelope.workspace_id !== null &&
              envelope.workspace_id !== expectedWorkspaceId
            ) {
              continue;
            }

            if (envelope.type === "identity.permission_revoked") {
              purgeWorkspaceStreamState();
              updateSnapshot({ state: "forbidden", lastEventId: null });
              clearHeartbeat();
              await reader.cancel().catch(() => undefined);
              return;
            }

            if (!rememberEventId(envelope.event_id)) {
              continue;
            }

            cursor = frame.id ?? envelope.event_id;
            updateSnapshot({ lastEventId: cursor });

            const previousVersion = aggregateVersions.get(envelope.aggregate_id);
            if (previousVersion !== undefined && envelope.aggregate_version <= previousVersion) {
              continue;
            }

            if (previousVersion !== undefined && envelope.aggregate_version > previousVersion + 1) {
              aggregateVersions.set(envelope.aggregate_id, envelope.aggregate_version);
              updateSnapshot({ state: "reconciling" });
              await onSnapshotRefreshRef.current?.({
                reason: "version_gap",
                workspaceSlug,
                aggregateId: envelope.aggregate_id,
                expectedVersion: previousVersion + 1,
                receivedVersion: envelope.aggregate_version,
              });
              if (disposed) {
                return;
              }
              updateSnapshot({ state: "connected" });
            } else {
              aggregateVersions.set(envelope.aggregate_id, envelope.aggregate_version);
            }

            onEventRef.current?.(envelope);
          }
        }

        clearHeartbeat();
        activeReader = null;

        if (disposed) {
          return;
        }

        if (heartbeatExpired) {
          updateSnapshot({ state: "reconciling" });
          await onSnapshotRefreshRef.current?.({
            reason: "heartbeat_timeout",
            workspaceSlug,
          });
          if (!disposed) {
            scheduleReconnect(reconnectBaseDelayMs);
          }
          return;
        }

        attempt += 1;
        updateSnapshot({ state: "stale" });
        scheduleReconnect(computeBackoffMs(attempt));
      } catch {
        clearHeartbeat();
        activeReader = null;
        if (disposed) {
          return;
        }
        if (heartbeatExpired) {
          updateSnapshot({ state: "reconciling" });
          await onSnapshotRefreshRef.current?.({
            reason: "heartbeat_timeout",
            workspaceSlug,
          });
          if (!disposed) {
            scheduleReconnect(reconnectBaseDelayMs);
          }
          return;
        }
        attempt += 1;
        updateSnapshot({ state: "offline" });
        scheduleReconnect(computeBackoffMs(attempt));
      }
    };

    void openStream();

    return () => {
      disposed = true;
      clearHeartbeat();
      clearReconnect();
      activeAbort?.abort();
      if (activeReader !== null) {
        void activeReader.cancel().catch(() => undefined);
        activeReader = null;
      }
      seenEventIds.clear();
      aggregateVersions.clear();
    };
  }, [
    baseUrl,
    enabled,
    expectedWorkspaceId,
    heartbeatTimeoutMs,
    initialCursor,
    maxReconnectDelayMs,
    reconnectBaseDelayMs,
    workspaceSlug,
  ]);

  if (!activeStreamKey) {
    return {
      state: "offline",
      lastEventId: null,
      reconnectCount: 0,
    };
  }

  if (snapshot.streamKey !== activeStreamKey) {
    return {
      state: "connecting",
      lastEventId: initialCursor ?? null,
      reconnectCount: 0,
    };
  }

  return {
    state: snapshot.state,
    lastEventId: snapshot.lastEventId,
    reconnectCount: snapshot.reconnectCount,
  };
}
