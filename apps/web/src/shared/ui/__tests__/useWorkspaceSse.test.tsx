import type { EventEnvelope } from "@red2pr/ts-client";
import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useWorkspaceSse, type SnapshotRefreshContext } from "../../events/useWorkspaceSse";

function createSseStreamResponse(
  chunks: readonly string[],
  status = 200,
  keepOpen = true,
): {
  readonly response: Response;
  readonly push: (chunk: string) => void;
  readonly close: () => void;
} {
  let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;
  const encoder = new TextEncoder();

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controllerRef = controller;
      for (const chunk of chunks) {
        controller.enqueue(encoder.encode(chunk));
      }
      if (!keepOpen) {
        controller.close();
      }
    },
  });

  const response = new Response(stream, {
    status,
    headers: { "Content-Type": "text/event-stream" },
  });

  return {
    response,
    push(chunk: string) {
      controllerRef?.enqueue(encoder.encode(chunk));
    },
    close() {
      controllerRef?.close();
    },
  };
}

function makeRepairEvent(overrides: Partial<EventEnvelope> & { event_id: string }): EventEnvelope {
  return {
    schema_version: 1,
    event_id: overrides.event_id,
    type: overrides.type ?? "repair.diagnosed",
    occurred_at: overrides.occurred_at ?? "2026-10-27T07:00:00Z",
    workspace_id: overrides.workspace_id === undefined ? "ws-acme" : overrides.workspace_id,
    repository_id: overrides.repository_id ?? "repo-1",
    session_id: overrides.session_id ?? "rep-1",
    aggregate_id: overrides.aggregate_id ?? "rep-1",
    aggregate_version: overrides.aggregate_version ?? 1,
    correlation_id: overrides.correlation_id ?? "corr-sse-1",
    causation_id: overrides.causation_id ?? null,
    payload: overrides.payload ?? {
      repair_id: "rep-1",
      state: "diagnosed",
      reason_code: null,
    },
  };
}

function formatSseFrame(envelope: EventEnvelope): string {
  return `id: ${envelope.event_id}\nevent: ${envelope.type}\ndata: ${JSON.stringify(envelope)}\n\n`;
}

describe("U04 Deterministic SSE Client & Cursor Reconciler (T-UI-02-P, T-UI-02-N, S-19, SEC-032)", () => {
  it("connects with session credentials, deduplicates event_id, tracks Last-Event-ID, and detects aggregate_version gaps", async () => {
    const received: EventEnvelope[] = [];
    const snapshotCalls: SnapshotRefreshContext[] = [];
    const seenHeaders: Array<string | null> = [];

    const stream1 = createSseStreamResponse([
      ": heartbeat\n\n",
      formatSseFrame(makeRepairEvent({ event_id: "evt-001", aggregate_version: 1 })),
      // Duplicate event_id must be ignored
      formatSseFrame(makeRepairEvent({ event_id: "evt-001", aggregate_version: 1 })),
      // Version gap: jumps from 1 -> 3! Must trigger authoritative snapshot refetch
      formatSseFrame(
        makeRepairEvent({
          event_id: "evt-003",
          type: "repair.verification.completed",
          aggregate_version: 3,
          payload: { repair_id: "rep-1", outcome: "locally_verified", manifest_id: "man-1" },
        }),
      ),
    ]);

    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      seenHeaders.push(headers.get("Last-Event-ID"));
      return stream1.response;
    });

    const { result, unmount } = renderHook(() =>
      useWorkspaceSse({
        workspaceSlug: "acme",
        expectedWorkspaceId: "ws-acme",
        initialCursor: "evt-000",
        fetchImpl,
        onEvent: (env) => received.push(env),
        onSnapshotRefresh: async (ctx) => {
          snapshotCalls.push(ctx);
          return {};
        },
      }),
    );

    await waitFor(() => {
      expect(received).toHaveLength(2);
    });

    expect(seenHeaders[0]).toBe("evt-000");
    expect(result.current.lastEventId).toBe("evt-003");
    expect(snapshotCalls).toHaveLength(1);
    expect(snapshotCalls[0]?.reason).toBe("version_gap");
    unmount();
  });

  it("recovers from HTTP 410 cursor expiry by clearing stale cursor, fetching authoritative REST snapshot, and reconnecting", async () => {
    const snapshotCalls: SnapshotRefreshContext[] = [];
    const seenLastEventIds: Array<string | null> = [];
    let attempt = 0;

    const streamAfter410 = createSseStreamResponse([
      formatSseFrame(makeRepairEvent({ event_id: "evt-101", aggregate_version: 10 })),
    ]);

    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      attempt += 1;
      const headers = new Headers(init?.headers);
      seenLastEventIds.push(headers.get("Last-Event-ID"));
      if (attempt === 1) {
        return new Response(
          JSON.stringify({
            type: "https://red2pr.local/problems/cursor_expired",
            title: "Cursor expired",
            status: 410,
            code: "cursor_expired",
            detail: "Replay window exceeded.",
            correlation_id: "corr-410",
            errors: null,
          }),
          { status: 410, headers: { "Content-Type": "application/problem+json" } },
        );
      }
      return streamAfter410.response;
    });

    const { result, unmount } = renderHook(() =>
      useWorkspaceSse({
        workspaceSlug: "acme",
        expectedWorkspaceId: "ws-acme",
        initialCursor: "evt-expired-001",
        reconnectBaseDelayMs: 10,
        fetchImpl,
        onSnapshotRefresh: async (ctx) => {
          snapshotCalls.push(ctx);
          return { cursor: "evt-fresh-100" };
        },
      }),
    );

    await waitFor(() => {
      expect(result.current.lastEventId).toBe("evt-101");
    });

    expect(snapshotCalls).toHaveLength(1);
    expect(snapshotCalls[0]?.reason).toBe("cursor_expired_410");
    expect(seenLastEventIds[0]).toBe("evt-expired-001");
    expect(seenLastEventIds[1]).toBe("evt-fresh-100");
    unmount();
  });

  it("detects 15s missed heartbeat window, refetches snapshot, and reconnects with Last-Event-ID", async () => {
    vi.useFakeTimers();
    try {
      const snapshotCalls: SnapshotRefreshContext[] = [];
      const seenLastEventIds: Array<string | null> = [];
      let callCount = 0;

      const silentStream = createSseStreamResponse([
        formatSseFrame(makeRepairEvent({ event_id: "evt-hb-1", aggregate_version: 1 })),
      ]);
      const recoveredStream = createSseStreamResponse([
        ": heartbeat\n\n",
        formatSseFrame(makeRepairEvent({ event_id: "evt-hb-2", aggregate_version: 2 })),
      ]);

      const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        callCount += 1;
        seenLastEventIds.push(new Headers(init?.headers).get("Last-Event-ID"));
        return callCount === 1 ? silentStream.response : recoveredStream.response;
      });

      const { result, unmount } = renderHook(() =>
        useWorkspaceSse({
          workspaceSlug: "acme",
          expectedWorkspaceId: "ws-acme",
          heartbeatTimeoutMs: 15_000,
          reconnectBaseDelayMs: 20,
          fetchImpl,
          onSnapshotRefresh: async (ctx) => {
            snapshotCalls.push(ctx);
            return {};
          },
        }),
      );

      // Flush initial stream microtasks
      await act(async () => {
        await vi.advanceTimersByTimeAsync(50);
      });
      expect(result.current.lastEventId).toBe("evt-hb-1");

      // Advance past 15s heartbeat timeout + reconnect delay
      await act(async () => {
        await vi.advanceTimersByTimeAsync(15_200);
      });

      expect(snapshotCalls.some((c) => c.reason === "heartbeat_timeout")).toBe(true);
      expect(seenLastEventIds[1]).toBe("evt-hb-1");
      expect(result.current.lastEventId).toBe("evt-hb-2");
      unmount();
    } finally {
      vi.useRealTimers();
    }
  });

  it("stops retrying on 403 revocation and purges state across workspace switches (SEC-032)", async () => {
    const received: EventEnvelope[] = [];

    // First workspace emits a cross-workspace event (ws-other) which MUST be dropped, plus valid ws-a event
    const wsAStream = createSseStreamResponse([
      formatSseFrame(
        makeRepairEvent({
          event_id: "evt-cross-tenant",
          workspace_id: "ws-other",
          aggregate_version: 1,
        }),
      ),
      formatSseFrame(
        makeRepairEvent({
          event_id: "evt-ws-a-valid",
          workspace_id: "ws-a",
          aggregate_version: 1,
        }),
      ),
    ]);

    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/workspaces/ws-a/events")) {
        return wsAStream.response;
      }
      return new Response(null, { status: 403 });
    });

    const { result, rerender, unmount } = renderHook(
      ({ slug, wsId }: { slug: string; wsId: string }) =>
        useWorkspaceSse({
          workspaceSlug: slug,
          expectedWorkspaceId: wsId,
          reconnectBaseDelayMs: 10,
          fetchImpl,
          onEvent: (env) => received.push(env),
        }),
      { initialProps: { slug: "ws-a", wsId: "ws-a" } },
    );

    await waitFor(() => {
      expect(result.current.lastEventId).toBe("evt-ws-a-valid");
    });
    expect(received.map((e) => e.event_id)).toEqual(["evt-ws-a-valid"]);

    // Switch to ws-b which returns 403 -> prior cursor must be purged and status becomes 'forbidden' without retry loop
    rerender({ slug: "ws-b", wsId: "ws-b" });

    await waitFor(() => {
      expect(result.current.state).toBe("forbidden");
    });
    expect(result.current.lastEventId).toBeNull();
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    unmount();
  });
});
