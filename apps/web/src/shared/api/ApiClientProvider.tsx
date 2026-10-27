import {
  createRed2PrClient,
  type Red2PrClient,
  type Red2PrClientOptions,
} from "@red2pr/ts-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React, { createContext, useContext, useMemo } from "react";

export function createWorkspaceQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: 1,
        refetchOnWindowFocus: false,
        staleTime: 10_000,
      },
    },
  });
}

export async function invalidateWorkspaceQueries(
  queryClient: QueryClient,
  workspaceSlug: string,
): Promise<void> {
  await queryClient.invalidateQueries({
    predicate: (query) =>
      Array.isArray(query.queryKey) &&
      query.queryKey[0] === "workspace" &&
      query.queryKey[1] === workspaceSlug,
  });
}

export function purgeWorkspaceQueries(
  queryClient: QueryClient,
  workspaceIdentifiers: readonly string[],
): void {
  const idSet = new Set(workspaceIdentifiers.filter((id) => id.length > 0));
  if (idSet.size === 0) {
    return;
  }
  queryClient.removeQueries({
    predicate: (query) =>
      Array.isArray(query.queryKey) &&
      query.queryKey[0] === "workspace" &&
      typeof query.queryKey[1] === "string" &&
      idSet.has(query.queryKey[1]),
  });
}

export interface Red2PrTransportConfig {
  readonly baseUrl: string;
  readonly fetchImpl?: typeof fetch;
}

const Red2PrApiContext = createContext<Red2PrClient | null>(null);
const Red2PrTransportContext = createContext<Red2PrTransportConfig>({ baseUrl: "" });

export interface ApiClientProviderProps {
  readonly clientOptions?: Red2PrClientOptions;
  readonly queryClient?: QueryClient;
  readonly children: React.ReactNode;
}

export function ApiClientProvider({
  clientOptions,
  queryClient,
  children,
}: ApiClientProviderProps): React.JSX.Element {
  const resolvedQueryClient = useMemo(
    () => queryClient ?? createWorkspaceQueryClient(),
    [queryClient],
  );
  const apiClient = useMemo(() => createRed2PrClient(clientOptions), [clientOptions]);
  const transportConfig = useMemo<Red2PrTransportConfig>(() => {
    const rawFetch = clientOptions?.fetch;
    const adaptedFetch: typeof fetch | undefined = rawFetch
      ? (input, init) => {
          if (input instanceof Request) {
            return rawFetch(input);
          }
          let req: Request;
          try {
            req = new Request(input, init);
          } catch {
            // Handle cross-realm AbortSignal mismatch in test DOM environments (jsdom vs undici)
            const { signal: _ignoredSignal, ...safeInit } = init ?? {};
            req = new Request(input, safeInit);
          }
          return rawFetch(req);
        }
      : undefined;
    return {
      baseUrl: typeof clientOptions?.baseUrl === "string" ? clientOptions.baseUrl : "",
      fetchImpl: adaptedFetch,
    };
  }, [clientOptions]);

  return (
    <QueryClientProvider client={resolvedQueryClient}>
      <Red2PrTransportContext.Provider value={transportConfig}>
        <Red2PrApiContext.Provider value={apiClient}>{children}</Red2PrApiContext.Provider>
      </Red2PrTransportContext.Provider>
    </QueryClientProvider>
  );
}

export function useRed2PrApi(): Red2PrClient {
  const client = useContext(Red2PrApiContext);
  if (client === null) {
    throw new Error("useRed2PrApi must be used within an <ApiClientProvider>.");
  }
  return client;
}

export function useRed2PrTransportConfig(): Red2PrTransportConfig {
  return useContext(Red2PrTransportContext);
}
