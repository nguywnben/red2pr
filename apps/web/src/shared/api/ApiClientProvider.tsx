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

const Red2PrApiContext = createContext<Red2PrClient | null>(null);

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

  return (
    <QueryClientProvider client={resolvedQueryClient}>
      <Red2PrApiContext.Provider value={apiClient}>{children}</Red2PrApiContext.Provider>
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
