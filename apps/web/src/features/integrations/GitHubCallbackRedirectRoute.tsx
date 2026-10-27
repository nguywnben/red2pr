import { Red2PrApiError } from "@red2pr/ts-client";
import { useQuery } from "@tanstack/react-query";
import React from "react";
import { Navigate, useLocation, useNavigate, useSearchParams } from "react-router";
import { useRed2PrApi } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import { AppShell, StateView } from "../../shared/ui";
import { extractAuthProblemSummary } from "../auth";

export function GitHubCallbackRedirectRoute(): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const stateParam = searchParams.get("state");
  const installationIdParam = searchParams.get("installation_id");
  const setupActionParam = searchParams.get("setup_action");

  const callbackQuery = useQuery({
    queryKey: ["integrations", "github-callback-route", stateParam, installationIdParam, setupActionParam],
    queryFn: () =>
      api.handleGitHubCallback({
        state: stateParam,
        installation_id: installationIdParam,
        setup_action: setupActionParam,
      }),
    retry: false,
  });

  if (callbackQuery.isPending) {
    return (
      <AppShell activePath={location.pathname} activeWorkspaceSlug="default" sseState="offline">
        <StateView
          state="loading"
          title="Validating GitHub installation callback"
          description="Verifying single-use 10-minute callback state nonce without mutating workspace state."
        />
      </AppShell>
    );
  }

  if (callbackQuery.isError) {
    if (callbackQuery.error instanceof Red2PrApiError && callbackQuery.error.status === 401) {
      const target = `${location.pathname}${location.search}`;
      return <Navigate to={`/login?next=${encodeURIComponent(target)}`} replace />;
    }
    const errSummary = extractAuthProblemSummary(
      callbackQuery.error,
      t("state.error.description"),
    );
    return (
      <AppShell activePath={location.pathname} activeWorkspaceSlug="default" sseState="offline">
        <div className="red2pr-page-stack" data-testid="github-callback-route-error">
          <h1 style={{ margin: 0, fontSize: "1.5rem" }}>GitHub Callback Verification Failed</h1>
          <StateView
            state={errSummary.status === 403 ? "forbidden" : "error"}
            description={errSummary.detail}
            correlationId={errSummary.correlationId ?? undefined}
            primaryAction={{
              label: "Return to workspace",
              onClick: () => navigate("/w/default/integrations"),
            }}
          />
        </div>
      </AppShell>
    );
  }

  const data = callbackQuery.data.data;
  const nextQuery = new URLSearchParams();
  if (stateParam) {
    nextQuery.set("state", stateParam);
  }
  if (data.installation_id) {
    nextQuery.set("installation_id", data.installation_id);
  }
  if (data.setup_action) {
    nextQuery.set("setup_action", data.setup_action);
  }
  const dest = `/w/${encodeURIComponent(data.workspace_slug)}/integrations?${nextQuery.toString()}`;
  return <Navigate to={dest} replace />;
}
