import { Red2PrApiError, type Workspace } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from "react-router";
import { StepUpDialog, extractAuthProblemSummary, isStepUpValid, type AuthProblemSummary } from "../features/auth";
const AccountPage = lazy(() => import("../features/auth").then((module) => ({ default: module.AccountPage })));
const LoginPage = lazy(() => import("../features/auth").then((module) => ({ default: module.LoginPage })));
const IntegrationsPage = lazy(() => import("../features/integrations").then((module) => ({ default: module.IntegrationsPage })));
const GitHubCallbackRedirectRoute = lazy(() => import("../features/integrations").then((module) => ({ default: module.GitHubCallbackRedirectRoute })));
const AcceptInviteDialog = lazy(() => import("../features/members").then((module) => ({ default: module.AcceptInviteDialog })));
const MembersPage = lazy(() => import("../features/members").then((module) => ({ default: module.MembersPage })));
const AgentsPage = lazy(() => import("../features/agents").then((module) => ({ default: module.AgentsPage })));
const ModelsPage = lazy(() => import("../features/models").then((module) => ({ default: module.ModelsPage })));
const PipelinesPage = lazy(() => import("../features/pipelines").then((module) => ({ default: module.PipelinesPage })));
const QueuesPage = lazy(() => import("../features/queues").then((module) => ({ default: module.QueuesPage })));
const RepositoriesPage = lazy(() => import("../features/repositories").then((module) => ({ default: module.RepositoriesPage })));
const RepositoryDetailPage = lazy(() => import("../features/repositories").then((module) => ({ default: module.RepositoryDetailPage })));
const SetupWizardPage = lazy(() => import("../features/setup").then((module) => ({ default: module.SetupWizardPage })));
const WorkersPage = lazy(() => import("../features/workers").then((module) => ({ default: module.WorkersPage })));
const RepairDetailPage = lazy(() => import("../features/repairs").then((module) => ({ default: module.RepairDetailPage })));
const RepairsListPage = lazy(() => import("../features/repairs").then((module) => ({ default: module.RepairsListPage })));
const ApprovalsInboxPage = lazy(() => import("../features/approvals").then((module) => ({ default: module.ApprovalsInboxPage })));
const TelegramIntentConfirmPage = lazy(() => import("../features/approvals/TelegramIntentConfirmPage").then((module) => ({ default: module.TelegramIntentConfirmPage })));
const PullRequestsPage = lazy(() => import("../features/prs").then((module) => ({ default: module.PullRequestsPage })));
const NotificationsPage = lazy(() => import("../features/notifications").then((module) => ({ default: module.NotificationsPage })));
const AnalyticsPage = lazy(() => import("../features/analytics/AnalyticsPage").then((module) => ({ default: module.AnalyticsPage })));
const SecurityPage = lazy(() => import("../features/security/SecurityPage").then((module) => ({ default: module.SecurityPage })));
const SystemPage = lazy(() => import("../features/system/SystemPage").then((module) => ({ default: module.SystemPage })));
const OverviewPage = lazy(() => import("../features/overview/OverviewPage").then((module) => ({ default: module.OverviewPage })));
import {
  ApiClientProvider,
  invalidateWorkspaceQueries,
  purgeWorkspaceQueries,
  useRed2PrApi,
  useRed2PrTransportConfig,
} from "../shared/api";
import { useWorkspaceSse } from "../shared/events/useWorkspaceSse";
import { I18nProvider, useI18n } from "../shared/i18n";
import { ThemeProvider } from "../shared/theme";
import {
  AppShell,
  Button,
  StateView,
  StatusGlyph,
  sanitizeUntrustedText,
  type WorkspaceNavOption,
} from "../shared/ui";
import { AppErrorBoundary } from "./AppErrorBoundary";

function toWorkspaceNavOptions(workspaces: readonly Workspace[] | undefined): WorkspaceNavOption[] {
  return (workspaces ?? []).map((ws) => ({
    slug: ws.slug ?? ws.id,
    name: sanitizeUntrustedText(ws.name).text,
  }));
}

function buildLoginRedirectHref(pathname: string, search: string): string {
  const target = `${pathname}${search}`;
  return `/login?next=${encodeURIComponent(target)}`;
}

function WorkspaceSectionOutlet({
  workspace,
  meData,
}: {
  readonly workspace: Workspace;
  readonly meData: NonNullable<Awaited<ReturnType<ReturnType<typeof useRed2PrApi>["getMe"]>>["data"]>;
}): React.JSX.Element {
  const { t } = useI18n();
  return (
    <Routes>
      <Route path="overview" element={<OverviewPage workspace={workspace} me={meData} />} />
      <Route path="analytics" element={<AnalyticsPage workspace={workspace} me={meData} />} />
      <Route path="security" element={<SecurityPage workspace={workspace} />} />
      <Route path="members" element={<MembersPage workspace={workspace} me={meData} />} />
      <Route path="pipelines" element={<PipelinesPage workspace={workspace} me={meData} />} />
      <Route path="failures" element={<Navigate to="../pipelines" replace />} />
      <Route path="workers" element={<WorkersPage workspace={workspace} me={meData} />} />
      <Route path="queues" element={<QueuesPage workspace={workspace} me={meData} />} />
      <Route path="models" element={<ModelsPage workspace={workspace} me={meData} />} />
      <Route path="agents" element={<AgentsPage workspace={workspace} me={meData} />} />
      <Route path="repairs" element={<RepairsListPage workspace={workspace} me={meData} />} />
      <Route path="repairs/:repairId" element={<RepairDetailPage workspace={workspace} me={meData} />} />
      <Route path="approvals" element={<ApprovalsInboxPage workspace={workspace} me={meData} />} />
      <Route path="notifications" element={<NotificationsPage workspace={workspace} me={meData} />} />
      <Route path="prs" element={<PullRequestsPage workspace={workspace} me={meData} />} />
      <Route
        path="repositories"
        element={<RepositoriesPage workspace={workspace} me={meData} />}
      />
      <Route
        path="repositories/:repoId"
        element={<RepositoryDetailPage workspace={workspace} me={meData} />}
      />
      <Route
        path="integrations"
        element={<IntegrationsPage workspace={workspace} me={meData} />}
      />
      <Route path="connections" element={<Navigate to="../integrations" replace />} />
      <Route
        path="*"
        element={
          <StateView
            state="ready"
            title={t("shell.readyTitle")}
            description={t("shell.readyDescription")}
          />
        }
      />
    </Routes>
  );
}

export function WorkspaceRouteShell(): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const transport = useRed2PrTransportConfig();
  const queryClient = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();
  const params = useParams<{ ws?: string }>();
  const wsParam = params.ws ?? "default";

  const [acceptInviteOpen, setAcceptInviteOpen] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingBreakGlassSubmitRef = useRef(false);
  const [bgReason, setBgReason] = useState("");
  const [bgDuration, setBgDuration] = useState(30);
  const [bgError, setBgError] = useState<AuthProblemSummary | null>(null);

  const bgReasonId = useId();
  const bgDurationId = useId();

  const meQuery = useQuery({
    queryKey: ["auth", "me"],
    queryFn: () => api.getMe(),
    retry: false,
  });

  const isAuthenticated = meQuery.isSuccess;

  const workspaceQuery = useQuery({
    queryKey: ["workspace", wsParam, "meta"],
    queryFn: () => api.getWorkspace(wsParam),
    enabled: isAuthenticated,
    retry: false,
  });

  const resolvedWorkspace = workspaceQuery.data?.data ?? null;
  const canonicalSlug = resolvedWorkspace ? (resolvedWorkspace.slug ?? resolvedWorkspace.id) : wsParam;

  const handleSnapshotRefresh = useCallback(async () => {
    await invalidateWorkspaceQueries(queryClient, canonicalSlug);
    await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
  }, [canonicalSlug, queryClient]);

  const handleSseEvent = useCallback(() => {
    void invalidateWorkspaceQueries(queryClient, canonicalSlug);
  }, [canonicalSlug, queryClient]);

  const sse = useWorkspaceSse({
    workspaceSlug: resolvedWorkspace ? canonicalSlug : null,
    expectedWorkspaceId: resolvedWorkspace?.id ?? null,
    baseUrl: transport.baseUrl,
    fetchImpl: transport.fetchImpl,
    enabled: resolvedWorkspace !== null,
    onEvent: handleSseEvent,
    onSnapshotRefresh: handleSnapshotRefresh,
  });

  useEffect(() => {
    if (sse.state === "forbidden") {
      purgeWorkspaceQueries(queryClient, [
        wsParam,
        canonicalSlug,
        resolvedWorkspace?.id ?? "",
      ]);
      void queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
    }
  }, [canonicalSlug, queryClient, resolvedWorkspace?.id, sse.state, wsParam]);

  const breakGlassMutation = useMutation({
    mutationFn: async () => {
      return api.createBreakGlassGrant(wsParam, {
        reason: bgReason.trim(),
        duration_minutes: bgDuration,
      });
    },
    onSuccess: async () => {
      setBgError(null);
      setBgReason("");
      await queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
      await workspaceQuery.refetch();
    },
    onError: (err) => {
      if (err instanceof Red2PrApiError && err.problem.code === "step_up_required") {
        pendingBreakGlassSubmitRef.current = true;
        setStepUpOpen(true);
        return;
      }
      setBgError(extractAuthProblemSummary(err, t("state.error.description")));
    },
  });

  const me = meQuery.data?.data ?? null;
  const navOptions = useMemo(() => toWorkspaceNavOptions(me?.workspaces), [me?.workspaces]);

  const handleSelectWorkspace = useCallback(
    (nextSlug: string): void => {
      const subPathMatch = /^\/w\/[^/]+\/(.+)$/.exec(location.pathname);
      const subPath = subPathMatch?.[1] ?? "overview";
      navigate(`/w/${encodeURIComponent(nextSlug)}/${subPath}`);
    },
    [location.pathname, navigate],
  );

  if (meQuery.isPending) {
    return (
      <AppShell activePath={location.pathname} activeWorkspaceSlug={wsParam} sseState="offline">
        <StateView state="loading" />
      </AppShell>
    );
  }

  if (meQuery.isError || me === null) {
    if (meQuery.error instanceof Red2PrApiError && meQuery.error.status === 401) {
      return <Navigate to={buildLoginRedirectHref(location.pathname, location.search)} replace />;
    }
    const errSummary = extractAuthProblemSummary(meQuery.error, t("state.error.description"));
    return (
      <AppShell activePath={location.pathname} activeWorkspaceSlug={wsParam} sseState="offline">
        <StateView
          state={errSummary.status === null ? "offline" : "error"}
          description={errSummary.detail}
          correlationId={errSummary.correlationId ?? undefined}
          primaryAction={{
            label: "Retry",
            onClick: () => {
              void meQuery.refetch();
            },
          }}
        />
      </AppShell>
    );
  }

  if (sse.state === "unauthorized") {
    return <Navigate to={buildLoginRedirectHref(location.pathname, location.search)} replace />;
  }

  if (sse.state === "forbidden") {
    const fallbackWs = navOptions.find((opt) => opt.slug !== canonicalSlug) ?? null;
    return (
      <AppShell
        activePath={location.pathname}
        activeWorkspaceSlug={wsParam}
        workspaces={navOptions}
        onSelectWorkspace={handleSelectWorkspace}
        sseState="forbidden"
      >
        <div className="red2pr-page-stack" data-testid="workspace-revoked-guard">
          <h1 style={{ margin: 0, fontSize: "1.5rem" }}>{t("workspaceGuard.revokedTitle")}</h1>
          <StateView
            state="forbidden"
            title={t("workspaceGuard.revokedTitle")}
            description={t("workspaceGuard.revokedDesc")}
            primaryAction={
              fallbackWs
                ? {
                    label: t("workspaceGuard.switchToAuthorized", { name: fallbackWs.name }),
                    onClick: () => navigate(`/w/${encodeURIComponent(fallbackWs.slug)}/members`),
                  }
                : {
                    label: t("workspaceGuard.goToAccount"),
                    onClick: () => navigate("/account"),
                  }
            }
            secondaryAction={
              fallbackWs
                ? {
                    label: t("workspaceGuard.goToAccount"),
                    onClick: () => navigate("/account"),
                  }
                : undefined
            }
          />
        </div>
      </AppShell>
    );
  }

  if (workspaceQuery.isPending) {
    return (
      <AppShell
        activePath={location.pathname}
        activeWorkspaceSlug={wsParam}
        workspaces={navOptions}
        onSelectWorkspace={handleSelectWorkspace}
        sseState="connecting"
      >
        <StateView state="loading" />
      </AppShell>
    );
  }

  if (workspaceQuery.isError || resolvedWorkspace === null) {
    if (workspaceQuery.error instanceof Red2PrApiError && workspaceQuery.error.status === 401) {
      return <Navigate to={buildLoginRedirectHref(location.pathname, location.search)} replace />;
    }

    const isAccessDeniedOrMissing =
      workspaceQuery.error instanceof Red2PrApiError &&
      (workspaceQuery.error.status === 404 || workspaceQuery.error.status === 403);
    const errSummary = extractAuthProblemSummary(
      workspaceQuery.error,
      t("workspaceGuard.notFoundOrForbiddenDesc"),
    );
    const firstAuthorized = navOptions[0] ?? null;

    return (
      <AppShell
        activePath={location.pathname}
        activeWorkspaceSlug={wsParam}
        workspaces={navOptions}
        onSelectWorkspace={handleSelectWorkspace}
        sseState={isAccessDeniedOrMissing ? "forbidden" : "offline"}
      >
        <div className="red2pr-page-stack" data-testid="workspace-access-guard">
          <h1 style={{ margin: 0, fontSize: "1.5rem" }}>
            {t("workspaceGuard.notFoundOrForbiddenTitle")}
          </h1>

          <StateView
            state={isAccessDeniedOrMissing ? "forbidden" : "error"}
            title={t("workspaceGuard.notFoundOrForbiddenTitle")}
            description={
              isAccessDeniedOrMissing
                ? t("workspaceGuard.notFoundOrForbiddenDesc")
                : errSummary.detail
            }
            correlationId={errSummary.correlationId ?? undefined}
            primaryAction={
              firstAuthorized
                ? {
                    label: t("workspaceGuard.switchToAuthorized", {
                      name: firstAuthorized.name,
                    }),
                    onClick: () =>
                      navigate(`/w/${encodeURIComponent(firstAuthorized.slug)}/members`),
                  }
                : {
                    label: t("workspaceGuard.goToAccount"),
                    onClick: () => navigate("/account"),
                  }
            }
            secondaryAction={{
              label: t("members.redeemInviteAction"),
              onClick: () => setAcceptInviteOpen(true),
            }}
          />

          {isAccessDeniedOrMissing && me.is_instance_owner ? (
            <section
              className="red2pr-surface red2pr-card-section"
              aria-labelledby="owner-break-glass-heading"
              data-testid="owner-break-glass-panel"
            >
              <h2 id="owner-break-glass-heading" style={{ margin: "0 0 6px", fontSize: "1.125rem" }}>
                {t("workspaceGuard.ownerBreakGlassTitle")}
              </h2>
              <p className="red2pr-field-hint">{t("workspaceGuard.ownerBreakGlassDesc")}</p>

              <form
                className="red2pr-form-stack"
                onSubmit={(event) => {
                  event.preventDefault();
                  setBgError(null);
                  if (!isStepUpValid(me.step_up_valid_until)) {
                    pendingBreakGlassSubmitRef.current = true;
                    setStepUpOpen(true);
                    return;
                  }
                  breakGlassMutation.mutate();
                }}
                noValidate
              >
                {bgError !== null ? (
                  <div role="alert" className="red2pr-inline-alert red2pr-tone-danger">
                    <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
                      <StatusGlyph kind="error" />
                      <span>{bgError.detail}</span>
                    </div>
                  </div>
                ) : null}

                <div className="red2pr-field">
                  <label htmlFor={bgReasonId} className="red2pr-field-label">
                    {t("workspaceGuard.breakGlassReasonLabel")}
                  </label>
                  <input
                    id={bgReasonId}
                    className="red2pr-control-input"
                    type="text"
                    required
                    minLength={8}
                    maxLength={500}
                    value={bgReason}
                    onChange={(event) => setBgReason(event.target.value)}
                  />
                </div>

                <div className="red2pr-field">
                  <label htmlFor={bgDurationId} className="red2pr-field-label">
                    {t("workspaceGuard.breakGlassDurationLabel")}
                  </label>
                  <input
                    id={bgDurationId}
                    className="red2pr-control-input"
                    type="number"
                    min={5}
                    max={240}
                    required
                    value={bgDuration}
                    onChange={(event) =>
                      setBgDuration(
                        Math.min(240, Math.max(5, Number(event.target.value) || 30)),
                      )
                    }
                  />
                </div>

                <div>
                  <Button
                    label={t("workspaceGuard.breakGlassSubmit")}
                    variant="primary"
                    type="submit"
                    isLoading={breakGlassMutation.isPending}
                    isDisabled={bgReason.trim().length < 8 || breakGlassMutation.isPending}
                  />
                </div>
              </form>
            </section>
          ) : null}

          <AcceptInviteDialog
            isOpen={acceptInviteOpen}
            onOpenChange={setAcceptInviteOpen}
            onAccepted={(membership) => {
              navigate(`/w/${encodeURIComponent(membership.workspace_id)}/members`);
            }}
          />

          <StepUpDialog
            isOpen={stepUpOpen}
            mfaEnabled={me.mfa_enabled}
            onOpenChange={(nextOpen) => {
              if (!nextOpen) {
                pendingBreakGlassSubmitRef.current = false;
              }
              setStepUpOpen(nextOpen);
            }}
            onVerified={() => {
              void queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
              if (pendingBreakGlassSubmitRef.current) {
                pendingBreakGlassSubmitRef.current = false;
                breakGlassMutation.mutate();
              }
            }}
          />
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell
      activePath={location.pathname}
      activeWorkspaceSlug={canonicalSlug}
      workspaces={navOptions}
      onSelectWorkspace={handleSelectWorkspace}
      sseState={sse.state}
    >
      <WorkspaceSectionOutlet workspace={resolvedWorkspace} meData={me} />
    </AppShell>
  );
}

export function AccountRouteShell(): React.JSX.Element {
  const api = useRed2PrApi();
  const location = useLocation();
  const navigate = useNavigate();

  const meQuery = useQuery({
    queryKey: ["auth", "me"],
    queryFn: () => api.getMe(),
    retry: false,
  });

  if (meQuery.isError && meQuery.error instanceof Red2PrApiError && meQuery.error.status === 401) {
    return <Navigate to={buildLoginRedirectHref(location.pathname, location.search)} replace />;
  }

  const navOptions = toWorkspaceNavOptions(meQuery.data?.data.workspaces);
  const defaultSlug = navOptions[0]?.slug ?? "default";

  return (
    <AppShell
      activePath={location.pathname}
      activeWorkspaceSlug={defaultSlug}
      workspaces={navOptions}
      onSelectWorkspace={(nextSlug) => navigate(`/w/${encodeURIComponent(nextSlug)}/members`)}
      sseState="offline"
    >
      <AccountPage />
    </AppShell>
  );
}

export function AdminRouteShell(): React.JSX.Element {
  const { t } = useI18n();
  const api = useRed2PrApi();
  const location = useLocation();
  const navigate = useNavigate();

  const meQuery = useQuery({
    queryKey: ["auth", "me"],
    queryFn: () => api.getMe(),
    retry: false,
  });

  if (meQuery.isPending) {
    return (
      <AppShell activePath={location.pathname} activeWorkspaceSlug="default" sseState="offline">
        <StateView state="loading" />
      </AppShell>
    );
  }

  if (meQuery.isError) {
    if (meQuery.error instanceof Red2PrApiError && meQuery.error.status === 401) {
      return <Navigate to={buildLoginRedirectHref(location.pathname, location.search)} replace />;
    }
    const errSummary = extractAuthProblemSummary(meQuery.error, t("state.error.description"));
    return (
      <AppShell activePath={location.pathname} activeWorkspaceSlug="default" sseState="offline">
        <StateView
          state="error"
          description={errSummary.detail}
          correlationId={errSummary.correlationId ?? undefined}
        />
      </AppShell>
    );
  }

  const me = meQuery.data.data;
  const navOptions = toWorkspaceNavOptions(me.workspaces);
  const defaultSlug = navOptions[0]?.slug ?? "default";

  if (!me.is_instance_owner) {
    return (
      <AppShell
        activePath={location.pathname}
        activeWorkspaceSlug={defaultSlug}
        workspaces={navOptions}
        onSelectWorkspace={(nextSlug) => navigate(`/w/${encodeURIComponent(nextSlug)}/members`)}
        sseState="offline"
      >
        <StateView state="forbidden" />
      </AppShell>
    );
  }

  return (
    <AppShell
      activePath={location.pathname}
      activeWorkspaceSlug={defaultSlug}
      workspaces={navOptions}
      onSelectWorkspace={(nextSlug) => navigate(`/w/${encodeURIComponent(nextSlug)}/members`)}
      sseState="offline"
    >
      <StateView
        state="ready"
        title={t("shell.readyTitle")}
        description={t("shell.readyDescription")}
      />
    </AppShell>
  );
}

export function AppRoutes(): React.JSX.Element {
  return (
    <Suspense fallback={<StateView state="loading" />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/setup" element={<SetupWizardPage />} />
        <Route path="/setup/*" element={<SetupWizardPage />} />
        <Route path="/integrations/github/callback" element={<GitHubCallbackRedirectRoute />} />
        <Route path="/account" element={<AccountRouteShell />} />
        <Route path="/telegram/confirm" element={<TelegramIntentConfirmPage />} />
        <Route path="/system" element={<SystemPage />} />
        <Route path="/w/:ws/*" element={<WorkspaceRouteShell />} />
        <Route path="/admin/*" element={<AdminRouteShell />} />
        <Route path="*" element={<Navigate to="/w/default/overview" replace />} />
      </Routes>
    </Suspense>
  );
}

export function App(): React.JSX.Element {
  return (
    <I18nProvider>
      <ThemeProvider defaultMode="system">
        <ApiClientProvider>
          <BrowserRouter>
            <AppErrorBoundary>
              <AppRoutes />
            </AppErrorBoundary>
          </BrowserRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>
  );
}
