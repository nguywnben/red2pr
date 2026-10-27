import React from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation, useParams } from "react-router";
import { AccountPage, LoginPage } from "../features/auth";
import { ApiClientProvider } from "../shared/api";
import { I18nProvider, useI18n } from "../shared/i18n";
import { ThemeProvider } from "../shared/theme";
import { AppShell, StateView } from "../shared/ui";
import { AppErrorBoundary } from "./AppErrorBoundary";

function WorkspaceShellRoute(): React.JSX.Element {
  const { t } = useI18n();
  const location = useLocation();
  const params = useParams<{ ws?: string }>();
  const activeWorkspace = params.ws ?? "default";

  return (
    <AppShell
      activePath={location.pathname}
      activeWorkspaceSlug={activeWorkspace}
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

function AccountShellRoute(): React.JSX.Element {
  const location = useLocation();
  return (
    <AppShell activePath={location.pathname} activeWorkspaceSlug="default" sseState="offline">
      <AccountPage />
    </AppShell>
  );
}

export function App(): React.JSX.Element {
  return (
    <I18nProvider>
      <ThemeProvider defaultMode="system">
        <ApiClientProvider>
          <BrowserRouter>
            <AppErrorBoundary>
              <Routes>
                <Route path="/login" element={<LoginPage />} />
                <Route path="/account" element={<AccountShellRoute />} />
                <Route path="/w/:ws/*" element={<WorkspaceShellRoute />} />
                <Route path="/admin/*" element={<WorkspaceShellRoute />} />
                <Route path="*" element={<Navigate to="/w/default/overview" replace />} />
              </Routes>
            </AppErrorBoundary>
          </BrowserRouter>
        </ApiClientProvider>
      </ThemeProvider>
    </I18nProvider>
  );
}
