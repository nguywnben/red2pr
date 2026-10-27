import type { MeResponse, ProviderKind, Workspace } from "@red2pr/ts-client";
import React, { useState } from "react";
import { useI18n } from "../../shared/i18n";
import { StatusGlyph } from "../../shared/ui";
import { GitHubIntegrationPanel } from "./GitHubIntegrationPanel";
import { GitLabIntegrationPanel } from "./GitLabIntegrationPanel";

export interface IntegrationsPageProps {
  readonly workspace: Workspace;
  readonly me: MeResponse;
}

export function IntegrationsPage({ workspace, me }: IntegrationsPageProps): React.JSX.Element {
  const { t } = useI18n();
  const [activeProvider, setActiveProvider] = useState<ProviderKind>("github");

  return (
    <div className="red2pr-page-stack" data-testid="integrations-page">
      <div>
        <h1 style={{ margin: 0, fontSize: "1.5rem" }}>{t("integrations.pageTitle")}</h1>
        <p className="red2pr-field-hint" style={{ marginTop: 6 }}>
          {t("integrations.pageSubtitle")}
        </p>
      </div>

      <div className="red2pr-tab-strip" role="group" aria-label="Source control provider adapters">
        <button
          type="button"
          className="red2pr-tab-button"
          aria-pressed={activeProvider === "github"}
          onClick={() => setActiveProvider("github")}
        >
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <StatusGlyph kind="check" />
            <span>{t("integrations.tabGitHub")}</span>
          </span>
        </button>
        <button
          type="button"
          className="red2pr-tab-button"
          aria-pressed={activeProvider === "gitlab"}
          onClick={() => setActiveProvider("gitlab")}
        >
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <StatusGlyph kind="check" />
            <span>{t("integrations.tabGitLab")}</span>
          </span>
        </button>
      </div>

      {activeProvider === "github" ? (
        <GitHubIntegrationPanel workspace={workspace} me={me} />
      ) : (
        <GitLabIntegrationPanel workspace={workspace} me={me} />
      )}
    </div>
  );
}
