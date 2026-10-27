import type { MeResponse, ProviderKind, Workspace } from "@red2pr/ts-client";
import React, { useState } from "react";
import { useI18n } from "../../shared/i18n";
import { StateView, StatusGlyph } from "../../shared/ui";
import { GitHubIntegrationPanel } from "./GitHubIntegrationPanel";

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
            <StatusGlyph kind="clock" />
            <span>{t("integrations.tabGitLab")}</span>
          </span>
        </button>
      </div>

      {activeProvider === "github" ? (
        <GitHubIntegrationPanel workspace={workspace} me={me} />
      ) : (
        <section
          className="red2pr-surface red2pr-card-section"
          aria-labelledby="gitlab-pending-heading"
          data-testid="gitlab-integration-pending-panel"
        >
          <h2 id="gitlab-pending-heading" style={{ margin: 0, fontSize: "1.125rem" }}>
            GitLab Cloud &amp; Self-Managed Adapter (SRC-02)
          </h2>
          <StateView
            state="degraded"
            title="GitLab adapter not yet enabled on this build"
            description="GitLab OAuth, fine-grained token probes, Self-Managed custom CA / private CIDR binding, and .gitlab-ci.yml discovery are scheduled in Unit U10."
          />
        </section>
      )}
    </div>
  );
}
