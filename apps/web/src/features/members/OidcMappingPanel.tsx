import { InputControl } from "../../shared/ui";
import { SelectorControl } from "../../shared/ui";
import type { OidcGroupMappingSummary, WorkspaceRole } from "@red2pr/ts-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useId, useState } from "react";
import { useRed2PrApi, useRed2PrTransportConfig } from "../../shared/api";
import { useI18n } from "../../shared/i18n";
import { Button } from "../../shared/ui";
import { extractAuthProblemSummary } from "../auth";

interface CapabilityResponse {
  readonly oidc_providers?: readonly string[];
}

interface OidcMappingPanelProps {
  readonly workspaceSlug: string;
}

const MAPPING_ROLES: readonly WorkspaceRole[] = [
  "admin",
  "maintainer",
  "reviewer",
  "viewer",
  "auditor",
];

export function OidcMappingPanel({ workspaceSlug }: OidcMappingPanelProps): React.JSX.Element | null {
  const api = useRed2PrApi();
  const { baseUrl, fetchImpl } = useRed2PrTransportConfig();
  const queryClient = useQueryClient();
  const { t } = useI18n();
  const groupId = useId();
  const roleId = useId();
  const [providerId, setProviderId] = useState("");
  const [groupName, setGroupName] = useState("");
  const [role, setRole] = useState<WorkspaceRole>("viewer");
  const [enabled, setEnabled] = useState(true);
  const [editing, setEditing] = useState<OidcGroupMappingSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const capabilitiesQuery = useQuery({
    queryKey: ["system", "capabilities", "oidc"],
    queryFn: async (): Promise<CapabilityResponse> => {
      const response = await (fetchImpl ?? fetch)(
        `${baseUrl.replace(/\/$/, "")}/api/v1/system/capabilities`,
        { credentials: "include", headers: { Accept: "application/json" } },
      );
      if (!response.ok) throw new Error("capability_unavailable");
      return (await response.json()) as CapabilityResponse;
    },
    retry: false,
    staleTime: 60_000,
  });
  const providers = capabilitiesQuery.data?.oidc_providers ?? [];
  const mappingsQuery = useQuery({
    queryKey: ["workspace", workspaceSlug, "oidc-mappings"],
    queryFn: () => api.listWorkspaceOidcMappings(workspaceSlug),
    enabled: providers.length > 0,
    retry: false,
  });
  const saveMapping = useMutation({
    mutationFn: () =>
      api.configureWorkspaceOidcMapping(workspaceSlug, {
        provider_id: providerId || providers[0] || "",
        group_name: groupName.trim(),
        role,
        enabled,
      }),
    onSuccess: async () => {
      setError(null);
      setEditing(null);
      setGroupName("");
      setEnabled(true);
      await queryClient.invalidateQueries({
        queryKey: ["workspace", workspaceSlug, "oidc-mappings"],
      });
      await queryClient.invalidateQueries({
        predicate: (query) =>
          Array.isArray(query.queryKey) &&
          query.queryKey[0] === "workspace" &&
          query.queryKey[1] === workspaceSlug,
      });
    },
    onError: (cause) => {
      setError(extractAuthProblemSummary(cause, t("members.oidcSaveFailed")).detail);
    },
  });

  if (capabilitiesQuery.isLoading || capabilitiesQuery.isError || providers.length === 0) return null;

  return (
    <section className="red2pr-surface red2pr-card-section" aria-labelledby="oidc-mappings-title">
      <div className="red2pr-card-header">
        <div>
          <h2 id="oidc-mappings-title" >
            {t("members.oidcMappingsTitle")}
          </h2>
          <p className="red2pr-field-hint">{t("members.oidcMappingsDescription")}</p>
        </div>
      </div>
      {error ? <p role="alert" className="red2pr-tone-danger">{error}</p> : null}
      <form
        className="red2pr-form-stack"
        onSubmit={(event) => {
          event.preventDefault();
          setError(null);
          saveMapping.mutate();
        }}
      >
        <div className="red2pr-field">
          <label className="red2pr-field-label" htmlFor={`${groupId}-provider`}>
            {t("members.oidcProviderLabel")}
          </label>
          <SelectorControl
            id={`${groupId}-provider`}
            className="red2pr-control-select"
            value={providerId || providers[0]}
            onChange={(event) => setProviderId(event.target.value)}
            disabled={saveMapping.isPending}
          >
            {providers.map((provider) => <option value={provider} key={provider}>{provider}</option>)}
          </SelectorControl>
        </div>
        <div className="red2pr-field">
          <label className="red2pr-field-label" htmlFor={groupId}>{t("members.oidcGroupLabel")}</label>
          <InputControl
            id={groupId}
            className="red2pr-control-input"
            required
            maxLength={256}
            value={groupName}
            onChange={(event) => setGroupName(event.target.value)}
            disabled={saveMapping.isPending}
          />
        </div>
        <div className="red2pr-field">
          <label className="red2pr-field-label" htmlFor={roleId}>{t("members.oidcRoleLabel")}</label>
          <SelectorControl
            id={roleId}
            className="red2pr-control-select"
            value={role}
            onChange={(event) => setRole(event.target.value as WorkspaceRole)}
            disabled={saveMapping.isPending}
          >
            {MAPPING_ROLES.map((mappingRole) => (
              <option key={mappingRole} value={mappingRole}>{mappingRole}</option>
            ))}
          </SelectorControl>
        </div>
        <label className="red2pr-field-hint">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => setEnabled(event.target.checked)}
            disabled={saveMapping.isPending}
          /> {t("members.oidcEnabledLabel")}
        </label>
        <div className="red2pr-button-row">
          <Button
            label={t(editing ? "members.oidcUpdateAction" : "members.oidcAddAction")}
            variant="secondary"
            type="submit"
            isLoading={saveMapping.isPending}
            isDisabled={!groupName.trim() || saveMapping.isPending}
          />
          {editing ? (
            <Button
              label={t("members.oidcCancelEdit")}
              variant="ghost"
              type="button"
              onClick={() => {
                setEditing(null);
                setGroupName("");
                setEnabled(true);
              }}
            />
          ) : null}
        </div>
      </form>
      {mappingsQuery.isError ? (
        <p role="alert" className="red2pr-tone-danger">{t("members.oidcMappingsLoadFailed")}</p>
      ) : null}
      <ul aria-label={t("members.oidcMappingsTitle")}>
        {(mappingsQuery.data?.data ?? []).map((mapping) => (
          <li key={mapping.id}>
            <span>{mapping.provider_id} · {mapping.group_name} → {mapping.role}</span>
            <span>{mapping.enabled ? t("members.oidcEnabled") : t("members.oidcDisabled")}</span>
            <Button
              label={t("members.oidcEditAction")}
              variant="ghost"
              onClick={() => {
                setEditing(mapping);
                setProviderId(mapping.provider_id);
                setGroupName(mapping.group_name);
                setRole(mapping.role);
                setEnabled(mapping.enabled);
              }}
            />
          </li>
        ))}
      </ul>
    </section>
  );
}
