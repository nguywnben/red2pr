import React from "react";
import { sanitizeUntrustedText, StatusGlyph } from "../../shared/ui";

export interface FleetTrustDomainPanelProps {
  readonly trustDomain: string;
  readonly runtimeName: string;
  readonly hardenedAttestationVerified: boolean;
}

export function FleetTrustDomainPanel({
  trustDomain,
  runtimeName,
  hardenedAttestationVerified,
}: FleetTrustDomainPanelProps): React.JSX.Element {
  const safeDomain = sanitizeUntrustedText(trustDomain).text;
  const safeRuntime = sanitizeUntrustedText(runtimeName).text;

  return (
    <div
      className="red2pr-page-stack"
      aria-label="Fleet trust domain and runtime attestation"
      data-testid="fleet-trust-domain-panel"
    >
      <div>
        <span className="red2pr-badge-pill red2pr-tone-info">{safeDomain}</span>
      </div>
      <div>
        <span
          className={`red2pr-badge-pill ${hardenedAttestationVerified ? "red2pr-tone-success" : "red2pr-tone-warning"}`}
        >
          <StatusGlyph kind={hardenedAttestationVerified ? "check" : "warn"} />
          <span>
            {hardenedAttestationVerified
              ? "Hardened runtime attested"
              : "Hardened runtime not verified"}
          </span>
        </span>
      </div>
      <small>
        {safeRuntime} ·{" "}
        {hardenedAttestationVerified
          ? "Hostile jobs require this exact trust domain."
          : "Hostile multi-workspace jobs are blocked."}
      </small>
    </div>
  );
}
