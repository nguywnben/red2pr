import React from "react";
import { ArrowUpRightIcon, ShieldIcon } from "../components/Icons";
import { DOC_LINKS } from "../data/productContent";

export function ArchitectureSection(): React.JSX.Element {
  return (
    <section
      id="architecture"
      className="r2p-section r2p-section--subtle"
      aria-labelledby="architecture-heading"
    >
      <div className="r2p-container">
        <div className="r2p-section-header r2p-section-header--split">
          <div>
            <p className="r2p-kicker">Three-Zone Trust Architecture</p>
            <h2 id="architecture-heading" className="r2p-section-title">
              Strict privilege separation enforced at compile time and runtime.
            </h2>
          </div>
          <p className="r2p-section-desc">
            Repository code, dependency hooks, CI logs, and webhook payloads are treated as
            untrusted inputs. Compile-time <code>import-linter</code> contracts and mTLS worker
            boundaries isolate orchestration, credentials, and execution.
          </p>
        </div>

        <div className="r2p-zones-grid" aria-label="Red2PR Z1, Z2, and Z3 trust zones">
          <article className="r2p-zone-panel">
            <div className="r2p-zone-head">
              <span className="r2p-zone-badge">Zone Z1</span>
              <span className="r2p-zone-subtitle">Control Plane &amp; Console</span>
            </div>
            <h3>State, Policy &amp; Tenant Isolation</h3>
            <p>
              Hosts the React 19 + Astryx SPA, FastAPI <code>/api/v1/*</code> routes, deterministic
              state machines, and PostgreSQL 16 with <code>FORCE ROW LEVEL SECURITY</code> across 98
              tables.
            </p>
            <ul className="r2p-zone-list">
              <li>Argon2id sessions, TOTP 5m step-up &amp; PKCE OIDC</li>
              <li>Immutable policy revisions &amp; SHA-256 hash-chained audit trail</li>
              <li>AES-256-GCM encrypted local or S3-compatible artifact store</li>
            </ul>
          </article>

          <article className="r2p-zone-panel">
            <div className="r2p-zone-head">
              <span className="r2p-zone-badge">Zone Z2</span>
              <span className="r2p-zone-subtitle">Privileged Brokers</span>
            </div>
            <h3>Custody, Redaction &amp; Egress</h3>
            <p>
              The only boundary holding envelope-encrypted provider secrets and Meta API keys,
              protected behind an <code>ADR-037</code> DNS-pinning egress proxy.
            </p>
            <ul className="r2p-zone-list">
              <li>
                <code>MetaMuseInferenceBroker</code>: redaction-v1 + consent + USD ledger
              </li>
              <li>
                <code>SecretBroker</code>: AES-256-GCM key rotation &amp; RS256 App JWTs
              </li>
              <li>
                <code>PublisherSaga</code>: idempotent Draft PR/MR creation only
              </li>
            </ul>
          </article>

          <article className="r2p-zone-panel r2p-zone-panel--accent">
            <div className="r2p-zone-head">
              <span className="r2p-zone-badge r2p-zone-badge--accent">Zone Z3</span>
              <span className="r2p-zone-subtitle">Zero-Privilege Worker</span>
            </div>
            <h3>Isolated Sandbox A / B</h3>
            <p>
              <code>red2pr-worker</code> connects over TLS 1.3 mTLS with SPIFFE URI pinning and{" "}
              <code>lease_epoch</code> fencing to execute signed <code>S-21</code> jobs in ephemeral
              sandboxes.
            </p>
            <ul className="r2p-zone-list">
              <li>Zero GitHub/GitLab write tokens &amp; zero Meta API keys</li>
              <li>No shared host Docker socket; sanitized source archives</li>
              <li>External Ed25519 signing of execution results (ADR-035)</li>
            </ul>
          </article>
        </div>

        <div className="r2p-transparency-grid">
          <div className="r2p-transparency-card">
            <div className="r2p-transparency-title">
              <ShieldIcon size={18} />
              <h3>Role of Meta Technologies vs. Red2PR</h3>
            </div>
            <p>
              <strong>Meta Model API</strong> (<code>meta/muse-spark-1.3</code>,{" "}
              <code>meta/muse-wonder-1.0</code>) powers root-cause localization and candidate patch
              synthesis, while <strong>Meta Astryx</strong> (<code>0.7.4</code>) provides accessible
              Neutral-theme UI primitives. Red2PR independently engineers the{" "}
              <code>Z1/Z2/Z3</code> security architecture, pre-egress redaction, atomic USD budget
              ledger, <code>V-01–V-08</code> deterministic verifier, and Draft PR governance.
            </p>
          </div>

          <div className="r2p-transparency-card">
            <div className="r2p-transparency-title">
              <span className="r2p-status-dot" aria-hidden="true" />
              <h3>Truthful v0.1.0-beta.1 Readiness</h3>
            </div>
            <p>
              Units <code>U01–U30</code>, the 21-screen console, CLI, and provider adapters are
              implemented and locally/fixture verified (<code>399+</code> Python tests &amp;{" "}
              <code>104</code> frontend tests). Wave 6 (<code>U31–U36</code>: live multi-OS
              gVisor/Firecracker host certification, Chaos/DR drills, and <code>v1.0.0</code>{" "}
              release gates) remains scheduled next. Self-hosted custody requires outbound HTTPS
              consent to your configured Meta API endpoint when AI diagnosis is enabled.
            </p>
            <a
              href={DOC_LINKS.progressLedger}
              target="_blank"
              rel="noopener noreferrer"
              className="r2p-inline-doc-link"
            >
              <span>Inspect authoritative progress ledger (docs/23_PROGRESS.md)</span>
              <ArrowUpRightIcon size={14} />
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
