import { Button } from "@astryxdesign/core/Button";
import React from "react";
import { BrandLogo } from "../components/BrandLogo";
import { GitHubIcon } from "../components/Icons";
import { DOC_LINKS } from "../data/productContent";

export function SiteFooter(): React.JSX.Element {
  return (
    <footer className="r2p-footer">
      <div className="r2p-container">
        <div className="r2p-final-cta">
          <div className="r2p-final-cta-copy">
            <h2>Turn red builds into verified, human-reviewed Draft PRs.</h2>
            <p>
              Inspect the architecture, run the local source stack, or audit the 36-unit specification
              and security matrix on GitHub.
            </p>
          </div>
          <div className="r2p-final-cta-actions">
            <Button
              label="Explore Repository"
              variant="primary"
              size="lg"
              icon={<GitHubIcon size={16} />}
              href={DOC_LINKS.repo}
              target="_blank"
              rel="noopener noreferrer"
            />
            <Button
              label="Read User Guide"
              variant="secondary"
              size="lg"
              href={DOC_LINKS.quickstartGuide}
              target="_blank"
              rel="noopener noreferrer"
            />
          </div>
        </div>

        <div className="r2p-footer-grid">
          <div className="r2p-footer-brand-col">
            <a href="#top" className="r2p-brand-link" aria-label="Red2PR top of page">
              <BrandLogo decorative className="r2p-brand-svg" />
            </a>
            <p className="r2p-footer-tagline">
              Self-hosted CI failure investigation and deterministic repair platform. Proof over prose.
            </p>
          </div>

          <div className="r2p-footer-col">
            <h3>Platform</h3>
            <ul>
              <li>
                <a href="#why-proof">Why Proof Matters</a>
              </li>
              <li>
                <a href="#pipeline">6-Stage Lifecycle</a>
              </li>
              <li>
                <a href="#showcase">Product Tour</a>
              </li>
              <li>
                <a href="#architecture">Z1 / Z2 / Z3 Architecture</a>
              </li>
              <li>
                <a href="#quickstart">Local Quick Start</a>
              </li>
            </ul>
          </div>

          <div className="r2p-footer-col">
            <h3>Documentation</h3>
            <ul>
              <li>
                <a href={DOC_LINKS.quickstartGuide} target="_blank" rel="noopener noreferrer">
                  Quick Start &amp; User Guide
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.specIndex} target="_blank" rel="noopener noreferrer">
                  Specification Index
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.architecture} target="_blank" rel="noopener noreferrer">
                  System Architecture
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.verification} target="_blank" rel="noopener noreferrer">
                  Repair Verification (V-01–V-08)
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.metaAgent} target="_blank" rel="noopener noreferrer">
                  Meta Muse Agent Spec
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.cliOps} target="_blank" rel="noopener noreferrer">
                  CLI &amp; Operations
                </a>
              </li>
            </ul>
          </div>

          <div className="r2p-footer-col">
            <h3>Project &amp; Governance</h3>
            <ul>
              <li>
                <a href={DOC_LINKS.repo} target="_blank" rel="noopener noreferrer">
                  GitHub Repository
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.latestRelease} target="_blank" rel="noopener noreferrer">
                  Release v0.1.0-beta.1 &amp; Packages
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.license} target="_blank" rel="noopener noreferrer">
                  Apache-2.0 License
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.securityPolicy} target="_blank" rel="noopener noreferrer">
                  Security Policy
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.adrDecisions} target="_blank" rel="noopener noreferrer">
                  Architecture Decisions (ADR)
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.progressLedger} target="_blank" rel="noopener noreferrer">
                  Verification Progress
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.contributing} target="_blank" rel="noopener noreferrer">
                  Contributing
                </a>
              </li>
              <li>
                <a href={DOC_LINKS.changelog} target="_blank" rel="noopener noreferrer">
                  Changelog (v0.1.0-beta.1)
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="r2p-footer-legal">
          <p>
            <strong>Release &amp; License:</strong> Early-Access Beta Pre-Release{" "}
            <a href={DOC_LINKS.latestRelease} target="_blank" rel="noopener noreferrer">
              <code>v0.1.0-beta.1</code>
            </a>{" "}
            · Licensed under the{" "}
            <a href={DOC_LINKS.license} target="_blank" rel="noopener noreferrer">
              Apache License, Version 2.0
            </a>{" "}
            (
            <a href={DOC_LINKS.adrDecisions} target="_blank" rel="noopener noreferrer">
              ADR-052
            </a>
            ).
          </p>
          <p>
            Red2PR is an independent self-hosted software platform integrating the Meta Model API
            and the Meta Astryx design system. Not an official Meta product.
          </p>
        </div>
      </div>
    </footer>
  );
}
