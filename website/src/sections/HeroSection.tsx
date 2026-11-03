import { Button } from "@astryxdesign/core/Button";
import React from "react";
import { ArrowUpRightIcon, GitHubIcon } from "../components/Icons";
import { ProductShot } from "../components/ProductShot";
import { DOC_LINKS, HERO_PILLARS } from "../data/productContent";

export function HeroSection(): React.JSX.Element {
  return (
    <section id="top" className="r2p-hero" aria-labelledby="hero-heading">
      <div className="r2p-container">
        <div className="r2p-hero-copy">
          <div className="r2p-eyebrow-row">
            <span className="r2p-status-dot" aria-hidden="true" />
            <span>Self-Hosted CI Repair</span>
            <span className="r2p-eyebrow-sep" aria-hidden="true">
              ·
            </span>
            <span>Meta Muse + Astryx</span>
          </div>

          <h1 id="hero-heading" className="r2p-hero-title">
            Autonomous CI repair,{" "}
            <span className="r2p-text-brand">proven before every Draft PR.</span>
          </h1>

          <p className="r2p-hero-lead">
            Red2PR investigates failed GitHub Actions and GitLab CI runs, localizes root causes
            with Meta Muse, reproduces the exact failure inside a zero-credential sandbox, and
            verifies red-to-green patches before opening a human-reviewed Draft PR.
          </p>

          <div className="r2p-hero-actions">
            <Button label="Quick Start Locally" variant="primary" size="lg" href="#quickstart" />
            <Button
              label="View on GitHub"
              variant="secondary"
              size="lg"
              icon={<GitHubIcon size={16} />}
              href={DOC_LINKS.repo}
              target="_blank"
              rel="noopener noreferrer"
            />
            <a
              href={DOC_LINKS.specIndex}
              target="_blank"
              rel="noopener noreferrer"
              className="r2p-text-action"
            >
              <span>Explore 44-doc specification</span>
              <ArrowUpRightIcon size={15} />
            </a>
          </div>
        </div>

        <dl className="r2p-pillars-strip" aria-label="Core architectural guarantees">
          {HERO_PILLARS.map((pillar) => (
            <div key={pillar.code} className="r2p-pillar-cell">
              <dt className="r2p-pillar-code">{pillar.code}</dt>
              <dd className="r2p-pillar-body">
                <strong>{pillar.title}</strong>
                <span>{pillar.detail}</span>
              </dd>
            </div>
          ))}
        </dl>

        <div className="r2p-hero-stage">
          <ProductShot
            lightFile="hero-overview-light.png"
            darkFile="hero-overview-dark.png"
            alt="Red2PR Workspace Overview showing the 8-stage deterministic repair funnel, explicit stage denominators, outcome classification, and USD Meta Muse cost ledger"
            width={2720}
            height={2344}
            routeLabel="/w/acme-platform/overview"
            statusBadge="locally_verified → remotely_verified"
            statusTone="success"
            priority
          />
        </div>
      </div>
    </section>
  );
}
