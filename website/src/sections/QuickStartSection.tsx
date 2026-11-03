import { Button } from "@astryxdesign/core/Button";
import { CodeBlock } from "@astryxdesign/core/CodeBlock";
import React, { useRef, useState } from "react";
import { ArrowUpRightIcon } from "../components/Icons";
import { DOC_LINKS, QUICKSTART_TABS } from "../data/productContent";

export function QuickStartSection(): React.JSX.Element {
  const [selectedId, setSelectedId] = useState<string>(QUICKSTART_TABS[0]!.id);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const current = QUICKSTART_TABS.find((item) => item.id === selectedId) ?? QUICKSTART_TABS[0]!;

  const onTabKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, idx: number): void => {
    const total = QUICKSTART_TABS.length;
    let nextIdx: number | null = null;
    if (event.key === "ArrowRight") nextIdx = (idx + 1) % total;
    else if (event.key === "ArrowLeft") nextIdx = (idx - 1 + total) % total;
    else if (event.key === "Home") nextIdx = 0;
    else if (event.key === "End") nextIdx = total - 1;
    if (nextIdx !== null) {
      event.preventDefault();
      const target = QUICKSTART_TABS[nextIdx];
      if (target) {
        setSelectedId(target.id);
        tabRefs.current[nextIdx]?.focus();
      }
    }
  };

  return (
    <section id="quickstart" className="r2p-section r2p-section--bordered" aria-labelledby="quickstart-heading">
      <div className="r2p-container">
        <div className="r2p-quickstart-layout">
          <div className="r2p-quickstart-info">
            <p className="r2p-kicker">Verified Local Quick Start</p>
            <h2 id="quickstart-heading" className="r2p-section-title">
              Evaluate the full single-origin stack from source in minutes.
            </h2>
            <p className="r2p-section-desc">
              The verified quickstart launcher provisions a confined PostgreSQL 16 instance with
              Row-Level Security, runs migrations <code>0001..0025</code>, builds the Astryx web
              console, and starts the Control Plane on <code>http://127.0.0.1:4280</code>.
            </p>

            <div className="r2p-prereq-box">
              <span className="r2p-callout-label">Host Prerequisites</span>
              <ul className="r2p-prereq-list">
                <li>
                  <strong>Git</strong> &amp; <strong>Python 3.12.x</strong> with{" "}
                  <code>uv</code>
                </li>
                <li>
                  <strong>Node.js &gt;= 22.12.0</strong> &amp; <strong>pnpm 9.15.x</strong>
                </li>
              </ul>
            </div>

            <ol className="r2p-boot-steps">
              <li>
                <strong>1. Launch stack:</strong> Run the script for your OS; state persists cleanly
                under <code>.local-data/red2pr</code>.
              </li>
              <li>
                <strong>2. Claim owner account:</strong> Open the printed one-use 15-minute{" "}
                <code>/setup#bootstrap_token=...</code> URL.
              </li>
              <li>
                <strong>3. Connect safely:</strong> Complete the 10-phase Setup Wizard; new
                repositories default to read-only <code>Monitor</code> mode.
              </li>
            </ol>

            <div className="r2p-quickstart-links">
              <Button
                label="Full Quick Start & User Guide"
                variant="secondary"
                size="md"
                endContent={<ArrowUpRightIcon size={14} />}
                href={DOC_LINKS.quickstartGuide}
                target="_blank"
                rel="noopener noreferrer"
              />
              <Button
                label="Release v0.1.0-beta.1 & Packages"
                variant="ghost"
                size="md"
                endContent={<ArrowUpRightIcon size={14} />}
                href={DOC_LINKS.latestRelease}
                target="_blank"
                rel="noopener noreferrer"
              />
            </div>
          </div>

          <div className="r2p-quickstart-terminal">
            <div className="r2p-os-tabs" role="tablist" aria-label="Quick start operating system commands">
              {QUICKSTART_TABS.map((tab, idx) => {
                const active = tab.id === current.id;
                return (
                  <button
                    key={tab.id}
                    ref={(el) => {
                      tabRefs.current[idx] = el;
                    }}
                    id={`qs-tab-${tab.id}`}
                    type="button"
                    role="tab"
                    tabIndex={active ? 0 : -1}
                    aria-selected={active}
                    aria-controls={`qs-panel-${tab.id}`}
                    className={`r2p-os-tab${active ? " is-selected" : ""}`}
                    onClick={() => setSelectedId(tab.id)}
                    onKeyDown={(e) => onTabKeyDown(e, idx)}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </div>

            <div
              id={`qs-panel-${current.id}`}
              role="tabpanel"
              aria-labelledby={`qs-tab-${current.id}`}
              className="r2p-os-panel"
            >
              <CodeBlock
                code={current.code}
                language={current.language}
                title={current.title}
                hasLanguageLabel={false}
                hasCopyButton
                size="sm"
                width="100%"
              />
              <p className="r2p-os-caption">{current.caption}</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
