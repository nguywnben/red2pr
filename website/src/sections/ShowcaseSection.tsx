import { CodeBlock } from "@astryxdesign/core/CodeBlock";
import React, { useRef, useState } from "react";
import { CheckCircleIcon } from "../components/Icons";
import { ProductShot } from "../components/ProductShot";
import { SAMPLE_VERIFIED_DIFF, SHOWCASE_TABS } from "../data/productContent";

export function ShowcaseSection(): React.JSX.Element {
  const [activeId, setActiveId] = useState<string>(SHOWCASE_TABS[2]!.id);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const activeTab = SHOWCASE_TABS.find((tab) => tab.id === activeId) ?? SHOWCASE_TABS[0]!;

  const onTabKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, idx: number): void => {
    const total = SHOWCASE_TABS.length;
    let nextIdx: number | null = null;
    if (event.key === "ArrowRight") nextIdx = (idx + 1) % total;
    else if (event.key === "ArrowLeft") nextIdx = (idx - 1 + total) % total;
    else if (event.key === "Home") nextIdx = 0;
    else if (event.key === "End") nextIdx = total - 1;
    if (nextIdx !== null) {
      event.preventDefault();
      const target = SHOWCASE_TABS[nextIdx];
      if (target) {
        setActiveId(target.id);
        tabRefs.current[nextIdx]?.focus();
      }
    }
  };

  return (
    <section id="showcase" className="r2p-section" aria-labelledby="showcase-heading">
      <div className="r2p-container">
        <div className="r2p-section-header r2p-section-header--split">
          <div>
            <p className="r2p-kicker">Product Tour · Real Console Views</p>
            <h2 id="showcase-heading" className="r2p-section-title">
              Built on Meta Astryx Neutral for high-trust engineering review.
            </h2>
          </div>
          <p className="r2p-section-desc">
            Explore authentic screens from the 21-view Red2PR web console. Screenshots switch
            automatically between Light and Dark themes to match your active preference.
          </p>
        </div>

        <div className="r2p-showcase-tabs" role="tablist" aria-label="Product console views">
          {SHOWCASE_TABS.map((tab, idx) => {
            const selected = tab.id === activeTab.id;
            return (
              <button
                key={tab.id}
                ref={(el) => {
                  tabRefs.current[idx] = el;
                }}
                id={`showcase-tab-${tab.id}`}
                type="button"
                role="tab"
                tabIndex={selected ? 0 : -1}
                aria-selected={selected}
                aria-controls={`showcase-panel-${tab.id}`}
                className={`r2p-showcase-tab${selected ? " is-selected" : ""}`}
                onClick={() => setActiveId(tab.id)}
                onKeyDown={(e) => onTabKeyDown(e, idx)}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        <div
          id={`showcase-panel-${activeTab.id}`}
          role="tabpanel"
          aria-labelledby={`showcase-tab-${activeTab.id}`}
          className="r2p-showcase-body"
        >
          <div className="r2p-showcase-copy">
            <span className="r2p-mono-tag">{activeTab.eyebrow}</span>
            <h3>{activeTab.title}</h3>
            <p>{activeTab.description}</p>
            <ul className="r2p-check-list">
              {activeTab.highlights.map((point) => (
                <li key={point}>
                  <CheckCircleIcon size={16} />
                  <span>{point}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="r2p-showcase-visual">
            <ProductShot
              lightFile={activeTab.lightFile}
              darkFile={activeTab.darkFile}
              alt={activeTab.alt}
              width={activeTab.width}
              height={activeTab.height}
              routeLabel={activeTab.routeLabel}
              statusBadge={activeTab.statusBadge}
              statusTone={activeTab.statusTone}
            />
          </div>
        </div>

        <div className="r2p-diff-strip">
          <div className="r2p-diff-copy">
            <span className="r2p-mono-tag">Bounded Patch Artifact · Repair 0196f000</span>
            <h3>Every candidate diff stays minimal, inspectable, and sanitized.</h3>
            <p>
              Both the Red2PR web console and this preview use the official{" "}
              <code>@astryxdesign/core/CodeBlock</code> diff renderer—stripping untrusted control
              sequences before display while binding the exact SHA-256 patch digest to{" "}
              <code>EvidenceManifestV1</code>.
            </p>
          </div>
          <div className="r2p-diff-code">
            <CodeBlock
              code={SAMPLE_VERIFIED_DIFF}
              language="python"
              title="src/billing/proration.py · digest 9b4f18e20a71…"
              isDiff
              hasLineNumbers
              hasCopyButton
              size="sm"
              width="100%"
            />
          </div>
        </div>
      </div>
    </section>
  );
}
