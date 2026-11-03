import React, { useRef, useState } from "react";
import { PIPELINE_STAGES } from "../data/productContent";

export function PipelineSection(): React.JSX.Element {
  const [activeIndex, setActiveIndex] = useState(2);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const activeStage = PIPELINE_STAGES[activeIndex] ?? PIPELINE_STAGES[0]!;

  const onTabKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, idx: number): void => {
    const total = PIPELINE_STAGES.length;
    let nextIdx: number | null = null;
    if (event.key === "ArrowRight") nextIdx = (idx + 1) % total;
    else if (event.key === "ArrowLeft") nextIdx = (idx - 1 + total) % total;
    else if (event.key === "Home") nextIdx = 0;
    else if (event.key === "End") nextIdx = total - 1;
    if (nextIdx !== null) {
      event.preventDefault();
      setActiveIndex(nextIdx);
      tabRefs.current[nextIdx]?.focus();
    }
  };

  return (
    <section id="pipeline" className="r2p-section r2p-section--subtle" aria-labelledby="pipeline-heading">
      <div className="r2p-container">
        <div className="r2p-section-header">
          <p className="r2p-kicker">End-to-End Repair Lifecycle</p>
          <h2 id="pipeline-heading" className="r2p-section-title">
            Six deterministic gates between a red build and a Draft PR.
          </h2>
          <p className="r2p-section-desc">
            Every repair session advances through explicit proof grades—and abstains cleanly
            whenever a failure is transient, unreproducible, or outside repository policy.
          </p>
        </div>

        <div className="r2p-pipeline-rail" role="tablist" aria-label="Red2PR repair lifecycle stages">
          {PIPELINE_STAGES.map((stage, idx) => {
            const selected = idx === activeIndex;
            return (
              <button
                key={stage.id}
                ref={(el) => {
                  tabRefs.current[idx] = el;
                }}
                id={`pipeline-tab-${stage.id}`}
                type="button"
                role="tab"
                tabIndex={selected ? 0 : -1}
                aria-selected={selected}
                aria-controls={`pipeline-panel-${stage.id}`}
                className={`r2p-stage-tab${selected ? " is-selected" : ""}`}
                onClick={() => setActiveIndex(idx)}
                onKeyDown={(e) => onTabKeyDown(e, idx)}
              >
                <span className="r2p-stage-num">{stage.step}</span>
                <span className="r2p-stage-name">{stage.shortTitle}</span>
                <span className={`r2p-stage-proof r2p-stage-proof--${stage.proofTone}`}>
                  {stage.proofGrade.replace(/^proof:\s*/, "")}
                </span>
              </button>
            );
          })}
        </div>

        <div
          id={`pipeline-panel-${activeStage.id}`}
          role="tabpanel"
          aria-labelledby={`pipeline-tab-${activeStage.id}`}
          className="r2p-stage-detail"
        >
          <div className="r2p-stage-detail-main">
            <div className="r2p-stage-detail-meta">
              <span className="r2p-mono-tag">Stage {activeStage.step} / 06</span>
              <span className={`r2p-proof-pill r2p-proof-pill--${activeStage.proofTone}`}>
                {activeStage.proofGrade}
              </span>
            </div>
            <h3>{activeStage.title}</h3>
            <p className="r2p-stage-summary">{activeStage.summary}</p>

            <div className="r2p-stage-artifacts" aria-label="Persisted stage outputs">
              {activeStage.artifacts.map((item) => (
                <span key={item} className="r2p-artifact-chip">
                  {item}
                </span>
              ))}
            </div>
          </div>

          <div className="r2p-stage-detail-side">
            <div className="r2p-callout-box">
              <span className="r2p-callout-label">Security &amp; Proof Invariant</span>
              <p>{activeStage.invariant}</p>
            </div>
            <div className="r2p-callout-box r2p-callout-box--muted">
              <span className="r2p-callout-label">Unconfirmed / Abstention Path</span>
              <p>{activeStage.abstentionPath}</p>
            </div>
          </div>
        </div>

        <div className="r2p-proof-ladder" aria-label="Proof progression versus explicit abstention states">
          <div className="r2p-proof-ladder-group">
            <span className="r2p-proof-ladder-title">Proof progression</span>
            <div className="r2p-proof-steps">
              <code>none</code>
              <span aria-hidden="true">→</span>
              <code>baseline_confirmed</code>
              <span aria-hidden="true">→</span>
              <code>locally_verified</code>
              <span aria-hidden="true">→</span>
              <code>remotely_verified</code>
            </div>
          </div>
          <div className="r2p-proof-ladder-group">
            <span className="r2p-proof-ladder-title">First-class safe stops</span>
            <div className="r2p-proof-steps">
              <code>repro_unconfirmed</code>
              <span aria-hidden="true">·</span>
              <code>flaky_or_infra_abstained</code>
              <span aria-hidden="true">·</span>
              <code>policy_gate_held</code>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
