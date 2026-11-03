import React from "react";
import { CheckCircleIcon, CrossCircleIcon } from "../components/Icons";
import { CONTRAST_ROWS } from "../data/productContent";

export function ContrastSection(): React.JSX.Element {
  return (
    <section id="why-proof" className="r2p-section r2p-section--bordered" aria-labelledby="contrast-heading">
      <div className="r2p-container">
        <div className="r2p-section-header r2p-section-header--split">
          <div>
            <p className="r2p-kicker">Proof Over Prose</p>
            <h2 id="contrast-heading" className="r2p-section-title">
              Why AI patches without reproduction break engineering trust.
            </h2>
          </div>
          <p className="r2p-section-desc">
            Broken pipelines stall delivery—yet unguarded auto-fix bots introduce deeper hazards:
            patches guessed from partial logs, deleted assertions to force CI green, or leaked
            credentials in prompts. Red2PR treats model output as an untrusted hypothesis until
            deterministic executors prove it.
          </p>
        </div>

        <div className="r2p-ledger" role="table" aria-label="Comparison between conventional AI bots and Red2PR">
          <div role="rowgroup">
            <div className="r2p-ledger-head" role="row">
              <div role="columnheader" className="r2p-ledger-col-dim">
                Failure Mode
              </div>
              <div role="columnheader" className="r2p-ledger-col-bot">
                Unguarded AI Auto-Fix Bots
              </div>
              <div role="columnheader" className="r2p-ledger-col-r2p">
                Red2PR Evidence-Driven Platform
              </div>
            </div>
          </div>

          <div role="rowgroup">
            {CONTRAST_ROWS.map((row) => (
              <div key={row.dimension} className="r2p-ledger-row" role="row">
                <div role="cell" className="r2p-ledger-dim">
                  <strong>{row.dimension}</strong>
                  <span className="r2p-mono-tag">{row.guardrailRef}</span>
                </div>
                <div role="cell" className="r2p-ledger-bot">
                  <span className="r2p-ledger-icon r2p-ledger-icon--bad" aria-hidden="true">
                    <CrossCircleIcon size={16} />
                  </span>
                  <p>{row.conventionalBot}</p>
                </div>
                <div role="cell" className="r2p-ledger-r2p">
                  <span className="r2p-ledger-icon r2p-ledger-icon--good" aria-hidden="true">
                    <CheckCircleIcon size={16} />
                  </span>
                  <p>{row.red2prApproach}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
