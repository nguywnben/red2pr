import React from "react";
import { CAPABILITY_ITEMS } from "../data/productContent";

export function CapabilitiesSection(): React.JSX.Element {
  return (
    <section className="r2p-section r2p-section--bordered" aria-labelledby="capabilities-heading">
      <div className="r2p-container">
        <div className="r2p-section-header">
          <p className="r2p-kicker">Core Platform Capabilities</p>
          <h2 id="capabilities-heading" className="r2p-section-title">
            Engineered for teams that cannot compromise on custody or auditability.
          </h2>
        </div>

        <div className="r2p-cap-matrix">
          {CAPABILITY_ITEMS.map((item) => (
            <article key={item.title} className="r2p-cap-cell">
              <span className="r2p-mono-tag">{item.eyebrow}</span>
              <h3>{item.title}</h3>
              <p>{item.body}</p>
              <div className="r2p-cap-tags">
                {item.specs.map((spec) => (
                  <span key={spec} className="r2p-spec-pill">
                    {spec}
                  </span>
                ))}
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
