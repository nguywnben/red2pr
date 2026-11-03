import React from "react";
import { ArchitectureSection } from "./sections/ArchitectureSection";
import { CapabilitiesSection } from "./sections/CapabilitiesSection";
import { ContrastSection } from "./sections/ContrastSection";
import { HeroSection } from "./sections/HeroSection";
import { PipelineSection } from "./sections/PipelineSection";
import { QuickStartSection } from "./sections/QuickStartSection";
import { ShowcaseSection } from "./sections/ShowcaseSection";
import { SiteFooter } from "./sections/SiteFooter";
import { SiteHeader } from "./sections/SiteHeader";
import "./styles/landing.css";
import { WebsiteThemeProvider } from "./theme/ThemeProvider";

export function App(): React.JSX.Element {
  return (
    <WebsiteThemeProvider>
      <a href="#main-content" className="r2p-skip-link">
        Skip to main content
      </a>
      <SiteHeader />
      <main id="main-content" className="r2p-main">
        <HeroSection />
        <ContrastSection />
        <PipelineSection />
        <ShowcaseSection />
        <CapabilitiesSection />
        <ArchitectureSection />
        <QuickStartSection />
      </main>
      <SiteFooter />
    </WebsiteThemeProvider>
  );
}
