import { Button } from "@astryxdesign/core/Button";
import React, { useEffect, useState } from "react";
import { BrandLogo } from "../components/BrandLogo";
import {
  CloseIcon,
  GitHubIcon,
  MenuIcon,
  MonitorIcon,
  MoonIcon,
  SunIcon,
} from "../components/Icons";
import { DOC_LINKS } from "../data/productContent";
import { useWebsiteTheme, type ThemeMode } from "../theme/ThemeProvider";

const NAV_ITEMS = [
  { label: "Why Proof", href: "#why-proof" },
  { label: "How It Works", href: "#pipeline" },
  { label: "Product Tour", href: "#showcase" },
  { label: "Architecture", href: "#architecture" },
  { label: "Quick Start", href: "#quickstart" },
] as const;

const THEME_OPTIONS: readonly { readonly value: ThemeMode; readonly label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "System" },
];

function renderThemeIcon(value: ThemeMode): React.JSX.Element {
  if (value === "light") return <SunIcon size={14} />;
  if (value === "dark") return <MoonIcon size={14} />;
  return <MonitorIcon size={14} />;
}

export function SiteHeader(): React.JSX.Element {
  const { mode, setMode } = useWebsiteTheme();
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    if (!mobileOpen) {
      return undefined;
    }
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        setMobileOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [mobileOpen]);

  return (
    <header className="r2p-header">
      <div className="r2p-container r2p-header-inner">
        <div className="r2p-header-brand">
          <a href="#top" className="r2p-brand-link" aria-label="Red2PR home">
            <BrandLogo decorative className="r2p-brand-svg" />
          </a>
          <a
            href={DOC_LINKS.latestRelease}
            target="_blank"
            rel="noopener noreferrer"
            className="r2p-version-tag"
            aria-label="Release v0.1.0-beta.1 on GitHub"
          >
            v0.1.0-beta.1
          </a>
        </div>

        <nav className="r2p-desktop-nav" aria-label="Primary navigation">
          {NAV_ITEMS.map((item) => (
            <a key={item.href} href={item.href} className="r2p-nav-link">
              {item.label}
            </a>
          ))}
          <a
            href={DOC_LINKS.specIndex}
            target="_blank"
            rel="noopener noreferrer"
            className="r2p-nav-link"
          >
            Docs
          </a>
        </nav>

        <div className="r2p-header-actions">
          <div className="r2p-theme-switch" role="group" aria-label="Color theme">
            {THEME_OPTIONS.map((opt) => {
              const active = mode === opt.value;
              return (
                <button
                  key={opt.value}
                  type="button"
                  className={`r2p-theme-btn${active ? " is-active" : ""}`}
                  aria-pressed={active}
                  aria-label={`${opt.label} theme`}
                  title={`${opt.label} theme`}
                  onClick={() => setMode(opt.value)}
                >
                  {renderThemeIcon(opt.value)}
                </button>
              );
            })}
          </div>

          <div className="r2p-header-cta-desktop">
            <Button
              label="GitHub"
              variant="ghost"
              size="sm"
              icon={<GitHubIcon size={15} />}
              href={DOC_LINKS.repo}
              target="_blank"
              rel="noopener noreferrer"
            />
            <Button label="Get Started" variant="primary" size="sm" href="#quickstart" />
          </div>

          <button
            type="button"
            className="r2p-mobile-toggle"
            aria-expanded={mobileOpen}
            aria-controls="r2p-mobile-drawer"
            aria-label={mobileOpen ? "Close navigation menu" : "Open navigation menu"}
            onClick={() => setMobileOpen((prev) => !prev)}
          >
            {mobileOpen ? <CloseIcon size={19} /> : <MenuIcon size={19} />}
          </button>
        </div>
      </div>

      {mobileOpen ? (
        <div id="r2p-mobile-drawer" className="r2p-mobile-drawer">
          <div className="r2p-container r2p-mobile-drawer-inner">
            <nav aria-label="Mobile navigation" className="r2p-mobile-nav-list">
              {NAV_ITEMS.map((item) => (
                <a
                  key={item.href}
                  href={item.href}
                  className="r2p-mobile-nav-link"
                  onClick={() => setMobileOpen(false)}
                >
                  {item.label}
                </a>
              ))}
              <a
                href={DOC_LINKS.specIndex}
                target="_blank"
                rel="noopener noreferrer"
                className="r2p-mobile-nav-link"
                onClick={() => setMobileOpen(false)}
              >
                Specification Docs
              </a>
            </nav>
            <div className="r2p-mobile-cta-row">
              <Button
                label="Get Started"
                variant="primary"
                size="md"
                width="100%"
                href="#quickstart"
                onClick={() => setMobileOpen(false)}
              />
              <Button
                label="View on GitHub"
                variant="secondary"
                size="md"
                width="100%"
                icon={<GitHubIcon size={15} />}
                href={DOC_LINKS.repo}
                target="_blank"
                rel="noopener noreferrer"
              />
            </div>
          </div>
        </div>
      ) : null}
    </header>
  );
}
