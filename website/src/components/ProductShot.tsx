import React from "react";
import { useWebsiteTheme } from "../theme/ThemeProvider";

export interface ProductShotProps {
  readonly lightFile: string;
  readonly darkFile: string;
  readonly alt: string;
  readonly width: number;
  readonly height: number;
  readonly routeLabel: string;
  readonly statusBadge?: string;
  readonly statusTone?: "success" | "info" | "neutral";
  readonly priority?: boolean;
}

export function ProductShot({
  lightFile,
  darkFile,
  alt,
  width,
  height,
  routeLabel,
  statusBadge,
  statusTone = "success",
  priority = false,
}: ProductShotProps): React.JSX.Element {
  const { resolvedTheme } = useWebsiteTheme();
  const baseUrl = import.meta.env.BASE_URL;
  const activeFile = resolvedTheme === "dark" ? darkFile : lightFile;
  const src = `${baseUrl}screenshots/${activeFile}`;

  return (
    <figure className="r2p-browser-frame">
      <div className="r2p-browser-chrome" aria-hidden="true">
        <div className="r2p-browser-dots">
          <span />
          <span />
          <span />
        </div>
        <div className="r2p-browser-address">
          <span className="r2p-browser-lock">127.0.0.1:4280</span>
          <span className="r2p-browser-path">{routeLabel}</span>
        </div>
        {statusBadge ? (
          <span className={`r2p-chrome-pill r2p-chrome-pill--${statusTone}`}>{statusBadge}</span>
        ) : (
          <span className="r2p-browser-spacer" />
        )}
      </div>
      <div className="r2p-browser-viewport">
        <img
          src={src}
          alt={alt}
          width={width}
          height={height}
          loading={priority ? "eager" : "lazy"}
          decoding={priority ? "sync" : "async"}
          fetchPriority={priority ? "high" : "auto"}
          className="r2p-browser-image"
        />
      </div>
    </figure>
  );
}
