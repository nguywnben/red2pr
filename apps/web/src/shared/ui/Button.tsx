import {
  Button as AstryxButton,
  type ButtonProps as AstryxButtonProps,
  type ButtonSize,
  type ButtonVariant,
} from "@astryxdesign/core/Button";
import React from "react";
import { sanitizeNavigationHref } from "./sanitizeText";

export type { ButtonSize, ButtonVariant };

/**
 * Thin Red2PR adapter over source-verified `@astryxdesign/core/Button` (`0.7.4`).
 * Preserves Astryx's exact `label` / `isDisabled` / `isLoading` / `onClick` / `clickAction`
 * contract (zero invented `disabled` or `loading` aliases) while enforcing `SEC-040`
 * safe URL validation when `href` is supplied.
 */
export type Red2PrButtonProps = Omit<AstryxButtonProps, "xstyle" | "as">;

export function Button({
  href,
  target,
  rel,
  isDisabled,
  ...rest
}: Red2PrButtonProps): React.JSX.Element {
  const sanitizedHref = href !== undefined ? sanitizeNavigationHref(href) : undefined;
  const blockedUnsafeHref = href !== undefined && sanitizedHref === null;

  const safeRel =
    target === "_blank"
      ? rel
        ? `${rel} noopener noreferrer`
        : "noopener noreferrer"
      : rel;

  return (
    <>
      <AstryxButton
        {...rest}
        isDisabled={blockedUnsafeHref ? true : isDisabled}
        href={sanitizedHref ?? undefined}
        target={sanitizedHref ? target : undefined}
        rel={sanitizedHref ? safeRel : undefined}
      />
    </>
  );
}
