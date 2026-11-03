import React from "react";

export interface BrandLogoProps {
  readonly className?: string;
  readonly style?: React.CSSProperties;
  readonly label?: string;
  readonly decorative?: boolean;
  readonly markOnly?: boolean;
}

export function BrandLogo({
  className,
  style,
  label = "Red2PR",
  decorative = false,
  markOnly = false,
}: BrandLogoProps): React.JSX.Element {
  const a11yProps = decorative
    ? ({ "aria-hidden": true, focusable: "false" } as const)
    : ({ role: "img", "aria-label": label, focusable: "false" } as const);

  if (markOnly) {
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 48 48"
        className={className}
        style={{ color: "var(--color-text-primary)", ...style }}
        {...a11yProps}
      >
        <g fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round">
          <rect x="2" y="2" width="44" height="44" rx="13" strokeWidth="2" />
          <path d="M13 13v22M19 16h11M19 23h8M19 30h4" strokeWidth="2.2" />
          <path
            d="m27 30 3.2 3.2L37 25"
            stroke="var(--red2pr-brand-accent, #BC4D45)"
            strokeWidth="2.6"
          />
        </g>
      </svg>
    );
  }

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 172 48"
      className={className}
      style={{ color: "var(--color-text-primary)", ...style }}
      {...a11yProps}
    >
      <g fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="2" width="44" height="44" rx="13" strokeWidth="2" />
        <path d="M13 13v22M19 16h11M19 23h8M19 30h4" strokeWidth="2.2" />
        <path
          d="m27 30 3.2 3.2L37 25"
          stroke="var(--red2pr-brand-accent, #BC4D45)"
          strokeWidth="2.6"
        />
      </g>
      <text
        x="59"
        y="32.5"
        fill="currentColor"
        fontFamily="Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
        fontSize="25"
        fontWeight="650"
        letterSpacing="-1"
      >
        Red
      </text>
      <text
        x="105"
        y="32.5"
        fill="var(--red2pr-brand-accent, #BC4D45)"
        fontFamily="Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
        fontSize="25"
        fontWeight="650"
        letterSpacing="-1"
      >
        2PR
      </text>
    </svg>
  );
}
