import React from "react";

type NativeSelectProps = React.ComponentPropsWithoutRef<"select"> & {
  "data-testid"?: string;
};

/**
 * Shared Astryx-Neutral-styled select adapter: renders sleek token-aligned single
 * and multi-select controls while preserving native `<select>` / `<option>` semantics,
 * keyboard navigation, `<label htmlFor>`, and mobile OS pickers.
 */
export function SelectorControl({
  children,
  multiple = false,
  className,
  style,
  ...rest
}: NativeSelectProps): React.JSX.Element {
  if (multiple) {
    const multiClass = ["red2pr-native-multiselect", className].filter(Boolean).join(" ");
    return (
      <select multiple className={multiClass} style={style} {...rest}>
        {children}
      </select>
    );
  }

  const selectClass = ["red2pr-native-select", className].filter(Boolean).join(" ");
  return (
    <span className="red2pr-select-shell" style={style}>
      <select className={selectClass} {...rest}>
        {children}
      </select>
      <svg
        className="red2pr-select-chevron"
        viewBox="0 0 16 16"
        width="16"
        height="16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        focusable="false"
      >
        <path d="M4.5 6.25 8 9.75l3.5-3.5" />
      </svg>
    </span>
  );
}
