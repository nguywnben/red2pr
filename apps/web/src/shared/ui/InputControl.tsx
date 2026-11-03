import React from "react";

type NativeInputProps = React.ComponentPropsWithoutRef<"input"> & {
  "data-testid"?: string;
};

/**
 * Shared Astryx-Neutral-styled input adapter for externally labeled form controls.
 * Preserves native HTML5 / ARIA semantics (`<label htmlFor>`, `name`, `defaultValue`,
 * `min`/`max`/`step`, `aria-invalid`, and screen-reader accessible names) without
 * generating duplicate hidden `<label>` wrappers.
 */
export function InputControl({
  type = "text",
  className,
  ...rest
}: NativeInputProps): React.JSX.Element {
  const mergedClassName = ["red2pr-native-input", className].filter(Boolean).join(" ");
  return <input type={type} className={mergedClassName} {...rest} />;
}
