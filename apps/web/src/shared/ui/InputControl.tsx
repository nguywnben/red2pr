import React, { useState } from "react";
import { DateInput } from "@astryxdesign/core/DateInput";
import { NumberInput } from "@astryxdesign/core/NumberInput";
import { TextInput } from "@astryxdesign/core/TextInput";
import { TimeInput } from "@astryxdesign/core/TimeInput";

type InputValue = string | number | null;
type NativeInputProps = Omit<React.ComponentPropsWithoutRef<"input">, "onChange"> & {
  onChange?: React.ChangeEventHandler<HTMLInputElement>;
  "data-testid"?: string;
};

function asString(value: InputValue | readonly string[] | undefined): string {
  if (value === null || value === undefined || Array.isArray(value)) return "";
  return String(value);
}

function valueEvent(value: string): React.ChangeEvent<HTMLInputElement> {
  const target = { value } as HTMLInputElement;
  return { target, currentTarget: target } as React.ChangeEvent<HTMLInputElement>;
}

function numericConstraint(value: string | number | undefined): number | undefined {
  if (value === undefined || value === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/** Routes native text-like inputs through Astryx's typed field components. */
export function InputControl({
  type = "text",
  id,
  name,
  value,
  defaultValue,
  onChange,
  disabled,
  readOnly,
  required,
  min,
  max,
  step,
  style,
  placeholder,
  autoComplete,
  maxLength,
  minLength,
  pattern,
  inputMode,
  "aria-label": ariaLabel,
  "aria-describedby": ariaDescribedBy,
  "aria-labelledby": ariaLabelledBy,
  "data-testid": testId,
}: NativeInputProps): React.JSX.Element {
  const initial = defaultValue === undefined ? "" : String(defaultValue);
  const [uncontrolledValue, setUncontrolledValue] = useState<InputValue>(initial);
  const current = value === undefined ? uncontrolledValue : value;
  const label = ariaLabel ?? id?.replace(/[-_]+/g, " ") ?? "Input";
  const handleTextChange = (next: string, event: React.ChangeEvent<HTMLInputElement>) => {
    if (value === undefined) setUncontrolledValue(next);
    onChange?.(event);
  };
  const common = {
    id,
    label,
    isLabelHidden: true,
    size: "md" as const,
    statusVariant: "attached" as const,
    isDisabled: disabled,
    isReadOnly: readOnly,
    isRequired: required,
    hasClear: false,
    hasAutoFocus: false,
    placeholder,
    autoComplete,
    htmlName: name,
    // The old red2pr-control-input class styles native inputs. Astryx applies
    // controlClassName to its wrapper, so reusing that class overrides the
    // component's own border and focus-within ring. Keep the legacy full-width
    // layout through the component's width prop instead.
    width: "100%",
    controlStyle: style,
    ...(ariaDescribedBy ? { "aria-describedby": ariaDescribedBy } : {}),
    ...(ariaLabelledBy ? { "aria-labelledby": ariaLabelledBy } : {}),
    ...(testId ? { "data-testid": testId } : {}),
  };

  if (type === "number") {
    const numericValue = current === "" || current === null ? null : Number(current);
    return (
      <NumberInput
        {...common}
        value={Number.isFinite(numericValue) ? numericValue : null}
        min={numericConstraint(min)}
        max={numericConstraint(max)}
        step={numericConstraint(step)}
        hasClear
        onChange={(next) => {
          const text = next === null ? "" : String(next);
          if (value === undefined) setUncontrolledValue(text);
          onChange?.(valueEvent(text));
        }}
      />
    );
  }

  if (type === "date") {
    return (
      <DateInput
        {...common}
        value={(asString(current) || undefined) as React.ComponentProps<typeof DateInput>["value"]}
        min={(min === undefined || min === "" ? undefined : String(min)) as React.ComponentProps<typeof DateInput>["min"]}
        max={(max === undefined || max === "" ? undefined : String(max)) as React.ComponentProps<typeof DateInput>["max"]}
        onChange={(next) => {
          const text = next ?? "";
          if (value === undefined) setUncontrolledValue(text);
          onChange?.(valueEvent(text));
        }}
      />
    );
  }

  if (type === "time") {
    return (
      <TimeInput
        {...common}
        value={(asString(current) || undefined) as React.ComponentProps<typeof TimeInput>["value"]}
        min={(min === undefined || min === "" ? undefined : String(min)) as React.ComponentProps<typeof TimeInput>["min"]}
        max={(max === undefined || max === "" ? undefined : String(max)) as React.ComponentProps<typeof TimeInput>["max"]}
        onChange={(next) => {
          const text = next ?? "";
          if (value === undefined) setUncontrolledValue(text);
          onChange?.(valueEvent(text));
        }}
      />
    );
  }

  const textType = (type === "email" || type === "password" ? type : "text") as "text" | "email" | "password";
  return (
    <TextInput
      {...common}
      type={textType}
      value={asString(current)}
      onChange={handleTextChange}
      {...(maxLength !== undefined ? { maxLength } : {})}
      {...(minLength !== undefined ? { minLength } : {})}
      {...(pattern ? { pattern } : {})}
      {...(inputMode ? { inputMode } : type === "search" ? { role: "searchbox" as const } : type === "url" ? { inputMode: "url" as const } : {})}
    />
  );
}
