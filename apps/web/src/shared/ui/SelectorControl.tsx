import React, { useMemo, useState } from "react";
import { MultiSelector } from "@astryxdesign/core/MultiSelector";
import { Selector } from "@astryxdesign/core/Selector";

type NativeOption = { value: string; label: string; disabled?: boolean };
type NativeSelectProps = Omit<React.ComponentPropsWithoutRef<"select">, "onChange"> & {
  onChange?: React.ChangeEventHandler<HTMLSelectElement>;
  "data-testid"?: string;
};

function optionText(node: React.ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(optionText).join("");
  if (React.isValidElement<{ children?: React.ReactNode }>(node)) return optionText(node.props.children);
  return "";
}

/** Shared native-select adapter: keeps existing form contracts while rendering Astryx selectors. */
export function SelectorControl({
  children,
  value,
  defaultValue,
  onChange,
  multiple = false,
  disabled,
  required,
  id,
  name,
  className,
  style,
  "data-testid": testId,
  "aria-label": ariaLabel,
}: NativeSelectProps): React.JSX.Element {
  const options = useMemo(() => React.Children.toArray(children).flatMap((child) => {
    if (!React.isValidElement<{ value?: string; disabled?: boolean; children?: React.ReactNode }>(child) || child.type !== "option") return [];
    const optionValue = child.props.value ?? optionText(child.props.children);
    return [{ value: optionValue, label: optionText(child.props.children), ...(child.props.disabled ? { disabled: true } : {}) } satisfies NativeOption];
  }), [children]);
  const initial: string | string[] = defaultValue === undefined
    ? (multiple ? [] : options[0]?.value ?? "")
    : Array.isArray(defaultValue) ? defaultValue.map(String) : String(defaultValue);
  const [uncontrolledValue, setUncontrolledValue] = useState<string | string[]>(initial);
  const currentValue = value ?? (multiple || options.some((option) => option.value === uncontrolledValue)
    ? uncontrolledValue
    : options[0]?.value ?? "");
  const label = ariaLabel ?? id?.replace(/[-_]+/g, " ") ?? "Select option";

  const notify = (next: string | string[]) => {
    if (value === undefined) setUncontrolledValue(next);
    if (!onChange) return;
    const selected = Array.isArray(next) ? next : [next];
    const selectedOptions = selected.map((selectedValue) => {
      const option = options.find((item) => item.value === selectedValue);
      return { value: selectedValue, text: option?.label ?? selectedValue } as HTMLOptionElement;
    });
    const target = { value: Array.isArray(next) ? selected.join(",") : next, selectedOptions } as unknown as HTMLSelectElement;
    onChange({ target, currentTarget: target } as React.ChangeEvent<HTMLSelectElement>);
  };

  const common = {
    label,
    options,
    hasClear: false as const,
    hasSearch: false,
    placeholder: "Select...",
    size: "md" as const,
    variant: "input" as const,
    isDisabled: disabled,
    isRequired: required,
    isLabelHidden: true,
    presentation: "popover" as const,
    id,
    htmlName: name,
    controlClassName: className,
    controlStyle: style,
    ...(typeof testId === "string" ? { "data-testid": testId } : {}),
  };

  return multiple ? (
    <MultiSelector {...common} value={Array.isArray(currentValue) ? currentValue : []} onChange={(next) => notify(next)} />
  ) : (
    <Selector {...common} value={Array.isArray(currentValue) ? currentValue[0] ?? "" : currentValue} onChange={(next) => notify(next)} />
  );
}
