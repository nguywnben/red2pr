import {
  Dialog as AstryxDialog,
  DialogHeader,
  type DialogPurpose,
  type DialogVariant,
} from "@astryxdesign/core/Dialog";
import { Layout, LayoutContent, LayoutFooter } from "@astryxdesign/core/Layout";
import React, { useCallback, useEffect, useLayoutEffect, useRef } from "react";
import { useI18n } from "../i18n";

export type { DialogPurpose, DialogVariant };

export interface Red2PrDialogProps {
  readonly isOpen: boolean;
  readonly onOpenChange: (isOpen: boolean) => void;
  readonly title: string;
  readonly subtitle?: React.ReactNode;
  readonly purpose?: DialogPurpose;
  readonly variant?: DialogVariant;
  readonly width?: number | string;
  readonly maxHeight?: number | string;
  readonly correlationId?: string;
  readonly footer?: React.ReactNode;
  readonly children: React.ReactNode;
  readonly "data-testid"?: string;
}

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not(:disabled)",
  "input:not(:disabled)",
  "select:not(:disabled)",
  "textarea:not(:disabled)",
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

export function Dialog({
  isOpen,
  onOpenChange,
  title,
  subtitle,
  purpose = "info",
  variant = "standard",
  width = 520,
  maxHeight,
  correlationId,
  footer,
  children,
  "data-testid": dataTestId,
}: Red2PrDialogProps): React.JSX.Element | null {
  const { t } = useI18n();
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const openerRef = useRef<HTMLElement | null>(null);

  useLayoutEffect(() => {
    if (!isOpen || typeof document === "undefined") {
      return undefined;
    }
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body) {
      openerRef.current = active;
    }
    return undefined;
  }, [isOpen]);

  useEffect(() => {
    if (isOpen) {
      return undefined;
    }
    const opener = openerRef.current;
    if (opener && opener.isConnected) {
      opener.focus();
    }
    openerRef.current = null;
    return undefined;
  }, [isOpen]);

  const handleKeyDownCapture = useCallback(
    (event: React.KeyboardEvent<HTMLDialogElement>): void => {
      if (event.key !== "Tab") {
        return;
      }
      const root = dialogRef.current;
      if (!root) {
        return;
      }
      const focusables = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => !el.hasAttribute("disabled") && el.getAttribute("aria-hidden") !== "true",
      );
      if (focusables.length === 0) {
        event.preventDefault();
        return;
      }
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (!first || !last) {
        return;
      }
      const current = document.activeElement;
      if (event.shiftKey) {
        if (current === first || !root.contains(current)) {
          event.preventDefault();
          last.focus();
        }
      } else if (current === last || !root.contains(current)) {
        event.preventDefault();
        first.focus();
      }
    },
    [],
  );

  if (!isOpen) {
    return null;
  }

  return (
    <AstryxDialog
      ref={dialogRef}
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      purpose={purpose}
      variant={variant}
      width={width}
      maxHeight={maxHeight}
      onKeyDownCapture={handleKeyDownCapture}
      data-testid={dataTestId}
    >
      <Layout
        header={
          <DialogHeader
            title={title}
            subtitle={subtitle}
            onOpenChange={purpose === "required" ? undefined : onOpenChange}
            hasDivider
          />
        }
        content={
          <LayoutContent>
            {correlationId ? (
              <div style={{ marginBottom: 12 }}>
                <span className="red2pr-badge-pill red2pr-tone-neutral">
                  <code>{t("state.correlationId", { correlationId })}</code>
                </span>
              </div>
            ) : null}
            {children}
          </LayoutContent>
        }
        footer={footer ? <LayoutFooter hasDivider>{footer}</LayoutFooter> : undefined}
      />
    </AstryxDialog>
  );
}
