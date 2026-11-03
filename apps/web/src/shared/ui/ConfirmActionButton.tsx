import React, { useState } from "react";
import { AlertDialog } from "./AstryxComponents";
import { Button, type ButtonVariant, type Red2PrButtonProps } from "./Button";

export interface ConfirmActionButtonProps
  extends Omit<Red2PrButtonProps, "href" | "onClick" | "type"> {
  readonly confirmationTitle: string;
  readonly confirmationDescription: string;
  readonly confirmationActionLabel: string;
  readonly confirmationActionVariant?: ButtonVariant;
  readonly onConfirm: () => unknown | Promise<unknown>;
  readonly onConfirmError?: (error: unknown) => void;
}

/** Button that requires a modal, accessible AlertDialog confirmation before running its action. */
export function ConfirmActionButton({
  label,
  confirmationTitle,
  confirmationDescription,
  confirmationActionLabel,
  confirmationActionVariant = "destructive",
  onConfirm,
  onConfirmError,
  ...buttonProps
}: ConfirmActionButtonProps): React.JSX.Element {
  const [isOpen, setIsOpen] = useState(false);
  const [isActionLoading, setIsActionLoading] = useState(false);

  const confirm = async (): Promise<void> => {
    setIsActionLoading(true);
    try {
      await onConfirm();
    } catch (error) {
      onConfirmError?.(error);
    } finally {
      setIsActionLoading(false);
      setIsOpen(false);
    }
  };

  return (
    <>
      <Button
        {...buttonProps}
        label={label}
        type="button"
        onClick={() => setIsOpen(true)}
      />
      <AlertDialog
        isOpen={isOpen}
        onOpenChange={setIsOpen}
        title={confirmationTitle}
        description={confirmationDescription}
        actionLabel={confirmationActionLabel}
        actionVariant={confirmationActionVariant}
        isActionLoading={isActionLoading}
        onAction={confirm}
      />
    </>
  );
}
