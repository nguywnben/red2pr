import { Card } from "@astryxdesign/core/Card";
import { EmptyState as AstryxEmptyState } from "@astryxdesign/core/EmptyState";
import { Spinner } from "@astryxdesign/core/Spinner";
import React from "react";
import { useI18n, type MessageKey } from "../i18n";
import { HStack, Text, VStack } from "./AstryxComponents";
import { Button, type Red2PrButtonProps } from "./Button";

export const ALL_UX_STATE_KINDS = [
  "loading",
  "empty",
  "ready",
  "partial_evidence",
  "stale",
  "degraded",
  "offline",
  "unauthorized",
  "forbidden",
  "rate_limited",
  "approval_required",
  "unsupported_runtime",
  "reconciling",
  "interrupted",
  "error",
] as const;

export type UxStateKind = (typeof ALL_UX_STATE_KINDS)[number];
export type UxStateInput = UxStateKind | "success" | "permission_denied";

export type ProofStage =
  | "diagnosed"
  | "reproduced"
  | "locally_verified"
  | "remotely_verified"
  | "repro_unconfirmed"
  | "needs_human"
  | "unsupported"
  | "unverified";

export type RemoteCiOutcome = "pending" | "passed" | "failed" | null;

type ToneClass =
  | "red2pr-tone-success"
  | "red2pr-tone-warning"
  | "red2pr-tone-danger"
  | "red2pr-tone-info"
  | "red2pr-tone-neutral";

interface StateVisualMeta {
  readonly toneClass: ToneClass;
  readonly iconKind: "check" | "warn" | "error" | "info" | "clock" | "lock" | "offline";
  readonly badgeKey: MessageKey;
  readonly titleKey: MessageKey;
  readonly descriptionKey: MessageKey;
}

const STATE_META: Record<UxStateKind, StateVisualMeta> = {
  loading: {
    toneClass: "red2pr-tone-info",
    iconKind: "clock",
    badgeKey: "state.loading.badge",
    titleKey: "state.loading.title",
    descriptionKey: "state.loading.description",
  },
  empty: {
    toneClass: "red2pr-tone-neutral",
    iconKind: "info",
    badgeKey: "state.empty.badge",
    titleKey: "state.empty.title",
    descriptionKey: "state.empty.description",
  },
  ready: {
    toneClass: "red2pr-tone-success",
    iconKind: "check",
    badgeKey: "state.ready.badge",
    titleKey: "state.ready.title",
    descriptionKey: "state.ready.description",
  },
  partial_evidence: {
    toneClass: "red2pr-tone-warning",
    iconKind: "clock",
    badgeKey: "state.partial_evidence.badge",
    titleKey: "state.partial_evidence.title",
    descriptionKey: "state.partial_evidence.description",
  },
  stale: {
    toneClass: "red2pr-tone-warning",
    iconKind: "clock",
    badgeKey: "state.stale.badge",
    titleKey: "state.stale.title",
    descriptionKey: "state.stale.description",
  },
  degraded: {
    toneClass: "red2pr-tone-warning",
    iconKind: "warn",
    badgeKey: "state.degraded.badge",
    titleKey: "state.degraded.title",
    descriptionKey: "state.degraded.description",
  },
  offline: {
    toneClass: "red2pr-tone-danger",
    iconKind: "offline",
    badgeKey: "state.offline.badge",
    titleKey: "state.offline.title",
    descriptionKey: "state.offline.description",
  },
  unauthorized: {
    toneClass: "red2pr-tone-warning",
    iconKind: "lock",
    badgeKey: "state.unauthorized.badge",
    titleKey: "state.unauthorized.title",
    descriptionKey: "state.unauthorized.description",
  },
  forbidden: {
    toneClass: "red2pr-tone-danger",
    iconKind: "lock",
    badgeKey: "state.forbidden.badge",
    titleKey: "state.forbidden.title",
    descriptionKey: "state.forbidden.description",
  },
  rate_limited: {
    toneClass: "red2pr-tone-warning",
    iconKind: "clock",
    badgeKey: "state.rate_limited.badge",
    titleKey: "state.rate_limited.title",
    descriptionKey: "state.rate_limited.description",
  },
  approval_required: {
    toneClass: "red2pr-tone-info",
    iconKind: "lock",
    badgeKey: "state.approval_required.badge",
    titleKey: "state.approval_required.title",
    descriptionKey: "state.approval_required.description",
  },
  unsupported_runtime: {
    toneClass: "red2pr-tone-neutral",
    iconKind: "info",
    badgeKey: "state.unsupported_runtime.badge",
    titleKey: "state.unsupported_runtime.title",
    descriptionKey: "state.unsupported_runtime.description",
  },
  reconciling: {
    toneClass: "red2pr-tone-info",
    iconKind: "clock",
    badgeKey: "state.reconciling.badge",
    titleKey: "state.reconciling.title",
    descriptionKey: "state.reconciling.description",
  },
  interrupted: {
    toneClass: "red2pr-tone-warning",
    iconKind: "warn",
    badgeKey: "state.interrupted.badge",
    titleKey: "state.interrupted.title",
    descriptionKey: "state.interrupted.description",
  },
  error: {
    toneClass: "red2pr-tone-danger",
    iconKind: "error",
    badgeKey: "state.error.badge",
    titleKey: "state.error.title",
    descriptionKey: "state.error.description",
  },
};

function normalizeUxState(state: UxStateInput): UxStateKind {
  if (state === "success") {
    return "ready";
  }
  if (state === "permission_denied") {
    return "forbidden";
  }
  return state;
}

export function StatusGlyph({
  kind,
}: {
  readonly kind: StateVisualMeta["iconKind"];
}): React.JSX.Element {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {kind === "check" && <path d="M3 8.5L6.5 12L13 4.5" />}
      {kind === "warn" && (
        <>
          <path d="M8 2.5L14 13H2L8 2.5Z" />
          <path d="M8 6.5V9.5" />
          <circle cx="8" cy="11.5" r="0.5" fill="currentColor" />
        </>
      )}
      {kind === "error" && (
        <>
          <circle cx="8" cy="8" r="6" />
          <path d="M5.5 5.5L10.5 10.5M10.5 5.5L5.5 10.5" />
        </>
      )}
      {kind === "info" && (
        <>
          <circle cx="8" cy="8" r="6" />
          <path d="M8 7.5V11" />
          <circle cx="8" cy="5" r="0.5" fill="currentColor" />
        </>
      )}
      {kind === "clock" && (
        <>
          <circle cx="8" cy="8" r="6" />
          <path d="M8 4.8V8L10.4 9.6" />
        </>
      )}
      {kind === "lock" && (
        <>
          <rect x="3.5" y="7.5" width="9" height="6" rx="1.2" />
          <path d="M5.5 7.5V5.5C5.5 4.1 6.6 3 8 3C9.4 3 10.5 4.1 10.5 5.5V7.5" />
        </>
      )}
      {kind === "offline" && (
        <>
          <path d="M2 2L14 14" />
          <path d="M4.5 7.5C6.8 5.8 9.8 5.8 12 7.5" />
          <circle cx="8" cy="12" r="0.8" fill="currentColor" />
        </>
      )}
    </svg>
  );
}

export interface StateViewAction {
  readonly label: string;
  readonly onClick?: Red2PrButtonProps["onClick"];
  readonly href?: string;
  readonly variant?: Red2PrButtonProps["variant"];
  readonly isDisabled?: boolean;
  readonly isLoading?: boolean;
}

export interface StateViewProps {
  readonly state: UxStateInput;
  readonly title?: string;
  readonly description?: string;
  readonly correlationId?: string | null;
  readonly primaryAction?: StateViewAction;
  readonly secondaryAction?: StateViewAction;
  readonly children?: React.ReactNode;
}

export function StateView({
  state,
  title,
  description,
  correlationId,
  primaryAction,
  secondaryAction,
  children,
}: StateViewProps): React.JSX.Element {
  const { t } = useI18n();
  const normalized = normalizeUxState(state);
  const meta = STATE_META[normalized];

  const resolvedBadge = t(meta.badgeKey);
  const resolvedTitle = title ?? t(meta.titleKey);
  const resolvedDescription = description ?? t(meta.descriptionKey);

  const actionGroup =
    primaryAction || secondaryAction ? (
      <HStack gap={2} wrap="wrap">
        {primaryAction ? (
          <Button
            label={primaryAction.label}
            variant={primaryAction.variant ?? "primary"}
            onClick={primaryAction.onClick}
            href={primaryAction.href}
            isDisabled={primaryAction.isDisabled}
            isLoading={primaryAction.isLoading}
          />
        ) : null}
        {secondaryAction ? (
          <Button
            label={secondaryAction.label}
            variant={secondaryAction.variant ?? "secondary"}
            onClick={secondaryAction.onClick}
            href={secondaryAction.href}
            isDisabled={secondaryAction.isDisabled}
            isLoading={secondaryAction.isLoading}
          />
        ) : null}
      </HStack>
    ) : null;

  const correlationBadge = correlationId ? (
    <Text type="code" color="secondary">
      {t("state.correlationId", { correlationId })}
    </Text>
  ) : null;

  const isAlert = normalized === "error" || normalized === "offline" || normalized === "forbidden";
  return (
    <Card
      className="red2pr-state-view"
      data-ux-state={normalized}
      role={isAlert ? "alert" : "status"}
      aria-live={isAlert ? "assertive" : "polite"}
      aria-busy={normalized === "loading" ? true : undefined}
      variant="transparent"
      padding={4}
    >
      <HStack gap={3} vAlign="start">
        <HStack className="red2pr-state-icon" gap={0}>
          {normalized === "loading" ? (
            <Spinner size="md" aria-label={resolvedTitle} />
          ) : (
            <StatusGlyph kind={meta.iconKind} />
          )}
        </HStack>
        <VStack gap={2} width="100%">
          <VStack gap={1}>
            <Text type="supporting" weight="semibold">
              {resolvedBadge}
            </Text>
            {normalized === "empty" ? (
              <AstryxEmptyState
                headingLevel={3}
                isCompact
                title={resolvedTitle}
                description={resolvedDescription}
              />
            ) : (
              <>
                <Text as="h2" type="label" weight="semibold">
                  {resolvedTitle}
                </Text>
                <Text as="p" color="secondary">
                  {resolvedDescription}
                </Text>
              </>
            )}
          </VStack>
          {correlationBadge}
          {actionGroup}
          {children}
        </VStack>
      </HStack>
    </Card>
  );
}

export interface ProofStatusBadgeProps {
  readonly proofStage: ProofStage;
  readonly remoteCiOutcome?: RemoteCiOutcome;
}

/**
 * Renders Red2PR's non-negotiable proof-over-prose badge (`ADR-009`, `ADR-031`, `UX-03`).
 * Always pairs a distinct icon shape with explicit status text (never color alone)
 * and explicitly surfaces `Locally Verified · Remote CI Failed` when remote CI fails
 * after a passing local sandbox verification (`UX-03`).
 */
export function ProofStatusBadge({
  proofStage,
  remoteCiOutcome = null,
}: ProofStatusBadgeProps): React.JSX.Element {
  const { t } = useI18n();

  if (proofStage === "locally_verified" && remoteCiOutcome === "failed") {
    return (
      <span
        className="red2pr-badge-pill red2pr-tone-danger"
        data-testid="proof-badge-remote_ci_failed"
        data-proof-state="remote_ci_failed"
      >
        <StatusGlyph kind="error" />
        <span>{t("proof.remote_ci_failed")}</span>
      </span>
    );
  }

  const mapping: Record<
    ProofStage,
    { readonly key: MessageKey; readonly tone: ToneClass; readonly icon: StateVisualMeta["iconKind"] }
  > = {
    diagnosed: { key: "proof.diagnosed", tone: "red2pr-tone-info", icon: "info" },
    reproduced: { key: "proof.reproduced", tone: "red2pr-tone-info", icon: "clock" },
    locally_verified: { key: "proof.locally_verified", tone: "red2pr-tone-success", icon: "check" },
    remotely_verified: {
      key: "proof.remotely_verified",
      tone: "red2pr-tone-success",
      icon: "check",
    },
    repro_unconfirmed: {
      key: "proof.repro_unconfirmed",
      tone: "red2pr-tone-warning",
      icon: "warn",
    },
    needs_human: { key: "proof.needs_human", tone: "red2pr-tone-warning", icon: "warn" },
    unsupported: { key: "proof.unsupported", tone: "red2pr-tone-neutral", icon: "info" },
    unverified: { key: "proof.unverified", tone: "red2pr-tone-neutral", icon: "clock" },
  };

  const entry = mapping[proofStage];
  return (
    <span
      className={`red2pr-badge-pill ${entry.tone}`}
      data-testid={`proof-badge-${proofStage}`}
      data-proof-state={proofStage}
    >
      <StatusGlyph kind={entry.icon} />
      <span>{t(entry.key)}</span>
    </span>
  );
}
