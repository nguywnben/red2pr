"""Canonical versioned domain events and SSE envelope contracts (S-19, docs/08).

Enforces the exact 24-event canonical v1 registry from docs/08_EVENTS_STATE_MACHINES.md
and allowlisted per-family payload schemas from docs/36_CANONICAL_CONTRACTS.md (S-19).
Retired legacy aliases (e.g. 'ci.failure_detected', 'repair.pr_created') are rejected.
"""

from __future__ import annotations

from typing import Any, Literal, Self

from pydantic import model_validator

from py_contracts.primitives import (
    BoundedName,
    InternalId,
    OpaqueProviderId,
    PositiveVersion,
    StrictContractModel,
    UtcTimestamp,
)

EventType = Literal[
    "provider.connection.created",
    "provider.run.failed",
    "provider.run.retried",
    "repair.session.created",
    "repair.diagnosed",
    "repair.reproduction.completed",
    "repair.patch.proposed",
    "repair.verification.completed",
    "repair.approval.requested",
    "repair.approval.decided",
    "repair.publication.created",
    "repair.remote_ci.completed",
    "repair.blocked",
    "repair.cancelled",
    "worker.offline",
    "worker.quarantined",
    "integration.disconnected",
    "usage.budget.exceeded",
    "security.policy.denied",
    "backup.failed",
    "release.update_available",
    "identity.permission_revoked",
    "notification.delivery.failed",
    "operations.restore.completed",
]

_INSTANCE_LEVEL_EVENTS: frozenset[str] = frozenset(
    {
        "worker.offline",
        "worker.quarantined",
        "backup.failed",
        "release.update_available",
        "operations.restore.completed",
    }
)


class ProviderConnectionEventPayload(StrictContractModel):
    connection_id: InternalId
    status: BoundedName


class RunEventPayload(StrictContractModel):
    run_id: InternalId
    attempt_key: OpaqueProviderId
    head_sha: BoundedName


class RepairPhaseEventPayload(StrictContractModel):
    repair_id: InternalId
    state: BoundedName
    reason_code: BoundedName | None = None


class ReproVerificationEventPayload(StrictContractModel):
    repair_id: InternalId
    outcome: BoundedName
    manifest_id: InternalId | None = None


class ApprovalEventPayload(StrictContractModel):
    approval_id: InternalId
    status: BoundedName
    expires_at: UtcTimestamp | None = None


class PublicationEventPayload(StrictContractModel):
    publication_id: InternalId
    status: BoundedName


class RemoteCiEventPayload(StrictContractModel):
    publication_id: InternalId
    head_sha: BoundedName
    outcome: BoundedName


class WorkerEventPayload(StrictContractModel):
    worker_id: InternalId
    status: BoundedName


class BudgetEventPayload(StrictContractModel):
    budget_id: InternalId
    reason_code: BoundedName


class SecurityIdentityEventPayload(StrictContractModel):
    target_id: InternalId
    reason_code: BoundedName


class OperationsEventPayload(StrictContractModel):
    operation_id: InternalId
    status: BoundedName


class DeliveryEventPayload(StrictContractModel):
    delivery_id: InternalId
    reason_code: BoundedName


EventPayload = (
    ProviderConnectionEventPayload
    | RunEventPayload
    | RepairPhaseEventPayload
    | ReproVerificationEventPayload
    | ApprovalEventPayload
    | PublicationEventPayload
    | RemoteCiEventPayload
    | WorkerEventPayload
    | BudgetEventPayload
    | SecurityIdentityEventPayload
    | OperationsEventPayload
    | DeliveryEventPayload
)

_EVENT_TYPE_TO_PAYLOAD_MODEL: dict[str, type[StrictContractModel]] = {
    "provider.connection.created": ProviderConnectionEventPayload,
    "integration.disconnected": ProviderConnectionEventPayload,
    "provider.run.failed": RunEventPayload,
    "provider.run.retried": RunEventPayload,
    "repair.session.created": RepairPhaseEventPayload,
    "repair.diagnosed": RepairPhaseEventPayload,
    "repair.patch.proposed": RepairPhaseEventPayload,
    "repair.blocked": RepairPhaseEventPayload,
    "repair.cancelled": RepairPhaseEventPayload,
    "repair.reproduction.completed": ReproVerificationEventPayload,
    "repair.verification.completed": ReproVerificationEventPayload,
    "repair.approval.requested": ApprovalEventPayload,
    "repair.approval.decided": ApprovalEventPayload,
    "repair.publication.created": PublicationEventPayload,
    "repair.remote_ci.completed": RemoteCiEventPayload,
    "worker.offline": WorkerEventPayload,
    "worker.quarantined": WorkerEventPayload,
    "usage.budget.exceeded": BudgetEventPayload,
    "security.policy.denied": SecurityIdentityEventPayload,
    "identity.permission_revoked": SecurityIdentityEventPayload,
    "backup.failed": OperationsEventPayload,
    "release.update_available": OperationsEventPayload,
    "operations.restore.completed": OperationsEventPayload,
    "notification.delivery.failed": DeliveryEventPayload,
}


class EventEnvelope(StrictContractModel):
    """S-19 canonical domain event and SSE frame payload."""

    event_id: InternalId
    schema_version: Literal[1] = 1
    type: EventType
    occurred_at: UtcTimestamp
    workspace_id: InternalId | None = None
    repository_id: InternalId | None = None
    session_id: InternalId | None = None
    aggregate_id: InternalId
    aggregate_version: PositiveVersion
    correlation_id: BoundedName
    causation_id: InternalId | None = None
    payload: EventPayload

    @model_validator(mode="before")
    @classmethod
    def _coerce_payload_by_event_type(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        evt_type = data.get("type")
        raw_payload = data.get("payload")
        if isinstance(evt_type, str) and evt_type in _EVENT_TYPE_TO_PAYLOAD_MODEL:
            target_cls = _EVENT_TYPE_TO_PAYLOAD_MODEL[evt_type]
            if isinstance(raw_payload, dict):
                copied = dict(data)
                copied["payload"] = target_cls.model_validate(raw_payload)
                return copied
        return data

    @model_validator(mode="after")
    def _validate_scope_and_payload_family(self) -> Self:
        if self.workspace_id is None and self.type not in _INSTANCE_LEVEL_EVENTS:
            raise ValueError(
                f"Event type {self.type!r} is workspace-scoped and requires workspace_id"
            )
        expected_cls = _EVENT_TYPE_TO_PAYLOAD_MODEL[self.type]
        if not isinstance(self.payload, expected_cls):
            raw = self.payload.model_dump(mode="python")
            object.__setattr__(self, "payload", expected_cls.model_validate(raw))
        return self


__all__ = [
    "ApprovalEventPayload",
    "BudgetEventPayload",
    "DeliveryEventPayload",
    "EventEnvelope",
    "EventPayload",
    "EventType",
    "OperationsEventPayload",
    "ProviderConnectionEventPayload",
    "PublicationEventPayload",
    "RemoteCiEventPayload",
    "RepairPhaseEventPayload",
    "ReproVerificationEventPayload",
    "RunEventPayload",
    "SecurityIdentityEventPayload",
    "WorkerEventPayload",
]
