"""Typed U19 request and response contracts for repairs and approvals."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from py_contracts.primitives import InternalId, StrictContractModel, UtcTimestamp
from py_contracts.repairs import Approval, Repair


class RepairCreateRequest(StrictContractModel):
    run_id: InternalId
    mode: Literal["approval", "auto_repair"]
    reason: Annotated[str, Field(min_length=1, max_length=1000)]


class RepairActionRequest(StrictContractModel):
    action: Literal["pause", "resume", "cancel", "retry"]
    reason: Annotated[str, Field(min_length=1, max_length=1000)]
    expected_version: Annotated[int, Field(ge=1)]


class ApprovalDecisionRequest(StrictContractModel):
    decision: Literal["approve", "reject"]
    reason: Annotated[str | None, Field(max_length=1000)] = None
    expected_patch_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    expected_policy_revision: Annotated[int, Field(ge=1)]


class RepairPageResponse(StrictContractModel):
    items: list[Repair]
    next_cursor: str | None
    snapshot_at: UtcTimestamp


class ApprovalInboxEntry(StrictContractModel):
    approval: Approval
    requested_by: InternalId | None
    risk_level: str
    scope_description: str
    sensitive_change: bool
    decision: Literal["approve", "reject"] | None
    reason: str | None


class ApprovalPageResponse(StrictContractModel):
    items: list[ApprovalInboxEntry]
    next_cursor: str | None
    snapshot_at: UtcTimestamp
