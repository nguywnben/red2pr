from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from red2pr_control.core.errors import ConflictError, ForbiddenError
from red2pr_control.publisher import saga as publisher_module
from red2pr_control.publisher.saga import PublisherSaga


class _Db:
    def __init__(self, approval: Any) -> None:
        self.approval = approval

    async def scalar(self, _statement: Any) -> Any:
        return self.approval


@pytest.mark.asyncio
async def test_approved_handoff_seals_only_bindings_loaded_from_approval(monkeypatch) -> None:
    approval = SimpleNamespace(
        id="approval-id",
        intent_type="publish_draft_pr",
        status="approved",
        decision="approve",
        repair_id="repair-id",
        patch_digest="a" * 64,
        policy_revision=7,
        correlation_id="persisted-correlation",
    )

    @asynccontextmanager
    async def session(_factory: Any, *, workspace_id: str):
        assert workspace_id == "workspace-id"
        yield _Db(approval)

    monkeypatch.setattr(publisher_module, "workspace_rls_session", session)
    publisher = object.__new__(PublisherSaga)
    publisher._session_factory = object()
    publisher._intent_signing_key = b"k" * 32

    async def capture(intent: Any) -> Any:
        publisher._verify_seal(intent)
        assert intent.workspace_id == "workspace-id"
        assert intent.repair_id == "repair-id"
        assert intent.approval_id == "approval-id"
        assert intent.patch_digest == "a" * 64
        assert intent.policy_revision == 7
        assert intent.correlation_id == "request-correlation"
        return "persisted-publication"

    monkeypatch.setattr(publisher, "publish", capture)
    result = await publisher.publish_approved(
        workspace_id="workspace-id",
        approval_id="approval-id",
        correlation_id="request-correlation",
    )
    assert result == "persisted-publication"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"status": "pending", "decision": None}, ForbiddenError),
        ({"intent_type": "other"}, ConflictError),
    ],
)
async def test_unapproved_or_non_publication_handoff_is_rejected(
    monkeypatch, changes: dict[str, Any], error: type[Exception]
) -> None:
    values = {
        "id": "approval-id",
        "intent_type": "publish_draft_pr",
        "status": "approved",
        "decision": "approve",
        "repair_id": "repair-id",
        "patch_digest": "a" * 64,
        "policy_revision": 7,
        "correlation_id": "persisted-correlation",
    }
    values.update(changes)
    approval = SimpleNamespace(**values)

    @asynccontextmanager
    async def session(_factory: Any, *, workspace_id: str):
        yield _Db(approval)

    monkeypatch.setattr(publisher_module, "workspace_rls_session", session)
    publisher = object.__new__(PublisherSaga)
    publisher._session_factory = object()
    publisher._intent_signing_key = b"k" * 32

    with pytest.raises(error):
        await publisher.publish_approved(
            workspace_id="workspace-id",
            approval_id="approval-id",
            correlation_id="request-correlation",
        )
