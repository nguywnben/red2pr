from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from py_contracts.models import MetaChatCompletionRequest, MetaChatMessage
from red2pr_control.core.errors import DependencyUnavailableError
from red2pr_control.extensions.model_fallback import (
    select_fallback_model,
    transient_fallback_reason,
)
from red2pr_control.inference import meta_client
from red2pr_control.inference.meta_client import MetaMuseInferenceService


@pytest.mark.parametrize("reason", ["429", "503", "capability_unavailable"])
def test_fallback_uses_consented_available_same_vendor_secondary(reason: str) -> None:
    decision = select_fallback_model(
        requested_model="muse-wonder-1.0",
        primary_model="muse-wonder-1.0",
        secondary_model="muse-spark-1.3",
        reason=reason,  # type: ignore[arg-type]
        policy_enabled=True,
        consent_active=True,
        secondary_available=True,
        repository_scope_matches=True,
    )

    assert decision is not None
    assert decision.model_id == "muse-spark-1.3"
    assert decision.reason == reason


@pytest.mark.parametrize(
    "changes",
    [
        {"policy_enabled": False},
        {"consent_active": False},
        {"secondary_available": False},
        {"repository_scope_matches": False},
        {"requested_model": "muse-spark-1.3"},
        {"secondary_model": "muse-wonder-1.0"},
        {"reason": "401"},
    ],
)
def test_fallback_fails_closed_for_unapproved_or_nonretryable_cases(
    changes: dict[str, object],
) -> None:
    inputs: dict[str, object] = {
        "requested_model": "muse-wonder-1.0",
        "primary_model": "muse-wonder-1.0",
        "secondary_model": "muse-spark-1.3",
        "reason": "503",
        "policy_enabled": True,
        "consent_active": True,
        "secondary_available": True,
        "repository_scope_matches": True,
    }
    inputs.update(changes)

    assert select_fallback_model(**inputs) is None  # type: ignore[arg-type]


@pytest.mark.parametrize("status", [401, 403, 404, 500, 502, 504])
def test_only_429_and_503_are_transient_fallback_triggers(status: int) -> None:
    assert transient_fallback_reason(status_code=status) is None


@pytest.mark.parametrize(("status", "expected"), [(429, "429"), (503, "503")])
def test_exact_transient_statuses_are_triggered(status: int, expected: str) -> None:
    assert transient_fallback_reason(status_code=status) == expected


@pytest.mark.asyncio
async def test_runtime_fallback_preserves_session_budget_and_tool_schema(monkeypatch) -> None:
    now = datetime(2026, 11, 1, tzinfo=UTC)
    snapshot = SimpleNamespace(status="available")
    policy = SimpleNamespace(
        id="01960000-0000-7000-8000-000000000101",
        enabled=True,
        primary_model_profile_id="01960000-0000-7000-8000-000000000701",
        secondary_model_profile_id="01960000-0000-7000-8000-000000000702",
        version=1,
        updated_at=now,
    )
    observed: list[tuple[MetaChatCompletionRequest, dict[str, object]]] = []

    db_calls = 0

    class FakeDb:
        def __init__(self, result):
            self.result = result

        async def scalar(self, _statement):
            return self.result

    @asynccontextmanager
    async def fake_workspace_session(*_args, **_kwargs):
        nonlocal db_calls
        db_calls += 1
        yield FakeDb(snapshot if db_calls == 1 else policy)

    async def complete_once(request, **kwargs):
        observed.append((request, kwargs))
        if len(observed) == 1:
            raise DependencyUnavailableError(
                code="meta_upstream_503", detail="Temporary model unavailability."
            )
        return object()

    monkeypatch.setattr(meta_client, "workspace_rls_session", fake_workspace_session)
    service = SimpleNamespace(
        _fallback_policy_for_request=AsyncMock(
            return_value=(
                policy,
                "01960000-0000-7000-8000-000000000201",
                "muse-spark-1.3",
                "muse-wonder-1.0",
                policy.secondary_model_profile_id,
            )
        ),
        _session_factory=object(),
        _iam=SimpleNamespace(now=lambda: now),
        _complete_chat_once=AsyncMock(side_effect=complete_once),
    )
    request = MetaChatCompletionRequest(
        workspace_id="01960000-0000-7000-8000-000000000301",
        repository_id="01960000-0000-7000-8000-000000000401",
        repair_id="01960000-0000-7000-8000-000000000501",
        session_budget_account_id="01960000-0000-7000-8000-000000000601",
        model_profile_id=policy.primary_model_profile_id,
        model_id="muse-spark-1.3",
        messages=[MetaChatMessage(role="user", content="Inspect this test failure.")],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a declared workspace file.",
                    "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
                    "strict": True,
                },
            }
        ],
    )

    result = await MetaMuseInferenceService.complete_chat(service, request)

    assert result is not None
    assert len(observed) == 2
    primary, primary_kwargs = observed[0]
    secondary, secondary_kwargs = observed[1]
    assert primary_kwargs["allow_transient_fallback"] is True
    assert secondary_kwargs.get("allow_transient_fallback", False) is False
    assert primary.model_id == "muse-spark-1.3"
    assert secondary.model_id == "muse-wonder-1.0"
    assert secondary.model_profile_id == policy.secondary_model_profile_id
    assert primary.session_budget_account_id == secondary.session_budget_account_id
    assert primary.tools == secondary.tools
    assert secondary.consent_id == "01960000-0000-7000-8000-000000000201"
    assert policy.last_fallback_reason == "503"


@pytest.mark.asyncio
async def test_fallback_policy_matches_workspace_profile_ids_and_enabled_models(
    monkeypatch,
) -> None:
    primary_profile_id = "01960000-0000-7000-8000-000000000701"
    secondary_profile_id = "01960000-0000-7000-8000-000000000702"
    policy = SimpleNamespace(
        primary_model_profile_id=primary_profile_id,
        secondary_model_profile_id=secondary_profile_id,
        consent_id="01960000-0000-7000-8000-000000000201",
    )
    profiles = [
        SimpleNamespace(id=primary_profile_id, enabled=True, model_id="muse-spark-1.3"),
        SimpleNamespace(id=secondary_profile_id, enabled=True, model_id="muse-wonder-1.0"),
    ]
    snapshot = SimpleNamespace(id="available-secondary")

    class FakeDb:
        async def scalar(self, _statement):
            return policy if not hasattr(self, "policy_read") else snapshot

        async def scalars(self, _statement):
            self.policy_read = True
            return SimpleNamespace(all=lambda: profiles)

    @asynccontextmanager
    async def fake_workspace_session(*_args, **_kwargs):
        yield FakeDb()

    now = datetime(2026, 11, 1, tzinfo=UTC)
    service = SimpleNamespace(
        _session_factory=object(),
        _iam=SimpleNamespace(now=lambda: now),
        _ensure_workspace_config_in_tx=AsyncMock(return_value=SimpleNamespace(
            endpoint_base_url="https://api.meta.ai/v1", endpoint_registration_id=None
        )),
        _validate_meta_endpoint_in_tx=AsyncMock(
            return_value=("https://api.meta.ai/v1", None, None)
        ),
        _verify_active_inference_consent_in_tx=AsyncMock(
            return_value=(SimpleNamespace(id=policy.consent_id), None)
        ),
    )
    monkeypatch.setattr(meta_client, "workspace_rls_session", fake_workspace_session)
    request = MetaChatCompletionRequest(
        workspace_id="01960000-0000-7000-8000-000000000301",
        repository_id="01960000-0000-7000-8000-000000000401",
        session_budget_account_id="01960000-0000-7000-8000-000000000601",
        model_profile_id=primary_profile_id,
        model_id="muse-spark-1.3",
        messages=[MetaChatMessage(role="user", content="Use this profile.")],
    )

    resolved = await MetaMuseInferenceService._fallback_policy_for_request(service, request)

    assert resolved == (
        policy,
        policy.consent_id,
        "muse-spark-1.3",
        "muse-wonder-1.0",
        secondary_profile_id,
    )

    mismatched_profile_request = request.model_copy(
        update={"model_profile_id": secondary_profile_id}
    )
    rejected = await MetaMuseInferenceService._fallback_policy_for_request(
        service, mismatched_profile_request
    )
    assert rejected == (None, None, None, None, None)
