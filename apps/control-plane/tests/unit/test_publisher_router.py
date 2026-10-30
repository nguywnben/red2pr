from datetime import UTC, datetime

from red2pr_control.db.base import RemoteCiCheckModel
from red2pr_control.publisher.router import _remote_dto


def _remote_check() -> RemoteCiCheckModel:
    return RemoteCiCheckModel(
        id="019a2800-0000-7000-8000-000000000101",
        workspace_id="019a2800-0000-7000-8000-000000000102",
        publication_id="019a2800-0000-7000-8000-000000000103",
        head_sha="a" * 40,
        expected_check_set_digest="b" * 64,
        observations_json=[
            {
                "check_name": "build",
                "external_id": "check-1",
                "head_sha": "a" * 40,
                "status": "completed",
                "conclusion": "success",
            }
        ],
        outcome="passed",
        observed_at=datetime(2026, 10, 30, tzinfo=UTC),
    )


def test_remote_dto_fails_closed_when_observation_binding_differs_from_publication() -> None:
    dto = _remote_dto(
        _remote_check(),
        repository_id="019a2800-0000-7000-8000-000000000104",
        required_check_names=["build"],
        publication_check_set_digest="c" * 64,
    )

    assert dto is not None
    assert dto.outcome == "unknown"
    assert dto.required_check_names == []


def test_remote_dto_exposes_names_only_for_matching_immutable_binding() -> None:
    dto = _remote_dto(
        _remote_check(),
        repository_id="019a2800-0000-7000-8000-000000000104",
        required_check_names=["build"],
        publication_check_set_digest="b" * 64,
    )

    assert dto is not None
    assert dto.outcome == "passed"
    assert dto.required_check_names == ["build"]
    assert dto.observations[0].head_sha == "a" * 40
