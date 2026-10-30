"""Contract and negative security tests for FastAPI /api/v1 shell & OpenAPI v1 export (U02).

Covers:
- A-18 public minimal liveness GET /api/v1/system/health (200, X-Correlation-Id, zero secret leak)
- Deterministic contracts/openapi/openapi.v1.json parity & S-01..S-22 schema registration
- S-03 application/problem+json handlers across 400, 401, 403, 404, 409, 410, 412, 422,
  429 (with Retry-After), 503, and 500 (stack-trace & host-path stripping)
- Extra-field rejection (422), malformed JSON rejection (400), and >1 MiB body limit rejection
"""

from __future__ import annotations

import json
import pathlib

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from py_contracts.primitives import MAX_JSON_BODY_BYTES, StrictContractModel
from red2pr_control.api.app import create_app, render_openapi_v1_json
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    BadRequestError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    PreconditionFailedError,
    RateLimitedError,
    Red2PrError,
    UnauthorizedError,
    UnprocessableEntityError,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR

REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]


class _ProbeInput(StrictContractModel):
    name: str


def _build_probe_client() -> TestClient:
    app = create_app()
    probe = APIRouter(prefix="/api/v1/_contract_probes", include_in_schema=False)

    @probe.post("/echo")
    async def _echo(payload: _ProbeInput) -> dict[str, str]:
        return {"name": payload.name}

    @probe.get("/raise/{status_code}")
    async def _raise_domain_error(status_code: int) -> dict[str, str]:
        mapping: dict[int, Red2PrError] = {
            400: BadRequestError(detail="Malformed input parameter"),
            401: UnauthorizedError(detail="Authentication required"),
            403: ForbiddenError(detail="Operation denied by policy"),
            404: NotFoundError(detail="Resource not found"),
            409: ConflictError(code="version_conflict", detail="Stale resource version"),
            410: GoneError(code="cursor_expired", detail="SSE replay cursor expired"),
            412: PreconditionFailedError(detail="If-Match precondition failed"),
            422: UnprocessableEntityError(detail="Semantic validation failed"),
            429: RateLimitedError(detail="Rate limit exceeded", retry_after_seconds=15),
            503: DependencyUnavailableError(detail="Upstream dependency unavailable"),
        }
        if status_code == 500:
            raise RuntimeError("Unhandled crash at /var/lib/red2pr/db.sock token=ghp_" + "X" * 36)
        raise mapping[status_code]

    app.include_router(probe)
    return TestClient(app, raise_server_exceptions=False)


def test_a18_system_health_returns_minimal_liveness_and_correlation_id() -> None:
    client = TestClient(create_app())
    resp = client.get(
        "/api/v1/system/health",
        headers={"X-Correlation-Id": "corr-health-check-01"},
    )
    assert resp.status_code == 200
    assert resp.headers["X-Correlation-Id"] == "corr-health-check-01"
    body = resp.json()
    assert set(body.keys()) == {"status", "service", "api_version", "timestamp"}
    assert body["status"] == "ok"
    assert body["service"] == "red2pr-control-plane"
    assert body["api_version"] == "v1"
    assert body["timestamp"].endswith("Z")


def test_openapi_v1_export_is_deterministic_and_registers_all_canonical_schemas() -> None:
    rendered = render_openapi_v1_json()
    committed_path = REPO_ROOT / "contracts" / "openapi" / "openapi.v1.json"
    assert committed_path.is_file(), f"Missing exported OpenAPI file: {committed_path}"
    assert committed_path.read_text(encoding="utf-8") == rendered

    parsed = json.loads(rendered)
    assert parsed["info"]["version"] == "1.0.0"
    assert "/api/v1/system/health" in parsed["paths"]
    assert "/api/v1/workspaces/{ws}/publications" in parsed["paths"]
    assert "/api/v1/workspaces/{ws}/publications/{publication_id}" in parsed["paths"]
    assert (
        "/api/v1/workspaces/{ws}/publications/{publication_id}/reconciliations" in parsed["paths"]
    )
    assert "post" not in parsed["paths"]["/api/v1/workspaces/{ws}/publications"]

    schemas = set(parsed["components"]["schemas"].keys())
    required_canonical_models = {
        "Problem",
        "ProblemFieldError",
        "ActionReceipt",
        "PageParams",
        "Money",
        "User",
        "Session",
        "Workspace",
        "Membership",
        "Invite",
        "Connection",
        "ConnectionWrite",
        "Repository",
        "RepositoryPolicy",
        "CiRun",
        "CiJob",
        "Repair",
        "Diagnosis",
        "Patch",
        "Verification",
        "Approval",
        "Publication",
        "PublicationPageResponse",
        "PublicationDetailResponse",
        "PublicationReconciliationRequest",
        "RemoteCheck",
        "Artifact",
        "Worker",
        "TaskJob",
        "NotificationDestination",
        "NotificationDelivery",
        "NotificationPreference",
        "AuditRecord",
        "ModelUsageRecord",
        "ReportExportRequest",
        "SetupState",
        "LifecycleOperation",
        "SystemHealthResponse",
        "EventEnvelope",
        "ToolCallRequest",
        "ToolCallResponse",
        "SandboxJobV1",
        "ResultV1",
        "EvidenceManifestV1",
    }
    missing = required_canonical_models - schemas
    assert not missing, f"Missing canonical schemas in OpenAPI components: {sorted(missing)}"


def test_publication_routes_fail_closed_without_iam_and_expose_no_raw_create_endpoint() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/workspaces/acme/publications")
    assert response.status_code == 503
    assert response.headers["content-type"].startswith(PROBLEM_JSON_MEDIA_TYPE)
    raw_create = client.post("/api/v1/workspaces/acme/publications", json={"branch": "main"})
    assert raw_create.status_code == 405


@pytest.mark.parametrize(
    "status_code",
    [400, 401, 403, 404, 409, 410, 412, 422, 429, 503, 500],
)
def test_s03_problem_json_handlers_cover_all_canonical_statuses_and_strip_500_internals(
    status_code: int,
) -> None:
    DEFAULT_REDACTOR.register_canary("CANARY_ERR_SECRET_7788")
    client = _build_probe_client()
    resp = client.get(
        f"/api/v1/_contract_probes/raise/{status_code}",
        headers={"X-Correlation-Id": f"corr-err-{status_code}"},
    )
    assert resp.status_code == status_code
    assert resp.headers["content-type"].startswith(PROBLEM_JSON_MEDIA_TYPE)
    assert resp.headers["X-Correlation-Id"] == f"corr-err-{status_code}"
    if status_code == 429:
        assert resp.headers.get("Retry-After") == "15"

    prob = resp.json()
    assert prob["status"] == status_code
    assert prob["correlation_id"] == f"corr-err-{status_code}"
    assert prob["type"].startswith("https://red2pr.local/problems/")
    if status_code == 500:
        assert "/var/lib/red2pr" not in prob["detail"]
        assert "ghp_" not in prob["detail"]
        assert "RuntimeError" not in prob["detail"]


def test_unknown_route_extra_fields_malformed_json_and_oversized_body_guards() -> None:
    client = _build_probe_client()

    # Unknown route -> 404 Problem+JSON (never raw Starlette {"detail": "Not Found"})
    not_found = client.get("/api/v1/does-not-exist")
    assert not_found.status_code == 404
    assert not_found.headers["content-type"].startswith(PROBLEM_JSON_MEDIA_TYPE)
    assert not_found.json()["code"] == "not_found"

    # Extra undeclared property -> 422 Problem+JSON
    extra_resp = client.post(
        "/api/v1/_contract_probes/echo",
        json={"name": "ok", "role": "admin"},
    )
    assert extra_resp.status_code == 422
    assert extra_resp.headers["content-type"].startswith(PROBLEM_JSON_MEDIA_TYPE)
    assert extra_resp.json()["errors"] is not None

    # Malformed JSON syntax -> 400 Problem+JSON
    malformed_resp = client.post(
        "/api/v1/_contract_probes/echo",
        content=b'{"name": "unterminated',
        headers={"Content-Type": "application/json"},
    )
    assert malformed_resp.status_code == 400
    assert malformed_resp.headers["content-type"].startswith(PROBLEM_JSON_MEDIA_TYPE)
    assert malformed_resp.json()["code"] == "malformed_json"

    # Oversized JSON payload (> 1 MiB) -> 413 Problem+JSON (Content-Length fast reject)
    oversized_bytes = b'{"name":"' + (b"x" * MAX_JSON_BODY_BYTES) + b'"}'
    huge_resp = client.post(
        "/api/v1/_contract_probes/echo",
        content=oversized_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert huge_resp.status_code == 413
    assert huge_resp.headers["content-type"].startswith(PROBLEM_JSON_MEDIA_TYPE)
    assert huge_resp.json()["code"] == "payload_too_large"

    # Oversized streamed/chunked body (> 1 MiB without Content-Length) -> 413 Problem+JSON
    chunked_resp = client.post(
        "/api/v1/_contract_probes/echo",
        content=(b"x" * 100_000 for _ in range(12)),
        headers={"Content-Type": "application/json"},
    )
    assert chunked_resp.status_code == 413
    assert chunked_resp.headers["content-type"].startswith(PROBLEM_JSON_MEDIA_TYPE)
    assert chunked_resp.json()["code"] == "payload_too_large"
