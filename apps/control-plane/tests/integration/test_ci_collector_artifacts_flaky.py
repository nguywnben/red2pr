"""PostgreSQL 16 + Hermetic CI Collector, Encrypted ArtifactStore & Flaky Suite (`U13`, `IG-03`).

Verifies against a real disposable PostgreSQL 16 instance (`pgserver` / `fsync=on`):
- `0009_ci_runs_jobs_artifacts` expand/contract reversibility (`downgrade -> upgrade`), `>= 41`
  `FORCE ROW LEVEL SECURITY` tables (`artifact_blobs`, `failure_fingerprints`, `ci_runs`,
  `artifacts`, `ci_jobs`), and strict cross-workspace tenant isolation (`SEC-032`).
- Adversarial `archive_guard.py` suite (`NFR-14`, `SEC-007`, `SEC-036`):
  - Valid `.zip` and `.tar.gz` extraction confined within `dest_dir`.
  - Pre-write rejection (`0` escaped writes) on zip-slip `../../etc/passwd`, absolute `/etc/shadow`,
    Windows drive prefix `C:/...`, backslash `..\\escape.txt`, control characters, ZIP symlink,
    TAR symlink, TAR hardlink, TAR FIFO, TAR char device, compression-ratio bomb (`> 100:1`),
    `> max_files`, `> max_compressed_bytes`, and `> max_expanded_bytes`.
- Parametrized `ArtifactStore` suite across BOTH `LocalEncryptedArtifactStore` AND
  `S3CompatibleArtifactStore` (`CR-002` / `ADR-041`, `S-14`, `A-10`, `SEC-024`, `SEC-025`,
  `SEC-032`):
  - Local HTTP `AWS4-HMAC-SHA256` wire-protocol S3 test server verifying every `HEAD`/`PUT`/`GET`/
    `DELETE`/`ListObjectsV2` signature (or `RED2PR_TEST_S3_ENDPOINT` when set in lab gates),
    rejecting wrong S3 credentials (`403 SignatureDoesNotMatch`) and unregistered S3 hosts via
    `ADR-037` `EgressPolicyEngine` (`EgressBlockedError`).
  - Staged upload -> AEAD + SHA-256 verify -> DB commit -> finalize -> verified decrypt roundtrip
    with zero plaintext on disk or S3.
  - `SEC-025` quarantine on SHA-256 mismatch or tampered staged/finalized ciphertext.
  - `SEC-032` tenant-scoped deduplication within a workspace vs cross-tenant storage ref denial.
  - Orphan staged sweeper and `retention_until` expiry purge (`410 artifact_expired`).
- `T-TRI-01-P`, `T-TRI-01-N`, `T-TRI-03-P`, `T-TRI-03-N` (`TRI-01`, `TRI-03`, `SEC-016`, `SEC-017`,
  `SEC-033`, `SEC-040`):
  - GitHub attempt 1 vs attempt 2 job isolation, cross-origin `302` CDN redirect stripping
    `Authorization`, secret canary redaction BEFORE `ArtifactStore` write, valid archive storage +
    malicious archive rejection (`security.policy.denied`), and deterministic `TRI-03` progression
    (`insufficient_history -> single_pass_unproven -> flaky` vs `persistent_failure`).
  - GitLab parent + downstream child bridge pipeline jobs, `HTTP 410` expired trace (`log_status=
    'expired'`, `ingestion_state='incomplete'`, `410 log_expired` on `A-08`), `<=20 MiB` cap tail
    truncation + UTF-8 multi-chunk pagination, and `SEC-016` stale `head_sha` detection.
- `IG-03` Wave 2 end-to-end gate (`A-08`, `A-10`, `S-14`, `SEC-010`, `SEC-032`, `ADR-033`):
  - Signed GitHub failure webhook -> `ci_run.triage` queue job -> `process_next_triage_job` on a
    `monitor`-mode repository (`0` `is_repair_job=True` sandbox jobs), `S-14` `storage_ref`
    non-exposure, `restricted` artifact RBAC (`viewer` `403` vs `admin` `200` + `410` post-expiry),
    immediate `repo_grants` revocation enforcement (`0` runs / `404`), and `verify_audit_chain`.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import pgserver
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import KeyRing, MasterKeyRing, verify_rs256_jwt
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.egress import (
    EgressBlockedError,
    EgressPolicyEngine,
    InMemoryCaBundleResolver,
)
from red2pr_control.core.errors import DependencyUnavailableError, ForbiddenError, GoneError
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    ArtifactBlobModel,
    ArtifactDeletionJobModel,
    ArtifactModel,
    AuditLogModel,
    CiJobModel,
    CiRunModel,
    EndpointRegistrationModel,
    FailureFingerprintModel,
    OutboxEventModel,
    ProviderConnectionModel,
    RepositoryModel,
    SchemaMigrationRecordModel,
    TaskJobModel,
    UserModel,
    WorkspaceModel,
)
from red2pr_control.db.engine import (
    create_admin_engine,
    create_app_engine,
    create_session_factory,
    ensure_compatible_event_loop,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.sessions import IamService
from red2pr_control.integrations import (
    GITHUB_API_VERSION,
    GitHubAppAdapter,
    GitLabAdapter,
    LocalPollingService,
    MissedEventReconciler,
    ProviderIntegrationService,
    WebhookIngestService,
)
from red2pr_control.operations.retention import RetentionPurgeWorker
from red2pr_control.operations.setup_wizard import (
    DbEndpointAllowlistProvider,
    SetupStepRegistry,
    SetupWizardService,
)
from red2pr_control.orchestrator import DurableTaskQueueService, OperationReceiptService
from red2pr_control.repositories import RepositoryCatalogService
from red2pr_control.secrets.broker import (
    SecretBroker,
    SecretBrokerProviderVault,
    SecretBrokerTotpVault,
)
from red2pr_control.triage_evidence import (
    TRUNCATION_BANNER,
    ArchiveSecurityError,
    ArtifactIntegrityError,
    ArtifactStoreProtocol,
    CiRunCollectorService,
    LocalEncryptedArtifactStore,
    S3CompatibleArtifactStore,
    S3Credentials,
    TriageEvidenceService,
    inspect_and_extract_archive,
    normalize_safe_archive_member_path,
    persist_encrypted_artifact,
    purge_expired_artifacts_in_tx,
    read_artifact_for_authorized_caller,
    verify_s3_v4_request,
)

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_13"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#13"
VIEWER_CREDENTIAL = "ViewerSup3rStr0ng!Pass#13"
SECRET_CANARY_GH = "ghp_SecretCanaryTokenValue1234567890ABCD"
SECRET_CANARY_BEARER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZWNyZXQifQ.sig987654321"


class ManualClock:
    """Deterministic controllable UTC clock for retention & session checks."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 28, 9, 0, 0, tzinfo=UTC)).astimezone(UTC)

    def __call__(self) -> datetime:
        return self._current

    def advance(self, **delta_kwargs: float) -> datetime:
        self._current = self._current + timedelta(**delta_kwargs)
        return self._current


@dataclass(frozen=True)
class PgTestUrls:
    admin_url: str
    app_url: str


def _build_role_url(base_uri: str, *, username: str, password: str) -> str:
    parsed = urlparse(base_uri)
    host = parsed.hostname or "127.0.0.1"
    port_part = f":{parsed.port}" if parsed.port else ""
    netloc = f"{username}:{password}@{host}{port_part}"
    return urlunparse(
        (
            "postgresql+psycopg",
            netloc,
            parsed.path or "/postgres",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def _csrf_headers(
    token: str,
    *,
    idem_key: str | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {"X-CSRF-Token": token, **ORIGIN_HEADERS}
    if idem_key is not None:
        headers["Idempotency-Key"] = idem_key
    if extra:
        headers.update(extra)
    return headers


def _gh_hmac_header(secret: str, raw_body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class _U13DnsResolver:
    """Hermetic DNS resolver for GitHub, GitLab, CDN redirects & lab S3 endpoints."""

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        _ = port
        if host in {"api.github.com", "objects.githubusercontent.com", "gitlab.com"}:
            return ("140.82.112.6",)
        if host == "minio.lab.internal":
            return ("10.24.0.10",)
        if host == "rogue-s3.internal":
            return ("10.99.0.10",)
        return (host,)


def _make_zip_bytes(entries: Mapping[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _make_tar_gz_bytes(entries: Mapping[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@dataclass
class S3WireServerState:
    """In-memory object state behind the `AWS4-HMAC-SHA256` wire-protocol server (`ADR-041`)."""

    credentials: S3Credentials
    buckets: dict[str, dict[str, tuple[bytes, datetime]]] = field(default_factory=dict)
    request_log: list[tuple[str, str, int]] = field(default_factory=list)


def _build_s3v4_wire_app(state: S3WireServerState) -> FastAPI:
    """Build a strict S3 REST + SigV4 (`AWS4-HMAC-SHA256`) wire-protocol test server."""
    s3 = FastAPI()

    async def _authenticate(request: Request) -> tuple[bool, bytes, str]:
        raw_body = await request.body()
        ok, reason = verify_s3_v4_request(
            method=request.method,
            raw_path=request.url.path,
            raw_query=request.url.query,
            headers=dict(request.headers.items()),
            body=raw_body,
            credentials=state.credentials,
        )
        return ok, raw_body, reason

    def _sig_error_xml(reason: str) -> Response:
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<Error><Code>SignatureDoesNotMatch</Code>"
            f"<Message>{html.escape(reason)}</Message></Error>"
        )
        return Response(content=xml, status_code=403, media_type="application/xml")

    @s3.api_route("/{bucket}", methods=["HEAD", "PUT", "GET"])
    async def handle_bucket(bucket: str, request: Request) -> Response:
        ok, _, reason = await _authenticate(request)
        if not ok:
            state.request_log.append((request.method, f"/{bucket}", 403))
            return _sig_error_xml(reason)

        if request.method == "HEAD":
            code = 200 if bucket in state.buckets else 404
            state.request_log.append(("HEAD", f"/{bucket}", code))
            return Response(status_code=code)

        if request.method == "PUT":
            state.buckets.setdefault(bucket, {})
            state.request_log.append(("PUT", f"/{bucket}", 200))
            return Response(status_code=200)

        # GET ListObjectsV2 (`?list-type=2&prefix=...`)
        if bucket not in state.buckets:
            state.request_log.append(("GET", f"/{bucket}", 404))
            return Response(status_code=404)
        prefix = request.query_params.get("prefix", "")
        objs = state.buckets[bucket]
        items_xml: list[str] = []
        for key in sorted(objs):
            if prefix and not key.startswith(prefix):
                continue
            raw_bytes, mod_dt = objs[key]
            iso_mod = mod_dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            items_xml.append(
                "<Contents>"
                f"<Key>{html.escape(key)}</Key>"
                f"<LastModified>{iso_mod}</LastModified>"
                f"<Size>{len(raw_bytes)}</Size>"
                "</Contents>"
            )
        xml_out = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<Name>{html.escape(bucket)}</Name>"
            f"<Prefix>{html.escape(prefix)}</Prefix>"
            f"{''.join(items_xml)}"
            "</ListBucketResult>"
        )
        state.request_log.append(("GET", f"/{bucket}", 200))
        return Response(content=xml_out, status_code=200, media_type="application/xml")

    @s3.api_route("/{bucket}/{object_key:path}", methods=["HEAD", "PUT", "GET", "DELETE"])
    async def handle_object(bucket: str, object_key: str, request: Request) -> Response:
        ok, raw_body, reason = await _authenticate(request)
        if not ok:
            state.request_log.append((request.method, f"/{bucket}/{object_key}", 403))
            return _sig_error_xml(reason)

        if bucket not in state.buckets:
            state.request_log.append((request.method, f"/{bucket}/{object_key}", 404))
            return Response(status_code=404)

        b_map = state.buckets[bucket]
        if request.method == "PUT":
            b_map[object_key] = (raw_body, datetime.now(tz=UTC))
            state.request_log.append(("PUT", f"/{bucket}/{object_key}", 200))
            return Response(status_code=200, headers={"ETag": '"s3v4-etag"'})

        if request.method == "HEAD":
            if object_key not in b_map:
                state.request_log.append(("HEAD", f"/{bucket}/{object_key}", 404))
                return Response(status_code=404)
            data, _ = b_map[object_key]
            state.request_log.append(("HEAD", f"/{bucket}/{object_key}", 200))
            return Response(
                status_code=200,
                headers={"Content-Length": str(len(data))},
            )

        if request.method == "GET":
            if object_key not in b_map:
                state.request_log.append(("GET", f"/{bucket}/{object_key}", 404))
                return Response(status_code=404)
            data, _ = b_map[object_key]
            state.request_log.append(("GET", f"/{bucket}/{object_key}", 200))
            return Response(
                content=data,
                status_code=200,
                media_type="application/octet-stream",
            )

        b_map.pop(object_key, None)
        state.request_log.append(("DELETE", f"/{bucket}/{object_key}", 204))
        return Response(status_code=204)

    return s3


@dataclass
class MockCiProviderState:
    """Hermetic GitHub & GitLab CI run/job/log/artifact provider state for `U13` tests."""

    clock: ManualClock
    gh_app_id: str
    gh_installation_id: str
    gh_public_key: rsa.RSAPublicKey
    gh_issued_tokens: set[str] = field(default_factory=set)
    gh_token_seq: int = 0

    # run_id -> workflow_run dict
    gh_runs: dict[str, dict[str, Any]] = field(default_factory=dict)
    # (run_id, attempt_number) -> list of job dicts
    gh_attempt_jobs: dict[tuple[str, int], list[dict[str, Any]]] = field(default_factory=dict)
    # job_id -> (status_code, bytes, use_cdn_redirect)
    gh_job_logs: dict[str, tuple[int, bytes, bool]] = field(default_factory=dict)
    # run_id -> list of artifact metadata dicts
    gh_run_artifacts: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # artifact_id -> (status_code, bytes)
    gh_artifact_blobs: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    cdn_redirect_auth_leaked: bool = False
    cdn_redirect_hits: int = 0

    gl_valid_tokens: set[str] = field(default_factory=set)
    gl_pipelines: dict[str, dict[str, Any]] = field(default_factory=dict)
    gl_bridges: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    gl_pipeline_jobs: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    gl_job_traces: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    gl_job_artifacts: dict[str, tuple[int, bytes]] = field(default_factory=dict)


def _create_mock_github_ci_app(state: MockCiProviderState) -> FastAPI:
    gh = FastAPI()

    def _verify_app_jwt(request: Request) -> Response | None:
        assert request.headers.get("X-GitHub-Api-Version") == GITHUB_API_VERSION
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"message": "Missing App JWT"}, status_code=401)
        pub_pem = state.gh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        claims = verify_rs256_jwt(
            auth.removeprefix("Bearer ").strip(),
            public_key_pem=pub_pem,
            now=state.clock(),
        )
        assert claims.get("iss") == state.gh_app_id
        return None

    def _verify_inst_token(request: Request) -> Response | None:
        assert request.headers.get("X-GitHub-Api-Version") == GITHUB_API_VERSION
        auth = request.headers.get("Authorization", "")
        tok = auth.removeprefix("Bearer ").strip()
        if tok not in state.gh_issued_tokens:
            return JSONResponse({"message": "Invalid installation token"}, status_code=401)
        return None

    @gh.post("/app/installations/{install_id}/access_tokens")
    async def mint_token(install_id: str, request: Request) -> Response:
        err = _verify_app_jwt(request)
        if err is not None:
            return err
        if install_id != state.gh_installation_id:
            return JSONResponse({"message": "Not Found"}, status_code=404)
        state.gh_token_seq += 1
        tok = f"ghs_u13_scoped_{state.gh_token_seq:04d}_secret"
        state.gh_issued_tokens.add(tok)
        exp = (state.clock() + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        return JSONResponse({"token": tok, "expires_at": exp}, status_code=201)

    @gh.get("/repos/{owner}/{repo}/actions/runs/{run_id}")
    async def get_run(owner: str, repo: str, run_id: str, request: Request) -> Response:
        _ = (owner, repo)
        err = _verify_inst_token(request)
        if err is not None:
            return err
        data = state.gh_runs.get(run_id)
        if data is None:
            return JSONResponse({"message": "Not Found"}, status_code=404)
        return JSONResponse(data)

    @gh.get("/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs")
    async def list_attempt_jobs(
        owner: str,
        repo: str,
        run_id: str,
        attempt_number: int,
        request: Request,
    ) -> Response:
        _ = (owner, repo)
        err = _verify_inst_token(request)
        if err is not None:
            return err
        jobs = state.gh_attempt_jobs.get((run_id, attempt_number), [])
        return JSONResponse({"total_count": len(jobs), "jobs": jobs})

    @gh.get("/repos/{owner}/{repo}/actions/jobs/{job_id}/logs")
    async def get_job_logs(owner: str, repo: str, job_id: str, request: Request) -> Response:
        _ = (owner, repo)
        err = _verify_inst_token(request)
        if err is not None:
            return err
        spec = state.gh_job_logs.get(job_id)
        if spec is None:
            return JSONResponse({"message": "Not Found"}, status_code=404)
        status_code, payload, use_cdn = spec
        if status_code != 200:
            return JSONResponse({"message": f"Log status {status_code}"}, status_code=status_code)
        if use_cdn:
            return Response(
                status_code=302,
                headers={"Location": f"https://objects.githubusercontent.com/cdn-logs/{job_id}"},
            )
        return Response(content=payload, status_code=200, media_type="text/plain")

    @gh.get("/cdn-logs/{job_id}")
    async def get_cdn_log(job_id: str, request: Request) -> Response:
        state.cdn_redirect_hits += 1
        # SEC-033: cross-origin redirect MUST strip Authorization / credential headers!
        if "authorization" in {k.lower() for k in request.headers}:
            state.cdn_redirect_auth_leaked = True
            return Response(content="Credential header leaked to CDN!", status_code=400)
        spec = state.gh_job_logs.get(job_id)
        if spec is None:
            return Response(status_code=404)
        return Response(content=spec[1], status_code=200, media_type="text/plain")

    @gh.get("/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts")
    async def list_run_artifacts(owner: str, repo: str, run_id: str, request: Request) -> Response:
        _ = (owner, repo)
        err = _verify_inst_token(request)
        if err is not None:
            return err
        arts = state.gh_run_artifacts.get(run_id, [])
        return JSONResponse({"total_count": len(arts), "artifacts": arts})

    @gh.get("/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip")
    async def download_artifact_zip(
        owner: str,
        repo: str,
        artifact_id: str,
        request: Request,
    ) -> Response:
        _ = (owner, repo)
        err = _verify_inst_token(request)
        if err is not None:
            return err
        spec = state.gh_artifact_blobs.get(artifact_id)
        if spec is None:
            return JSONResponse({"message": "Not Found"}, status_code=404)
        code, raw = spec
        if code != 200:
            return JSONResponse({"message": f"Artifact HTTP {code}"}, status_code=code)
        return Response(content=raw, status_code=200, media_type="application/zip")

    return gh


def _create_mock_gitlab_ci_app(state: MockCiProviderState) -> FastAPI:
    gl = FastAPI()

    def _verify_gl_token(request: Request) -> Response | None:
        tok = request.headers.get("PRIVATE-TOKEN", "")
        if tok not in state.gl_valid_tokens:
            return JSONResponse({"message": "401 Unauthorized"}, status_code=401)
        return None

    @gl.get("/api/v4/projects/{project_path:path}/pipelines/{pipeline_id}/bridges")
    async def list_bridges(
        project_path: str,
        pipeline_id: str,
        request: Request,
    ) -> Response:
        _ = project_path
        err = _verify_gl_token(request)
        if err is not None:
            return err
        return JSONResponse(state.gl_bridges.get(pipeline_id, []))

    @gl.get("/api/v4/projects/{project_path:path}/pipelines/{pipeline_id}/jobs")
    async def list_pipeline_jobs(
        project_path: str,
        pipeline_id: str,
        request: Request,
    ) -> Response:
        _ = project_path
        err = _verify_gl_token(request)
        if err is not None:
            return err
        return JSONResponse(
            state.gl_pipeline_jobs.get(pipeline_id, []),
            headers={"x-next-page": ""},
        )

    @gl.get("/api/v4/projects/{project_path:path}/pipelines/{pipeline_id}")
    async def get_pipeline(
        project_path: str,
        pipeline_id: str,
        request: Request,
    ) -> Response:
        _ = project_path
        err = _verify_gl_token(request)
        if err is not None:
            return err
        pipe = state.gl_pipelines.get(pipeline_id)
        if pipe is None:
            return JSONResponse({"message": "404 Not Found"}, status_code=404)
        return JSONResponse(pipe)

    @gl.get("/api/v4/projects/{project_path:path}/jobs/{job_id}/trace")
    async def get_job_trace(
        project_path: str,
        job_id: str,
        request: Request,
    ) -> Response:
        _ = project_path
        err = _verify_gl_token(request)
        if err is not None:
            return err
        spec = state.gl_job_traces.get(job_id)
        if spec is None:
            return JSONResponse({"message": "404 Not Found"}, status_code=404)
        code, raw = spec
        if code != 200:
            return JSONResponse({"message": f"Trace HTTP {code}"}, status_code=code)
        return Response(content=raw, status_code=200, media_type="text/plain")

    @gl.get("/api/v4/projects/{project_path:path}/jobs/{job_id}/artifacts")
    async def get_job_artifacts(
        project_path: str,
        job_id: str,
        request: Request,
    ) -> Response:
        _ = project_path
        err = _verify_gl_token(request)
        if err is not None:
            return err
        spec = state.gl_job_artifacts.get(job_id)
        if spec is None:
            return JSONResponse({"message": "404 Not Found"}, status_code=404)
        code, raw = spec
        if code != 200:
            return JSONResponse({"message": f"Artifact HTTP {code}"}, status_code=code)
        return Response(content=raw, status_code=200, media_type="application/octet-stream")

    return gl


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[PgTestUrls]:
    """Provide a real disposable PostgreSQL 16 server (`pgserver` / env override)."""
    ensure_compatible_event_loop()
    external_admin = os.environ.get("RED2PR_TEST_ADMIN_DATABASE_URL")
    if external_admin:
        app_url = os.environ.get("RED2PR_TEST_APP_DATABASE_URL") or _build_role_url(
            external_admin,
            username=APP_ROLE_NAME,
            password=APP_ROLE_PASSWORD,
        )
        yield PgTestUrls(admin_url=external_admin, app_url=app_url)
        return

    with (
        tempfile.TemporaryDirectory(prefix="red2pr_u13_pg_") as tmp_dir,
        pgserver.get_server(tmp_dir, cleanup_mode="delete") as server,
    ):
        raw_uri = server.get_uri()
        parsed = urlparse(raw_uri)
        admin_url = urlunparse(
            (
                "postgresql+psycopg",
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        app_url = _build_role_url(
            raw_uri,
            username=APP_ROLE_NAME,
            password=APP_ROLE_PASSWORD,
        )
        yield PgTestUrls(admin_url=admin_url, app_url=app_url)


@pytest.fixture
async def migrated_db(pg_urls: PgTestUrls) -> AsyncIterator[PgTestUrls]:
    """Reset schema cleanly to head (`0009`) before each test."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


@dataclass
class U13Harness:
    app_engine: AsyncEngine
    app_factory: async_sessionmaker[AsyncSession]
    iam: IamService
    redactor: Redactor
    kek_ring: MasterKeyRing
    egress_engine: EgressPolicyEngine
    artifact_store: LocalEncryptedArtifactStore
    collector: CiRunCollectorService
    triage_service: TriageEvidenceService
    queue_service: DurableTaskQueueService
    webhook_service: WebhookIngestService
    api_app: FastAPI
    state: MockCiProviderState
    gh_private_pem: str
    store_dir: Path


def _build_u13_harness(
    app_url: str,
    *,
    clock: ManualClock,
    store_dir: Path,
    max_log_bytes: int = 20 * 1024 * 1024,
) -> U13Harness:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    state = MockCiProviderState(
        clock=clock,
        gh_app_id="510200",
        gh_installation_id="88010",
        gh_public_key=rsa_key.public_key(),
        gl_valid_tokens={"glpat-u13CloudTokenSecret99887766"},
    )
    mock_gh = _create_mock_github_ci_app(state)
    mock_gl = _create_mock_gitlab_ci_app(state)

    app_engine = create_app_engine(app_url, pool_size=8, max_overflow=8)
    app_factory = create_session_factory(app_engine)
    redactor = Redactor()
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x5a" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(broker)
    provider_vault = SecretBrokerProviderVault(broker)

    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x6b" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
    )
    egress_engine = EgressPolicyEngine(
        allowlist_provider=DbEndpointAllowlistProvider(app_factory),
        dns_resolver=_U13DnsResolver(),
    )
    gh_adapter = GitHubAppAdapter(
        vault=provider_vault,
        egress_policy=egress_engine,
        redactor=redactor,
        transport_override=httpx.ASGITransport(app=mock_gh),
    )
    gl_adapter = GitLabAdapter(
        vault=provider_vault,
        egress_policy=egress_engine,
        ca_bundle_resolver=InMemoryCaBundleResolver({}),
        redactor=redactor,
        transport_override=httpx.ASGITransport(app=mock_gl),
    )
    integration_service = ProviderIntegrationService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        vault=provider_vault,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        redactor=redactor,
    )
    webhook_service = WebhookIngestService(
        session_factory=app_factory,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        integration_service=integration_service,
        redactor=redactor,
        clock=clock,
    )
    poller = LocalPollingService(
        session_factory=app_factory,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        integration_service=integration_service,
        redactor=redactor,
        clock=clock,
    )
    reconciler = MissedEventReconciler(
        session_factory=app_factory,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        poller=poller,
        integration_service=integration_service,
        redactor=redactor,
        clock=clock,
    )
    repo_catalog = RepositoryCatalogService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        clock=clock,
    )
    queue_service = DurableTaskQueueService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        redactor=redactor,
    )
    op_service = OperationReceiptService(session_factory=app_factory)
    step_registry = SetupStepRegistry()
    setup_service = SetupWizardService(
        iam_service=iam,
        step_registry=step_registry,
        redactor=redactor,
    )
    artifact_store = LocalEncryptedArtifactStore(root_dir=store_dir, key_ring=kek_ring)
    collector = CiRunCollectorService(
        session_factory=app_factory,
        artifact_store=artifact_store,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        redactor=redactor,
        max_log_bytes=max_log_bytes,
        clock=clock,
    )
    triage_service = TriageEvidenceService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        artifact_store=artifact_store,
        clock=clock,
    )
    api_app = create_app(
        iam_service=iam,
        setup_wizard_service=setup_service,
        setup_step_registry=step_registry,
        task_queue_service=queue_service,
        operation_receipt_service=op_service,
        github_integration_service=integration_service,
        webhook_ingest_service=webhook_service,
        polling_service=poller,
        reconciler_service=reconciler,
        repository_catalog_service=repo_catalog,
        triage_evidence_service=triage_service,
        artifact_store=artifact_store,
    )
    return U13Harness(
        app_engine=app_engine,
        app_factory=app_factory,
        iam=iam,
        redactor=redactor,
        kek_ring=kek_ring,
        egress_engine=egress_engine,
        artifact_store=artifact_store,
        collector=collector,
        triage_service=triage_service,
        queue_service=queue_service,
        webhook_service=webhook_service,
        api_app=api_app,
        state=state,
        gh_private_pem=private_pem,
        store_dir=store_dir,
    )


async def _claim_owner_and_workspace(
    transport: httpx.ASGITransport,
    iam: IamService,
    *,
    slug: str = "acme",
    name: str = "Acme Core",
) -> tuple[httpx.AsyncClient, str, str, str]:
    raw_boot, _ = await iam.issue_bootstrap_token()
    client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    pre_csrf = (await client.get("/api/v1/auth/csrf")).json()["csrf_token"]
    claim_resp = await client.post(
        "/api/v1/setup/claim",
        headers=_csrf_headers(pre_csrf),
        json={
            "bootstrap_token": raw_boot,
            "display_name": "Owner U13",
            "email": "owner.u13@red2pr.local",
            "password": OWNER_CREDENTIAL,
        },
    )
    assert claim_resp.status_code == 201, claim_resp.text
    csrf_token = str(claim_resp.json()["csrf_token"])
    owner_id = str(claim_resp.json()["user"]["id"])

    ws_resp = await client.post(
        "/api/v1/workspaces",
        headers=_csrf_headers(csrf_token),
        json={"name": name, "slug": slug},
    )
    assert ws_resp.status_code == 201, ws_resp.text
    return client, csrf_token, owner_id, str(ws_resp.json()["id"])


async def _seed_connection_and_repo(
    harness: U13Harness,
    *,
    admin_client: httpx.AsyncClient,
    csrf: str,
    ws_slug: str,
    ws_id: str,
    provider: str,
    auth_mode: str,
    webhook_secret: str,
    external_repo_id: str,
    repo_name: str,
    visibility: str = "private",
    mode: str = "monitor",
    now: datetime,
) -> tuple[str, str]:
    body: dict[str, Any] = {
        "provider": provider,
        "auth_mode": auth_mode,
        "display_name": f"{provider.upper()} U13",
        "base_url": "https://api.github.com" if provider == "github" else "https://gitlab.com",
        "webhook_secret": webhook_secret,
    }
    if provider == "github":
        body["app_id"] = harness.state.gh_app_id
        body["private_key_pem"] = harness.gh_private_pem
    else:
        body["access_token"] = "glpat-u13CloudTokenSecret99887766"

    create_resp = await admin_client.post(
        f"/api/v1/workspaces/{ws_slug}/integrations",
        headers=_csrf_headers(csrf, idem_key=new_uuid7(now=now)),
        json=body,
    )
    assert create_resp.status_code == 201, create_resp.text
    conn_id = str(create_resp.json()["id"])

    repo_id = new_uuid7(now=now)
    async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
        conn_row = await db.scalar(
            select(ProviderConnectionModel).where(
                ProviderConnectionModel.workspace_id == ws_id,
                ProviderConnectionModel.id == conn_id,
            )
        )
        assert conn_row is not None
        conn_row.status = "ready"
        if provider == "github":
            conn_row.external_installation_id = harness.state.gh_installation_id
            conn_row.account_login = "acme-red2pr-app"
        else:
            conn_row.account_login = "acme-gitlab-bot"
        conn_row.checked_at = now
        conn_row.updated_at = now

        db.add(
            RepositoryModel(
                id=repo_id,
                workspace_id=ws_id,
                provider_connection_id=conn_id,
                external_repo_id=external_repo_id,
                name=repo_name,
                default_branch="main",
                visibility=visibility,
                mode=mode,
                paused=False,
                active=True,
                archived=False,
                is_fork=False,
                policy_revision=1,
                tags_json=[],
                workflow_hazard_status="clean",
                workflow_hazards_json=[],
                auto_repair_blocked=False,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        await db.flush()
    return conn_id, repo_id


@pytest.mark.asyncio
async def test_0009_ci_runs_jobs_artifacts_migration_reversible_and_rls_tenant_isolation(
    migrated_db: PgTestUrls,
) -> None:
    """Verify `0009` downgrade/upgrade reversibility, `>= 41` RLS tables & tenant isolation."""
    run_alembic_downgrade(
        migrated_db.admin_url,
        "0008_repository_policies",
        app_role_name=APP_ROLE_NAME,
    )
    run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )

    admin_engine = create_admin_engine(migrated_db.admin_url)
    app_engine = create_app_engine(migrated_db.app_url, pool_size=2, max_overflow=2)
    try:
        admin_factory = create_session_factory(admin_engine)
        app_factory = create_session_factory(app_engine)

        async with admin_factory() as admin_db, admin_db.begin():
            rows = (
                await admin_db.execute(
                    text(
                        """
                        SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                          AND c.relkind = 'r'
                          AND c.relname <> 'alembic_version'
                        ORDER BY c.relname
                        """
                    )
                )
            ).fetchall()
            assert len(rows) >= 41
            relnames = {r[0] for r in rows}
            assert {
                "artifact_blobs",
                "failure_fingerprints",
                "ci_runs",
                "artifacts",
                "ci_jobs",
            }.issubset(relnames)
            for relname, has_rls, force_rls in rows:
                assert has_rls is True, f"{relname} missing ENABLE ROW LEVEL SECURITY"
                assert force_rls is True, f"{relname} missing FORCE ROW LEVEL SECURITY"

            mig_row = await admin_db.scalar(
                select(SchemaMigrationRecordModel).where(
                    SchemaMigrationRecordModel.revision == "0009_ci_runs_jobs_artifacts"
                )
            )
            assert mig_row is not None

        now = datetime(2026, 10, 28, 9, 0, 0, tzinfo=UTC)
        ws_a = new_uuid7(now=now)
        ws_b = new_uuid7(now=now)
        conn_a = new_uuid7(now=now)
        repo_a = new_uuid7(now=now)
        blob_a = new_uuid7(now=now)
        fp_a = new_uuid7(now=now)
        run_a = new_uuid7(now=now)
        art_a = new_uuid7(now=now)
        job_a = new_uuid7(now=now)
        sample_digest = hashlib.sha256(b"tenant-a-blob").hexdigest()

        async with instance_rls_session(app_factory, mode="instance_admin") as db:
            for ws_id, slug in ((ws_a, "ws-u13-a"), (ws_b, "ws-u13-b")):
                db.add(
                    WorkspaceModel(
                        id=ws_id,
                        name=slug,
                        slug=slug,
                        status="active",
                        paused=False,
                        version=1,
                        created_at=now,
                        updated_at=now,
                    )
                )

        async with workspace_rls_session(app_factory, workspace_id=ws_a) as db:
            db.add(
                ProviderConnectionModel(
                    id=conn_a,
                    workspace_id=ws_a,
                    provider="github",
                    display_name="GH A",
                    base_url="https://api.github.com",
                    status="ready",
                    auth_mode="github_app",
                    capabilities_json={},
                    granted_permissions_json={},
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            db.add(
                RepositoryModel(
                    id=repo_a,
                    workspace_id=ws_a,
                    provider_connection_id=conn_a,
                    external_repo_id="101",
                    name="acme/repo-a",
                    default_branch="main",
                    visibility="private",
                    mode="monitor",
                    paused=False,
                    active=True,
                    archived=False,
                    is_fork=False,
                    policy_revision=1,
                    tags_json=[],
                    workflow_hazard_status="clean",
                    workflow_hazards_json=[],
                    auto_repair_blocked=False,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            db.add(
                ArtifactBlobModel(
                    id=blob_a,
                    workspace_id=ws_a,
                    digest=sample_digest,
                    size_bytes=13,
                    storage_backend="local_encrypted",
                    storage_ref=f"local://v1/{ws_a}/blobs/{sample_digest[:2]}/{sample_digest}.enc",
                    staged_ref=None,
                    blob_state="finalized",
                    kek_version=1,
                    aad_digest="a" * 64,
                    quarantine_reason=None,
                    verified_at=now,
                    finalized_at=now,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            db.add(
                FailureFingerprintModel(
                    id=fp_a,
                    workspace_id=ws_a,
                    repository_id=repo_a,
                    fingerprint_hash="b" * 64,
                    signature_label="AssertionError in tests/test_a.py::test_1",
                    test_identifier="tests/test_a.py::test_1",
                    error_kind="AssertionError",
                    classification="insufficient_history",
                    confidence_reason="Initial observation.",
                    failure_count=1,
                    pass_on_same_sha_count=0,
                    distinct_sha_count=1,
                    recent_observations_json=[],
                    first_seen_at=now,
                    last_seen_at=now,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            db.add(
                CiRunModel(
                    id=run_a,
                    workspace_id=ws_a,
                    repository_id=repo_a,
                    connection_id=conn_a,
                    trigger_id=None,
                    provider="github",
                    external_id="9001",
                    attempt_key="9001:1",
                    attempt_number=1,
                    head_sha="c" * 40,
                    observed_head_sha="c" * 40,
                    head_sha_verified=True,
                    ref="main",
                    event_type="push",
                    status="completed",
                    conclusion="failure",
                    jobs_complete=True,
                    raw_vendor_status="completed",
                    is_rerun=False,
                    untrusted_fork=False,
                    ingestion_state="ingested",
                    incomplete_reason=None,
                    failed_job_count=1,
                    total_job_count=1,
                    artifact_count=1,
                    flaky_classification="insufficient_history",
                    child_pipeline_ids_json=[],
                    started_at=now,
                    completed_at=now,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            db.add(
                ArtifactModel(
                    id=art_a,
                    workspace_id=ws_a,
                    repository_id=repo_a,
                    run_id=run_a,
                    job_id=None,
                    blob_id=blob_a,
                    manifest_id=None,
                    external_artifact_id="art-1",
                    name="report.zip",
                    kind="ci_artifact_archive",
                    mime="application/zip",
                    size_bytes=13,
                    digest=sample_digest,
                    storage_ref=f"local://v1/{ws_a}/blobs/{sample_digest[:2]}/{sample_digest}.enc",
                    redaction_version="v1",
                    retention_until=now + timedelta(days=7),
                    access_class="restricted",
                    lifecycle_state="finalized",
                    extracted_file_count=1,
                    purge_reason=None,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            db.add(
                CiJobModel(
                    id=job_a,
                    workspace_id=ws_a,
                    repository_id=repo_a,
                    run_id=run_a,
                    external_id="job-9001",
                    name="pytest",
                    stage=None,
                    matrix_dimensions_json={"py": "3.12"},
                    retry_of_id=None,
                    is_child_pipeline_job=False,
                    child_pipeline_id=None,
                    status="completed",
                    conclusion="failure",
                    started_at=now,
                    completed_at=now,
                    log_artifact_id=art_a,
                    log_status="available",
                    log_size_bytes=13,
                    log_truncated=False,
                    failure_excerpt="FAILED tests/test_a.py::test_1",
                    failure_fingerprint_id=fp_a,
                    failure_fingerprint_hash="b" * 64,
                    flaky_classification="insufficient_history",
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )

        # Workspace B MUST observe 0 rows across all 5 new RLS-forced tables (SEC-032)
        async with workspace_rls_session(app_factory, workspace_id=ws_b) as db_b:
            for model_cls in (
                ArtifactBlobModel,
                FailureFingerprintModel,
                CiRunModel,
                ArtifactModel,
                CiJobModel,
            ):
                cnt = await db_b.scalar(select(func.count()).select_from(model_cls))
                assert int(cnt or 0) == 0, f"Cross-tenant leak in {model_cls.__tablename__}"
    finally:
        await app_engine.dispose()
        await admin_engine.dispose()


def test_archive_guard_valid_archives_and_adversarial_rejection_matrix(tmp_path: Path) -> None:
    """Verify `NFR-14`, `SEC-007` & `SEC-036` archive inspection and pre-write rejection."""
    # 1. Valid .zip & .tar.gz archives extract inside confined root
    valid_zip = _make_zip_bytes(
        {
            "reports/junit.xml": b"<testsuite tests='2' failures='1'/>",
            "coverage/summary.json": b'{"lines": 94.5}',
        }
    )
    zip_dest = tmp_path / "valid_zip_out"
    zip_res = inspect_and_extract_archive(valid_zip, filename="reports.zip", dest_dir=zip_dest)
    assert zip_res.archive_format == "zip"
    assert zip_res.file_count == 2
    assert (zip_dest / "reports" / "junit.xml").read_bytes().startswith(b"<testsuite")

    valid_tgz = _make_tar_gz_bytes({"logs/output.txt": b"all checks ran\n"})
    tgz_dest = tmp_path / "valid_tgz_out"
    tgz_res = inspect_and_extract_archive(valid_tgz, filename="logs.tar.gz", dest_dir=tgz_dest)
    assert tgz_res.archive_format == "tar"
    assert tgz_res.file_count == 1
    assert (tgz_dest / "logs" / "output.txt").read_bytes() == b"all checks ran\n"

    # 2. Adversarial path traversal (`SEC-007`) & special entry types (`SEC-036`)
    sandbox_parent = tmp_path / "confinement_check"
    sandbox_parent.mkdir(parents=True, exist_ok=True)
    target_dir = sandbox_parent / "extract_here"

    bad_path_cases = [
        "../../etc/passwd",
        "/etc/shadow",
        "C:/Windows/win.ini",
        "..\\escape_win.txt",
        "safe/\x1fhidden.txt",
    ]
    for idx, bad_name in enumerate(bad_path_cases):
        raw_bad_zip = _make_zip_bytes({bad_name: b"pwned"})
        sub_dest = target_dir / f"case_{idx}"
        with pytest.raises(ArchiveSecurityError) as exc_info:
            inspect_and_extract_archive(raw_bad_zip, filename="bad.zip", dest_dir=sub_dest)
        assert exc_info.value.code == "archive_path_traversal"

    with pytest.raises(ArchiveSecurityError) as nul_exc:
        normalize_safe_archive_member_path("safe/\x00hidden.txt")
    assert nul_exc.value.code == "archive_path_traversal"

    # 3. ZIP symbolic link (`stat.S_IFLNK` in `external_attr`, `SEC-036`)
    symlink_zip_buf = io.BytesIO()
    with zipfile.ZipFile(symlink_zip_buf, mode="w") as zf:
        zinfo = zipfile.ZipInfo("link_to_secret")
        zinfo.create_system = 3
        zinfo.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(zinfo, "/etc/passwd")
    with pytest.raises(ArchiveSecurityError) as sym_zip_exc:
        inspect_and_extract_archive(
            symlink_zip_buf.getvalue(),
            filename="symlink.zip",
            dest_dir=target_dir / "sym_zip",
        )
    assert sym_zip_exc.value.code == "archive_forbidden_entry_type"

    # 4. TAR symlink, hardlink, FIFO, and character device (`SEC-036`)
    for label, tar_type in (
        ("sym", tarfile.SYMTYPE),
        ("lnk", tarfile.LNKTYPE),
        ("fifo", tarfile.FIFOTYPE),
        ("chr", tarfile.CHRTYPE),
    ):
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo(name=f"special_{label}")
            ti.type = tar_type
            if tar_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                ti.linkname = "../outside"
            tf.addfile(ti)
        with pytest.raises(ArchiveSecurityError) as tar_exc:
            inspect_and_extract_archive(
                tar_buf.getvalue(),
                filename=f"{label}.tar.gz",
                dest_dir=target_dir / f"tar_{label}",
            )
        assert tar_exc.value.code == "archive_forbidden_entry_type"

    # 5. Compression-ratio bomb (`> 100:1` once expanded >= 1 MiB, `SEC-036`)
    bomb_zip = _make_zip_bytes({"zero_bomb.bin": b"\x00" * (2 * 1024 * 1024)})
    with pytest.raises(ArchiveSecurityError) as bomb_exc:
        inspect_and_extract_archive(
            bomb_zip,
            filename="bomb.zip",
            dest_dir=target_dir / "bomb",
        )
    assert bomb_exc.value.code == "archive_compression_bomb"

    # 6. `NFR-14` ceilings: max_files, max_compressed_bytes, max_expanded_bytes
    many_files_zip = _make_zip_bytes({f"f_{i}.txt": b"ok" for i in range(6)})
    with pytest.raises(ArchiveSecurityError) as cnt_exc:
        inspect_and_extract_archive(
            many_files_zip,
            filename="many.zip",
            dest_dir=target_dir / "many",
            max_files=5,
        )
    assert cnt_exc.value.code == "archive_file_count_exceeded"

    with pytest.raises(ArchiveSecurityError) as comp_exc:
        inspect_and_extract_archive(
            valid_zip,
            filename="oversize_comp.zip",
            max_compressed_bytes=16,
        )
    assert comp_exc.value.code == "archive_compressed_limit_exceeded"

    random_payload = os.urandom(2048)
    exp_zip = _make_zip_bytes({"blob.bin": random_payload})
    with pytest.raises(ArchiveSecurityError) as exp_exc:
        inspect_and_extract_archive(
            exp_zip,
            filename="oversize_exp.zip",
            max_expanded_bytes=1024,
        )
    assert exp_exc.value.code == "archive_expanded_limit_exceeded"

    # Confirm zero escaped files were written into `sandbox_parent` outside `extract_here`
    escaped = [p for p in sandbox_parent.iterdir() if p.name != "extract_here"]
    assert escaped == []


@pytest.mark.asyncio
@pytest.mark.parametrize("backend_kind", ["local_encrypted", "s3_encrypted"])
async def test_encrypted_artifact_store_contract_local_and_s3v4(
    migrated_db: PgTestUrls,
    tmp_path: Path,
    backend_kind: str,
) -> None:
    """Verify identical `ArtifactStore` contract on `LocalEncryptedArtifactStore` & S3v4 store."""
    now = datetime(2026, 10, 28, 10, 0, 0, tzinfo=UTC)
    app_engine = create_app_engine(migrated_db.app_url, pool_size=4, max_overflow=4)
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x33" * 32})
    ws_a = new_uuid7(now=now)
    ws_b = new_uuid7(now=now)
    owner_id = new_uuid7(now=now)
    conn_a = new_uuid7(now=now)
    repo_a = new_uuid7(now=now)
    conn_b = new_uuid7(now=now)
    repo_b = new_uuid7(now=now)

    s3_state: S3WireServerState | None = None
    store: ArtifactStoreProtocol

    try:
        app_factory = create_session_factory(app_engine)
        async with instance_rls_session(app_factory, mode="instance_admin") as db:
            db.add(
                UserModel(
                    id=owner_id,
                    username="s3-owner",
                    email="s3.owner@red2pr.local",
                    display_name="S3 Owner",
                    password_hash="argon2id$stub",
                    is_instance_owner=True,
                    status="active",
                    mfa_enabled=False,
                    grant_epoch=1,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            for ws_id, slug in ((ws_a, "ws-store-a"), (ws_b, "ws-store-b")):
                db.add(
                    WorkspaceModel(
                        id=ws_id,
                        name=slug,
                        slug=slug,
                        status="active",
                        paused=False,
                        version=1,
                        created_at=now,
                        updated_at=now,
                    )
                )
            db.add(
                EndpointRegistrationModel(
                    id=new_uuid7(now=now),
                    adapter="s3_artifacts",
                    scheme="http",
                    host="minio.lab.internal",
                    port=9000,
                    cidrs_json=["10.24.0.0/16"],
                    ca_ref=None,
                    description="Lab S3v4 wire server (`ADR-041`)",
                    created_by_user_id=owner_id,
                    revoked_by_user_id=None,
                    revoked_at=None,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )

        for ws_id, conn_id, repo_id in (
            (ws_a, conn_a, repo_a),
            (ws_b, conn_b, repo_b),
        ):
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as db:
                db.add(
                    ProviderConnectionModel(
                        id=conn_id,
                        workspace_id=ws_id,
                        provider="github",
                        display_name="GH",
                        base_url="https://api.github.com",
                        status="ready",
                        auth_mode="github_app",
                        capabilities_json={},
                        granted_permissions_json={},
                        version=1,
                        created_at=now,
                        updated_at=now,
                    )
                )
                await db.flush()
                db.add(
                    RepositoryModel(
                        id=repo_id,
                        workspace_id=ws_id,
                        provider_connection_id=conn_id,
                        external_repo_id=f"ext-{repo_id[:8]}",
                        name=f"acme/{repo_id[:8]}",
                        default_branch="main",
                        visibility="private",
                        mode="monitor",
                        paused=False,
                        active=True,
                        archived=False,
                        is_fork=False,
                        policy_revision=1,
                        tags_json=[],
                        workflow_hazard_status="clean",
                        workflow_hazards_json=[],
                        auto_repair_blocked=False,
                        version=1,
                        created_at=now,
                        updated_at=now,
                    )
                )

        egress = EgressPolicyEngine(
            allowlist_provider=DbEndpointAllowlistProvider(app_factory),
            dns_resolver=_U13DnsResolver(),
        )

        if backend_kind == "local_encrypted":
            store = LocalEncryptedArtifactStore(
                root_dir=tmp_path / "local_enc_store",
                key_ring=kek_ring,
            )
        else:
            env_ep = os.environ.get("RED2PR_TEST_S3_ENDPOINT")
            if env_ep:
                creds = S3Credentials(
                    access_key_id=os.environ.get("RED2PR_TEST_S3_ACCESS_KEY", "minioadmin"),
                    secret_access_key=os.environ.get("RED2PR_TEST_S3_SECRET_KEY", "minioadmin"),
                    region=os.environ.get("RED2PR_TEST_S3_REGION", "us-east-1"),
                )
                s3_store = S3CompatibleArtifactStore(
                    endpoint_url=env_ep,
                    bucket=os.environ.get("RED2PR_TEST_S3_BUCKET", "red2pr-u13-test"),
                    credentials=creds,
                    key_ring=kek_ring,
                )
                await s3_store.ensure_bucket_exists(now=now)
                store = s3_store
            else:
                creds = S3Credentials(
                    access_key_id="AKIAU13LOCALTEST0001",
                    secret_access_key="s3v4SuperSecretSigningKeyForU13Tests!99",
                    region="us-east-1",
                )
                s3_state = S3WireServerState(credentials=creds)
                s3_transport = httpx.ASGITransport(app=_build_s3v4_wire_app(s3_state))
                s3_store = S3CompatibleArtifactStore(
                    endpoint_url="http://minio.lab.internal:9000",
                    bucket="red2pr-artifacts",
                    credentials=creds,
                    key_ring=kek_ring,
                    egress_policy=egress,
                    transport_override=s3_transport,
                )
                await s3_store.ensure_bucket_exists(now=now)

                # Verify invalid AWS4-HMAC-SHA256 signature is rejected 403 by wire server
                bad_sig_store = S3CompatibleArtifactStore(
                    endpoint_url="http://minio.lab.internal:9000",
                    bucket="red2pr-artifacts",
                    credentials=S3Credentials(
                        access_key_id=creds.access_key_id,
                        secret_access_key="WRONG_SECRET_KEY",
                        region="us-east-1",
                    ),
                    key_ring=kek_ring,
                    egress_policy=egress,
                    transport_override=s3_transport,
                )
                with pytest.raises(DependencyUnavailableError):
                    await bad_sig_store.stage_upload(
                        workspace_id=ws_a,
                        plaintext=b"forged",
                        expected_digest=hashlib.sha256(b"forged").hexdigest(),
                        now=now,
                    )

                # Verify ADR-037 egress blocks unregistered S3 host BEFORE wire transmission
                prior_req_count = len(s3_state.request_log)
                rogue_store = S3CompatibleArtifactStore(
                    endpoint_url="http://rogue-s3.internal:9000",
                    bucket="red2pr-artifacts",
                    credentials=creds,
                    key_ring=kek_ring,
                    egress_policy=egress,
                    transport_override=s3_transport,
                )
                with pytest.raises(EgressBlockedError):
                    await rogue_store.ensure_bucket_exists(now=now)
                assert len(s3_state.request_log) == prior_req_count

                store = s3_store

        # 1. Staged -> SHA-256 verify -> DB commit -> finalize -> verified decrypt roundtrip
        secret_free_payload = b"SENSITIVE_PLAINTEXT_MARKER_9911::pytest junit report bytes"
        expected_sha = hashlib.sha256(secret_free_payload).hexdigest()

        async with workspace_rls_session(app_factory, workspace_id=ws_a) as db:
            art_1 = await persist_encrypted_artifact(
                db,
                store=store,
                workspace_id=ws_a,
                repository_id=repo_a,
                name="junit-1.xml",
                kind="ci_artifact_archive",
                mime="application/xml",
                plaintext=secret_free_payload,
                retention_delta=timedelta(days=7),
                now=now,
            )
            # Dedup within SAME workspace (`SEC-032` allowed): 2nd artifact reuses blob_id
            art_2 = await persist_encrypted_artifact(
                db,
                store=store,
                workspace_id=ws_a,
                repository_id=repo_a,
                name="junit-copy.xml",
                kind="ci_artifact_archive",
                mime="application/xml",
                plaintext=secret_free_payload,
                retention_delta=timedelta(days=1),
                now=now,
            )
            assert art_1.blob_id == art_2.blob_id
            assert art_1.digest == expected_sha
            ws_a_storage_ref = art_1.storage_ref
            art_1_id = art_1.id
            art_2_id = art_2.id

            decrypted = await read_artifact_for_authorized_caller(
                db,
                store=store,
                artifact_row=art_1,
                now=now,
            )
            assert decrypted == secret_free_payload

        # Confirm raw stored ciphertext NEVER contains plaintext bytes (`SEC-024`)
        if isinstance(store, LocalEncryptedArtifactStore):
            enc_files = list(store.root_dir.rglob("*.enc"))
            assert len(enc_files) >= 1
            for ef in enc_files:
                assert b"SENSITIVE_PLAINTEXT_MARKER_9911" not in ef.read_bytes()
        elif s3_state is not None:
            bucket_objs = s3_state.buckets["red2pr-artifacts"]
            assert len(bucket_objs) >= 1
            for raw_obj, _ in bucket_objs.values():
                assert b"SENSITIVE_PLAINTEXT_MARKER_9911" not in raw_obj

        # 2. Cross-tenant isolation (`SEC-032`): Workspace B gets its own blob + cannot read A ref
        async with workspace_rls_session(app_factory, workspace_id=ws_b) as db_b:
            art_b = await persist_encrypted_artifact(
                db_b,
                store=store,
                workspace_id=ws_b,
                repository_id=repo_b,
                name="junit-b.xml",
                kind="ci_artifact_archive",
                mime="application/xml",
                plaintext=secret_free_payload,
                now=now,
            )
            assert art_b.blob_id != art_1.blob_id
            assert art_b.storage_ref != ws_a_storage_ref

        with pytest.raises(ForbiddenError) as cross_exc:
            await store.read_verified(
                workspace_id=ws_b,
                storage_ref=ws_a_storage_ref,
                expected_digest=expected_sha,
            )
        assert cross_exc.value.code == "cross_tenant_artifact_ref"

        # 3. `SEC-025`: SHA-256 mismatch during staged upload MUST quarantine & never mark verified
        wrong_digest = hashlib.sha256(b"different-expected-bytes").hexdigest()
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as db:
            with pytest.raises(ArtifactIntegrityError) as mismatch_exc:
                await persist_encrypted_artifact(
                    db,
                    store=store,
                    workspace_id=ws_a,
                    repository_id=repo_a,
                    name="corrupt.bin",
                    kind="ci_artifact_archive",
                    mime="application/octet-stream",
                    plaintext=b"actual-corrupted-stream",
                    expected_digest=wrong_digest,
                    now=now,
                )
            assert mismatch_exc.value.code == "artifact_sha256_mismatch"

            q_blob = await db.scalar(
                select(ArtifactBlobModel).where(
                    ArtifactBlobModel.workspace_id == ws_a,
                    ArtifactBlobModel.digest == wrong_digest,
                )
            )
            assert q_blob is not None
            assert q_blob.blob_state == "quarantined"
            assert q_blob.verified_at is None
            assert q_blob.finalized_at is None

        # 4. Orphan staged sweeper deletes stale staged objects while preserving fresh ones
        old_stage = await store.stage_upload(
            workspace_id=ws_a,
            plaintext=b"orphan-old",
            expected_digest=hashlib.sha256(b"orphan-old").hexdigest(),
            now=now - timedelta(hours=5),
        )
        fresh_stage = await store.stage_upload(
            workspace_id=ws_a,
            plaintext=b"orphan-fresh",
            expected_digest=hashlib.sha256(b"orphan-fresh").hexdigest(),
            now=now,
        )
        swept = await store.sweep_orphan_staged(
            older_than=now - timedelta(hours=1),
            workspace_id=ws_a,
        )
        assert swept == 1
        with pytest.raises(ArtifactIntegrityError):
            await store.verify_staged(old_stage)
        assert await store.verify_staged(fresh_stage) == len(b"orphan-fresh")

        # 5. Retention expiry (`410`) & ref-counted physical purge (`A-10`, `OPS-03`)
        t_plus_2d = now + timedelta(days=2)
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as db:
            purged_first = await purge_expired_artifacts_in_tx(
                db,
                store=store,
                workspace_id=ws_a,
                now=t_plus_2d,
            )
            # Only art_2 (1d retention) expired; art_1 (7d retention) still references the blob!
            assert purged_first == 1
            art_2_row = await db.scalar(select(ArtifactModel).where(ArtifactModel.id == art_2_id))
            art_1_row = await db.scalar(select(ArtifactModel).where(ArtifactModel.id == art_1_id))
            assert art_2_row is not None and art_2_row.lifecycle_state == "purged"
            assert art_1_row is not None and art_1_row.lifecycle_state == "finalized"
            with pytest.raises(GoneError):
                await read_artifact_for_authorized_caller(
                    db,
                    store=store,
                    artifact_row=art_2_row,
                    now=t_plus_2d,
                )
            assert (
                await read_artifact_for_authorized_caller(
                    db,
                    store=store,
                    artifact_row=art_1_row,
                    now=t_plus_2d,
                )
                == secret_free_payload
            )

        # At t+8d, art_1 also expires -> durable job is committed before physical deletion.
        t_plus_8d = now + timedelta(days=8)
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as db:
            purged_second = await purge_expired_artifacts_in_tx(
                db,
                store=store,
                workspace_id=ws_a,
                now=t_plus_8d,
            )
            assert purged_second == 1
            deletion_job = await db.scalar(
                select(ArtifactDeletionJobModel).where(
                    ArtifactDeletionJobModel.workspace_id == ws_a,
                    ArtifactDeletionJobModel.blob_id == art_1.blob_id,
                )
            )
            assert deletion_job is not None and deletion_job.state == "pending"

        class FailOnceStore:
            def __init__(self, wrapped: ArtifactStoreProtocol) -> None:
                self.wrapped = wrapped
                self.failed = False

            async def delete_blob(self, *, workspace_id: str, storage_ref: str) -> bool:
                if not self.failed:
                    self.failed = True
                    raise OSError("synthetic object store interruption")
                return await self.wrapped.delete_blob(
                    workspace_id=workspace_id, storage_ref=storage_ref
                )

            def __getattr__(self, name: str) -> object:
                return getattr(self.wrapped, name)

        retention = RetentionPurgeWorker(
            session_factory=app_factory,
            store=FailOnceStore(store),  # type: ignore[arg-type]
        )
        assert await retention.process_one(workspace_id=ws_a, now=t_plus_8d)
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as db:
            failed_job = await db.scalar(
                select(ArtifactDeletionJobModel).where(
                    ArtifactDeletionJobModel.workspace_id == ws_a,
                    ArtifactDeletionJobModel.blob_id == art_1.blob_id,
                )
            )
            assert failed_job is not None
            assert failed_job.state == "pending"
            assert failed_job.error_code == "storage_delete_failed"
        assert await retention.process_one(workspace_id=ws_a, now=t_plus_8d + timedelta(seconds=3))
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as db:
            blob_after = await db.scalar(
                select(ArtifactBlobModel).where(
                    ArtifactBlobModel.workspace_id == ws_a,
                    ArtifactBlobModel.digest == expected_sha,
                )
            )
            assert blob_after is not None and blob_after.blob_state == "purged"

        # 6. `SEC-025`: Tampering with finalized ciphertext in storage fails AEAD authentication
        tamper_payload = b"immutable-verified-payload"
        tamper_sha = hashlib.sha256(tamper_payload).hexdigest()
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as db:
            tamper_art = await persist_encrypted_artifact(
                db,
                store=store,
                workspace_id=ws_a,
                repository_id=repo_a,
                name="tamper-target.bin",
                kind="ci_artifact_archive",
                mime="application/octet-stream",
                plaintext=tamper_payload,
                now=t_plus_8d,
            )
            tamper_ref = tamper_art.storage_ref

        if isinstance(store, LocalEncryptedArtifactStore):
            rel_parts = tamper_ref.removeprefix("local://v1/").split("/")
            disk_file = store.root_dir.joinpath(*rel_parts)
            parsed_env = json.loads(disk_file.read_text(encoding="utf-8"))
            orig_ct = str(parsed_env["envelope"]["ciphertext_b64"])
            flipped = ("A" if orig_ct[0] != "A" else "B") + orig_ct[1:]
            parsed_env["envelope"]["ciphertext_b64"] = flipped
            disk_file.write_text(json.dumps(parsed_env), encoding="utf-8")
            with pytest.raises(ArtifactIntegrityError) as tamper_exc:
                await store.read_verified(
                    workspace_id=ws_a,
                    storage_ref=tamper_ref,
                    expected_digest=tamper_sha,
                )
            assert tamper_exc.value.code == "artifact_tampered"
        elif s3_state is not None:
            obj_key = tamper_ref.removeprefix("s3://v1/red2pr-artifacts/")
            orig_bytes, orig_dt = s3_state.buckets["red2pr-artifacts"][obj_key]
            parsed_env = json.loads(orig_bytes.decode("utf-8"))
            orig_ct = str(parsed_env["envelope"]["ciphertext_b64"])
            flipped = ("A" if orig_ct[0] != "A" else "B") + orig_ct[1:]
            parsed_env["envelope"]["ciphertext_b64"] = flipped
            s3_state.buckets["red2pr-artifacts"][obj_key] = (
                json.dumps(parsed_env).encode("utf-8"),
                orig_dt,
            )
            with pytest.raises(ArtifactIntegrityError) as tamper_exc:
                await store.read_verified(
                    workspace_id=ws_a,
                    storage_ref=tamper_ref,
                    expected_digest=tamper_sha,
                )
            assert tamper_exc.value.code == "artifact_tampered"
    finally:
        await app_engine.dispose()


@pytest.mark.asyncio
async def test_github_attempt_isolation_cdn_redirect_redaction_and_flaky_progression(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """Verify `T-TRI-01-P/N`, `T-TRI-03-P/N`, `SEC-017` redaction & `SEC-033` CDN redirect."""
    clock = ManualClock()
    harness = _build_u13_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "u13_gh_store",
    )
    transport = httpx.ASGITransport(app=harness.api_app)
    admin_client, csrf, _, ws_id = await _claim_owner_and_workspace(transport, harness.iam)

    try:
        _, repo_id = await _seed_connection_and_repo(
            harness,
            admin_client=admin_client,
            csrf=csrf,
            ws_slug="acme",
            ws_id=ws_id,
            provider="github",
            auth_mode="github_app",
            webhook_secret="ghwh_u13_secret_1122334455",
            external_repo_id="700501",
            repo_name="acme/payments",
            visibility="public",
            now=clock(),
        )

        sha_1 = "1" * 40
        sha_2 = "2" * 40
        sha_3 = "3" * 40

        # Configure Run 5001 Attempt 1 (failing matrix job + passing sibling + valid & evil zips)
        harness.state.gh_runs["5001"] = {
            "id": 5001,
            "run_attempt": 1,
            "head_branch": "main",
            "head_sha": sha_1,
            "event": "push",
            "status": "completed",
            "conclusion": "failure",
            "head_repository": {"id": 700501, "fork": False},
        }
        harness.state.gh_attempt_jobs[("5001", 1)] = [
            {
                "id": 1001,
                "name": "pytest (py=3.12, os=ubuntu)",
                "status": "completed",
                "conclusion": "failure",
                "started_at": "2026-10-28T09:00:00Z",
                "completed_at": "2026-10-28T09:01:00Z",
                "labels": ["ubuntu-latest"],
            },
            {
                "id": 1002,
                "name": "typecheck",
                "status": "completed",
                "conclusion": "failure",
                "started_at": "2026-10-28T09:00:00Z",
                "completed_at": "2026-10-28T09:00:45Z",
            },
        ]
        log_1001 = (
            "2026-10-28T09:00:12.100Z \x1b[31m\u202eRunning checkout tests\x1b[0m\n"
            f"env TOKEN={SECRET_CANARY_GH} Authorization: Bearer {SECRET_CANARY_BEARER}\n"
            "FAILED tests/test_checkout.py::test_gateway_timeout - TimeoutError: socket 150ms\n"
            "Process completed with exit code 1.\n"
        ).encode()
        log_1002 = (
            b"2026-10-28T09:00:20.000Z mypy --strict src/\n"
            b"TypeError: incompatible return type in billing.py:42\n"
            b"Process completed with exit code 1.\n"
        )
        harness.state.gh_job_logs["1001"] = (200, log_1001, True)  # Cross-origin 302 CDN redirect!
        harness.state.gh_job_logs["1002"] = (200, log_1002, False)

        good_zip = _make_zip_bytes(
            {
                "junit/results.xml": b"<testsuite tests='1' failures='1'/>",
                "junit/meta.json": b'{"attempt": 1}',
            }
        )
        evil_zip = _make_zip_bytes({"../../etc/passwd": b"root:x:0:0"})
        harness.state.gh_run_artifacts["5001"] = [
            {
                "id": 801,
                "name": "junit-report.zip",
                "size_in_bytes": len(good_zip),
                "expired": False,
                "created_at": "2026-10-28T09:01:00Z",
                "expires_at": "2026-11-28T09:01:00Z",
            },
            {
                "id": 802,
                "name": "evil-traversal.zip",
                "size_in_bytes": len(evil_zip),
                "expired": False,
                "created_at": "2026-10-28T09:01:00Z",
                "expires_at": "2026-11-28T09:01:00Z",
            },
        ]
        harness.state.gh_artifact_blobs["801"] = (200, good_zip)
        harness.state.gh_artifact_blobs["802"] = (200, evil_zip)

        # 1. Collect Attempt 1 (`5001:1`)
        run_a1 = await harness.collector.collect_run_attempt(
            workspace_id=ws_id,
            repository_id=repo_id,
            external_run_id="5001",
            attempt_key="5001:1",
            expected_head_sha=sha_1,
            now=clock(),
        )
        assert harness.state.cdn_redirect_hits >= 1
        assert harness.state.cdn_redirect_auth_leaked is False  # SEC-033 proven!
        assert run_a1.attempt_number == 1
        assert run_a1.total_job_count == 2
        assert run_a1.failed_job_count == 2
        assert run_a1.artifact_count == 1  # good_zip stored; evil_zip rejected!
        assert run_a1.ingestion_state == "incomplete"
        assert run_a1.incomplete_reason is not None
        assert "archive_path_traversal" in run_a1.incomplete_reason
        assert run_a1.flaky_classification == "insufficient_history"

        # Verify secret canary NEVER entered stored log artifact, excerpt, or fingerprint (SEC-017)
        log_resp = await admin_client.get(f"/api/v1/workspaces/acme/runs/{run_a1.id}/jobs")
        assert log_resp.status_code == 200, log_resp.text
        jobs_a1 = log_resp.json()["items"]
        pytest_job_a1 = next(j for j in jobs_a1 if j["external_id"] == "1001")
        assert pytest_job_a1["matrix_dimensions"] == {
            "py": "3.12",
            "os": "ubuntu",
            "runner": "ubuntu-latest",
        }
        assert SECRET_CANARY_GH not in (pytest_job_a1["failure_excerpt"] or "")

        chunk_resp = await admin_client.get(
            f"/api/v1/workspaces/acme/jobs/{pytest_job_a1['id']}/log"
        )
        assert chunk_resp.status_code == 200, chunk_resp.text
        chunk_text = chunk_resp.json()["content"]
        assert SECRET_CANARY_GH not in chunk_text
        assert SECRET_CANARY_BEARER not in chunk_text
        assert "[REDACTED" in chunk_text

        # Verify `security.policy.denied` outbox event emitted for `evil-traversal.zip`
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
            denied_evt = await db.scalar(
                select(OutboxEventModel).where(
                    OutboxEventModel.workspace_id == ws_id,
                    OutboxEventModel.event_type == "security.policy.denied",
                )
            )
            assert denied_evt is not None

        # 2. Attempt 2 (`5001:2`) on SAME `sha_1`: `pytest` turns GREEN (`success`)!
        clock.advance(minutes=3)
        harness.state.gh_runs["5001"] = {
            "id": 5001,
            "run_attempt": 2,
            "head_branch": "main",
            "head_sha": sha_1,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_repository": {"id": 700501, "fork": False},
        }
        harness.state.gh_attempt_jobs[("5001", 2)] = [
            {
                "id": 2001,
                "name": "pytest (py=3.12, os=ubuntu)",
                "status": "completed",
                "conclusion": "success",
                "retry_of_id": "1001",
                "started_at": "2026-10-28T09:03:00Z",
                "completed_at": "2026-10-28T09:04:00Z",
            }
        ]
        harness.state.gh_job_logs["2001"] = (200, b"1 passed in 0.42s\n", False)
        harness.state.gh_run_artifacts["5001"] = []

        run_a2 = await harness.collector.collect_run_attempt(
            workspace_id=ws_id,
            repository_id=repo_id,
            external_run_id="5001",
            attempt_key="5001:2",
            expected_head_sha=sha_1,
            is_rerun=True,
            now=clock(),
        )
        assert run_a2.attempt_number == 2
        assert run_a2.is_rerun is True
        assert run_a2.total_job_count == 1
        # T-TRI-03-N: 1 failure + 1 green rerun MUST be `single_pass_unproven`, NEVER `flaky`!
        assert run_a2.flaky_classification == "single_pass_unproven"

        # Re-collecting Attempt 1 while live run 5001 is at attempt 2 (`success`) MUST keep
        # Attempt 1 `conclusion == 'failure'` and isolated to its 2 attempt-1 jobs!
        run_a1_recheck = await harness.collector.collect_run_attempt(
            workspace_id=ws_id,
            repository_id=repo_id,
            external_run_id="5001",
            attempt_key="5001:1",
            expected_head_sha=sha_1,
            now=clock(),
        )
        assert run_a1_recheck.conclusion == "failure"
        assert run_a1_recheck.total_job_count == 2
        assert run_a1_recheck.flaky_classification == "single_pass_unproven"

        # 3. Run 5002 on `sha_2`: `pytest` fails a 2nd time (with drifted timestamp & duration)
        #    -> transitions deterministically to `flaky` (`T-TRI-03-P`), while `typecheck` fails
        #    a 2nd time and then a 3rd time on `sha_3` (`persistent_failure`)!
        clock.advance(minutes=5)
        harness.state.gh_runs["5002"] = {
            "id": 5002,
            "run_attempt": 1,
            "head_branch": "main",
            "head_sha": sha_2,
            "event": "push",
            "status": "completed",
            "conclusion": "failure",
            "head_repository": {"id": 700501, "fork": False},
        }
        harness.state.gh_attempt_jobs[("5002", 1)] = [
            {
                "id": 3001,
                "name": "pytest (py=3.12, os=ubuntu)",
                "status": "completed",
                "conclusion": "failure",
            },
            {
                "id": 3002,
                "name": "typecheck",
                "status": "completed",
                "conclusion": "failure",
            },
        ]
        harness.state.gh_job_logs["3001"] = (
            200,
            (
                b"2026-10-28T09:08:55.999Z FAILED tests/test_checkout.py::"
                b"test_gateway_timeout - TimeoutError: socket 890ms\n"
            ),
            False,
        )
        harness.state.gh_job_logs["3002"] = (
            200,
            b"TypeError: incompatible return type in billing.py:99\n",
            False,
        )
        run_5002 = await harness.collector.collect_run_attempt(
            workspace_id=ws_id,
            repository_id=repo_id,
            external_run_id="5002",
            attempt_key="5002:1",
            expected_head_sha=sha_2,
            now=clock(),
        )
        assert run_5002.flaky_classification == "flaky"

        # 3rd consecutive failure of `typecheck` on `sha_3` -> `persistent_failure`
        clock.advance(minutes=5)
        harness.state.gh_runs["5003"] = {
            "id": 5003,
            "run_attempt": 1,
            "head_branch": "main",
            "head_sha": sha_3,
            "event": "push",
            "status": "completed",
            "conclusion": "failure",
            "head_repository": {"id": 700501, "fork": False},
        }
        harness.state.gh_attempt_jobs[("5003", 1)] = [
            {
                "id": 4002,
                "name": "typecheck",
                "status": "completed",
                "conclusion": "failure",
            }
        ]
        harness.state.gh_job_logs["4002"] = (
            200,
            b"TypeError: incompatible return type in billing.py:108\n",
            False,
        )
        run_5003 = await harness.collector.collect_run_attempt(
            workspace_id=ws_id,
            repository_id=repo_id,
            external_run_id="5003",
            attempt_key="5003:1",
            expected_head_sha=sha_3,
            now=clock(),
        )
        assert run_5003.flaky_classification == "persistent_failure"

        # Verify `A-08` `flaky_only=true` filter returns only `flaky` runs
        flaky_list = await admin_client.get(
            "/api/v1/workspaces/acme/runs",
            params={"flaky_only": "true"},
        )
        assert flaky_list.status_code == 200
        flaky_ids = [item["id"] for item in flaky_list.json()["items"]]
        assert run_5002.id in flaky_ids
        assert run_5003.id not in flaky_ids
    finally:
        await admin_client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_gitlab_child_pipelines_410_expired_logs_truncation_and_stale_sha(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """Verify GitLab child pipelines, `410` expired logs, log cap truncation & `SEC-016` SHA."""
    clock = ManualClock()
    # Set a tight 2048-byte log cap to deterministically exercise truncation + UTF-8 pagination
    harness = _build_u13_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "u13_gl_store",
        max_log_bytes=2048,
    )
    transport = httpx.ASGITransport(app=harness.api_app)
    admin_client, csrf, _, ws_id = await _claim_owner_and_workspace(transport, harness.iam)

    try:
        _, gl_repo_id = await _seed_connection_and_repo(
            harness,
            admin_client=admin_client,
            csrf=csrf,
            ws_slug="acme",
            ws_id=ws_id,
            provider="gitlab",
            auth_mode="gitlab_legacy_token",
            webhook_secret="glwh_u13_secret_99887766",
            external_repo_id="9901",
            repo_name="acme-gl/core-api",
            now=clock(),
        )

        gl_sha = "a" * 40
        harness.state.gl_pipelines["7701"] = {
            "id": 7701,
            "project_id": 9901,
            "sha": gl_sha,
            "ref": "main",
            "status": "failed",
            "source": "push",
        }
        harness.state.gl_bridges["7701"] = [
            {
                "id": 880,
                "name": "trigger-e2e",
                "status": "failed",
                "downstream_pipeline": {
                    "id": 7702,
                    "project_id": 9901,
                    "status": "failed",
                    "sha": gl_sha,
                    "ref": "main",
                },
            }
        ]
        harness.state.gl_pipeline_jobs["7701"] = [
            {
                "id": 501,
                "name": "build: [linux, amd64]",
                "stage": "build",
                "status": "success",
                "started_at": "2026-10-28T09:00:00Z",
                "finished_at": "2026-10-28T09:01:00Z",
                "artifacts": [],
            }
        ]
        harness.state.gl_pipeline_jobs["7702"] = [
            {
                "id": 601,
                "name": "e2e-smoke",
                "stage": "test",
                "status": "failed",
                "started_at": "2026-10-28T09:01:10Z",
                "finished_at": "2026-10-28T09:02:00Z",
                "artifacts": [],
            }
        ]

        # Oversized UTF-8 trace (> 2048 bytes) with multi-byte characters ("việt 🚀")
        utf8_line = "Bước kiểm thử UTF-8 🚀 hoàn tất dòng log dài\n"
        oversized_trace = (utf8_line * 90 + "TAIL_SENTINEL_MARKER_END\n").encode("utf-8")
        assert len(oversized_trace) > 2048
        harness.state.gl_job_traces["501"] = (200, oversized_trace)
        # Child pipeline job 601 trace has EXPIRED upstream (`410 Gone`, `T-TRI-01-N`)
        harness.state.gl_job_traces["601"] = (410, b"")

        gl_run = await harness.collector.collect_run_attempt(
            workspace_id=ws_id,
            repository_id=gl_repo_id,
            external_run_id="7701",
            attempt_key="pipeline:7701",
            expected_head_sha=gl_sha,
            now=clock(),
        )
        assert gl_run.child_pipeline_ids == ["7702"]
        assert gl_run.total_job_count == 2
        assert gl_run.failed_job_count == 1
        # Expired 410 log MUST keep ingestion_state == 'incomplete' (NEVER assumed passing!)
        assert gl_run.ingestion_state == "incomplete"
        assert gl_run.incomplete_reason is not None
        assert "log_expired:601" in gl_run.incomplete_reason
        assert gl_run.flaky_classification == "unknown"

        jobs_resp = await admin_client.get(f"/api/v1/workspaces/acme/runs/{gl_run.id}/jobs")
        assert jobs_resp.status_code == 200
        gl_jobs = jobs_resp.json()["items"]
        build_job = next(j for j in gl_jobs if j["external_id"] == "501")
        child_job = next(j for j in gl_jobs if j["is_child_pipeline_job"] is True)
        assert child_job["child_pipeline_id"] == "7702"
        assert child_job["log_status"] == "expired"

        # `A-08`: expired log endpoint MUST return `410 Gone` (`Problem.code == 'log_expired'`)
        expired_resp = await admin_client.get(f"/api/v1/workspaces/acme/jobs/{child_job['id']}/log")
        assert expired_resp.status_code == 410, expired_resp.text
        assert expired_resp.json()["code"] == "log_expired"

        # `A-08`: truncated UTF-8 log paginates across 512-byte slices without U+FFFD corruption
        assert build_job["log_truncated"] is True
        assembled_parts: list[str] = []
        offset = 0
        for _ in range(10):
            slice_resp = await admin_client.get(
                f"/api/v1/workspaces/acme/jobs/{build_job['id']}/log",
                params={"start_offset": offset, "max_bytes": 512},
            )
            assert slice_resp.status_code == 200, slice_resp.text
            body = slice_resp.json()
            assert body["truncated"] is True
            assert body["incomplete_marker"] == "upstream_log_truncated_at_cap"
            assembled_parts.append(str(body["content"]))
            offset = int(body["next_offset"])
            if not body["has_more"]:
                break
        assembled = "".join(assembled_parts)
        assert TRUNCATION_BANNER.strip() in assembled
        assert "TAIL_SENTINEL_MARKER_END" in assembled
        assert "\ufffd" not in assembled[len(TRUNCATION_BANNER) + 8 :]

        # `SEC-016`: Stale / force-pushed `head_sha` mismatch on pipeline 7703
        harness.state.gl_pipelines["7703"] = {
            "id": 7703,
            "project_id": 9901,
            "sha": "f" * 40,  # Live provider SHA differs from pinned trigger SHA!
            "ref": "main",
            "status": "failed",
            "source": "push",
        }
        harness.state.gl_pipeline_jobs["7703"] = [
            {
                "id": 701,
                "name": "unit",
                "stage": "test",
                "status": "failed",
                "artifacts": [],
            }
        ]
        harness.state.gl_job_traces["701"] = (
            200,
            b"FAILED tests/test_sec.py::test_sha - AssertionError\n",
        )
        stale_run = await harness.collector.collect_run_attempt(
            workspace_id=ws_id,
            repository_id=gl_repo_id,
            external_run_id="7703",
            attempt_key="pipeline:7703",
            expected_head_sha="e" * 40,
            now=clock(),
        )
        assert stale_run.head_sha_verified is False
        assert stale_run.observed_head_sha == "f" * 40
        assert stale_run.ingestion_state == "stale_sha"
        assert stale_run.flaky_classification == "unknown"
    finally:
        await admin_client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_ig03_wave2_end_to_end_webhook_to_pipelines_api_rbac_and_repo_grants(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """Verify `IG-03` Wave 2 gate: webhook -> triage queue -> `A-08`/`A-10` RBAC & `repo_grants`."""
    clock = ManualClock()
    harness = _build_u13_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "u13_ig03_store",
    )
    gh_secret = "ghwh_ig03_wave2_secret_9988776655"
    transport = httpx.ASGITransport(app=harness.api_app)
    admin_client, csrf, _, ws_id = await _claim_owner_and_workspace(transport, harness.iam)

    viewer_dto = await harness.iam.provision_local_user(
        display_name="Pipelines Viewer",
        email="viewer.u13@red2pr.local",
        password=VIEWER_CREDENTIAL,
    )
    viewer_client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    v_pre_csrf = (await viewer_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
    v_login = await viewer_client.post(
        "/api/v1/auth/login",
        headers=_csrf_headers(v_pre_csrf),
        json={"identifier": "viewer.u13@red2pr.local", "password": VIEWER_CREDENTIAL},
    )
    assert v_login.status_code == 200, v_login.text
    v_csrf = str(v_login.json()["csrf_token"])

    try:
        conn_id, repo_1 = await _seed_connection_and_repo(
            harness,
            admin_client=admin_client,
            csrf=csrf,
            ws_slug="acme",
            ws_id=ws_id,
            provider="github",
            auth_mode="github_app",
            webhook_secret=gh_secret,
            external_repo_id="710001",
            repo_name="acme/monitored-api",
            visibility="private",  # -> CI artifacts get `access_class='restricted'`
            mode="monitor",
            now=clock(),
        )
        # Second private repository that viewer is NOT granted access to (`SEC-010`)
        repo_2 = new_uuid7(now=clock())
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
            db.add(
                RepositoryModel(
                    id=repo_2,
                    workspace_id=ws_id,
                    provider_connection_id=conn_id,
                    external_repo_id="710002",
                    name="acme/ungranted-vault",
                    default_branch="main",
                    visibility="private",
                    mode="monitor",
                    paused=False,
                    active=True,
                    archived=False,
                    is_fork=False,
                    policy_revision=1,
                    tags_json=[],
                    workflow_hazard_status="clean",
                    workflow_hazards_json=[],
                    auto_repair_blocked=False,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        # Invite viewer with `repo_grants` ONLY for `repo_1`
        inv_resp = await admin_client.post(
            "/api/v1/workspaces/acme/invitations",
            headers=_csrf_headers(csrf),
            json={
                "email": "viewer.u13@red2pr.local",
                "role": "viewer",
                "repository_grants": [repo_1],
            },
        )
        assert inv_resp.status_code == 201, inv_resp.text
        acc_resp = await viewer_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(v_csrf),
            json={"token": inv_resp.json()["invite_token"]},
        )
        assert acc_resp.status_code == 200, acc_resp.text
        viewer_membership_id = str(acc_resp.json()["id"])

        # Seed provider state for run 9101 (repo_1 via webhook) and run 9201 (repo_2 direct)
        sha_r1 = "b" * 40
        sha_r2 = "d" * 40
        archive_payload = _make_zip_bytes({"diagnostics/summary.txt": b"captured failure trace"})
        harness.state.gh_runs["9101"] = {
            "id": 9101,
            "run_attempt": 1,
            "head_branch": "main",
            "head_sha": sha_r1,
            "event": "push",
            "status": "completed",
            "conclusion": "failure",
            "head_repository": {"id": 710001, "fork": False},
        }
        harness.state.gh_attempt_jobs[("9101", 1)] = [
            {
                "id": 91011,
                "name": "unit-tests (ubuntu-latest)",
                "status": "completed",
                "conclusion": "failure",
            }
        ]
        harness.state.gh_job_logs["91011"] = (
            200,
            b"FAILED tests/test_auth.py::test_token - AssertionError: expected 200\n",
            False,
        )
        harness.state.gh_run_artifacts["9101"] = [
            {
                "id": 9501,
                "name": "diag-bundle.zip",
                "size_in_bytes": len(archive_payload),
                "expired": False,
                "created_at": "2026-10-28T09:00:00Z",
                "expires_at": "2026-10-30T09:00:00Z",
            }
        ]
        harness.state.gh_artifact_blobs["9501"] = (200, archive_payload)

        harness.state.gh_runs["9201"] = {
            "id": 9201,
            "run_attempt": 1,
            "head_branch": "main",
            "head_sha": sha_r2,
            "event": "push",
            "status": "completed",
            "conclusion": "failure",
            "head_repository": {"id": 710002, "fork": False},
        }
        harness.state.gh_attempt_jobs[("9201", 1)] = [
            {
                "id": 92011,
                "name": "vault-check",
                "status": "completed",
                "conclusion": "failure",
            }
        ]
        harness.state.gh_job_logs["92011"] = (200, b"FAILED tests/test_vault.py::test_1\n", False)
        ungranted_run = await harness.collector.collect_run_attempt(
            workspace_id=ws_id,
            repository_id=repo_2,
            external_run_id="9201",
            attempt_key="9201:1",
            expected_head_sha=sha_r2,
            now=clock(),
        )

        # 1. Deliver signed GitHub `workflow_run` failure webhook -> `202 Accepted`
        webhook_payload = {
            "action": "completed",
            "installation": {"id": int(harness.state.gh_installation_id)},
            "repository": {
                "id": 710001,
                "name": "monitored-api",
                "full_name": "acme/monitored-api",
            },
            "sender": {"login": "dev-alice"},
            "workflow_run": {
                "id": 9101,
                "run_attempt": 1,
                "head_branch": "main",
                "head_sha": sha_r1,
                "event": "push",
                "status": "completed",
                "conclusion": "failure",
                "created_at": "2026-10-28T09:00:00Z",
                "updated_at": "2026-10-28T09:01:00Z",
                "head_commit": {"message": "feat: add endpoint"},
                "head_repository": {"id": 710001, "fork": False},
            },
        }
        raw_wh = json.dumps(webhook_payload).encode("utf-8")
        async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL) as hook_client:
            wh_resp = await hook_client.post(
                f"/api/v1/hooks/github/{conn_id}",
                content=raw_wh,
                headers={
                    "Content-Type": "application/json",
                    "X-GitHub-Event": "workflow_run",
                    "X-GitHub-Delivery": "deliv-ig03-9101-1",
                    "X-Hub-Signature-256": _gh_hmac_header(gh_secret, raw_wh),
                },
            )
        assert wh_resp.status_code == 202, wh_resp.text
        assert wh_resp.json()["disposition"] == "accepted_trigger"

        # 2. Lease & execute `ci_run.triage` job; verify `0` `is_repair_job=True` sandbox jobs
        triaged_run = await harness.collector.process_next_triage_job(
            task_queue=harness.queue_service,
            worker_id=new_uuid7(now=clock()),
            now=clock(),
        )
        assert triaged_run is not None
        assert triaged_run.ingestion_state == "ingested"
        assert triaged_run.artifact_count == 1

        async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
            repair_job_count = await db.scalar(
                select(func.count())
                .select_from(TaskJobModel)
                .where(
                    TaskJobModel.workspace_id == ws_id,
                    TaskJobModel.is_repair_job.is_(True),
                )
            )
            assert int(repair_job_count or 0) == 0  # ADR-033: monitor mode = zero sandbox jobs!

        # 3. `A-08` & `S-14`: Viewer sees ONLY `repo_1` run (`0` `repo_2` runs); `404` on `repo_2`
        v_runs = await viewer_client.get("/api/v1/workspaces/acme/runs", params={"limit": 1})
        assert v_runs.status_code == 200, v_runs.text
        v_page = v_runs.json()
        assert [r["id"] for r in v_page["items"]] == [triaged_run.id]
        assert v_page["next_cursor"] is None

        # Admin sees BOTH runs across signed S-04 cursor pages
        adm_p1 = await admin_client.get("/api/v1/workspaces/acme/runs", params={"limit": 1})
        assert adm_p1.status_code == 200
        adm_p2 = await admin_client.get(
            "/api/v1/workspaces/acme/runs",
            params={"limit": 5, "cursor": adm_p1.json()["next_cursor"]},
        )
        assert adm_p2.status_code == 200
        all_admin_run_ids = {r["id"] for r in (*adm_p1.json()["items"], *adm_p2.json()["items"])}
        assert {triaged_run.id, ungranted_run.id}.issubset(all_admin_run_ids)

        assert (
            await viewer_client.get(f"/api/v1/workspaces/acme/runs/{ungranted_run.id}")
        ).status_code == 404

        detail_resp = await viewer_client.get(f"/api/v1/workspaces/acme/runs/{triaged_run.id}")
        assert detail_resp.status_code == 200, detail_resp.text
        assert "storage_ref" not in detail_resp.text  # S-14 non-exposure invariant!
        detail_json = detail_resp.json()
        art_id = str(detail_json["artifacts"][0]["id"])
        job_id = str(detail_json["jobs"][0]["id"])

        # 4. `A-10`: `restricted` artifact denies `viewer` (`403`) & allows `admin` (`200`)
        v_dl = await viewer_client.get(f"/api/v1/workspaces/acme/artifacts/{art_id}/download")
        assert v_dl.status_code == 403, v_dl.text
        assert v_dl.json()["code"] == "insufficient_role"

        adm_dl = await admin_client.get(f"/api/v1/workspaces/acme/artifacts/{art_id}/download")
        assert adm_dl.status_code == 200
        assert adm_dl.content == archive_payload
        assert adm_dl.headers["x-content-type-options"] == "nosniff"
        assert adm_dl.headers["cache-control"] == "no-store"
        assert adm_dl.headers["x-artifact-digest"] == (
            f"sha256:{hashlib.sha256(archive_payload).hexdigest()}"
        )

        # 5. Live `repo_grants` revocation (`SEC-010`, `SEC-032`) immediately hides runs & `404`s
        revoke_resp = await admin_client.patch(
            f"/api/v1/workspaces/acme/members/{viewer_membership_id}",
            headers=_csrf_headers(csrf),
            json={"repository_grants": []},
        )
        assert revoke_resp.status_code == 200, revoke_resp.text

        v_after_list = await viewer_client.get("/api/v1/workspaces/acme/runs")
        assert v_after_list.status_code == 200
        assert v_after_list.json()["items"] == []

        for denied_path in (
            f"/api/v1/workspaces/acme/runs/{triaged_run.id}",
            f"/api/v1/workspaces/acme/runs/{triaged_run.id}/jobs",
            f"/api/v1/workspaces/acme/jobs/{job_id}/log",
            f"/api/v1/workspaces/acme/artifacts/{art_id}/download",
        ):
            r_den = await viewer_client.get(denied_path)
            assert r_den.status_code == 404, (
                f"Expected 404 on {denied_path}, got {r_den.status_code}"
            )

        # 6. Advancing clock past 2-day `expires_at` returns `410 artifact_expired` on `A-10`
        clock.advance(days=3)
        reauth_csrf = (await admin_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
        reauth_resp = await admin_client.post(
            "/api/v1/auth/login",
            headers=_csrf_headers(reauth_csrf),
            json={"identifier": "owner.u13@red2pr.local", "password": OWNER_CREDENTIAL},
        )
        assert reauth_resp.status_code == 200, reauth_resp.text
        exp_dl = await admin_client.get(f"/api/v1/workspaces/acme/artifacts/{art_id}/download")
        assert exp_dl.status_code == 410, exp_dl.text
        assert exp_dl.json()["code"] == "artifact_expired"

        # Confirm both allow & deny download audit entries exist and full hash chain is intact
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
            dl_actions = set(
                (
                    await db.scalars(
                        select(AuditLogModel.action).where(
                            AuditLogModel.workspace_id == ws_id,
                            AuditLogModel.action.in_(("artifact.download", "artifact.downloaded")),
                        )
                    )
                ).all()
            )
            assert dl_actions == {"artifact.download", "artifact.downloaded"}

        ckpt_store = ExternalCheckpointStore(tmp_path / "audit_ckpt.json")
        async with instance_rls_session(harness.app_factory, mode="audit_verifier") as audit_db:
            entries_checked = await verify_audit_chain(
                audit_db,
                external_store=ckpt_store,
                keyring=KeyRing(),
            )
            assert entries_checked >= 10
        _ = viewer_dto
    finally:
        await viewer_client.aclose()
        await admin_client.aclose()
        await harness.app_engine.dispose()
