"""FastAPI `/api/v1` router & query service for `A-08` CI runs/jobs/logs & `A-10` downloads (`U13`).

Implements:
- `GET /api/v1/workspaces/{ws}/runs` (`A-08`: signed `S-04` cursor pagination, scoped strictly
  by live `repo_grants` so unauthorized repositories return `0` rows / `404` anti-enumeration).
- `GET /api/v1/workspaces/{ws}/runs/{run_id}` (`A-08`: `CiRunDetailResponse` with sibling rerun
  attempts, matrix jobs, `S-14` `Artifact` list without `storage_ref`, and `TRI-03` fingerprints).
- `GET /api/v1/workspaces/{ws}/runs/{run_id}/jobs` (`A-08`: `CiJobListResponse`).
- `GET /api/v1/workspaces/{ws}/jobs/{job_id}/log` (`A-08`: UTF-8 boundary-safe log slices up to
  `max_bytes <= 65536`, `410 log_expired` on expired upstream/retained logs, explicit `truncated`
  and `incomplete_marker` indicators).
- `GET /api/v1/workspaces/{ws}/artifacts/{artifact_id}/download` (`A-10`: live in-transaction
  membership + `repo_grants` + `access_class` reauthorization, `410 artifact_expired` after
  `retention_until`, AEAD + SHA-256 verification on read, and hash-chained audit logging).
"""

from __future__ import annotations

import hashlib
import re
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path as FsPath
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import and_, desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import MasterKeyRing
from py_contracts.evidence import Artifact, CiRunDetailResponse
from py_contracts.iam import WorkspaceRole
from py_contracts.integrations import (
    CiConclusion,
    CiJobListResponse,
    CiRunIngestionState,
    CiRunPage,
    CiRunStatus,
    FailureFingerprintSummary,
    FlakyClassification,
    JobLogChunkResponse,
    JobLogStatus,
)
from py_contracts.primitives import InternalId, Problem
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    DependencyUnavailableError,
    ForbiddenError,
    GoneError,
    NotFoundError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.core.redaction import REDACTION_VERSION
from red2pr_control.db.base import (
    ArtifactModel,
    BreakGlassGrantModel,
    CiJobModel,
    CiRunModel,
    FailureFingerprintModel,
    MembershipModel,
    RepoGrantModel,
    RepositoryModel,
)
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.iam.csrf import set_csrf_cookie
from red2pr_control.iam.rbac import (
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import IamService, extract_client_ip
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    LocalEncryptedArtifactStore,
    artifact_model_to_public_dto,
    read_artifact_for_authorized_caller,
)
from red2pr_control.triage_evidence.collector import ci_job_model_to_dto, ci_run_model_to_dto
from red2pr_control.triage_evidence.flaky import fingerprint_model_to_dto

MAX_LOG_CHUNK_BYTES = 65536
_UUID_ADAPTER: TypeAdapter[str] = TypeAdapter(InternalId)
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_RESTRICTED_ARTIFACT_ROLES: frozenset[WorkspaceRole] = frozenset(
    {"admin", "maintainer", "reviewer", "auditor"}
)

_COMMON_PROBLEM_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    401: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    403: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    404: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    409: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    410: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    422: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    429: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    503: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
}


def _default_utc_clock() -> datetime:
    return datetime.now(tz=UTC)


def _validate_uuid_or_404(raw_id: str, *, code: str, detail: str) -> str:
    try:
        return _UUID_ADAPTER.validate_python(raw_id.strip())
    except ValidationError as exc:
        raise NotFoundError(code=code, detail=detail) from exc


def _slice_utf8_safe(data: bytes, *, start_offset: int, max_bytes: int) -> tuple[str, int, int]:
    """Return `(decoded_chunk, effective_start, next_offset)` without splitting UTF-8 codepoints."""
    total = len(data)
    if start_offset >= total or total == 0:
        return "", total, total

    eff_start = max(0, start_offset)
    # If caller specified a mid-codepoint offset, step forward to next UTF-8 lead/ASCII byte
    while eff_start < total and (0x80 <= data[eff_start] < 0xC0):
        eff_start += 1
    if eff_start >= total:
        return "", total, total

    end = min(total, eff_start + max_bytes)
    if end < total:
        # Step back up to 3 bytes if `end` cuts through a multi-byte UTF-8 sequence
        probe = end
        while probe > eff_start and (0x80 <= data[probe] < 0xC0):
            probe -= 1
        if probe > eff_start or (probe == eff_start and (0x80 <= data[end] < 0xC0)):
            lead = data[probe]
            seq_len = (
                4
                if (lead & 0xF8) == 0xF0
                else 3
                if (lead & 0xF0) == 0xE0
                else 2
                if (lead & 0xE0) == 0xC0
                else 1
            )
            if probe + seq_len > end and probe > eff_start:
                end = probe

    chunk_bytes = data[eff_start:end]
    return chunk_bytes.decode("utf-8", errors="replace"), eff_start, end


def _safe_attachment_filename(raw_name: str | None, *, fallback: str) -> str:
    candidate = (raw_name or fallback).strip()
    cleaned = _SAFE_FILENAME_RE.sub("_", candidate).strip("._")
    return cleaned[:100] or fallback


class TriageEvidenceService:
    """Workspace- & `repo_grants`-scoped `A-08` / `A-10` query and artifact download service."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        signing_key: bytes,
        artifact_store: ArtifactStoreProtocol,
        clock: Callable[[], datetime] = _default_utc_clock,
    ) -> None:
        self._session_factory = session_factory
        self._signing_key = signing_key
        self._artifact_store = artifact_store
        self._clock = clock

    @property
    def artifact_store(self) -> ArtifactStoreProtocol:
        return self._artifact_store

    async def _resolve_live_repo_scope_in_tx(
        self,
        db: AsyncSession,
        ws_ctx: WorkspaceAccessContext,
        *,
        now: datetime,
    ) -> tuple[bool, frozenset[str], WorkspaceRole | Literal["break_glass"]]:
        """Re-verify live DB membership / `repo_grants` / break-glass inside the active tx."""
        uid = ws_ctx.auth.user.id
        ws_id = ws_ctx.workspace_id

        mem = await db.scalar(
            select(MembershipModel).where(
                MembershipModel.workspace_id == ws_id,
                MembershipModel.user_id == uid,
            )
        )
        if mem is not None:
            role = cast(WorkspaceRole, mem.role)
            if role == "admin":
                return True, frozenset(), "admin"
            granted_ids = frozenset(
                (
                    await db.scalars(
                        select(RepoGrantModel.repository_id).where(
                            RepoGrantModel.workspace_id == ws_id,
                            RepoGrantModel.membership_id == mem.id,
                        )
                    )
                ).all()
            )
            return False, granted_ids, role

        if ws_ctx.auth.user.is_instance_owner:
            bg = await db.scalar(
                select(BreakGlassGrantModel).where(
                    BreakGlassGrantModel.workspace_id == ws_id,
                    BreakGlassGrantModel.user_id == uid,
                    BreakGlassGrantModel.revoked_at.is_(None),
                    BreakGlassGrantModel.expires_at > now,
                )
            )
            if bg is not None:
                return True, frozenset(), "break_glass"

        raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")

    async def list_runs(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        cursor: str | None = None,
        limit: int = 25,
        repository_id: str | None = None,
        status: CiRunStatus | None = None,
        conclusion: CiConclusion | None = None,
        ingestion_state: CiRunIngestionState | None = None,
        flaky_classification: FlakyClassification | None = None,
        head_sha: str | None = None,
        flaky_only: bool = False,
    ) -> CiRunPage:
        """List authorized `CiRun` attempts with signed `S-04` keyset pagination (`A-08`)."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        grant_epoch = ws_ctx.auth.user.grant_epoch

        clean_repo_id: str | None = None
        if repository_id is not None and repository_id.strip():
            clean_repo_id = _validate_uuid_or_404(
                repository_id,
                code="repository_not_found",
                detail="Repository not found.",
            )

        clean_sha = head_sha.strip().lower()[:64] if head_sha and head_sha.strip() else None
        q_hash = compute_query_filter_hash(
            {
                "conclusion": conclusion,
                "flaky_classification": flaky_classification,
                "flaky_only": flaky_only,
                "head_sha": clean_sha,
                "ingestion_state": ingestion_state,
                "repository_id": clean_repo_id,
                "status": status,
            }
        )
        decoded_cursor = (
            decode_signed_cursor(
                cursor,
                signing_key=self._signing_key,
                expected_workspace_scope=ws_id,
                expected_principal_id=ws_ctx.auth.user.id,
                current_grant_epoch=grant_epoch,
                expected_query_hash=q_hash,
                now=ref_now,
            )
            if cursor is not None
            else None
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            all_repos, granted_ids, _ = await self._resolve_live_repo_scope_in_tx(
                db,
                ws_ctx,
                now=ref_now,
            )
            if clean_repo_id is not None and not all_repos and clean_repo_id not in granted_ids:
                raise NotFoundError(
                    code="repository_not_found",
                    detail="Repository not found.",
                )
            if not all_repos and not granted_ids:
                return CiRunPage(items=[], next_cursor=None, snapshot_at=ref_now)

            stmt = (
                select(CiRunModel, RepositoryModel.name)
                .join(
                    RepositoryModel,
                    and_(
                        RepositoryModel.workspace_id == CiRunModel.workspace_id,
                        RepositoryModel.id == CiRunModel.repository_id,
                    ),
                )
                .where(CiRunModel.workspace_id == ws_id)
            )
            if not all_repos:
                stmt = stmt.where(CiRunModel.repository_id.in_(sorted(granted_ids)))
            if clean_repo_id is not None:
                stmt = stmt.where(CiRunModel.repository_id == clean_repo_id)
            if status is not None:
                stmt = stmt.where(CiRunModel.status == status)
            if conclusion is not None:
                stmt = stmt.where(CiRunModel.conclusion == conclusion)
            if ingestion_state is not None:
                stmt = stmt.where(CiRunModel.ingestion_state == ingestion_state)
            if flaky_classification is not None:
                stmt = stmt.where(CiRunModel.flaky_classification == flaky_classification)
            if flaky_only:
                stmt = stmt.where(CiRunModel.flaky_classification == "flaky")
            if clean_sha is not None:
                stmt = stmt.where(CiRunModel.head_sha == clean_sha)
            if decoded_cursor is not None:
                stmt = stmt.where(
                    or_(
                        CiRunModel.created_at < decoded_cursor.created_at,
                        and_(
                            CiRunModel.created_at == decoded_cursor.created_at,
                            CiRunModel.id < decoded_cursor.item_id,
                        ),
                    )
                )

            stmt = stmt.order_by(desc(CiRunModel.created_at), desc(CiRunModel.id)).limit(limit + 1)
            rows = list((await db.execute(stmt)).all())

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        items = [
            ci_run_model_to_dto(run_row, repository_name=str(repo_name))
            for run_row, repo_name in page_rows
        ]
        next_cursor: str | None = None
        if has_more and page_rows:
            last_run = page_rows[-1][0]
            next_cursor = encode_signed_cursor(
                signing_key=self._signing_key,
                workspace_scope=ws_id,
                principal_id=ws_ctx.auth.user.id,
                grant_epoch=grant_epoch,
                query_hash=q_hash,
                created_at=last_run.created_at,
                item_id=last_run.id,
                now=ref_now,
            )

        return CiRunPage(items=items, next_cursor=next_cursor, snapshot_at=ref_now)

    async def get_run_detail(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        run_id: str,
    ) -> CiRunDetailResponse:
        """Return `CiRunDetailResponse` (`A-08`) with attempts, jobs, S-14 artifacts & flaky."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        clean_run_id = _validate_uuid_or_404(
            run_id,
            code="ci_run_not_found",
            detail="CI run not found.",
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            all_repos, granted_ids, _ = await self._resolve_live_repo_scope_in_tx(
                db,
                ws_ctx,
                now=ref_now,
            )
            run_row = await db.scalar(
                select(CiRunModel).where(
                    CiRunModel.workspace_id == ws_id,
                    CiRunModel.id == clean_run_id,
                )
            )
            if run_row is None or (not all_repos and run_row.repository_id not in granted_ids):
                raise NotFoundError(code="ci_run_not_found", detail="CI run not found.")

            repo_name = await db.scalar(
                select(RepositoryModel.name).where(
                    RepositoryModel.workspace_id == ws_id,
                    RepositoryModel.id == run_row.repository_id,
                )
            )

            sibling_rows = list(
                (
                    await db.scalars(
                        select(CiRunModel)
                        .where(
                            CiRunModel.workspace_id == ws_id,
                            CiRunModel.repository_id == run_row.repository_id,
                            or_(
                                CiRunModel.external_id == run_row.external_id,
                                CiRunModel.head_sha == run_row.head_sha,
                            ),
                        )
                        .order_by(CiRunModel.attempt_number.asc(), CiRunModel.created_at.asc())
                        .limit(20)
                    )
                ).all()
            )
            job_rows = list(
                (
                    await db.scalars(
                        select(CiJobModel)
                        .where(
                            CiJobModel.workspace_id == ws_id,
                            CiJobModel.run_id == run_row.id,
                        )
                        .order_by(CiJobModel.created_at.asc(), CiJobModel.id.asc())
                    )
                ).all()
            )
            # Exclude internal per-job raw log blobs from downloadable archives list? No: return
            # both or non-log CI artifacts + log artifacts clearly distinguished by `kind`, never
            # exposing `storage_ref` (`S-14`)!
            art_rows = list(
                (
                    await db.scalars(
                        select(ArtifactModel)
                        .where(
                            ArtifactModel.workspace_id == ws_id,
                            ArtifactModel.run_id == run_row.id,
                            ArtifactModel.kind != "ci_job_log",
                        )
                        .order_by(ArtifactModel.created_at.asc(), ArtifactModel.id.asc())
                    )
                ).all()
            )

            fp_ids = [
                jid
                for jid in dict.fromkeys(j.failure_fingerprint_id for j in job_rows)
                if jid is not None
            ]
            fp_dtos: list[FailureFingerprintSummary] = []
            if fp_ids:
                fp_rows = list(
                    (
                        await db.scalars(
                            select(FailureFingerprintModel).where(
                                FailureFingerprintModel.workspace_id == ws_id,
                                FailureFingerprintModel.id.in_(fp_ids),
                            )
                        )
                    ).all()
                )
                fp_dtos = [fingerprint_model_to_dto(fp) for fp in fp_rows]

        r_name = str(repo_name) if repo_name is not None else None
        return CiRunDetailResponse(
            run=ci_run_model_to_dto(run_row, repository_name=r_name),
            sibling_attempts=[ci_run_model_to_dto(s, repository_name=r_name) for s in sibling_rows],
            jobs=[ci_job_model_to_dto(j) for j in job_rows],
            artifacts=[artifact_model_to_public_dto(a, now=ref_now) for a in art_rows],
            fingerprints=fp_dtos,
        )

    async def list_run_jobs(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        run_id: str,
    ) -> CiJobListResponse:
        """Return normalized `CiJobListResponse` for an authorized `CiRun` (`A-08`)."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        clean_run_id = _validate_uuid_or_404(
            run_id,
            code="ci_run_not_found",
            detail="CI run not found.",
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            all_repos, granted_ids, _ = await self._resolve_live_repo_scope_in_tx(
                db,
                ws_ctx,
                now=ref_now,
            )
            run_row = await db.scalar(
                select(CiRunModel).where(
                    CiRunModel.workspace_id == ws_id,
                    CiRunModel.id == clean_run_id,
                )
            )
            if run_row is None or (not all_repos and run_row.repository_id not in granted_ids):
                raise NotFoundError(code="ci_run_not_found", detail="CI run not found.")

            job_rows = list(
                (
                    await db.scalars(
                        select(CiJobModel)
                        .where(
                            CiJobModel.workspace_id == ws_id,
                            CiJobModel.run_id == run_row.id,
                        )
                        .order_by(CiJobModel.created_at.asc(), CiJobModel.id.asc())
                    )
                ).all()
            )

        return CiJobListResponse(
            run_id=run_row.id,
            items=[ci_job_model_to_dto(j) for j in job_rows],
        )

    async def get_job_log_chunk(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        job_id: str,
        start_offset: int = 0,
        max_bytes: int = MAX_LOG_CHUNK_BYTES,
    ) -> JobLogChunkResponse:
        """Return a redacted UTF-8 log slice (`<= 65536` bytes) or `410 log_expired` (`A-08`)."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        clean_job_id = _validate_uuid_or_404(
            job_id,
            code="ci_job_not_found",
            detail="CI job not found.",
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            all_repos, granted_ids, _ = await self._resolve_live_repo_scope_in_tx(
                db,
                ws_ctx,
                now=ref_now,
            )
            job_row = await db.scalar(
                select(CiJobModel).where(
                    CiJobModel.workspace_id == ws_id,
                    CiJobModel.id == clean_job_id,
                )
            )
            if job_row is None or (not all_repos and job_row.repository_id not in granted_ids):
                raise NotFoundError(code="ci_job_not_found", detail="CI job not found.")

            if job_row.log_status == "expired":
                raise GoneError(
                    code="log_expired",
                    detail=(
                        "Upstream CI job log has expired and cannot be retrieved; "
                        "run status remains incomplete (never assumed passing)."
                    ),
                )

            if job_row.log_artifact_id is None or job_row.log_status in ("unavailable", "pending"):
                marker = "log_pending" if job_row.log_status == "pending" else "log_unavailable"
                return JobLogChunkResponse(
                    job_id=job_row.id,
                    run_id=job_row.run_id,
                    log_status=cast(JobLogStatus, job_row.log_status),
                    content="",
                    start_offset=0,
                    next_offset=0,
                    returned_bytes=0,
                    total_bytes=0,
                    has_more=False,
                    truncated=False,
                    log_complete=False,
                    redaction_version=REDACTION_VERSION,
                    incomplete_marker=marker,
                )

            art_row = await db.scalar(
                select(ArtifactModel).where(
                    ArtifactModel.workspace_id == ws_id,
                    ArtifactModel.id == job_row.log_artifact_id,
                )
            )
            if art_row is None:
                raise GoneError(
                    code="log_expired",
                    detail="Stored CI job log artifact is no longer available.",
                )

            try:
                plaintext = await read_artifact_for_authorized_caller(
                    db,
                    store=self._artifact_store,
                    artifact_row=art_row,
                    now=ref_now,
                )
            except GoneError as exc:
                raise GoneError(
                    code="log_expired",
                    detail="Stored CI job log retention window has expired.",
                ) from exc

        chunk_text, eff_start, next_off = _slice_utf8_safe(
            plaintext,
            start_offset=start_offset,
            max_bytes=min(MAX_LOG_CHUNK_BYTES, max(1, max_bytes)),
        )
        returned_bytes = len(chunk_text.encode("utf-8"))
        total_bytes = len(plaintext)
        has_more = next_off < total_bytes
        return JobLogChunkResponse(
            job_id=job_row.id,
            run_id=job_row.run_id,
            log_status=cast(JobLogStatus, job_row.log_status),
            content=chunk_text,
            start_offset=eff_start,
            next_offset=next_off,
            returned_bytes=returned_bytes,
            total_bytes=total_bytes,
            has_more=has_more,
            truncated=job_row.log_truncated,
            log_complete=not job_row.log_truncated,
            redaction_version=art_row.redaction_version,
            incomplete_marker=("upstream_log_truncated_at_cap" if job_row.log_truncated else None),
        )

    async def download_artifact(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        artifact_id: str,
        correlation_id: str,
        client_ip: str | None = None,
    ) -> tuple[Artifact, bytes]:
        """Reauthorize `repo_grants` & RBAC, verify AEAD+SHA-256, audit & return bytes (`A-10`)."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        clean_art_id = _validate_uuid_or_404(
            artifact_id,
            code="artifact_not_found",
            detail="Artifact not found.",
        )

        denied_role = False
        dto: Artifact | None = None
        plaintext = b""

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            all_repos, granted_ids, live_role = await self._resolve_live_repo_scope_in_tx(
                db,
                ws_ctx,
                now=ref_now,
            )
            art_row = await db.scalar(
                select(ArtifactModel).where(
                    ArtifactModel.workspace_id == ws_id,
                    ArtifactModel.id == clean_art_id,
                )
            )
            if art_row is None or (not all_repos and art_row.repository_id not in granted_ids):
                raise NotFoundError(code="artifact_not_found", detail="Artifact not found.")

            if (
                art_row.access_class == "restricted"
                and live_role != "break_glass"
                and live_role not in _RESTRICTED_ARTIFACT_ROLES
            ):
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=ws_ctx.auth.user.id,
                    action="artifact.download",
                    target=f"artifact:{art_row.id}",
                    decision="deny",
                    reason_code="restricted_artifact_role_denied",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "repository_id": art_row.repository_id,
                        "access_class": art_row.access_class,
                        "role": live_role,
                    },
                    occurred_at=ref_now,
                )
                denied_role = True
            else:
                plaintext = await read_artifact_for_authorized_caller(
                    db,
                    store=self._artifact_store,
                    artifact_row=art_row,
                    now=ref_now,
                )
                dto = artifact_model_to_public_dto(art_row, now=ref_now)

                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=ws_ctx.auth.user.id,
                    action="artifact.downloaded",
                    target=f"artifact:{art_row.id}",
                    decision="allow",
                    reason_code="authorized_download",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "repository_id": art_row.repository_id,
                        "run_id": art_row.run_id,
                        "kind": art_row.kind,
                        "access_class": art_row.access_class,
                        "digest": art_row.digest,
                        "size_bytes": len(plaintext),
                        "role": live_role,
                    },
                    occurred_at=ref_now,
                )

        if denied_role or dto is None:
            raise ForbiddenError(
                code="insufficient_role",
                detail=(
                    "Restricted CI artifacts require reviewer, maintainer, auditor, or admin role."
                ),
            )

        return dto, plaintext


def _req_corr_id(request: Request) -> str:
    state_corr = getattr(request.state, "correlation_id", None)
    if isinstance(state_corr, str) and state_corr:
        return state_corr
    return current_correlation_id()


def _resolve_iam(request: Request) -> IamService:
    svc = getattr(request.app.state, "iam_service", None)
    if not isinstance(svc, IamService):
        raise DependencyUnavailableError(
            code="iam_unconfigured",
            detail="IAM persistence service is not configured on this control-plane instance.",
        )
    return svc


def _resolve_triage_evidence_service(request: Request) -> TriageEvidenceService:
    existing = getattr(request.app.state, "triage_evidence_service", None)
    if isinstance(existing, TriageEvidenceService):
        return existing
    iam = _resolve_iam(request)
    store = getattr(request.app.state, "artifact_store", None)
    if store is None:
        derived_kek = hashlib.sha256(
            b"red2pr:default_artifact_kek:v1:" + iam.csrf_signing_key
        ).digest()
        default_dir = FsPath(tempfile.gettempdir()) / "red2pr_default_artifact_store"
        store = LocalEncryptedArtifactStore(
            root_dir=default_dir,
            key_ring=MasterKeyRing(active_version=1, keys={1: derived_kek}),
        )
        request.app.state.artifact_store = store
    created = TriageEvidenceService(
        session_factory=iam.session_factory,
        signing_key=iam.csrf_signing_key,
        artifact_store=store,
        clock=iam.now,
    )
    request.app.state.triage_evidence_service = created
    return created


def _maybe_refresh_csrf(
    response: Response,
    ws_ctx: WorkspaceAccessContext,
    iam: IamService,
) -> None:
    if ws_ctx.auth.csrf_cookie_refreshed:
        set_csrf_cookie(response, csrf_token=ws_ctx.auth.csrf_token, secure=iam.secure_cookies)


_require_triage_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="triage_evidence.read",
)


def build_triage_evidence_router() -> APIRouter:
    """Build `/api/v1` router exposing `A-08` CI runs/jobs/logs and `A-10` artifact download."""
    router = APIRouter(prefix="/api/v1")

    @router.get(
        "/workspaces/{ws}/runs",
        operation_id="listWorkspaceRuns",
        tags=["triage_evidence"],
        response_model=CiRunPage,
        summary="List authorized CI runs with attempt keys & flaky badges (A-08)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_workspace_runs(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_triage_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[TriageEvidenceService, Depends(_resolve_triage_evidence_service)],
        response: Response,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        repository_id: Annotated[str | None, Query(max_length=64)] = None,
        status: Annotated[CiRunStatus | None, Query()] = None,
        conclusion: Annotated[CiConclusion | None, Query()] = None,
        ingestion_state: Annotated[CiRunIngestionState | None, Query()] = None,
        flaky_classification: Annotated[FlakyClassification | None, Query()] = None,
        head_sha: Annotated[str | None, Query(max_length=64)] = None,
        flaky_only: Annotated[bool, Query()] = False,
    ) -> CiRunPage:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return await svc.list_runs(
            ws_ctx,
            cursor=cursor,
            limit=limit,
            repository_id=repository_id,
            status=status,
            conclusion=conclusion,
            ingestion_state=ingestion_state,
            flaky_classification=flaky_classification,
            head_sha=head_sha,
            flaky_only=flaky_only,
        )

    @router.get(
        "/workspaces/{ws}/runs/{run_id}",
        operation_id="getWorkspaceRun",
        tags=["triage_evidence"],
        response_model=CiRunDetailResponse,
        summary="Get CI run attempt detail with attempts, jobs, S-14 artifacts & flaky (A-08)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_workspace_run(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_triage_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[TriageEvidenceService, Depends(_resolve_triage_evidence_service)],
        response: Response,
        run_id: Annotated[str, Path(min_length=1, max_length=64)],
    ) -> CiRunDetailResponse:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return await svc.get_run_detail(ws_ctx, run_id=run_id)

    @router.get(
        "/workspaces/{ws}/runs/{run_id}/jobs",
        operation_id="listWorkspaceRunJobs",
        tags=["triage_evidence"],
        response_model=CiJobListResponse,
        summary="List matrix & retry CI jobs for a specific CI run attempt (A-08)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_workspace_run_jobs(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_triage_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[TriageEvidenceService, Depends(_resolve_triage_evidence_service)],
        response: Response,
        run_id: Annotated[str, Path(min_length=1, max_length=64)],
    ) -> CiJobListResponse:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return await svc.list_run_jobs(ws_ctx, run_id=run_id)

    @router.get(
        "/workspaces/{ws}/jobs/{job_id}/log",
        operation_id="getWorkspaceJobLog",
        tags=["triage_evidence"],
        response_model=JobLogChunkResponse,
        summary="Read redacted UTF-8 CI job log chunk (<= 65536 bytes; 410 if expired) (A-08)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_workspace_job_log(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_triage_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[TriageEvidenceService, Depends(_resolve_triage_evidence_service)],
        response: Response,
        job_id: Annotated[str, Path(min_length=1, max_length=64)],
        start_offset: Annotated[int, Query(ge=0)] = 0,
        max_bytes: Annotated[int, Query(ge=1, le=MAX_LOG_CHUNK_BYTES)] = MAX_LOG_CHUNK_BYTES,
    ) -> JobLogChunkResponse:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return await svc.get_job_log_chunk(
            ws_ctx,
            job_id=job_id,
            start_offset=start_offset,
            max_bytes=max_bytes,
        )

    @router.get(
        "/workspaces/{ws}/artifacts/{artifact_id}/download",
        operation_id="downloadWorkspaceArtifact",
        tags=["triage_evidence"],
        response_class=Response,
        summary="Download verified artifact with live repo_grants & 410 retention check (A-10)",
        responses={
            200: {
                "description": "Verified decrypted artifact payload",
                "content": {
                    "application/octet-stream": {
                        "schema": {"type": "string", "format": "binary"},
                    }
                },
            },
            **_COMMON_PROBLEM_RESPONSES,
        },
    )
    async def download_workspace_artifact(
        request: Request,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_triage_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[TriageEvidenceService, Depends(_resolve_triage_evidence_service)],
        artifact_id: Annotated[str, Path(min_length=1, max_length=64)],
    ) -> Response:
        corr_id = _req_corr_id(request)
        dto, payload_bytes = await svc.download_artifact(
            ws_ctx,
            artifact_id=artifact_id,
            correlation_id=corr_id,
            client_ip=extract_client_ip(request),
        )
        safe_name = _safe_attachment_filename(dto.name, fallback=f"artifact-{dto.id}.bin")
        dl_resp = Response(
            content=payload_bytes,
            status_code=200,
            media_type=dto.mime,
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name}"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
                "X-Artifact-Digest": f"sha256:{dto.digest}",
            },
        )
        _maybe_refresh_csrf(dl_resp, ws_ctx, iam)
        return dl_resp

    return router
