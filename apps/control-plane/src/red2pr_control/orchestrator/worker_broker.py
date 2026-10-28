"""Control-plane Z1 Worker Broker, mTLS CA, Lease Fence & Result Verifier (`U14`).

Implements `SAN-01`, `A-13`, `S-15`, `S-21`, `UI-S13`, `W-04`, `W-08`, `NFR-02`, `NFR-14`,
`ADR-016`, `ADR-034`, `ADR-035`, `SEC-006`, `SEC-013`, `SEC-014`, `SEC-021`, `SEC-029`,
`SEC-030`, and `SEC-032`:
- Envelope-encrypted internal Worker X.509 ECDSA P-256 CA (`OPS-03`, zero `Z2` imports).
- One-time SHA-256 hashed enrollment token -> PKCS#10 CSR -> short-lived SPIFFE X.509
  client certificate (`TLS 1.3` mTLS; browser `Cookie`/`Origin` headers rejected).
- Multi-workspace isolation gate (`ADR-034` / `ADR-016`): `oci_trusted_local` requires
  explicit owner risk acknowledgement and is blocked for multi-workspace or VM-required jobs.
- Write-only per-lease HMAC upload capabilities (`<=100 MiB` cap, `Redactor` scrubbing,
  4-phase AES-256-GCM `ArtifactStore` persistence).
- Monotonic `lease_epoch` fencing (`409 stale_job_lease`, `0` stale writes) and external
  Ed25519 `ResultV1` signature + artifact digest + cleanup verification (`SEC-030`),
  automatically quarantining workers on conflicting duplicate results or failed cleanup.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import secrets
import ssl
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from fastapi import Request
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.types import Receive, Scope, Send
from uvicorn.protocols.http.h11_impl import H11Protocol

from py_contracts.crypto import (
    DOMAIN_RESULT_V1,
    CryptoVerificationError,
    EnvelopeCiphertext,
    KeyRing,
    MasterKeyRing,
    PublicKeyRecord,
    VerifiedWorkerCertIdentity,
    decrypt_envelope,
    encrypt_envelope,
    generate_worker_ca_keypair,
    issue_worker_client_certificate,
    issue_worker_server_certificate,
    mint_upload_capability_ticket,
    sha256_canonical_json,
    verify_model_ed25519,
    verify_upload_capability_ticket,
    verify_worker_client_certificate,
)
from py_contracts.events import (
    EventEnvelope,
    SecurityIdentityEventPayload,
    WorkerEventPayload,
)
from py_contracts.primitives import (
    ActionReceipt,
    ActionState,
    InternalId,
    Problem,
    new_uuid7,
    parse_uuid7_timestamp_ms,
    validate_idempotency_key_window,
)
from py_contracts.worker import (
    IsolationCheckResult,
    ResultArtifactRef,
    ResultV1,
    SandboxJobV1,
    SandboxLeaseStatus,
    SandboxResourceLimits,
    Worker,
    WorkerActionRequest,
    WorkerArtifactUploadRequest,
    WorkerArtifactUploadResponse,
    WorkerCancelAckRequest,
    WorkerCancelAckResponse,
    WorkerEnrollHandshakeRequest,
    WorkerEnrollHandshakeResponse,
    WorkerEnrollmentCreateRequest,
    WorkerEnrollmentCreateResponse,
    WorkerFleetSummary,
    WorkerIsolationAttestation,
    WorkerIsolationMode,
    WorkerJobHeartbeatRequest,
    WorkerJobHeartbeatResponse,
    WorkerJobResultReceipt,
    WorkerPage,
    WorkerPollRequest,
    WorkerPollResponse,
    WorkerSelfTestResponse,
    WorkerStatus,
    WorkspaceSandboxLeaseSummary,
    WorkspaceWorkerReadinessResponse,
)
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    PayloadTooLargeError,
    UnauthorizedError,
    UnprocessableEntityError,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    OperationReceiptModel,
    RepositoryModel,
    SandboxLeaseModel,
    SecretEntryModel,
    SigningKeyModel,
    TaskJobModel,
    WorkerEnrollmentModel,
    WorkerModel,
    WorkspaceModel,
)
from red2pr_control.db.idempotency import upsert_operation_receipt
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    derive_iam_subkey,
    encode_signed_cursor,
    enforce_optimistic_version,
)
from red2pr_control.iam.sessions import (
    STEP_UP_VALIDITY_WINDOW,
    AuthenticatedContext,
)
from red2pr_control.operations.setup_wizard import (
    SetupStepProbeResult,
    SetupStepRegistry,
)
from red2pr_control.orchestrator.queue import DurableTaskQueueService
from red2pr_control.orchestrator.sweeper import QueueLeaseSweeper
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    persist_encrypted_artifact,
)

MAX_SANDBOX_UPLOAD_BYTES = 104_857_600  # 100 MiB (NFR-14)
MAX_SANDBOX_UPLOAD_WIRE_BYTES = 148_000_000  # JSON+base64 wire envelope for <=100 MiB
DEFAULT_WORKER_STALE_TIMEOUT = timedelta(seconds=90)  # <=90s orphan detection (NFR-02)
DEFAULT_WORKER_CERT_VALID_HOURS = 24
SANDBOX_TASK_KIND = "sandbox.execute"

_WORKER_CA_ENTRY_REF = "sec:instance:worker_mtls_ca:v1"
_DEFAULT_NET_POLICY_DIGEST = hashlib.sha256(b"red2pr:network:none:v1").hexdigest()
_DEFAULT_SUPERVISOR_POLICY_DIGEST = hashlib.sha256(
    b"red2pr:supervisor:seccomp+capdrop+nnp:v1"
).hexdigest()

_UUID_ADAPTER: TypeAdapter[str] = TypeAdapter(InternalId)


def _validate_uuid_or_404(raw_id: str, *, code: str, detail: str) -> str:
    try:
        return _UUID_ADAPTER.validate_python(raw_id.strip())
    except ValidationError as exc:
        raise NotFoundError(code=code, detail=detail) from exc


def _hash_enrollment_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _to_worker_dto(row: WorkerModel, *, active_leases: int = 0) -> Worker:
    return Worker(
        id=row.id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        trust_domain=row.trust_domain,
        profile_ids=list(row.profile_ids_json),
        capabilities=dict(row.capabilities_json),
        heartbeat_at=row.heartbeat_at,
        status=cast(WorkerStatus, row.status),
        host_id=row.host_id,
        isolation_mode=cast(WorkerIsolationMode, row.isolation_mode),
        runtime_name=row.runtime_name,
        cpu_limit=row.cpu_limit,
        memory_limit_bytes=row.memory_limit_bytes,
        disk_limit_bytes=row.disk_limit_bytes,
        pids_limit=row.pids_limit,
        signer_key_id=row.active_signer_key_id,
        mtls_cert_fingerprint_sha256=row.mtls_cert_fingerprint_sha256,
        mtls_cert_expires_at=row.mtls_cert_expires_at,
        quarantine_reason=row.quarantine_reason,
        drain_reason=row.drain_reason,
        active_leases=max(0, active_leases),
        host_escape_warning=row.isolation_mode == "oci_trusted_local",
    )


def _to_lease_summary_dto(row: SandboxLeaseModel) -> WorkspaceSandboxLeaseSummary:
    return WorkspaceSandboxLeaseSummary(
        id=row.id,
        job_id=row.job_id,
        repository_id=row.repository_id,
        repair_id=row.repair_id,
        profile_id=row.profile_id,
        lease_epoch=row.lease_epoch,
        status=cast(SandboxLeaseStatus, row.status),
        issued_at=row.issued_at,
        lease_expires_at=row.lease_expires_at,
    )


class MtlsH11Protocol(H11Protocol):
    """Uvicorn HTTP/1.1 protocol binding OpenSSL peer certificate DER into ASGI TLS scope.

    Prevents any header-spoofing vector: `scope['extensions']['tls']` is populated
    exclusively from `transport.get_extra_info('ssl_object')` on the kernel TLS socket.
    """

    def connection_made(  # type: ignore[override]
        self,
        transport: asyncio.Transport,
    ) -> None:
        super().connection_made(transport)
        orig_app = self.app

        async def _bind_socket_tls_extension(
            scope: Scope,
            receive: Receive,
            send: Send,
        ) -> None:
            ssl_obj = transport.get_extra_info("ssl_object")
            if ssl_obj is not None:
                peer_der: bytes | None = ssl_obj.getpeercert(binary_form=True)
                tls_ver: str | None = ssl_obj.version()
                exts = dict(scope.get("extensions") or {})
                exts["tls"] = {
                    "client_cert_der": peer_der,
                    "tls_version": tls_ver,
                }
                scope = {**scope, "extensions": exts}
            await orig_app(scope, receive, send)

        self.app = _bind_socket_tls_extension


@dataclass(frozen=True, slots=True)
class ServerTlsMaterial:
    """Server TLS 1.3 certificate + key bundle issued by the internal Worker CA."""

    ca_cert_pem: str
    server_cert_pem: str
    server_key_pem: str

    def build_ssl_context(
        self,
        *,
        cert_reqs: ssl.VerifyMode = ssl.CERT_REQUIRED,
    ) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = cert_reqs
        ctx.load_verify_locations(cadata=self.ca_cert_pem)

        tmp_dir = Path(tempfile.mkdtemp(prefix="red2pr-srv-mtls-"))
        cert_path = tmp_dir / "server.crt"
        key_path = tmp_dir / "server.key"
        try:
            cert_path.write_text(self.server_cert_pem, encoding="utf-8", newline="\n")
            key_path.write_text(self.server_key_pem, encoding="utf-8", newline="\n")
            ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        finally:
            cert_path.unlink(missing_ok=True)
            key_path.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                tmp_dir.rmdir()
        return ctx


class WorkerCertificateAuthority:
    """Envelope-encrypted internal ECDSA P-256 X.509 CA for `/internal/v1/*` mTLS (`OPS-03`)."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        master_key_ring: MasterKeyRing,
    ) -> None:
        self._session_factory = session_factory
        self._key_ring = master_key_ring
        self._cached_ca: tuple[str, str] | None = None  # (ca_cert_pem, ca_key_pem)

    async def _load_or_create_ca(
        self,
        *,
        now: datetime,
    ) -> tuple[str, str]:
        if self._cached_ca is not None:
            return self._cached_ca

        ref_now = now.astimezone(UTC)
        aad = {"purpose": "storage_encryption", "secret_ref": _WORKER_CA_ENTRY_REF}
        aad_digest = sha256_canonical_json(aad)

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            existing = await db.scalar(
                select(SecretEntryModel)
                .where(SecretEntryModel.secret_ref == _WORKER_CA_ENTRY_REF)
                .with_for_update()
            )
            if existing is not None:
                envelope = EnvelopeCiphertext.model_validate(existing.envelope_json)
                plaintext = decrypt_envelope(
                    envelope,
                    key_ring=self._key_ring,
                    aad_context=aad,
                )
                bundle = json.loads(plaintext.decode("utf-8"))
                self._cached_ca = (str(bundle["ca_cert_pem"]), str(bundle["ca_key_pem"]))
                return self._cached_ca

            ca_cert_pem, ca_key_pem = generate_worker_ca_keypair(now=ref_now)
            raw_json = json.dumps(
                {"ca_cert_pem": ca_cert_pem, "ca_key_pem": ca_key_pem},
                sort_keys=True,
            ).encode("utf-8")
            encrypted = encrypt_envelope(
                raw_json,
                key_ring=self._key_ring,
                aad_context=aad,
            )
            entry = SecretEntryModel(
                id=new_uuid7(now=ref_now),
                secret_ref=_WORKER_CA_ENTRY_REF,
                workspace_id=None,
                purpose="storage_encryption",
                active_key_version=1,
                kek_version=encrypted.kek_version,
                envelope_json=encrypted.model_dump(mode="json"),
                previous_envelope_json=None,
                aad_digest=aad_digest,
                rotated_at=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(entry)
            await db.flush()

        self._cached_ca = (ca_cert_pem, ca_key_pem)
        return self._cached_ca

    async def get_ca_cert_pem(self, *, now: datetime | None = None) -> str:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        ca_cert_pem, _ = await self._load_or_create_ca(now=ref_now)
        return ca_cert_pem

    async def issue_server_bundle(
        self,
        *,
        hostnames: Sequence[str] = ("localhost",),
        ip_addresses: Sequence[str] = ("127.0.0.1", "::1"),
        now: datetime | None = None,
    ) -> ServerTlsMaterial:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        ca_cert_pem, ca_key_pem = await self._load_or_create_ca(now=ref_now)
        srv_cert_pem, srv_key_pem = issue_worker_server_certificate(
            ca_cert_pem=ca_cert_pem,
            ca_private_key_pem=ca_key_pem,
            hostnames=hostnames,
            ip_addresses=ip_addresses,
            now=ref_now,
        )
        return ServerTlsMaterial(
            ca_cert_pem=ca_cert_pem,
            server_cert_pem=srv_cert_pem,
            server_key_pem=srv_key_pem,
        )

    async def sign_worker_csr(
        self,
        *,
        csr_pem: str,
        worker_id: str,
        trust_domain: str,
        valid_hours: int = DEFAULT_WORKER_CERT_VALID_HOURS,
        now: datetime | None = None,
    ) -> tuple[str, VerifiedWorkerCertIdentity, str]:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        ca_cert_pem, ca_key_pem = await self._load_or_create_ca(now=ref_now)
        leaf_pem, _, _, _ = issue_worker_client_certificate(
            ca_cert_pem=ca_cert_pem,
            ca_private_key_pem=ca_key_pem,
            csr_pem=csr_pem,
            worker_id=worker_id,
            trust_domain=trust_domain,
            valid_hours=valid_hours,
            now=ref_now,
        )
        identity = verify_worker_client_certificate(
            cert_der_or_pem=leaf_pem,
            ca_cert_pem=ca_cert_pem,
            now=ref_now,
        )
        return leaf_pem, identity, ca_cert_pem


class WorkerBrokerService:
    """Authoritative Z1 broker for `A-13` fleet control and `S-21` internal mTLS workers."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        signing_key: bytes,
        queue_service: DurableTaskQueueService,
        artifact_store: ArtifactStoreProtocol,
        master_key_ring: MasterKeyRing | None = None,
        redactor: Redactor | None = None,
        stale_worker_timeout: timedelta = DEFAULT_WORKER_STALE_TIMEOUT,
        worker_cert_valid_hours: int = DEFAULT_WORKER_CERT_VALID_HOURS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._signing_key = signing_key
        self._clock: Callable[[], datetime] = clock or (lambda: datetime.now(tz=UTC))
        self._cursor_key = derive_iam_subkey(signing_key, context=b"red2pr:worker_cursor:v1")
        self._upload_cap_key = derive_iam_subkey(
            signing_key,
            context=b"red2pr:worker_upload_cap:v1",
        )
        eff_kek_ring = master_key_ring or MasterKeyRing(
            active_version=1,
            keys={1: derive_iam_subkey(signing_key, context=b"red2pr:worker_ca_kek:v1")},
        )
        self._ca = WorkerCertificateAuthority(
            session_factory=session_factory,
            master_key_ring=eff_kek_ring,
        )
        self._queue = queue_service
        self._sweeper = QueueLeaseSweeper(session_factory=session_factory)
        self._artifact_store = artifact_store
        self._redactor = redactor or DEFAULT_REDACTOR
        self._stale_worker_timeout = stale_worker_timeout
        self._worker_cert_valid_hours = worker_cert_valid_hours
        self._source_archives_in_memory: dict[str, bytes] = {}

    @property
    def ca(self) -> WorkerCertificateAuthority:
        return self._ca

    def register_source_archive(self, source_archive_bytes: bytes) -> str:
        """Register an immutable repository snapshot archive for worker staging in tests/runs."""
        digest = hashlib.sha256(source_archive_bytes).hexdigest()
        self._source_archives_in_memory[digest] = bytes(source_archive_bytes)
        return digest

    # ------------------------------------------------------------------
    # Authorization & mTLS Helpers
    # ------------------------------------------------------------------

    async def _require_instance_owner(
        self,
        auth: AuthenticatedContext,
        *,
        action: str,
        target: str,
        require_step_up: bool,
        client_ip: str | None,
        correlation_id: str,
        ref_now: datetime,
    ) -> None:
        if not auth.user.is_instance_owner:
            async with instance_rls_session(self._session_factory, mode="instance_only") as db:
                await append_audit_entry(
                    db,
                    workspace_id=None,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action=action,
                    target=target,
                    decision="deny",
                    reason_code="instance_owner_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={"is_instance_owner": False},
                    occurred_at=ref_now,
                )
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="security.policy.denied",
                        occurred_at=ref_now,
                        workspace_id=None,
                        aggregate_id=auth.user.id,
                        aggregate_version=auth.user.version,
                        correlation_id=correlation_id,
                        payload=SecurityIdentityEventPayload(
                            target_id=auth.user.id,
                            reason_code="instance_owner_required",
                        ),
                    ),
                    now=ref_now,
                )
            raise ForbiddenError(
                code="instance_owner_required",
                detail="Only the instance owner may access global worker fleet controls (ADR-034).",
            )

        if require_step_up:
            step_up_at = auth.session.step_up_at
            if step_up_at is None or (ref_now - step_up_at) > STEP_UP_VALIDITY_WINDOW:
                async with instance_rls_session(
                    self._session_factory,
                    mode="instance_only",
                ) as db:
                    await append_audit_entry(
                        db,
                        workspace_id=None,
                        actor_type="user",
                        actor_id=auth.user.id,
                        action=action,
                        target=target,
                        decision="deny",
                        reason_code="step_up_required",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={},
                        occurred_at=ref_now,
                    )
                raise ForbiddenError(
                    code="step_up_required",
                    detail="Fresh 5-minute MFA/password step-up is required for worker mutations.",
                )

    def _assert_no_browser_headers_on_worker_route(self, request: Request) -> None:
        if request.headers.get("cookie") or request.headers.get("origin"):
            raise BadRequestError(
                code="browser_session_forbidden_on_worker_protocol",
                detail=(
                    "Browser Cookie and Origin headers are prohibited on /internal/v1/* "
                    "mTLS worker endpoints (S-21)."
                ),
            )

    async def authenticate_mtls_worker(
        self,
        request: Request,
        *,
        expected_worker_id: str | None = None,
        now: datetime | None = None,
    ) -> WorkerModel:
        """Verify TLS 1.3 socket peer certificate + live `workers` revocation state (`S-21`)."""
        self._assert_no_browser_headers_on_worker_route(request)
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)

        tls_ext = (request.scope.get("extensions") or {}).get("tls")
        if not isinstance(tls_ext, Mapping):
            raise UnauthorizedError(
                code="mtls_client_certificate_required",
                detail="Mutual TLS client certificate is required on /internal/v1/*.",
            )
        tls_version = tls_ext.get("tls_version")
        if isinstance(tls_version, str) and tls_version != "TLSv1.3":
            raise UnauthorizedError(
                code="mtls_tls13_required",
                detail=f"TLS 1.3 is mandatory for worker mTLS (negotiated {tls_version!r}).",
            )
        raw_cert = tls_ext.get("client_cert_der")
        if not isinstance(raw_cert, (bytes, str)) or not raw_cert:
            raise UnauthorizedError(
                code="mtls_client_certificate_required",
                detail="No client X.509 certificate presented during TLS handshake.",
            )

        ca_cert_pem = await self._ca.get_ca_cert_pem(now=ref_now)
        try:
            verified = verify_worker_client_certificate(
                cert_der_or_pem=raw_cert,
                ca_cert_pem=ca_cert_pem,
                now=ref_now,
            )
        except CryptoVerificationError as exc:
            raise UnauthorizedError(
                code="mtls_certificate_invalid",
                detail=str(exc),
            ) from exc

        if expected_worker_id is not None and verified.worker_id != expected_worker_id:
            raise ForbiddenError(
                code="worker_identity_mismatch",
                detail="mTLS client certificate SPIFFE worker_id does not match target worker.",
            )

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            worker_row = await db.scalar(
                select(WorkerModel).where(WorkerModel.id == verified.worker_id)
            )
            if worker_row is None:
                raise UnauthorizedError(
                    code="worker_not_enrolled",
                    detail="Worker certificate does not match an enrolled worker record.",
                )
            if worker_row.mtls_cert_revoked_at is not None:
                raise ForbiddenError(
                    code="worker_certificate_revoked",
                    detail="Worker mTLS certificate has been revoked by an operator.",
                )
            if (
                worker_row.mtls_cert_serial != verified.serial_hex
                or worker_row.mtls_cert_fingerprint_sha256 != verified.fingerprint_sha256
            ):
                raise ForbiddenError(
                    code="worker_certificate_superseded",
                    detail="Presented worker certificate serial/fingerprint is no longer active.",
                )
            if worker_row.mtls_cert_expires_at <= ref_now:
                raise UnauthorizedError(
                    code="worker_certificate_expired",
                    detail="Worker certificate has expired.",
                )
            db.expunge(worker_row)
            return worker_row

    # ------------------------------------------------------------------
    # Stale Heartbeat & Lease Reconciler (NFR-02 <=90s)
    # ------------------------------------------------------------------

    async def reconcile_stale_workers_and_leases(
        self,
        *,
        now: datetime,
        correlation_id: str = "worker-reconciler",
    ) -> tuple[int, int]:
        """Mark silent workers `offline` (`<=90s`) and sweep expired job leases (`NFR-02`)."""
        ref_now = now.astimezone(UTC)
        stale_cutoff = ref_now - self._stale_worker_timeout
        offlined_workers = 0

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            stale_rows = (
                await db.scalars(
                    select(WorkerModel)
                    .where(
                        WorkerModel.status.in_(("online", "draining")),
                        WorkerModel.heartbeat_at <= stale_cutoff,
                    )
                    .with_for_update()
                )
            ).all()
            for w_row in stale_rows:
                w_row.status = "offline"
                w_row.version += 1
                w_row.updated_at = ref_now
                offlined_workers += 1
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="worker.offline",
                        occurred_at=ref_now,
                        workspace_id=None,
                        aggregate_id=w_row.id,
                        aggregate_version=w_row.version,
                        correlation_id=correlation_id,
                        payload=WorkerEventPayload(
                            worker_id=w_row.id,
                            status="offline",
                        ),
                    ),
                    now=ref_now,
                )
                await append_audit_entry(
                    db,
                    workspace_id=None,
                    actor_type="system",
                    actor_id="worker_reconciler",
                    action="worker.offline_detected",
                    target=f"worker:{w_row.id}",
                    decision="reconcile",
                    reason_code="heartbeat_timeout",
                    correlation_id=correlation_id,
                    metadata={"last_heartbeat_at": w_row.heartbeat_at.isoformat()},
                    occurred_at=ref_now,
                )

            expired_leases = (
                await db.scalars(
                    select(SandboxLeaseModel)
                    .where(
                        SandboxLeaseModel.status.in_(("leased", "running", "cancel_requested")),
                        SandboxLeaseModel.lease_expires_at <= ref_now,
                    )
                    .with_for_update()
                )
            ).all()
            for lease_row in expired_leases:
                lease_row.status = "expired"
                lease_row.ended_at = ref_now
                lease_row.version += 1
                lease_row.updated_at = ref_now

        sweep_report = await self._sweeper.sweep_expired_leases(now=ref_now)
        swept_count = (
            len(sweep_report.requeued_job_ids)
            + len(sweep_report.dead_lettered_job_ids)
            + len(sweep_report.cancelled_job_ids)
        )
        return offlined_workers, swept_count

    async def _count_active_leases_by_worker(self, db: AsyncSession) -> dict[str, int]:
        rows = (
            await db.execute(
                select(SandboxLeaseModel.worker_id, func.count())
                .where(SandboxLeaseModel.status.in_(("leased", "running", "cancel_requested")))
                .group_by(SandboxLeaseModel.worker_id)
            )
        ).all()
        return {str(r[0]): int(r[1]) for r in rows}

    # ------------------------------------------------------------------
    # Public A-13 & UI-S13 Methods
    # ------------------------------------------------------------------

    async def list_workers(
        self,
        auth: AuthenticatedContext,
        *,
        status: WorkerStatus | None = None,
        isolation_mode: WorkerIsolationMode | None = None,
        cursor: str | None = None,
        limit: int = 50,
        client_ip: str | None = None,
        correlation_id: str = "",
        now: datetime | None = None,
    ) -> WorkerPage:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        await self._require_instance_owner(
            auth,
            action="worker.list",
            target="workers:global",
            require_step_up=False,
            client_ip=client_ip,
            correlation_id=correlation_id,
            ref_now=ref_now,
        )
        await self.reconcile_stale_workers_and_leases(now=ref_now, correlation_id=correlation_id)

        query_hash = compute_query_filter_hash(
            {"status": status or "", "isolation_mode": isolation_mode or ""}
        )
        decoded_cursor = None
        if cursor:
            decoded_cursor = decode_signed_cursor(
                cursor,
                signing_key=self._cursor_key,
                expected_workspace_scope="instance:workers",
                expected_principal_id=auth.user.id,
                current_grant_epoch=auth.user.grant_epoch,
                expected_query_hash=query_hash,
                now=ref_now,
            )

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            lease_counts = await self._count_active_leases_by_worker(db)
            all_rows = (await db.scalars(select(WorkerModel))).all()

            stmt: Select[tuple[WorkerModel]] = select(WorkerModel)
            if status is not None:
                stmt = stmt.where(WorkerModel.status == status)
            if isolation_mode is not None:
                stmt = stmt.where(WorkerModel.isolation_mode == isolation_mode)
            if decoded_cursor is not None:
                c_dt = decoded_cursor.created_at
                c_id = decoded_cursor.item_id
                stmt = stmt.where(
                    (WorkerModel.created_at < c_dt)
                    | ((WorkerModel.created_at == c_dt) & (WorkerModel.id < c_id))
                )
            stmt = stmt.order_by(WorkerModel.created_at.desc(), WorkerModel.id.desc()).limit(
                limit + 1
            )
            rows = list((await db.scalars(stmt)).all())

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        next_cursor: str | None = None
        if has_more and page_rows:
            last = page_rows[-1]
            next_cursor = encode_signed_cursor(
                signing_key=self._cursor_key,
                workspace_scope="instance:workers",
                principal_id=auth.user.id,
                grant_epoch=auth.user.grant_epoch,
                query_hash=query_hash,
                created_at=last.created_at,
                item_id=last.id,
                now=ref_now,
            )

        summary = WorkerFleetSummary(
            total_count=len(all_rows),
            online_count=sum(1 for r in all_rows if r.status == "online"),
            draining_count=sum(1 for r in all_rows if r.status == "draining"),
            quarantined_count=sum(1 for r in all_rows if r.status == "quarantined"),
            offline_count=sum(1 for r in all_rows if r.status == "offline"),
            vm_isolated_count=sum(
                1 for r in all_rows if r.isolation_mode == "vm_isolated" and r.status == "online"
            ),
            trusted_local_warning_count=sum(
                1
                for r in all_rows
                if r.isolation_mode == "oci_trusted_local" and r.status in ("online", "draining")
            ),
            active_leases_count=sum(lease_counts.values()),
        )

        return WorkerPage(
            items=[_to_worker_dto(r, active_leases=lease_counts.get(r.id, 0)) for r in page_rows],
            next_cursor=next_cursor,
            snapshot_at=ref_now,
            summary=summary,
        )

    async def create_enrollment(
        self,
        auth: AuthenticatedContext,
        *,
        payload: WorkerEnrollmentCreateRequest,
        client_ip: str | None = None,
        correlation_id: str = "",
        now: datetime | None = None,
    ) -> WorkerEnrollmentCreateResponse:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        await self._require_instance_owner(
            auth,
            action="worker.enrollment.create",
            target="workers:enrollments",
            require_step_up=True,
            client_ip=client_ip,
            correlation_id=correlation_id,
            ref_now=ref_now,
        )
        ca_cert_pem = await self._ca.get_ca_cert_pem(now=ref_now)

        raw_token = f"r2pw_enroll_{secrets.token_urlsafe(32)}"
        token_hash = _hash_enrollment_token(raw_token)
        enrollment_id = new_uuid7(now=ref_now)
        expires_at = ref_now + timedelta(minutes=payload.ttl_minutes)

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            row = WorkerEnrollmentModel(
                id=enrollment_id,
                token_hash=token_hash,
                trust_domain=payload.trust_domain.strip(),
                profile_ids_json=list(payload.profile_ids),
                isolation_mode=payload.isolation_mode,
                host_escape_risk_acknowledged=payload.host_escape_risk_acknowledged,
                created_by_user_id=auth.user.id,
                enrolled_worker_id=None,
                expires_at=expires_at,
                used_at=None,
                revoked_at=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(row)
            await db.flush()
            await append_audit_entry(
                db,
                workspace_id=None,
                actor_type="user",
                actor_id=auth.user.id,
                action="worker.enrollment.created",
                target=f"worker_enrollment:{enrollment_id}",
                decision="allow",
                reason_code="one_time_token_minted",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "trust_domain": row.trust_domain,
                    "isolation_mode": row.isolation_mode,
                    "host_escape_risk_acknowledged": row.host_escape_risk_acknowledged,
                    "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
                },
                occurred_at=ref_now,
            )

        return WorkerEnrollmentCreateResponse(
            enrollment_id=enrollment_id,
            enrollment_token=raw_token,
            trust_domain=payload.trust_domain.strip(),
            profile_ids=list(payload.profile_ids),
            isolation_mode=payload.isolation_mode,
            expires_at=expires_at,
            ca_cert_pem=ca_cert_pem,
        )

    async def perform_worker_action(
        self,
        auth: AuthenticatedContext,
        *,
        worker_id: str,
        payload: WorkerActionRequest,
        idempotency_key: str | None,
        if_match_header: str | None = None,
        client_ip: str | None = None,
        correlation_id: str = "",
        now: datetime | None = None,
    ) -> ActionReceipt:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        clean_worker_id = _validate_uuid_or_404(
            worker_id,
            code="worker_not_found",
            detail="Worker not found.",
        )
        await self._require_instance_owner(
            auth,
            action=f"worker.action.{payload.action}",
            target=f"worker:{clean_worker_id}",
            require_step_up=True,
            client_ip=client_ip,
            correlation_id=correlation_id,
            ref_now=ref_now,
        )

        if not idempotency_key:
            raise BadRequestError(
                code="missing_idempotency_key",
                detail="Idempotency-Key header (UUIDv7) is required on worker actions (S-05).",
            )
        try:
            parse_uuid7_timestamp_ms(idempotency_key)
            validate_idempotency_key_window(
                idempotency_key,
                now=ref_now,
                max_age=timedelta(days=7),
                max_future_skew=timedelta(minutes=5),
            )
        except ValueError as exc:
            msg = str(exc)
            if msg.startswith("key_expired:"):
                raise ConflictError(code="key_expired", detail=msg) from exc
            raise BadRequestError(code="invalid_idempotency_key", detail=msg) from exc

        req_hash = sha256_canonical_json(
            {
                "worker_id": clean_worker_id,
                "action": payload.action,
                "reason": payload.reason,
                "expected_version": payload.expected_version,
            }
        )
        op_kind = f"worker.action:{idempotency_key}"

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            existing_op = await db.scalar(
                select(OperationReceiptModel)
                .where(
                    OperationReceiptModel.scope == "instance",
                    OperationReceiptModel.principal_id == auth.user.id,
                    OperationReceiptModel.operation_kind == op_kind,
                )
                .with_for_update()
            )
            if existing_op is not None:
                if existing_op.logical_effect_key != req_hash:
                    raise ConflictError(
                        code="idempotency_payload_mismatch",
                        detail="Idempotency-Key was already claimed with a different payload.",
                    )
                prob = (
                    Problem.model_validate(existing_op.problem_payload)
                    if existing_op.problem_payload is not None
                    else None
                )
                return ActionReceipt(
                    operation_id=existing_op.id,
                    resource_id=existing_op.resource_id,
                    state=cast(ActionState, existing_op.state),
                    correlation_id=existing_op.correlation_id,
                    status_url=existing_op.status_url,
                    result_id=existing_op.result_id,
                    problem=prob,
                )

            w_row = await db.scalar(
                select(WorkerModel).where(WorkerModel.id == clean_worker_id).with_for_update()
            )
            if w_row is None:
                raise NotFoundError(code="worker_not_found", detail="Worker not found.")

            enforce_optimistic_version(
                current_version=w_row.version,
                if_match_header=if_match_header,
                expected_version=payload.expected_version,
            )

            clean_reason = self._redactor.redact_text(payload.reason.strip())[:512]
            if payload.action == "drain":
                if w_row.status == "quarantined":
                    raise ConflictError(
                        code="worker_quarantined",
                        detail="Quarantined worker cannot enter draining state without resume.",
                    )
                w_row.status = "draining"
                w_row.drain_reason = clean_reason
            elif payload.action == "quarantine":
                w_row.status = "quarantined"
                w_row.quarantine_reason = clean_reason
            elif payload.action == "revoke":
                w_row.status = "quarantined"
                w_row.mtls_cert_revoked_at = ref_now
                w_row.quarantine_reason = f"revoked: {clean_reason}"[:512]
                signer_rows = (
                    await db.scalars(
                        select(SigningKeyModel)
                        .where(
                            SigningKeyModel.worker_id == w_row.id,
                            SigningKeyModel.revoked_at.is_(None),
                        )
                        .with_for_update()
                    )
                ).all()
                for sk in signer_rows:
                    sk.revoked_at = ref_now
                    sk.revoke_reason = clean_reason
                    sk.version += 1
                    sk.updated_at = ref_now
            elif payload.action == "resume":
                if w_row.mtls_cert_revoked_at is not None or w_row.mtls_cert_expires_at <= ref_now:
                    raise ConflictError(
                        code="worker_certificate_revoked_or_expired",
                        detail=(
                            "Revoked or expired worker certificate cannot be resumed; "
                            "re-enroll the worker with a new one-time token."
                        ),
                    )
                w_row.status = "online"
                w_row.quarantine_reason = None
                w_row.drain_reason = None
                w_row.heartbeat_at = ref_now

            w_row.version += 1
            w_row.updated_at = ref_now
            await db.flush()

            if payload.action in ("quarantine", "revoke"):
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="worker.quarantined",
                        occurred_at=ref_now,
                        workspace_id=None,
                        aggregate_id=w_row.id,
                        aggregate_version=w_row.version,
                        correlation_id=correlation_id,
                        payload=WorkerEventPayload(
                            worker_id=w_row.id,
                            status="quarantined",
                        ),
                    ),
                    now=ref_now,
                )

            op_id = new_uuid7(now=ref_now)
            receipt = await upsert_operation_receipt(
                db,
                operation_id=op_id,
                scope="instance",
                workspace_id=None,
                principal_id=auth.user.id,
                required_role="instance_owner",
                operation_kind=op_kind,
                resource_id=w_row.id,
                state="succeeded",
                correlation_id=correlation_id,
                status_url=f"/api/v1/operations/{op_id}",
                logical_effect_key=req_hash,
                result_id=w_row.id,
                now=ref_now,
            )
            await append_audit_entry(
                db,
                workspace_id=None,
                actor_type="user",
                actor_id=auth.user.id,
                action=f"worker.action.{payload.action}",
                target=f"worker:{w_row.id}",
                decision="allow",
                reason_code=f"worker_{payload.action}",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "reason": clean_reason,
                    "new_status": w_row.status,
                    "version": w_row.version,
                },
                occurred_at=ref_now,
            )
            return receipt

    async def run_worker_self_test(
        self,
        auth: AuthenticatedContext,
        *,
        worker_id: str,
        client_ip: str | None = None,
        correlation_id: str = "",
        now: datetime | None = None,
    ) -> WorkerSelfTestResponse:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        clean_worker_id = _validate_uuid_or_404(
            worker_id,
            code="worker_not_found",
            detail="Worker not found.",
        )
        await self._require_instance_owner(
            auth,
            action="worker.self_test",
            target=f"worker:{clean_worker_id}",
            require_step_up=False,
            client_ip=client_ip,
            correlation_id=correlation_id,
            ref_now=ref_now,
        )

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            w_row = await db.scalar(
                select(WorkerModel).where(WorkerModel.id == clean_worker_id).with_for_update()
            )
            if w_row is None:
                raise NotFoundError(code="worker_not_found", detail="Worker not found.")

            signer_row = (
                await db.scalar(
                    select(SigningKeyModel).where(
                        SigningKeyModel.key_id == w_row.active_signer_key_id,
                        SigningKeyModel.worker_id == w_row.id,
                    )
                )
                if w_row.active_signer_key_id is not None
                else None
            )
            caps = dict(w_row.capabilities_json or {})
            cert_valid = w_row.mtls_cert_revoked_at is None and w_row.mtls_cert_expires_at > ref_now
            signer_valid = (
                signer_row is not None
                and signer_row.revoked_at is None
                and signer_row.purpose == "worker_result"
                and signer_row.trust_domain == w_row.trust_domain
            )
            hb_fresh = (ref_now - w_row.heartbeat_at) <= self._stale_worker_timeout
            isolation_ok = bool(
                caps.get("network_none") is True
                and caps.get("seccomp") is True
                and caps.get("no_new_privileges") is True
                and (
                    caps.get("rootless") is True
                    or (
                        w_row.isolation_mode == "oci_trusted_local"
                        and w_row.host_escape_risk_acknowledged
                    )
                )
            )

            checks = [
                IsolationCheckResult(
                    check_id="mtls_certificate_active",
                    passed=cert_valid,
                    detail=(
                        f"serial={w_row.mtls_cert_serial}, "
                        f"revoked={w_row.mtls_cert_revoked_at is not None}"
                    ),
                ),
                IsolationCheckResult(
                    check_id="external_ed25519_signer_active",
                    passed=signer_valid,
                    detail=f"key_id={w_row.active_signer_key_id} (ADR-035)",
                ),
                IsolationCheckResult(
                    check_id="sandbox_isolation_posture",
                    passed=isolation_ok,
                    detail=f"mode={w_row.isolation_mode}, runtime={w_row.runtime_name}",
                ),
                IsolationCheckResult(
                    check_id="heartbeat_freshness",
                    passed=hb_fresh and w_row.status == "online",
                    detail=f"status={w_row.status}, heartbeat_at={w_row.heartbeat_at.isoformat()}",
                ),
            ]
            passed = all(c.passed for c in checks)
            if not isolation_ok and w_row.status != "quarantined":
                w_row.status = "quarantined"
                w_row.quarantine_reason = "self_test_isolation_failed"
                w_row.version += 1
                w_row.updated_at = ref_now
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="worker.quarantined",
                        occurred_at=ref_now,
                        workspace_id=None,
                        aggregate_id=w_row.id,
                        aggregate_version=w_row.version,
                        correlation_id=correlation_id,
                        payload=WorkerEventPayload(
                            worker_id=w_row.id,
                            status="quarantined",
                        ),
                    ),
                    now=ref_now,
                )
            await db.flush()

            await append_audit_entry(
                db,
                workspace_id=None,
                actor_type="user",
                actor_id=auth.user.id,
                action="worker.self_test",
                target=f"worker:{w_row.id}",
                decision="allow" if passed else "deny",
                reason_code="self_test_passed" if passed else "self_test_failed",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={"passed": passed, "isolation_mode": w_row.isolation_mode},
                occurred_at=ref_now,
            )

        return WorkerSelfTestResponse(
            worker_id=clean_worker_id,
            passed=passed,
            isolation_mode=cast(WorkerIsolationMode, w_row.isolation_mode),
            checks=checks,
            checked_at=ref_now,
            detail=(
                "All mTLS, external Ed25519 signer, and sandbox isolation checks passed."
                if passed
                else "One or more worker self-test checks failed."
            ),
        )

    async def get_workspace_worker_readiness(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        now: datetime | None = None,
    ) -> WorkspaceWorkerReadinessResponse:
        """Return workspace-scoped readiness + leases without leaking global host inventory."""
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        await self.reconcile_stale_workers_and_leases(now=ref_now)

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            active_ws_count = int(
                (
                    await db.scalar(
                        select(func.count())
                        .select_from(WorkspaceModel)
                        .where(
                            WorkspaceModel.status == "active",
                            WorkspaceModel.deleted_at.is_(None),
                        )
                    )
                )
                or 0
            )
            workers = (await db.scalars(select(WorkerModel))).all()

        eligible_online: list[WorkerModel] = []
        blocked_by_multi_ws = False
        for w in workers:
            if (
                w.status == "online"
                and w.mtls_cert_revoked_at is None
                and w.mtls_cert_expires_at > ref_now
            ):
                if w.isolation_mode == "oci_trusted_local" and active_ws_count > 1:
                    blocked_by_multi_ws = True
                    continue
                if w.isolation_mode == "oci_trusted_local" and not w.host_escape_risk_acknowledged:
                    continue
                eligible_online.append(w)

        profiles = sorted({p for w in eligible_online for p in w.profile_ids_json})
        vm_available = any(w.isolation_mode == "vm_isolated" for w in eligible_online)
        trusted_local_warning = any(w.isolation_mode == "oci_trusted_local" for w in workers)
        degraded_reason: str | None = None
        if not eligible_online:
            if blocked_by_multi_ws:
                degraded_reason = (
                    "Trusted-local OCI workers are blocked in multi-workspace instances "
                    "(ADR-034); enroll rootless OCI or microVM workers."
                )
            else:
                degraded_reason = (
                    "No online isolated sandbox workers are currently available for execution."
                )

        async with workspace_rls_session(
            self._session_factory,
            workspace_id=ws_ctx.workspace.id,
        ) as ws_db:
            lease_rows = (
                await ws_db.scalars(
                    select(SandboxLeaseModel)
                    .where(
                        SandboxLeaseModel.workspace_id == ws_ctx.workspace.id,
                        SandboxLeaseModel.status.in_(("leased", "running", "cancel_requested")),
                    )
                    .order_by(SandboxLeaseModel.issued_at.desc(), SandboxLeaseModel.id.desc())
                    .limit(25)
                )
            ).all()

        return WorkspaceWorkerReadinessResponse(
            workspace_id=ws_ctx.workspace.id,
            ready=len(eligible_online) > 0,
            eligible_online_workers=len(eligible_online),
            available_profiles=profiles,
            vm_isolation_available=vm_available,
            trusted_local_warning=trusted_local_warning,
            active_workspace_leases=[_to_lease_summary_dto(r) for r in lease_rows],
            degraded_reason=degraded_reason,
            snapshot_at=ref_now,
        )

    def register_setup_probe(self, registry: SetupStepRegistry) -> None:
        """Wire live `worker_readiness` setup probe (`U07` -> `U14`)."""

        async def _probe_worker_readiness(
            _phase: str,
            draft: Mapping[str, Any],
        ) -> SetupStepProbeResult:
            ref_now = self._clock().astimezone(UTC)
            await self.reconcile_stale_workers_and_leases(now=ref_now)
            backend = str(draft.get("sandbox_backend") or "").strip().lower()
            profile_id = str(draft.get("runtime_profile_id") or "").strip()
            ack_risk = bool(draft.get("host_escape_risk_acknowledged", False))

            async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
                active_ws_count = int(
                    (
                        await db.scalar(
                            select(func.count())
                            .select_from(WorkspaceModel)
                            .where(
                                WorkspaceModel.status == "active",
                                WorkspaceModel.deleted_at.is_(None),
                            )
                        )
                    )
                    or 0
                )
                workers = (
                    await db.scalars(
                        select(WorkerModel).where(
                            WorkerModel.status == "online",
                            WorkerModel.mtls_cert_revoked_at.is_(None),
                            WorkerModel.mtls_cert_expires_at > ref_now,
                        )
                    )
                ).all()

            matching: list[WorkerModel] = []
            for w in workers:
                if profile_id and profile_id not in w.profile_ids_json:
                    continue
                if backend in ("vm", "vm_isolated", "firecracker") and (
                    w.isolation_mode != "vm_isolated"
                ):
                    continue
                if w.isolation_mode == "oci_trusted_local":
                    if not (ack_risk and w.host_escape_risk_acknowledged):
                        continue
                    if active_ws_count > 1:
                        continue
                matching.append(w)

            if not matching:
                return SetupStepProbeResult(
                    probe_status="failed",
                    detail=(
                        "No online enrolled isolated worker matches the requested runtime "
                        f"profile ({profile_id or 'any'}) and sandbox backend ({backend or 'any'})."
                    ),
                    blocking_reasons=(
                        "Enroll and start at least one healthy mTLS worker supporting the profile.",
                    ),
                )

            return SetupStepProbeResult(
                probe_status="passed",
                detail=(
                    f"Verified {len(matching)} online isolated worker(s) supporting "
                    f"profile {profile_id or 'default'}."
                ),
            )

        registry.register_probe("worker_readiness", _probe_worker_readiness)

    # ------------------------------------------------------------------
    # Internal S-21 mTLS Worker Protocol Methods
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_enrollment_attestation(
        att: WorkerIsolationAttestation,
        *,
        expected_mode: str,
    ) -> None:
        if att.isolation_mode != expected_mode:
            raise UnprocessableEntityError(
                code="enrollment_isolation_mode_mismatch",
                detail=(
                    f"Worker reported isolation_mode {att.isolation_mode!r}, expected "
                    f"{expected_mode!r} from enrollment token."
                ),
            )
        if not att.network_none_supported:
            raise UnprocessableEntityError(
                code="worker_egress_isolation_failed",
                detail="Guest network=none egress isolation must be supported (SEC-014).",
            )
        if not att.seccomp_verified or not att.no_new_privileges_verified:
            raise UnprocessableEntityError(
                code="worker_seccomp_or_nnp_unverified",
                detail="Restrictive seccomp and no-new-privileges confinement are mandatory.",
            )
        if expected_mode in ("oci_rootless", "vm_isolated") and not att.rootless_verified:
            raise UnprocessableEntityError(
                code="worker_rootless_or_vm_required",
                detail=f"Mode {expected_mode!r} requires verified rootless/VM execution.",
            )

    async def enroll_worker(
        self,
        request: Request,
        *,
        payload: WorkerEnrollHandshakeRequest,
        client_ip: str | None = None,
        correlation_id: str = "",
        now: datetime | None = None,
    ) -> WorkerEnrollHandshakeResponse:
        """Consume a one-time enrollment token and issue short-lived mTLS X.509 cert (`S-21`)."""
        self._assert_no_browser_headers_on_worker_route(request)
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        token_hash = _hash_enrollment_token(payload.enrollment_token.strip())

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            enrollment = await db.scalar(
                select(WorkerEnrollmentModel)
                .where(WorkerEnrollmentModel.token_hash == token_hash)
                .with_for_update()
            )
            if enrollment is None:
                raise UnauthorizedError(
                    code="invalid_enrollment_token",
                    detail="Worker enrollment token is invalid.",
                )
            if enrollment.revoked_at is not None:
                raise ForbiddenError(
                    code="enrollment_token_revoked",
                    detail="Worker enrollment token has been revoked.",
                )
            if enrollment.used_at is not None:
                await append_audit_entry(
                    db,
                    workspace_id=None,
                    actor_type="service",
                    actor_id=f"host:{payload.attestation.host_id}",
                    action="worker.enroll",
                    target=f"worker_enrollment:{enrollment.id}",
                    decision="deny",
                    reason_code="enrollment_token_replay",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={"enrollment_id": enrollment.id},
                    occurred_at=ref_now,
                )
                raise ConflictError(
                    code="enrollment_token_already_used",
                    detail="One-time worker enrollment token has already been consumed.",
                )
            if enrollment.expires_at <= ref_now:
                raise GoneError(
                    code="enrollment_token_expired",
                    detail="One-time worker enrollment token has expired.",
                )

            pub_key = payload.signer_public_key
            if pub_key.trust_domain != enrollment.trust_domain:
                raise UnprocessableEntityError(
                    code="signer_trust_domain_mismatch",
                    detail=(
                        f"Signer trust_domain {pub_key.trust_domain!r} does not match "
                        f"enrollment trust_domain {enrollment.trust_domain!r} (ADR-035)."
                    ),
                )
            if pub_key.revoked_at is not None:
                raise UnprocessableEntityError(
                    code="revoked_signer_public_key",
                    detail="Cannot enroll a pre-revoked Ed25519 signer public key.",
                )

            self._validate_enrollment_attestation(
                payload.attestation,
                expected_mode=enrollment.isolation_mode,
            )

            existing_key = await db.scalar(
                select(SigningKeyModel.id).where(SigningKeyModel.key_id == pub_key.key_id)
            )
            if existing_key is not None:
                raise ConflictError(
                    code="duplicate_signing_key_id",
                    detail="Worker Ed25519 signing key_id is already registered.",
                )

            effective_profiles = sorted(
                set(payload.profile_ids).intersection(enrollment.profile_ids_json)
            )
            if not effective_profiles:
                raise UnprocessableEntityError(
                    code="no_permitted_runtime_profiles",
                    detail="Worker reported zero runtime profiles permitted by enrollment token.",
                )

            worker_id = new_uuid7(now=ref_now)
            try:
                client_cert_pem, cert_identity, ca_cert_pem = await self._ca.sign_worker_csr(
                    csr_pem=payload.csr_pem,
                    worker_id=worker_id,
                    trust_domain=enrollment.trust_domain,
                    valid_hours=self._worker_cert_valid_hours,
                    now=ref_now,
                )
            except CryptoVerificationError as exc:
                raise BadRequestError(
                    code="invalid_worker_csr",
                    detail=str(exc),
                ) from exc

            att = payload.attestation
            capabilities = {
                "rootless": att.rootless_verified,
                "seccomp": att.seccomp_verified,
                "no_new_privileges": att.no_new_privileges_verified,
                "network_none": att.network_none_supported,
                "external_ed25519_signer": True,
            }

            worker_row = WorkerModel(
                id=worker_id,
                host_id=att.host_id.strip(),
                trust_domain=enrollment.trust_domain,
                isolation_mode=enrollment.isolation_mode,
                runtime_name=att.runtime_name.strip(),
                profile_ids_json=effective_profiles,
                capabilities_json=capabilities,
                cpu_limit=att.cpu_limit,
                memory_limit_bytes=att.memory_limit_bytes,
                disk_limit_bytes=att.disk_limit_bytes,
                pids_limit=min(att.pids_limit, 512),
                status="online",
                heartbeat_at=ref_now,
                mtls_cert_serial=cert_identity.serial_hex,
                mtls_cert_fingerprint_sha256=cert_identity.fingerprint_sha256,
                mtls_cert_pem=client_cert_pem,
                mtls_cert_expires_at=cert_identity.not_valid_after,
                mtls_cert_revoked_at=None,
                active_signer_key_id=pub_key.key_id,
                last_workspace_id=None,
                host_escape_risk_acknowledged=enrollment.host_escape_risk_acknowledged,
                quarantine_reason=None,
                drain_reason=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(worker_row)
            await db.flush()

            signer_row = SigningKeyModel(
                id=new_uuid7(now=ref_now),
                key_id=pub_key.key_id,
                algorithm="ed25519",
                purpose="worker_result",
                public_key_b64=pub_key.public_key_b64,
                worker_id=worker_id,
                trust_domain=enrollment.trust_domain,
                not_before=pub_key.not_before,
                revoked_at=None,
                revoke_reason=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(signer_row)

            enrollment.used_at = ref_now
            enrollment.enrolled_worker_id = worker_id
            enrollment.version += 1
            enrollment.updated_at = ref_now
            await db.flush()

            await append_audit_entry(
                db,
                workspace_id=None,
                actor_type="service",
                actor_id=f"worker:{worker_id}",
                action="worker.enrolled",
                target=f"worker:{worker_id}",
                decision="allow",
                reason_code="mtls_csr_exchanged",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "enrollment_id": enrollment.id,
                    "host_id": worker_row.host_id,
                    "isolation_mode": worker_row.isolation_mode,
                    "cert_serial": cert_identity.serial_hex,
                    "signer_key_id": signer_row.key_id,
                },
                occurred_at=ref_now,
            )
            worker_dto = _to_worker_dto(worker_row, active_leases=0)

        return WorkerEnrollHandshakeResponse(
            worker=worker_dto,
            client_cert_pem=client_cert_pem,
            ca_cert_pem=ca_cert_pem,
            cert_expires_at=cert_identity.not_valid_after,
        )

    async def enqueue_sandbox_job(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        profile_id: str,
        image_digest: str,
        base_sha: str,
        source_archive_digest: str,
        command_ids: Sequence[str],
        correlation_id: str,
        now: datetime,
        profile_revision: int = 1,
        patch_digest: str | None = None,
        patch_diff_text: str | None = None,
        resource_limits: SandboxResourceLimits | None = None,
        allowed_output_slots: Sequence[str] = ("stdout", "stderr", "junit_xml"),
        requires_vm_isolation: bool = False,
        dedup_key: str | None = None,
        logical_effect_key: str | None = None,
        budget_key: str | None = None,
        priority: int = 100,
        max_attempts: int = 2,
    ) -> str:
        """Enqueue a durable `sandbox.execute` task job for isolated `Z3` workers."""
        eff_limits = resource_limits or SandboxResourceLimits(
            cpu=2,
            memory_bytes=2_147_483_648,
            disk_bytes=10_737_418_240,
            pids=256,
            wall_seconds=300,
            output_bytes=MAX_SANDBOX_UPLOAD_BYTES,
        )
        spec_payload: dict[str, Any] = {
            "repair_id": repair_id,
            "profile_id": profile_id,
            "profile_revision": profile_revision,
            "image_digest": image_digest,
            "base_sha": base_sha,
            "source_archive_digest": source_archive_digest,
            "patch_digest": patch_digest,
            "patch_diff_text": patch_diff_text,
            "command_ids": list(command_ids),
            "resource_limits": eff_limits.model_dump(mode="json"),
            "allowed_output_slots": list(allowed_output_slots),
            "requires_vm_isolation": requires_vm_isolation,
        }
        task_dto = await self._queue.enqueue_job(
            workspace_id=workspace_id,
            repository_id=repository_id,
            repair_id=None,  # repair_sessions row is created in U15+; repair_id carried in spec
            is_repair_job=True,
            kind=SANDBOX_TASK_KIND,
            resource_id=repair_id,
            correlation_id=correlation_id,
            now=now,
            priority=priority,
            max_attempts=max_attempts,
            dedup_key=dedup_key,
            logical_effect_key=logical_effect_key,
            budget_key=budget_key,
            payload=spec_payload,
        )
        return task_dto.id

    async def poll_worker_job(
        self,
        request: Request,
        *,
        worker_id: str,
        payload: WorkerPollRequest,
        now: datetime | None = None,
    ) -> WorkerPollResponse:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        clean_worker_id = _validate_uuid_or_404(
            worker_id,
            code="worker_not_found",
            detail="Worker not found.",
        )
        mtls_worker = await self.authenticate_mtls_worker(
            request,
            expected_worker_id=clean_worker_id,
            now=ref_now,
        )

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            w_row = await db.scalar(
                select(WorkerModel).where(WorkerModel.id == mtls_worker.id).with_for_update()
            )
            assert w_row is not None
            w_row.heartbeat_at = ref_now
            if w_row.status == "offline" and w_row.mtls_cert_revoked_at is None:
                w_row.status = "online"
            if payload.status_hint == "draining" and w_row.status == "online":
                w_row.status = "draining"
            w_row.updated_at = ref_now
            current_status = cast(WorkerStatus, w_row.status)
            worker_profiles = set(w_row.profile_ids_json)
            isolation_mode = cast(WorkerIsolationMode, w_row.isolation_mode)
            risk_acked = w_row.host_escape_risk_acknowledged
            trust_domain = w_row.trust_domain

            active_ws_count = int(
                (
                    await db.scalar(
                        select(func.count())
                        .select_from(WorkspaceModel)
                        .where(
                            WorkspaceModel.status == "active",
                            WorkspaceModel.deleted_at.is_(None),
                        )
                    )
                )
                or 0
            )
            await db.flush()

        if current_status != "online" or not worker_profiles:
            return WorkerPollResponse(worker_status=current_status, sandbox_job=None)
        if isolation_mode == "oci_trusted_local" and (not risk_acked or active_ws_count > 1):
            # ADR-016 / ADR-034: shared-daemon trusted-local never runs multi-workspace jobs.
            return WorkerPollResponse(worker_status=current_status, sandbox_job=None)

        leased = await self._queue.acquire_next_lease(
            worker_id=mtls_worker.id,
            now=ref_now,
            allowed_kinds={SANDBOX_TASK_KIND},
        )
        if leased is None:
            return WorkerPollResponse(worker_status=current_status, sandbox_job=None)

        task_job = leased.job
        spec = leased.payload
        profile_id = str(spec.get("profile_id") or "python-3.12-node-22")
        requires_vm = bool(spec.get("requires_vm_isolation", False))

        if profile_id not in worker_profiles or (requires_vm and isolation_mode != "vm_isolated"):
            await self._queue.fail_lease(
                job_id=task_job.id,
                worker_id=mtls_worker.id,
                lease_epoch=task_job.lease_epoch,
                error_code="worker_profile_or_isolation_incompatible",
                error_detail=(
                    f"Worker {mtls_worker.id} ({isolation_mode}) cannot execute "
                    f"profile={profile_id}, requires_vm={requires_vm}."
                ),
                now=ref_now,
                recoverable=True,
            )
            return WorkerPollResponse(worker_status=current_status, sandbox_job=None)

        repo_id = task_job.repository_id
        if repo_id is None:
            async with workspace_rls_session(
                self._session_factory,
                workspace_id=task_job.workspace_id,
            ) as ws_db:
                first_repo_id = await ws_db.scalar(
                    select(RepositoryModel.id)
                    .where(RepositoryModel.workspace_id == task_job.workspace_id)
                    .limit(1)
                )
            if first_repo_id is None:
                raise ConflictError(
                    code="sandbox_job_missing_repository",
                    detail="Sandbox execution job requires a repository scope.",
                )
            repo_id = str(first_repo_id)

        limits = SandboxResourceLimits.model_validate(spec.get("resource_limits") or {})
        allowed_slots = list(spec.get("allowed_output_slots") or ["stdout", "stderr"])
        capability_nonce = secrets.token_urlsafe(24)
        lease_expires_at = task_job.lease_expires_at or (ref_now + timedelta(seconds=60))
        repair_id = str(spec.get("repair_id") or task_job.resource_id)
        source_archive_digest = str(spec["source_archive_digest"])

        upload_ticket = mint_upload_capability_ticket(
            signing_key=self._upload_cap_key,
            job_id=task_job.id,
            workspace_id=task_job.workspace_id,
            repository_id=repo_id,
            lease_epoch=task_job.lease_epoch,
            capability_nonce=capability_nonce,
            allowed_slots=allowed_slots,
            max_output_bytes=limits.output_bytes,
            expires_at=lease_expires_at,
        )

        sandbox_job = SandboxJobV1(
            job_id=task_job.id,
            workspace_id=task_job.workspace_id,
            repository_id=repo_id,
            repair_id=repair_id,
            lease_epoch=task_job.lease_epoch,
            capability_nonce=capability_nonce,
            issued_at=ref_now,
            expires_at=lease_expires_at,
            base_sha=str(spec["base_sha"]),
            source_archive_digest=source_archive_digest,
            patch_digest=cast(str | None, spec.get("patch_digest")),
            profile_id=profile_id,
            profile_revision=int(spec.get("profile_revision", 1)),
            image_digest=str(spec["image_digest"]),
            command_ids=list(spec["command_ids"]),
            resource_limits=limits,
            network_policy_digest=_DEFAULT_NET_POLICY_DIGEST,
            artifact_upload_capability=upload_ticket,
            expected_worker_trust_domain=trust_domain,
            supervisor_policy_digest=_DEFAULT_SUPERVISOR_POLICY_DIGEST,
        )

        async with workspace_rls_session(
            self._session_factory,
            workspace_id=sandbox_job.workspace_id,
        ) as ws_db:
            lease_row = SandboxLeaseModel(
                id=new_uuid7(now=ref_now),
                workspace_id=sandbox_job.workspace_id,
                repository_id=sandbox_job.repository_id,
                repair_id=sandbox_job.repair_id,
                job_id=sandbox_job.job_id,
                worker_id=mtls_worker.id,
                lease_epoch=sandbox_job.lease_epoch,
                capability_nonce=capability_nonce,
                expected_worker_trust_domain=trust_domain,
                profile_id=sandbox_job.profile_id,
                profile_revision=sandbox_job.profile_revision,
                image_digest=sandbox_job.image_digest,
                base_sha=sandbox_job.base_sha,
                source_archive_digest=sandbox_job.source_archive_digest,
                patch_digest=sandbox_job.patch_digest,
                network_policy_digest=sandbox_job.network_policy_digest,
                supervisor_policy_digest=sandbox_job.supervisor_policy_digest,
                sandbox_job_json=sandbox_job.model_dump(mode="json"),
                upload_slots_json=allowed_slots,
                uploaded_artifacts_json=[],
                output_bytes_uploaded=0,
                status="leased",
                issued_at=ref_now,
                heartbeat_at=ref_now,
                lease_expires_at=lease_expires_at,
                ended_at=None,
                result_digest=None,
                result_json=None,
                cleanup_verified=False,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            ws_db.add(lease_row)
            await ws_db.flush()

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            w_row = await db.scalar(
                select(WorkerModel).where(WorkerModel.id == mtls_worker.id).with_for_update()
            )
            if w_row is not None:
                w_row.last_workspace_id = sandbox_job.workspace_id
                w_row.updated_at = ref_now

        raw_archive = self._source_archives_in_memory.get(source_archive_digest)
        archive_b64 = (
            base64.b64encode(raw_archive).decode("ascii")
            if raw_archive is not None and len(raw_archive) <= 10_000_000
            else None
        )

        return WorkerPollResponse(
            worker_status=current_status,
            sandbox_job=sandbox_job,
            source_archive_b64=archive_b64,
            patch_diff_text=cast(str | None, spec.get("patch_diff_text")),
            heartbeat_interval_seconds=15,
        )

    async def _load_sandbox_lease_context(
        self,
        job_id: str,
        *,
        lease_epoch: int,
    ) -> tuple[str, SandboxLeaseModel | None]:
        clean_job_id = _validate_uuid_or_404(
            job_id,
            code="task_job_not_found",
            detail="Sandbox job not found.",
        )
        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            ws_id = await db.scalar(
                select(TaskJobModel.workspace_id).where(TaskJobModel.id == clean_job_id)
            )
            if ws_id is None:
                raise NotFoundError(code="task_job_not_found", detail="Sandbox job not found.")
            lease_row = await db.scalar(
                select(SandboxLeaseModel).where(
                    SandboxLeaseModel.job_id == clean_job_id,
                    SandboxLeaseModel.lease_epoch == lease_epoch,
                )
            )
            if lease_row is not None:
                db.expunge(lease_row)
            return str(ws_id), lease_row

    async def heartbeat_sandbox_job(
        self,
        request: Request,
        *,
        job_id: str,
        payload: WorkerJobHeartbeatRequest,
        now: datetime | None = None,
    ) -> WorkerJobHeartbeatResponse:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        mtls_worker = await self.authenticate_mtls_worker(request, now=ref_now)
        ws_id, lease_snapshot = await self._load_sandbox_lease_context(
            job_id,
            lease_epoch=payload.lease_epoch,
        )
        if lease_snapshot is None or lease_snapshot.worker_id != mtls_worker.id:
            await self._queue.heartbeat_lease(
                job_id=job_id,
                worker_id=mtls_worker.id,
                lease_epoch=payload.lease_epoch,
                now=ref_now,
            )
            raise ConflictError(
                code="stale_job_lease",
                detail="Sandbox lease epoch is stale or owned by another worker (SEC-021).",
            )

        if not hmac.compare_digest(lease_snapshot.capability_nonce, payload.capability_nonce):
            raise ForbiddenError(
                code="invalid_capability_nonce",
                detail="Heartbeat capability_nonce does not match active sandbox lease.",
            )

        await self._queue.mark_lease_running(
            job_id=job_id,
            worker_id=mtls_worker.id,
            lease_epoch=payload.lease_epoch,
            now=ref_now,
        )
        hb_outcome = await self._queue.heartbeat_lease(
            job_id=job_id,
            worker_id=mtls_worker.id,
            lease_epoch=payload.lease_epoch,
            now=ref_now,
        )
        expires_at = hb_outcome.job.lease_expires_at or (ref_now + timedelta(seconds=60))

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as ws_db:
            l_row = await ws_db.scalar(
                select(SandboxLeaseModel)
                .where(SandboxLeaseModel.id == lease_snapshot.id)
                .with_for_update()
            )
            if l_row is not None:
                l_row.status = "cancel_requested" if hb_outcome.cancel_requested else "running"
                l_row.heartbeat_at = ref_now
                l_row.lease_expires_at = expires_at
                l_row.updated_at = ref_now

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            w_row = await db.scalar(
                select(WorkerModel).where(WorkerModel.id == mtls_worker.id).with_for_update()
            )
            if w_row is not None:
                w_row.heartbeat_at = ref_now
                w_row.updated_at = ref_now

        return WorkerJobHeartbeatResponse(
            job_id=hb_outcome.job.id,
            lease_epoch=hb_outcome.job.lease_epoch,
            lease_expires_at=expires_at,
            cancel_requested=hb_outcome.cancel_requested,
        )

    async def upload_sandbox_artifact(
        self,
        request: Request,
        *,
        job_id: str,
        upload_capability: str,
        payload: WorkerArtifactUploadRequest,
        now: datetime | None = None,
    ) -> WorkerArtifactUploadResponse:
        """Write-only artifact slot upload enforcing HMAC capability, fence & 100MiB cap."""
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        mtls_worker = await self.authenticate_mtls_worker(request, now=ref_now)

        try:
            verified_cap = verify_upload_capability_ticket(
                signing_key=self._upload_cap_key,
                ticket=upload_capability,
                expected_job_id=job_id,
                now=ref_now,
            )
        except CryptoVerificationError as exc:
            raise ForbiddenError(
                code="invalid_upload_capability",
                detail=str(exc),
            ) from exc

        if verified_cap.lease_epoch != payload.lease_epoch:
            raise ConflictError(
                code="stale_job_lease",
                detail="Upload capability lease_epoch does not match payload lease_epoch.",
            )
        if not hmac.compare_digest(verified_cap.capability_nonce, payload.capability_nonce):
            raise ForbiddenError(
                code="invalid_capability_nonce",
                detail="Upload capability_nonce mismatch.",
            )
        if payload.slot_name not in verified_cap.allowed_slots:
            raise ForbiddenError(
                code="upload_slot_not_permitted",
                detail=f"Artifact slot {payload.slot_name!r} is not permitted for this job.",
            )

        try:
            raw_bytes = base64.b64decode(payload.content_b64.encode("ascii"), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise BadRequestError(
                code="malformed_artifact_base64",
                detail="content_b64 is not valid base64.",
            ) from exc

        actual_raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        if not hmac.compare_digest(actual_raw_sha256, payload.digest.strip().lower()):
            raise BadRequestError(
                code="artifact_digest_mismatch",
                detail="Uploaded sandbox artifact bytes do not match declared SHA-256 digest.",
            )

        cap_limit = min(verified_cap.max_output_bytes, MAX_SANDBOX_UPLOAD_BYTES)
        if len(raw_bytes) > cap_limit:
            raise PayloadTooLargeError(
                detail=(
                    f"Artifact slot {payload.slot_name!r} exceeds job output_bytes cap "
                    f"({cap_limit} bytes, NFR-14)."
                )
            )

        # Verify live lease fence via heartbeat check before writing any bytes (SEC-021):
        hb_outcome = await self._queue.heartbeat_lease(
            job_id=job_id,
            worker_id=mtls_worker.id,
            lease_epoch=payload.lease_epoch,
            now=ref_now,
        )
        if hb_outcome.cancel_requested:
            raise ConflictError(
                code="job_cancel_requested",
                detail="Job cancellation was requested; artifact uploads are closed.",
            )

        clean_mime = payload.mime.strip()[:120] or "application/octet-stream"
        if clean_mime.startswith("text/") or clean_mime in (
            "application/json",
            "application/xml",
        ):
            decoded = raw_bytes.decode("utf-8", errors="replace")
            redacted_bytes = self._redactor.redact_text(decoded).encode("utf-8")
        else:
            redacted_bytes = raw_bytes

        stored_digest = hashlib.sha256(redacted_bytes).hexdigest()

        async with workspace_rls_session(
            self._session_factory,
            workspace_id=verified_cap.workspace_id,
        ) as ws_db:
            l_row = await ws_db.scalar(
                select(SandboxLeaseModel)
                .where(
                    SandboxLeaseModel.job_id == job_id,
                    SandboxLeaseModel.lease_epoch == payload.lease_epoch,
                )
                .with_for_update()
            )
            if l_row is None or l_row.worker_id != mtls_worker.id:
                raise ConflictError(
                    code="stale_job_lease",
                    detail="Sandbox lease is missing or reassigned (SEC-021).",
                )

            existing_items = list(l_row.uploaded_artifacts_json or [])
            for prev in existing_items:
                if prev.get("slot_name") == payload.slot_name:
                    if prev.get("raw_sha256") == actual_raw_sha256:
                        return WorkerArtifactUploadResponse(
                            artifact_ref=ResultArtifactRef(
                                id=str(prev["id"]),
                                digest=str(prev["digest"]),
                                size=int(prev["size"]),
                            ),
                            remaining_output_bytes=max(0, cap_limit - l_row.output_bytes_uploaded),
                        )
                    raise ConflictError(
                        code="duplicate_slot_upload_conflict",
                        detail=(
                            f"Artifact slot {payload.slot_name!r} was already uploaded "
                            "with different bytes."
                        ),
                    )

            new_total = l_row.output_bytes_uploaded + len(raw_bytes)
            if new_total > cap_limit:
                raise PayloadTooLargeError(
                    detail=(
                        f"Cumulative sandbox output ({new_total} B) exceeds job cap "
                        f"({cap_limit} B, NFR-14)."
                    )
                )

            art_row = await persist_encrypted_artifact(
                ws_db,
                store=self._artifact_store,
                workspace_id=verified_cap.workspace_id,
                repository_id=l_row.repository_id,
                name=f"sandbox-{payload.slot_name}-{job_id[:8]}",
                kind=f"sandbox_{payload.slot_name}",
                mime=clean_mime,
                plaintext=redacted_bytes,
                expected_digest=stored_digest,
                now=ref_now,
            )
            existing_items.append(
                {
                    "id": art_row.id,
                    "slot_name": payload.slot_name,
                    "digest": art_row.digest,
                    "size": art_row.size_bytes,
                    "raw_sha256": actual_raw_sha256,
                }
            )
            l_row.uploaded_artifacts_json = existing_items
            l_row.output_bytes_uploaded = new_total
            l_row.version += 1
            l_row.updated_at = ref_now
            await ws_db.flush()

            return WorkerArtifactUploadResponse(
                artifact_ref=ResultArtifactRef(
                    id=art_row.id,
                    digest=art_row.digest,
                    size=art_row.size_bytes,
                ),
                remaining_output_bytes=max(0, cap_limit - new_total),
            )

    async def _quarantine_worker_internal(
        self,
        *,
        worker_id: str,
        reason_code: str,
        detail: str,
        correlation_id: str,
        ref_now: datetime,
    ) -> None:
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            w_row = await db.scalar(
                select(WorkerModel).where(WorkerModel.id == worker_id).with_for_update()
            )
            if w_row is None:
                return
            w_row.status = "quarantined"
            w_row.quarantine_reason = f"{reason_code}: {detail}"[:512]
            w_row.version += 1
            w_row.updated_at = ref_now
            await db.flush()

            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=ref_now),
                    type="worker.quarantined",
                    occurred_at=ref_now,
                    workspace_id=None,
                    aggregate_id=w_row.id,
                    aggregate_version=w_row.version,
                    correlation_id=correlation_id,
                    payload=WorkerEventPayload(
                        worker_id=w_row.id,
                        status="quarantined",
                    ),
                ),
                now=ref_now,
            )
            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=ref_now),
                    type="security.policy.denied",
                    occurred_at=ref_now,
                    workspace_id=None,
                    aggregate_id=w_row.id,
                    aggregate_version=w_row.version,
                    correlation_id=correlation_id,
                    payload=SecurityIdentityEventPayload(
                        target_id=w_row.id,
                        reason_code=reason_code,
                    ),
                ),
                now=ref_now,
            )
            await append_audit_entry(
                db,
                workspace_id=None,
                actor_type="system",
                actor_id="worker_broker",
                action="worker.auto_quarantined",
                target=f"worker:{w_row.id}",
                decision="deny",
                reason_code=reason_code,
                correlation_id=correlation_id,
                metadata={"detail": detail[:256]},
                occurred_at=ref_now,
            )

    async def submit_sandbox_result(
        self,
        request: Request,
        *,
        job_id: str,
        result: ResultV1,
        correlation_id: str = "",
        now: datetime | None = None,
    ) -> WorkerJobResultReceipt:
        """Verify Ed25519 `ResultV1` signature, lease fence, uploaded artifacts & cleanup."""
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        if result.job_id != job_id:
            raise BadRequestError(
                code="result_job_id_mismatch",
                detail="Signed ResultV1.job_id does not match URL job_id.",
            )

        mtls_worker = await self.authenticate_mtls_worker(
            request,
            expected_worker_id=result.worker_id,
            now=ref_now,
        )

        result_digest = sha256_canonical_json(result.model_dump(mode="json"))
        ws_id, lease_snapshot = await self._load_sandbox_lease_context(
            job_id,
            lease_epoch=result.lease_epoch,
        )

        # SEC-030: Check duplicate / conflicting result replay BEFORE stale lease rejection!
        if lease_snapshot is not None and lease_snapshot.status in ("completed", "quarantined"):
            if lease_snapshot.result_digest is not None and hmac.compare_digest(
                lease_snapshot.result_digest, result_digest
            ):
                return WorkerJobResultReceipt(
                    job_id=job_id,
                    lease_epoch=result.lease_epoch,
                    accepted=True,
                    idempotent_replay=True,
                    worker_quarantined=mtls_worker.status == "quarantined",
                )

            await self._quarantine_worker_internal(
                worker_id=mtls_worker.id,
                reason_code="conflicting_duplicate_result",
                detail=f"Conflicting duplicate ResultV1 submitted for job {job_id}.",
                correlation_id=correlation_id or job_id,
                ref_now=ref_now,
            )
            raise ConflictError(
                code="conflicting_duplicate_result",
                detail=(
                    "Conflicting duplicate ResultV1 detected for completed lease; "
                    "worker has been quarantined (SEC-030)."
                ),
            )

        # Verify Ed25519 signature against enrolled non-revoked worker-supervisor key (SEC-030):
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            sk_row = await db.scalar(
                select(SigningKeyModel).where(
                    SigningKeyModel.key_id == result.signer_key_id,
                    SigningKeyModel.worker_id == mtls_worker.id,
                    SigningKeyModel.purpose == "worker_result",
                )
            )
        if sk_row is None:
            await self._quarantine_worker_internal(
                worker_id=mtls_worker.id,
                reason_code="unknown_result_signer",
                detail=f"Unknown or cross-worker key_id {result.signer_key_id!r}.",
                correlation_id=correlation_id or job_id,
                ref_now=ref_now,
            )
            raise ForbiddenError(
                code="invalid_result_signature",
                detail=("ResultV1 signer_key_id is unknown or not bound to this worker (SEC-030)."),
            )

        expected_td = (
            lease_snapshot.expected_worker_trust_domain
            if lease_snapshot is not None
            else mtls_worker.trust_domain
        )
        keyring = KeyRing(
            [
                PublicKeyRecord(
                    key_id=sk_row.key_id,
                    algorithm="ed25519",
                    public_key_b64=sk_row.public_key_b64,
                    not_before=sk_row.not_before,
                    revoked_at=sk_row.revoked_at,
                    trust_domain=sk_row.trust_domain,
                )
            ]
        )
        try:
            verify_model_ed25519(
                result,
                keyring=keyring,
                domain=DOMAIN_RESULT_V1,
                signed_at=max(result.ended_at, ref_now),
                expected_trust_domain=expected_td,
            )
        except CryptoVerificationError as exc:
            await self._quarantine_worker_internal(
                worker_id=mtls_worker.id,
                reason_code="invalid_result_signature",
                detail=str(exc),
                correlation_id=correlation_id or job_id,
                ref_now=ref_now,
            )
            raise ForbiddenError(
                code="invalid_result_signature",
                detail=f"ResultV1 Ed25519 signature verification failed (SEC-030): {exc}",
            ) from exc

        if lease_snapshot is None or lease_snapshot.worker_id != mtls_worker.id:
            await self._queue.complete_lease(
                job_id=job_id,
                worker_id=mtls_worker.id,
                lease_epoch=result.lease_epoch,
                now=ref_now,
            )
            raise ConflictError(code="stale_job_lease", detail="Stale sandbox lease epoch.")

        if not hmac.compare_digest(lease_snapshot.capability_nonce, result.capability_nonce):
            raise ForbiddenError(
                code="invalid_capability_nonce",
                detail="ResultV1 capability_nonce does not match leased SandboxJobV1.",
            )

        # SEC-030: Verify every referenced artifact was actually uploaded & verified in THIS lease!
        uploaded_by_id: dict[str, dict[str, Any]] = {
            str(item["id"]): dict(item) for item in (lease_snapshot.uploaded_artifacts_json or [])
        }
        for ref in result.artifact_refs:
            rec = uploaded_by_id.get(ref.id)
            if (
                rec is None
                or rec.get("digest") != ref.digest
                or int(rec.get("size", -1)) != ref.size
            ):
                await self._quarantine_worker_internal(
                    worker_id=mtls_worker.id,
                    reason_code="substituted_result_artifact",
                    detail=f"Artifact ref {ref.id} failed lease provenance check.",
                    correlation_id=correlation_id or job_id,
                    ref_now=ref_now,
                )
                raise ConflictError(
                    code="unverified_result_artifact",
                    detail=(
                        f"ResultV1 artifact_ref {ref.id!r} was not uploaded or "
                        "mismatched digest under this sandbox lease (SEC-030)."
                    ),
                )

        # SEC-029 / SEC-030: Verify ephemeral_cleanup & isolation_checks!
        cleanup_checks = [c for c in result.isolation_checks if c.check_id == "ephemeral_cleanup"]
        isolation_failed = (not cleanup_checks) or any(
            not chk.passed for chk in result.isolation_checks
        )
        if isolation_failed:
            await self._queue.fail_lease(
                job_id=job_id,
                worker_id=mtls_worker.id,
                lease_epoch=result.lease_epoch,
                error_code="worker_isolation_or_cleanup_failed",
                error_detail="Worker reported failed isolation or ephemeral cleanup check.",
                now=ref_now,
                recoverable=True,
            )
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as ws_db:
                l_row = await ws_db.scalar(
                    select(SandboxLeaseModel)
                    .where(SandboxLeaseModel.id == lease_snapshot.id)
                    .with_for_update()
                )
                if l_row is not None:
                    l_row.status = "quarantined"
                    l_row.result_digest = result_digest
                    l_row.result_json = result.model_dump(mode="json")
                    l_row.cleanup_verified = False
                    l_row.ended_at = ref_now
                    l_row.version += 1
                    l_row.updated_at = ref_now

            await self._quarantine_worker_internal(
                worker_id=mtls_worker.id,
                reason_code="sandbox_cleanup_or_isolation_failed",
                detail="Worker reported failed ephemeral cleanup or isolation check.",
                correlation_id=correlation_id or job_id,
                ref_now=ref_now,
            )
            return WorkerJobResultReceipt(
                job_id=job_id,
                lease_epoch=result.lease_epoch,
                accepted=True,
                idempotent_replay=False,
                worker_quarantined=True,
            )

        completed_job = await self._queue.complete_lease(
            job_id=job_id,
            worker_id=mtls_worker.id,
            lease_epoch=result.lease_epoch,
            now=ref_now,
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as ws_db:
            l_row = await ws_db.scalar(
                select(SandboxLeaseModel)
                .where(SandboxLeaseModel.id == lease_snapshot.id)
                .with_for_update()
            )
            if l_row is not None:
                l_row.status = "completed"
                l_row.result_digest = result_digest
                l_row.result_json = result.model_dump(mode="json")
                l_row.cleanup_verified = True
                l_row.ended_at = ref_now
                l_row.version += 1
                l_row.updated_at = ref_now
                await append_audit_entry(
                    ws_db,
                    workspace_id=ws_id,
                    repository_id=l_row.repository_id,
                    actor_type="service",
                    actor_id=f"worker:{mtls_worker.id}",
                    action="sandbox_lease.result_verified",
                    target=f"sandbox_lease:{l_row.id}",
                    decision="allow",
                    reason_code="ed25519_result_verified",
                    correlation_id=correlation_id or (completed_job.correlation_id or job_id),
                    metadata={
                        "job_id": job_id,
                        "lease_epoch": result.lease_epoch,
                        "signer_key_id": result.signer_key_id,
                        "passed_cleanly": result.passed_cleanly(),
                        "artifact_count": len(result.artifact_refs),
                    },
                    occurred_at=ref_now,
                )

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            w_row = await db.scalar(
                select(WorkerModel).where(WorkerModel.id == mtls_worker.id).with_for_update()
            )
            quarantined_now = False
            if w_row is not None:
                w_row.heartbeat_at = ref_now
                w_row.updated_at = ref_now
                quarantined_now = w_row.status == "quarantined"

        return WorkerJobResultReceipt(
            job_id=job_id,
            lease_epoch=result.lease_epoch,
            accepted=True,
            idempotent_replay=False,
            worker_quarantined=quarantined_now,
        )

    async def acknowledge_sandbox_cancel(
        self,
        request: Request,
        *,
        job_id: str,
        payload: WorkerCancelAckRequest,
        correlation_id: str = "",
        now: datetime | None = None,
    ) -> WorkerCancelAckResponse:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        mtls_worker = await self.authenticate_mtls_worker(request, now=ref_now)
        ws_id, lease_snapshot = await self._load_sandbox_lease_context(
            job_id,
            lease_epoch=payload.lease_epoch,
        )
        if lease_snapshot is not None and not hmac.compare_digest(
            lease_snapshot.capability_nonce,
            payload.capability_nonce,
        ):
            raise ForbiddenError(
                code="invalid_capability_nonce",
                detail="Cancel acknowledgement capability_nonce mismatch.",
            )

        cancelled_job = await self._queue.acknowledge_cancel(
            job_id=job_id,
            worker_id=mtls_worker.id,
            lease_epoch=payload.lease_epoch,
            now=ref_now,
        )

        cleanup_ok = (
            payload.cleanup_verified
            and payload.container_killed
            and all(chk.passed for chk in payload.isolation_checks)
        )
        if lease_snapshot is not None:
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as ws_db:
                l_row = await ws_db.scalar(
                    select(SandboxLeaseModel)
                    .where(SandboxLeaseModel.id == lease_snapshot.id)
                    .with_for_update()
                )
                if l_row is not None:
                    l_row.status = "cancelled" if cleanup_ok else "quarantined"
                    l_row.cleanup_verified = cleanup_ok
                    l_row.ended_at = payload.ended_at
                    l_row.version += 1
                    l_row.updated_at = ref_now

        if not cleanup_ok:
            await self._quarantine_worker_internal(
                worker_id=mtls_worker.id,
                reason_code="cancel_cleanup_failed",
                detail="Worker failed container teardown or cleanup after cancellation.",
                correlation_id=correlation_id or (cancelled_job.correlation_id or job_id),
                ref_now=ref_now,
            )

        return WorkerCancelAckResponse(
            job_id=cancelled_job.id,
            lease_epoch=payload.lease_epoch,
            state=cancelled_job.state,
            worker_quarantined=not cleanup_ok,
        )


__all__ = [
    "DEFAULT_WORKER_CERT_VALID_HOURS",
    "DEFAULT_WORKER_STALE_TIMEOUT",
    "MAX_SANDBOX_UPLOAD_BYTES",
    "MAX_SANDBOX_UPLOAD_WIRE_BYTES",
    "SANDBOX_TASK_KIND",
    "MtlsH11Protocol",
    "ResultArtifactRef",
    "ServerTlsMaterial",
    "WorkerBrokerService",
    "WorkerCertificateAuthority",
]
