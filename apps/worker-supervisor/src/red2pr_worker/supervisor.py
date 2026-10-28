"""Standalone Z3 Worker Supervisor loop (`SAN-01`, `S-21`, `W-04`, `W-08`, `NFR-02`).

Coordinates fail-closed preflight, mTLS job polling, safe archive extraction,
15s lease heartbeats with cooperative cancellation & 409 stale-fence abort,
write-only artifact uploads (`<=100 MiB`), verified ephemeral cleanup, and
external Ed25519 `ResultV1` signing (`ADR-035`, `SEC-021`, `SEC-029`, `SEC-030`).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import httpx

from py_contracts.crypto import sha256_canonical_json
from py_contracts.worker import (
    ResultArtifactRef,
    ResultTermination,
    ResultV1,
    SandboxJobV1,
    WorkerArtifactUploadRequest,
    WorkerArtifactUploadResponse,
    WorkerCancelAckRequest,
    WorkerCancelAckResponse,
    WorkerIsolationAttestation,
    WorkerJobHeartbeatRequest,
    WorkerJobHeartbeatResponse,
    WorkerJobResultReceipt,
    WorkerPollRequest,
    WorkerPollResponse,
)
from red2pr_worker.cleanup import (
    CleanupVerificationResult,
    EphemeralWorkspaceCleaner,
    UnsafeSourceArchiveError,
    safe_extract_source_archive,
)
from red2pr_worker.enroll import (
    MtlsWorkerCredentials,
    WorkerEnrollmentError,
    validate_attestation_fail_closed,
)
from red2pr_worker.oci_runner import (
    REVIEWED_PROFILE_COMMANDS,
    SandboxIsolationUnavailableError,
    SandboxRuntimeDriver,
    build_hardened_oci_invocation,
    write_seccomp_profile,
)
from red2pr_worker.signer import ExternalResultSigner

DEFAULT_SUPERVISOR_HEARTBEAT_SECONDS = 15.0

CycleDisposition = Literal[
    "completed",
    "cancelled",
    "aborted_stale_lease",
    "quarantined",
]


@dataclass(frozen=True, slots=True)
class SupervisorCycleOutcome:
    """Deterministic summary of a single polled & executed `SandboxJobV1` cycle."""

    job_id: str
    lease_epoch: int
    disposition: CycleDisposition
    result: ResultV1 | None
    receipt: WorkerJobResultReceipt | None
    cleanup: CleanupVerificationResult


class WorkerSupervisor:
    """Isolated `Z3` worker supervisor process with zero control-plane imports."""

    def __init__(
        self,
        *,
        credentials: MtlsWorkerCredentials,
        signer: ExternalResultSigner,
        driver: SandboxRuntimeDriver,
        scratch_dir: Path,
        state_dir: Path,
        supported_profiles: Sequence[str] | None = None,
        heartbeat_interval_seconds: float = DEFAULT_SUPERVISOR_HEARTBEAT_SECONDS,
        allow_trusted_local_mode: bool = False,
    ) -> None:
        if heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat_interval_seconds must be > 0")
        self._credentials = credentials
        self._signer = signer
        self._driver = driver
        self._cleaner = EphemeralWorkspaceCleaner(scratch_dir)
        self._signer.assert_outside_guest_workspace(self._cleaner.base_dir)
        self._seccomp_path = write_seccomp_profile(state_dir)
        self._supported_profiles = tuple(
            supported_profiles
            if supported_profiles is not None
            else sorted(REVIEWED_PROFILE_COMMANDS.keys())
        )
        self._heartbeat_interval = heartbeat_interval_seconds
        self._allow_trusted_local = allow_trusted_local_mode
        self._quarantined = False

    @property
    def worker_id(self) -> str:
        return self._credentials.worker_id

    @property
    def is_quarantined(self) -> bool:
        return self._quarantined

    async def preflight(self) -> WorkerIsolationAttestation:
        """Verify isolated OCI/VM posture fail-closed before accepting any work (`SAN-01`)."""
        if self._quarantined:
            raise SandboxIsolationUnavailableError(
                "Worker supervisor is quarantined and cannot accept new sandbox jobs."
            )
        attestation = await self._driver.probe_isolation()
        try:
            validate_attestation_fail_closed(attestation)
        except WorkerEnrollmentError as exc:
            raise SandboxIsolationUnavailableError(str(exc)) from exc

        if attestation.isolation_mode == "oci_trusted_local" and not self._allow_trusted_local:
            raise SandboxIsolationUnavailableError(
                "Worker is in oci_trusted_local mode without local operator acknowledgement."
            )
        self._signer.assert_outside_guest_workspace(self._cleaner.base_dir)
        return attestation

    async def _upload_slot_bytes(
        self,
        client: httpx.AsyncClient,
        *,
        job: SandboxJobV1,
        slot_name: str,
        mime: str,
        payload: bytes,
    ) -> ResultArtifactRef:
        digest = hashlib.sha256(payload).hexdigest()
        req = WorkerArtifactUploadRequest(
            lease_epoch=job.lease_epoch,
            capability_nonce=job.capability_nonce,
            slot_name=slot_name,
            mime=mime,
            content_b64=base64.b64encode(payload).decode("ascii"),
            digest=digest,
        )
        resp = await client.post(
            f"/internal/v1/jobs/{job.job_id}/upload",
            json=req.model_dump(mode="json"),
            headers={"X-Upload-Capability": job.artifact_upload_capability},
        )
        if resp.status_code == 409:
            raise _StaleLeaseAbortError(resp.text[:240])
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Artifact upload failed for slot {slot_name!r} (HTTP {resp.status_code}): "
                f"{resp.text[:240]}"
            )
        parsed = WorkerArtifactUploadResponse.model_validate(resp.json())
        return parsed.artifact_ref

    async def poll_and_execute_once(
        self,
        client: httpx.AsyncClient,
        *,
        source_fetcher: Callable[[SandboxJobV1], Awaitable[bytes | None]] | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> SupervisorCycleOutcome | None:
        """Poll one leased `SandboxJobV1`, execute in isolated guest, clean up, and sign result."""
        clock = now_fn or (lambda: datetime.now(tz=UTC))
        await self.preflight()

        poll_req = WorkerPollRequest(
            status_hint="ready",
            capabilities={
                "network_none": True,
                "seccomp": True,
                "external_ed25519_signer": True,
            },
        )
        poll_http = await client.post(
            f"/internal/v1/workers/{self.worker_id}/poll",
            json=poll_req.model_dump(mode="json"),
        )
        if poll_http.status_code == 403:
            if "quarantine" in poll_http.text.lower():
                self._quarantined = True
            raise SandboxIsolationUnavailableError(
                f"Control plane denied worker poll (HTTP 403): {poll_http.text[:240]}"
            )
        if poll_http.status_code != 200:
            raise RuntimeError(
                f"Worker poll failed (HTTP {poll_http.status_code}): {poll_http.text[:240]}"
            )

        poll_resp = WorkerPollResponse.model_validate(poll_http.json())
        if poll_resp.worker_status == "quarantined":
            self._quarantined = True
            return None
        if poll_resp.sandbox_job is None:
            return None

        job = poll_resp.sandbox_job
        dirs = self._cleaner.prepare_job_directories(job.job_id)

        cancel_event = asyncio.Event()
        stale_fence_detected = False
        cancel_requested = False
        stop_heartbeat = asyncio.Event()

        async def _heartbeat_loop() -> None:
            nonlocal stale_fence_detected, cancel_requested
            first_tick = True
            while not stop_heartbeat.is_set():
                if not first_tick:
                    try:
                        await asyncio.wait_for(
                            stop_heartbeat.wait(),
                            timeout=self._heartbeat_interval,
                        )
                        break
                    except TimeoutError:
                        pass
                first_tick = False

                hb_req = WorkerJobHeartbeatRequest(
                    lease_epoch=job.lease_epoch,
                    capability_nonce=job.capability_nonce,
                )
                hb_http = await client.post(
                    f"/internal/v1/jobs/{job.job_id}/heartbeat",
                    json=hb_req.model_dump(mode="json"),
                )
                if hb_http.status_code == 409:
                    stale_fence_detected = True
                    cancel_event.set()
                    return
                if hb_http.status_code == 200:
                    hb_body = WorkerJobHeartbeatResponse.model_validate(hb_http.json())
                    if hb_body.cancel_requested:
                        cancel_requested = True
                        cancel_event.set()
                        return

        try:
            archive_bytes: bytes | None = None
            if poll_resp.source_archive_b64:
                archive_bytes = base64.b64decode(poll_resp.source_archive_b64.encode("ascii"))
            elif source_fetcher is not None:
                archive_bytes = await source_fetcher(job)

            if archive_bytes is not None:
                actual_archive_digest = hashlib.sha256(archive_bytes).hexdigest()
                if not hmac.compare_digest(actual_archive_digest, job.source_archive_digest):
                    raise UnsafeSourceArchiveError(
                        "Source archive SHA-256 digest does not match SandboxJobV1."
                    )
                safe_extract_source_archive(
                    archive_bytes,
                    worktree_dir=dirs.worktree_dir,
                )

            invocation = build_hardened_oci_invocation(
                job,
                dirs=dirs,
                seccomp_profile_path=self._seccomp_path,
                isolation_mode=self._driver.isolation_mode,
            )

            started_at = clock().astimezone(UTC)
            hb_task = asyncio.create_task(_heartbeat_loop())
            try:
                exec_res = await self._driver.execute_job(
                    job,
                    invocation=invocation,
                    dirs=dirs,
                    cancel_event=cancel_event,
                )
            finally:
                stop_heartbeat.set()
                await hb_task

            if stale_fence_detected:
                cleanup_res = await self._cleaner.teardown_and_verify(
                    dirs,
                    kill_runtime=lambda: self._driver.force_kill_job(job.job_id),
                )
                if not cleanup_res.passed:
                    self._quarantined = True
                return SupervisorCycleOutcome(
                    job_id=job.job_id,
                    lease_epoch=job.lease_epoch,
                    disposition="aborted_stale_lease",
                    result=None,
                    receipt=None,
                    cleanup=cleanup_res,
                )

            if cancel_requested or exec_res.cancelled:
                cleanup_res = await self._cleaner.teardown_and_verify(
                    dirs,
                    kill_runtime=lambda: self._driver.force_kill_job(job.job_id),
                )
                if not cleanup_res.passed:
                    self._quarantined = True
                ack_req = WorkerCancelAckRequest(
                    lease_epoch=job.lease_epoch,
                    capability_nonce=job.capability_nonce,
                    ended_at=clock().astimezone(UTC),
                    container_killed=True,
                    cleanup_verified=cleanup_res.passed,
                    isolation_checks=[cleanup_res.to_isolation_check()],
                )
                ack_http = await client.post(
                    f"/internal/v1/jobs/{job.job_id}/cancel-ack",
                    json=ack_req.model_dump(mode="json"),
                )
                if ack_http.status_code == 200:
                    ack_resp = WorkerCancelAckResponse.model_validate(ack_http.json())
                    if ack_resp.worker_quarantined:
                        self._quarantined = True
                return SupervisorCycleOutcome(
                    job_id=job.job_id,
                    lease_epoch=job.lease_epoch,
                    disposition="cancelled",
                    result=None,
                    receipt=None,
                    cleanup=cleanup_res,
                )

            artifact_refs: list[ResultArtifactRef] = []
            max_out_bytes = job.resource_limits.output_bytes
            emitted_so_far = 0

            try:
                slot_candidates: list[tuple[str, str, bytes]] = []
                if exec_res.stdout_bytes:
                    slot_candidates.append(("stdout", "text/plain", exec_res.stdout_bytes))
                if exec_res.stderr_bytes:
                    slot_candidates.append(("stderr", "text/plain", exec_res.stderr_bytes))
                for slot_name, file_bytes in exec_res.output_files.items():
                    if file_bytes:
                        mime = (
                            "application/json"
                            if slot_name.endswith("json")
                            else "text/xml"
                            if slot_name.endswith("xml")
                            else "application/octet-stream"
                        )
                        slot_candidates.append((slot_name, mime, file_bytes))

                for slot_name, mime, raw_bytes in slot_candidates:
                    remaining = max_out_bytes - emitted_so_far
                    if remaining <= 0:
                        break
                    capped = raw_bytes[:remaining]
                    if not capped:
                        continue
                    ref = await self._upload_slot_bytes(
                        client,
                        job=job,
                        slot_name=slot_name,
                        mime=mime,
                        payload=capped,
                    )
                    artifact_refs.append(ref)
                    emitted_so_far += len(capped)
            except _StaleLeaseAbortError:
                cleanup_res = await self._cleaner.teardown_and_verify(
                    dirs,
                    kill_runtime=lambda: self._driver.force_kill_job(job.job_id),
                )
                if not cleanup_res.passed:
                    self._quarantined = True
                return SupervisorCycleOutcome(
                    job_id=job.job_id,
                    lease_epoch=job.lease_epoch,
                    disposition="aborted_stale_lease",
                    result=None,
                    receipt=None,
                    cleanup=cleanup_res,
                )

            # Destroy ephemeral scratch & container BEFORE signing ResultV1 so cleanup proof
            # is cryptographically sealed inside ResultV1.isolation_checks (SEC-029/SEC-030).
            cleanup_res = await self._cleaner.teardown_and_verify(
                dirs,
                kill_runtime=lambda: self._driver.force_kill_job(job.job_id),
            )
            all_checks = [*exec_res.isolation_checks, cleanup_res.to_isolation_check()]

            termination: ResultTermination
            if exec_res.infrastructure_error:
                termination = "infrastructure_error"
            elif exec_res.timed_out:
                termination = "timeout"
            elif exec_res.oom_killed:
                termination = "oom"
            else:
                termination = "exited"

            ended_at = max(started_at, clock().astimezone(UTC))
            cmd_digest = sha256_canonical_json(list(invocation.resolved_commands))
            env_digest = sha256_canonical_json(dict(invocation.guest_env))

            unsigned_result = ResultV1(
                job_id=job.job_id,
                lease_epoch=job.lease_epoch,
                capability_nonce=job.capability_nonce,
                worker_id=self.worker_id,
                started_at=started_at,
                ended_at=ended_at,
                exit_code=exec_res.exit_code,
                termination=termination,
                command_digest=cmd_digest,
                image_digest=job.image_digest,
                environment_digest=env_digest,
                source_digest=job.source_archive_digest,
                patch_digest=job.patch_digest,
                resource_usage=exec_res.resource_usage,
                artifact_refs=artifact_refs,
                isolation_checks=all_checks,
                signer_key_id=self._signer.key_id,
                signature="ed25519:unsigned-placeholder",
            )
            signed_result = self._signer.sign_result(
                unsigned_result,
                guest_workspace_root=self._cleaner.base_dir,
            )

            res_http = await client.post(
                f"/internal/v1/jobs/{job.job_id}/result",
                json=signed_result.model_dump(mode="json"),
            )
            if res_http.status_code == 409 and "stale_job_lease" in res_http.text:
                if not cleanup_res.passed:
                    self._quarantined = True
                return SupervisorCycleOutcome(
                    job_id=job.job_id,
                    lease_epoch=job.lease_epoch,
                    disposition="aborted_stale_lease",
                    result=signed_result,
                    receipt=None,
                    cleanup=cleanup_res,
                )
            if res_http.status_code != 200:
                if not cleanup_res.passed:
                    self._quarantined = True
                raise RuntimeError(
                    f"Result submission rejected (HTTP {res_http.status_code}): "
                    f"{res_http.text[:240]}"
                )

            receipt = WorkerJobResultReceipt.model_validate(res_http.json())
            if not cleanup_res.passed or receipt.worker_quarantined:
                self._quarantined = True
                return SupervisorCycleOutcome(
                    job_id=job.job_id,
                    lease_epoch=job.lease_epoch,
                    disposition="quarantined",
                    result=signed_result,
                    receipt=receipt,
                    cleanup=cleanup_res,
                )

            return SupervisorCycleOutcome(
                job_id=job.job_id,
                lease_epoch=job.lease_epoch,
                disposition="completed",
                result=signed_result,
                receipt=receipt,
                cleanup=cleanup_res,
            )
        finally:
            if dirs.root_dir.exists() or dirs.root_dir.is_symlink():
                residual_check = await self._cleaner.teardown_and_verify(
                    dirs,
                    kill_runtime=lambda: self._driver.force_kill_job(job.job_id),
                )
                if not residual_check.passed:
                    self._quarantined = True


class _StaleLeaseAbortError(RuntimeError):
    """Internal marker raised when upload hits a 409 stale lease fence."""
