"""gVisor `runsc` availability and attestation helpers (`SAN-04`)."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from py_contracts.worker import SandboxJobV1, WorkerIsolationAttestation
from red2pr_worker.backends.attestation import RuntimeAttestationReport, build_runtime_attestation
from red2pr_worker.cleanup import JobSandboxDirectories
from red2pr_worker.oci_runner import (
    GuestExecutionResult,
    HardenedOciInvocation,
    RootlessOciCliDriver,
    SandboxIsolationUnavailableError,
)


class GvisorRuntimeBackend:
    """Probe a configured gVisor runtime without treating presence as isolation proof."""

    def __init__(self, *, binary: str = "runsc") -> None:
        self._binary = binary

    async def probe(
        self,
        *,
        kernel_version: str,
        checks: Mapping[str, bool],
    ) -> RuntimeAttestationReport:
        resolved = shutil.which(self._binary)
        version = "unavailable"
        runtime_present = resolved is not None
        if resolved is not None:
            try:
                proc = await asyncio.to_thread(
                    subprocess.run,
                    [resolved, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                runtime_present = proc.returncode == 0
                version = (proc.stdout or proc.stderr).strip().splitlines()[0][:120]
            except (OSError, subprocess.SubprocessError, IndexError):
                runtime_present = False
        report_checks = dict(checks)
        report_checks["runtime_present"] = runtime_present
        return build_runtime_attestation(
            backend="gvisor_runsc",
            kernel_version=kernel_version,
            runtime_version=version,
            checks=report_checks,
        )


class GvisorSandboxDriver(RootlessOciCliDriver):
    """Rootless OCI execution explicitly pinned to gVisor `runsc`."""

    def __init__(self, *, gvisor_runtime: str = "runsc", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._gvisor_runtime = gvisor_runtime

    async def probe_isolation(self) -> WorkerIsolationAttestation:
        base = await super().probe_isolation()
        resolved = shutil.which(self._gvisor_runtime)
        runtime_version = "unavailable"
        present = resolved is not None
        if resolved is not None:
            try:
                proc = await asyncio.to_thread(
                    subprocess.run,
                    [resolved, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                present = proc.returncode == 0
                runtime_version = (proc.stdout or proc.stderr).strip().splitlines()[0][:120]
            except (OSError, subprocess.SubprocessError, IndexError):
                present = False
        checks = {
            "runtime_present": present,
            "guest_network_none": base.network_none_supported,
            "seccomp_verified": base.seccomp_verified,
            "no_new_privileges": base.no_new_privileges_verified,
        }
        report = build_runtime_attestation(
            backend="gvisor_runsc",
            kernel_version="unknown",
            runtime_version=runtime_version,
            checks=checks,
        )
        return base.model_copy(
            update={
                "runtime_name": self._gvisor_runtime,
                "runtime_backend": "gvisor_runsc",
                "kernel_version": "unknown",
                "runtime_version": runtime_version,
                "runtime_checks": checks,
                "isolation_self_test_digest": report.self_test_digest,
            }
        )

    async def execute_job(
        self,
        job: SandboxJobV1,
        *,
        invocation: HardenedOciInvocation,
        dirs: JobSandboxDirectories,
        cancel_event: asyncio.Event,
    ) -> GuestExecutionResult:
        if shutil.which(self._gvisor_runtime) is None:
            raise SandboxIsolationUnavailableError("gVisor runsc runtime is unavailable.")
        args = list(invocation.cli_args)
        if len(args) < 2 or args[1] != "run":
            raise SandboxIsolationUnavailableError("Invalid OCI run invocation for gVisor.")
        args.insert(2, f"--runtime={self._gvisor_runtime}")
        return await super().execute_job(
            job,
            invocation=replace(invocation, cli_args=tuple(args)),
            dirs=dirs,
            cancel_event=cancel_event,
        )
