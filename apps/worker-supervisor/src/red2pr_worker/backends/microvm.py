"""Ephemeral VM hypervisor discovery and attestation helpers (`SAN-04`)."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

from red2pr_worker.backends.attestation import RuntimeAttestationReport, build_runtime_attestation


class EphemeralVmBackend:
    """Probe a disposable VM runtime; KVM and caller-provided guest checks are mandatory."""

    def __init__(self, *, binary: str = "firecracker", kvm_path: Path = Path("/dev/kvm")) -> None:
        self._binary = binary
        self._kvm_path = kvm_path

    async def probe(
        self,
        *,
        kernel_version: str,
        checks: Mapping[str, bool],
    ) -> RuntimeAttestationReport:
        resolved = shutil.which(self._binary)
        version = "unavailable"
        runtime_present = resolved is not None and self._kvm_path.exists()
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
                runtime_present = runtime_present and proc.returncode == 0
                version = (proc.stdout or proc.stderr).strip().splitlines()[0][:120]
            except (OSError, subprocess.SubprocessError, IndexError):
                runtime_present = False
        report_checks = dict(checks)
        report_checks["runtime_present"] = runtime_present
        return build_runtime_attestation(
            backend="ephemeral_vm",
            kernel_version=kernel_version,
            runtime_version=version,
            checks=report_checks,
        )
