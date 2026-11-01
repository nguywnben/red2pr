"""Deterministic runtime attestation verification for hostile-workload scheduling.

The report digest binds the runtime identity and probe results. It is not a host
signature: enrollment still binds the report to the worker's authenticated
identity, and certification is deliberately separate from a successful probe.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from py_contracts.worker import runtime_attestation_digest

RuntimeBackend = Literal["gvisor_runsc", "ephemeral_vm", "oci_rootless"]
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_CHECKS: dict[RuntimeBackend, frozenset[str]] = {
    "gvisor_runsc": frozenset(
        {
            "runtime_present",
            "guest_network_none",
            "seccomp_verified",
            "no_new_privileges",
            "host_control_plane_unreachable",
        }
    ),
    "ephemeral_vm": frozenset(
        {
            "runtime_present",
            "guest_network_none",
            "seccomp_verified",
            "no_new_privileges",
            "host_control_plane_unreachable",
        }
    ),
    "oci_rootless": frozenset(
        {"rootless", "guest_network_none", "seccomp_verified", "no_new_privileges"}
    ),
}
_HARDENED_BACKENDS = frozenset({"gvisor_runsc", "ephemeral_vm"})


@dataclass(frozen=True, slots=True)
class RuntimeAttestationReport:
    backend: RuntimeBackend
    kernel_version: str
    runtime_version: str
    checks: Mapping[str, bool]
    self_test_digest: str


@dataclass(frozen=True, slots=True)
class RuntimeAttestationVerdict:
    verified: bool
    multi_tenant_hardened: bool
    reason: str | None = None


def build_runtime_attestation(
    *,
    backend: RuntimeBackend,
    kernel_version: str,
    runtime_version: str,
    checks: Mapping[str, bool],
) -> RuntimeAttestationReport:
    """Build a report with a stable digest; malformed values remain unverifiable."""
    normalized = dict(checks)
    digest = runtime_attestation_digest(
        backend=backend,
        kernel_version=kernel_version,
        runtime_version=runtime_version,
        checks=normalized,
    )
    return RuntimeAttestationReport(
        backend=backend,
        kernel_version=kernel_version,
        runtime_version=runtime_version,
        checks=normalized,
        self_test_digest=digest,
    )


def verify_runtime_attestation(report: RuntimeAttestationReport) -> RuntimeAttestationVerdict:
    """Verify digest, schema and required isolation checks, failing closed."""
    if report.backend not in _REQUIRED_CHECKS:
        return RuntimeAttestationVerdict(False, False, "unsupported_backend")
    if not report.kernel_version.strip() or not report.runtime_version.strip():
        return RuntimeAttestationVerdict(False, False, "runtime_identity_missing")
    if not _DIGEST_RE.fullmatch(report.self_test_digest):
        return RuntimeAttestationVerdict(False, False, "invalid_digest")
    if any(not isinstance(value, bool) for value in report.checks.values()):
        return RuntimeAttestationVerdict(False, False, "invalid_check_value")
    expected = runtime_attestation_digest(
        backend=report.backend,
        kernel_version=report.kernel_version,
        runtime_version=report.runtime_version,
        checks=dict(report.checks),
    )
    if not hmac.compare_digest(expected, report.self_test_digest):
        return RuntimeAttestationVerdict(False, False, "digest_mismatch")
    required = _REQUIRED_CHECKS[report.backend]
    if not required.issubset(report.checks):
        return RuntimeAttestationVerdict(False, False, "required_check_missing")
    if not all(report.checks[name] for name in required):
        return RuntimeAttestationVerdict(False, False, "required_check_failed")
    hardened = report.backend in _HARDENED_BACKENDS
    return RuntimeAttestationVerdict(True, hardened, None)


def worker_can_accept_hostile_job(
    *,
    worker_trust_domain: str,
    required_trust_domain: str,
    report: RuntimeAttestationReport,
) -> bool:
    """Permit hostile work only for exact domain matches and verified hardening."""
    if not worker_trust_domain or worker_trust_domain != required_trust_domain:
        return False
    verdict = verify_runtime_attestation(report)
    return verdict.verified and verdict.multi_tenant_hardened
