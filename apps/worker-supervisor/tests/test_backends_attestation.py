from __future__ import annotations

from dataclasses import replace

import pytest

from red2pr_worker.backends.attestation import (
    RuntimeAttestationReport,
    build_runtime_attestation,
    verify_runtime_attestation,
    worker_can_accept_hostile_job,
)


@pytest.mark.parametrize("backend", ["gvisor_runsc", "ephemeral_vm"])
def test_verified_isolation_backend_can_serve_its_exact_trust_domain(backend: str) -> None:
    report = build_runtime_attestation(
        backend=backend,
        kernel_version="6.8.0-test",
        runtime_version="1.2.3",
        checks={
            "runtime_present": True,
            "guest_network_none": True,
            "seccomp_verified": True,
            "no_new_privileges": True,
            "host_control_plane_unreachable": True,
        },
    )

    assert verify_runtime_attestation(report).verified is True
    assert verify_runtime_attestation(report).multi_tenant_hardened is True
    assert worker_can_accept_hostile_job(
        worker_trust_domain="ws-42",
        required_trust_domain="ws-42",
        report=report,
    )


def test_standard_shared_kernel_oci_never_claims_hardened_or_accepts_hostile_job() -> None:
    report = build_runtime_attestation(
        backend="oci_rootless",
        kernel_version="6.8.0-test",
        runtime_version="5.0.0",
        checks={
            "rootless": True,
            "guest_network_none": True,
            "seccomp_verified": True,
            "no_new_privileges": True,
        },
    )

    verdict = verify_runtime_attestation(report)
    assert verdict.verified is True
    assert verdict.multi_tenant_hardened is False
    assert not worker_can_accept_hostile_job(
        worker_trust_domain="ws-42",
        required_trust_domain="ws-42",
        report=report,
    )


def test_runtime_attestation_rejects_tampered_digest_or_failed_isolation_check() -> None:
    good = build_runtime_attestation(
        backend="gvisor_runsc",
        kernel_version="6.8.0-test",
        runtime_version="1.2.3",
        checks={"runtime_present": True, "guest_network_none": True},
    )
    tampered = replace(good, runtime_version="9.9.9")
    failed = build_runtime_attestation(
        backend="ephemeral_vm",
        kernel_version="6.8.0-test",
        runtime_version="1.2.3",
        checks={
            "runtime_present": True,
            "guest_network_none": False,
            "seccomp_verified": True,
            "no_new_privileges": True,
            "host_control_plane_unreachable": True,
        },
    )

    assert verify_runtime_attestation(tampered).reason == "digest_mismatch"
    assert verify_runtime_attestation(failed).reason == "required_check_failed"


def test_trust_domain_mismatch_and_invalid_digest_fail_closed() -> None:
    report = build_runtime_attestation(
        backend="ephemeral_vm",
        kernel_version="6.8.0-test",
        runtime_version="1.2.3",
        checks={"runtime_present": True, "guest_network_none": True},
    )
    malformed = RuntimeAttestationReport(
        backend=report.backend,
        kernel_version=report.kernel_version,
        runtime_version=report.runtime_version,
        checks=report.checks,
        self_test_digest="0" * 64,
    )

    assert not worker_can_accept_hostile_job(
        worker_trust_domain="ws-a", required_trust_domain="ws-b", report=report
    )
    assert verify_runtime_attestation(malformed).verified is False


def test_hardened_runtime_attestation_requires_every_security_signal() -> None:
    report = build_runtime_attestation(
        backend="gvisor_runsc",
        kernel_version="6.8.0-test",
        runtime_version="runsc 1.2.3",
        checks={
            "runtime_present": True,
            "guest_network_none": True,
            "seccomp_verified": True,
            "no_new_privileges": True,
            "host_control_plane_unreachable": True,
            "unknown_extra_check": True,
        },
    )
    assert verify_runtime_attestation(report).multi_tenant_hardened is True
    missing = build_runtime_attestation(
        backend="ephemeral_vm",
        kernel_version="6.8.0-test",
        runtime_version="firecracker 1.2.3",
        checks={"runtime_present": True, "guest_network_none": True},
    )
    assert verify_runtime_attestation(missing).reason == "required_check_missing"
