"""Isolated Worker Supervisor unit, confinement & adversarial security tests (`U14`).

Covers `SAN-01`, `T-SAN-01-P`, `T-SAN-01-N`, `NFR-14`, `ADR-016`, `ADR-035`,
`SEC-006`, `SEC-007`, `SEC-013`, `SEC-014`, `SEC-026`, `SEC-029`, `SEC-030`, `SEC-036`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import io
import os
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from py_contracts.crypto import DOMAIN_RESULT_V1, KeyRing, verify_model_ed25519
from py_contracts.primitives import new_uuid7
from py_contracts.worker import (
    IsolationCheckResult,
    ResultV1,
    SandboxJobV1,
    SandboxResourceLimits,
    SandboxResourceUsage,
    WorkerIsolationAttestation,
)
from red2pr_worker import (
    BLOCKED_SECCOMP_SYSCALLS,
    MAX_ALLOWED_DISK_BYTES,
    MAX_ALLOWED_OUTPUT_BYTES,
    EphemeralWorkspaceCleaner,
    ExternalResultSigner,
    GuestExecutionResult,
    HardenedOciInvocation,
    RootlessOciCliDriver,
    SandboxIsolationUnavailableError,
    UnsafeSourceArchiveError,
    VmSandboxDriver,
    WorkerEnrollmentError,
    build_default_seccomp_profile,
    build_hardened_oci_invocation,
    build_sanitized_guest_env,
    resolve_reviewed_commands,
    safe_extract_source_archive,
    validate_attestation_fail_closed,
    validate_oci_invocation_security,
    write_seccomp_profile,
)


def _sample_job(
    *,
    profile_id: str = "python-3.12-node-22",
    command_ids: list[str] | None = None,
    pids: int = 256,
    output_bytes: int = 1_048_576,
) -> SandboxJobV1:
    now = datetime(2026, 10, 28, 10, 0, 0, tzinfo=UTC)
    return SandboxJobV1(
        job_id=new_uuid7(now=now),
        workspace_id=new_uuid7(now=now),
        repository_id=new_uuid7(now=now),
        repair_id=new_uuid7(now=now),
        lease_epoch=1,
        capability_nonce="nonce_u14_unit_01",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        base_sha="a" * 40,
        source_archive_digest="b" * 64,
        profile_id=profile_id,
        profile_revision=1,
        image_digest="c" * 64,
        command_ids=command_ids or ["pytest-unit", "ruff-check"],
        resource_limits=SandboxResourceLimits(
            cpu=2,
            memory_bytes=2_147_483_648,
            disk_bytes=10_737_418_240,
            pids=pids,
            wall_seconds=120,
            output_bytes=output_bytes,
        ),
        network_policy_digest="d" * 64,
        artifact_upload_capability="cap_test_ticket_v1",
        expected_worker_trust_domain="red2pr.internal",
        supervisor_policy_digest="e" * 64,
    )


def _make_tar_gz(
    files: dict[str, bytes],
    *,
    symlink: tuple[str, str] | None = None,
    hardlink: tuple[str, str] | None = None,
    fifo_name: str | None = None,
) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel_name, payload in files.items():
            info = tarfile.TarInfo(name=rel_name)
            info.size = len(payload)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(payload))
        if symlink is not None:
            sym = tarfile.TarInfo(name=symlink[0])
            sym.type = tarfile.SYMTYPE
            sym.linkname = symlink[1]
            tf.addfile(sym)
        if hardlink is not None:
            lnk = tarfile.TarInfo(name=hardlink[0])
            lnk.type = tarfile.LNKTYPE
            lnk.linkname = hardlink[1]
            tf.addfile(lnk)
        if fifo_name is not None:
            fifo = tarfile.TarInfo(name=fifo_name)
            fifo.type = tarfile.FIFOTYPE
            tf.addfile(fifo)
    return buf.getvalue()


def test_fail_closed_when_oci_or_vm_runtime_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`T-SAN-01-N`: Missing OCI/VM runtime fails closed (`0` host shell fallback)."""
    monkeypatch.setattr("shutil.which", lambda _bin: None)

    cleaner = EphemeralWorkspaceCleaner(tmp_path / "scratch")
    job = _sample_job()
    dirs = cleaner.prepare_job_directories(job.job_id)
    seccomp_path = write_seccomp_profile(tmp_path / "seccomp")
    inv = build_hardened_oci_invocation(job, dirs=dirs, seccomp_profile_path=seccomp_path)

    oci_driver = RootlessOciCliDriver(
        preferred_binary="nonexistent-red2pr-podman-binary-u14",
        isolation_mode="oci_rootless",
    )
    oci_att = asyncio.run(oci_driver.probe_isolation())
    assert oci_att.network_none_supported is False
    with pytest.raises(WorkerEnrollmentError):
        validate_attestation_fail_closed(oci_att)

    with pytest.raises(SandboxIsolationUnavailableError, match="refusing host-shell execution"):
        asyncio.run(
            oci_driver.execute_job(
                job,
                invocation=inv,
                dirs=dirs,
                cancel_event=asyncio.Event(),
            )
        )

    vm_driver = VmSandboxDriver(
        hypervisor_binary="nonexistent-red2pr-firecracker-binary-u14",
    )
    vm_att = asyncio.run(vm_driver.probe_isolation())
    assert vm_att.rootless_verified is False
    with pytest.raises(WorkerEnrollmentError):
        validate_attestation_fail_closed(vm_att)

    with pytest.raises(SandboxIsolationUnavailableError, match="ADR-016"):
        asyncio.run(
            vm_driver.execute_job(
                job,
                invocation=inv,
                dirs=dirs,
                cancel_event=asyncio.Event(),
            )
        )


def test_rootful_oci_rejected_without_adr016_risk_acknowledgement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`ADR-016` / `T-SAN-01-N`: Rootful Docker daemon is rejected for `oci_rootless` and
    requires explicit `allow_trusted_local_rootful=True` for `oci_trusted_local`."""
    monkeypatch.setattr("shutil.which", lambda _bin: "/usr/bin/docker")

    class _FakeCompleted:
        returncode = 0
        stdout = '{"host": {"security": {"rootless": false}}, "SecurityOptions": ["name=seccomp"]}'
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *a, **kw: _FakeCompleted())

    cleaner = EphemeralWorkspaceCleaner(tmp_path / "scratch")
    job = _sample_job()
    dirs = cleaner.prepare_job_directories(job.job_id)
    seccomp_path = write_seccomp_profile(tmp_path / "seccomp")
    inv = build_hardened_oci_invocation(job, dirs=dirs, seccomp_profile_path=seccomp_path)

    rootless_driver = RootlessOciCliDriver(
        preferred_binary="docker",
        isolation_mode="oci_rootless",
    )
    att_rootful = asyncio.run(rootless_driver.probe_isolation())
    assert att_rootful.rootless_verified is False
    with pytest.raises(WorkerEnrollmentError, match="rootless"):
        validate_attestation_fail_closed(att_rootful)

    with pytest.raises(SandboxIsolationUnavailableError, match="rootless"):
        asyncio.run(
            rootless_driver.execute_job(
                job,
                invocation=inv,
                dirs=dirs,
                cancel_event=asyncio.Event(),
            )
        )

    with pytest.raises(ValueError, match="ADR-016"):
        RootlessOciCliDriver(
            preferred_binary="docker",
            isolation_mode="oci_trusted_local",
            allow_trusted_local_rootful=False,
        )

    ack_local_driver = RootlessOciCliDriver(
        preferred_binary="docker",
        isolation_mode="oci_trusted_local",
        allow_trusted_local_rootful=True,
    )
    att_ack = asyncio.run(ack_local_driver.probe_isolation())
    assert att_ack.isolation_mode == "oci_trusted_local"
    validate_attestation_fail_closed(att_ack)


def test_attestation_fail_closed_rejects_missing_network_or_seccomp() -> None:
    """`SEC-014` / `SEC-006`: Worker preflight rejects disabled network=none or seccomp."""
    bad_net = WorkerIsolationAttestation(
        host_id="node-01",
        runtime_name="podman-rootless",
        isolation_mode="oci_rootless",
        rootless_verified=True,
        seccomp_verified=True,
        no_new_privileges_verified=True,
        network_none_supported=False,
        cpu_limit=4,
        memory_limit_bytes=4_000_000_000,
        disk_limit_bytes=20_000_000_000,
        pids_limit=512,
    )
    with pytest.raises(WorkerEnrollmentError, match="network=none"):
        validate_attestation_fail_closed(bad_net)


def test_hardened_oci_invocation_and_adversarial_flag_rejection(tmp_path: Path) -> None:
    """`T-SAN-01-P/N`, `SEC-006`, `SEC-014`, `NFR-14`: Verify OCI flags, seccomp, and
    deterministic rejection of socket mounts, privileged flags, PIDs > 512, and env secrets."""
    cleaner = EphemeralWorkspaceCleaner(tmp_path / "scratch")
    job = _sample_job()
    dirs = cleaner.prepare_job_directories(job.job_id)
    seccomp_path = write_seccomp_profile(tmp_path / "seccomp")

    profile = build_default_seccomp_profile()
    blocked_names = set(profile["syscalls"][0]["names"])
    for dangerous in ("bpf", "ptrace", "mount", "unshare", "setns", "kexec_load", "userfaultfd"):
        assert dangerous in BLOCKED_SECCOMP_SYSCALLS
        assert dangerous in blocked_names

    spec = build_hardened_oci_invocation(
        job,
        dirs=dirs,
        seccomp_profile_path=seccomp_path,
        runtime_binary="/usr/bin/podman",
    )
    checks = validate_oci_invocation_security(spec)
    assert all(c.passed for c in checks)
    assert "--network=none" in spec.cli_args
    assert "--read-only" in spec.cli_args
    assert "--cap-drop=ALL" in spec.cli_args
    assert "--security-opt=no-new-privileges:true" in spec.cli_args
    assert f"--pids-limit={job.resource_limits.pids}" in spec.cli_args
    assert f"@sha256:{job.image_digest}" in spec.image_ref

    # 1. Reject Docker/Podman socket mount (`SEC-006` / `SEC-029`)
    bad_sock = dataclasses.replace(
        spec,
        mounts=(*spec.mounts, "/var/run/docker.sock:/var/run/docker.sock"),
    )
    with pytest.raises(SandboxIsolationUnavailableError, match="socket"):
        validate_oci_invocation_security(bad_sock)

    # 2. Reject `--privileged` or `--network=host` (`SEC-014`)
    bad_priv = dataclasses.replace(
        spec,
        cli_args=(*spec.cli_args, "--privileged"),
    )
    with pytest.raises(SandboxIsolationUnavailableError, match="Forbidden container escape flag"):
        validate_oci_invocation_security(bad_priv)

    # 3. Reject host/provider/meta secret env propagation (`SEC-006`)
    with pytest.raises(SandboxIsolationUnavailableError, match="Forbidden secret"):
        build_sanitized_guest_env(env_allowlist=("GITHUB_TOKEN",))

    bad_env = dataclasses.replace(
        spec,
        guest_env={**spec.guest_env, "META_LLAMA_API_KEY": "secret_leak"},
    )
    with pytest.raises(SandboxIsolationUnavailableError, match="Forbidden secret"):
        validate_oci_invocation_security(bad_env)

    # 4. Reject PIDs > 512, disk > 40 GiB, output > 100 MiB (`NFR-14`)
    bad_pids: HardenedOciInvocation = dataclasses.replace(spec, pids_limit=1024)
    with pytest.raises(SandboxIsolationUnavailableError, match="pids_limit"):
        validate_oci_invocation_security(bad_pids)

    bad_disk = dataclasses.replace(spec, disk_bytes=MAX_ALLOWED_DISK_BYTES + 1)
    with pytest.raises(SandboxIsolationUnavailableError, match="disk_bytes"):
        validate_oci_invocation_security(bad_disk)

    bad_out = dataclasses.replace(spec, output_bytes=MAX_ALLOWED_OUTPUT_BYTES + 1)
    with pytest.raises(SandboxIsolationUnavailableError, match="output_bytes"):
        validate_oci_invocation_security(bad_out)

    # 5. Reject unreviewed profile_id and unreviewed command_id
    with pytest.raises((ValueError, SandboxIsolationUnavailableError), match="unreviewed"):
        resolve_reviewed_commands(profile_id="unreviewed-custom-shell", command_ids=["pytest-unit"])
    with pytest.raises((ValueError, SandboxIsolationUnavailableError), match="not permitted"):
        resolve_reviewed_commands(
            profile_id="python-3.12-node-22",
            command_ids=["curl-exfiltrate-sh"],
        )


def test_safe_extract_and_non_following_symlink_cleanup_preserves_host_files(
    tmp_path: Path,
) -> None:
    """`SEC-007`, `SEC-026`, `SEC-029`, `SEC-036`: Reject malicious source archives and prove
    post-job cleanup unlinks guest-planted symlinks without touching host target files."""
    cleaner = EphemeralWorkspaceCleaner(tmp_path / "scratch")
    job = _sample_job()
    dirs = cleaner.prepare_job_directories(job.job_id)

    valid_tar = _make_tar_gz(
        {
            "src/app.py": b"def add(a: int, b: int) -> int:\n    return a + b\n",
            "tests/test_app.py": (
                b"from src.app import add\ndef test_add(): assert add(1, 2) == 3\n"
            ),
        }
    )
    count = safe_extract_source_archive(valid_tar, worktree_dir=dirs.worktree_dir)
    assert count == 2
    assert (dirs.worktree_dir / "src" / "app.py").is_file()

    # Adversarial tar cases: traversal, absolute path, symlink, hardlink, FIFO, file-count cap
    for bad_tar in (
        _make_tar_gz({"../../etc/passwd": b"root:x:0:0"}),
        _make_tar_gz({"/etc/shadow": b"shadow"}),
        _make_tar_gz({}, symlink=("evil_link", "/etc/hosts")),
        _make_tar_gz({"a.txt": b"x"}, hardlink=("hard_a.txt", "a.txt")),
        _make_tar_gz({}, fifo_name="named_pipe"),
    ):
        with pytest.raises(UnsafeSourceArchiveError):
            safe_extract_source_archive(bad_tar, worktree_dir=dirs.worktree_dir)

    with pytest.raises(UnsafeSourceArchiveError, match="maximum file count"):
        safe_extract_source_archive(valid_tar, worktree_dir=dirs.worktree_dir, max_files=1)

    # Plant an external sensitive host file & directory outside scratch root
    host_secret_dir = tmp_path / "host_sensitive"
    host_secret_dir.mkdir()
    host_secret_file = host_secret_dir / "host_canary.txt"
    host_secret_file.write_text("DO_NOT_DELETE_OR_MODIFY_HOST_DATA", encoding="utf-8")

    # Simulate an adversarial guest planting symlinks inside worktree targeting host paths
    symlink_planted = False
    try:
        os.symlink(host_secret_file, dirs.worktree_dir / "escape_file_link")
        os.symlink(
            host_secret_dir,
            dirs.worktree_dir / "escape_dir_link",
            target_is_directory=True,
        )
        symlink_planted = True
    except OSError:
        symlink_planted = False

    report = asyncio.run(cleaner.teardown_and_verify(dirs))
    assert report.passed is True
    assert not dirs.root_dir.exists()
    if symlink_planted:
        assert report.symlinks_unlinked >= 2

    # Host target file & directory MUST remain 100% untouched!
    assert host_secret_dir.is_dir()
    assert host_secret_file.read_text(encoding="utf-8") == "DO_NOT_DELETE_OR_MODIFY_HOST_DATA"


def test_external_result_signer_isolation_and_ed25519_verification(tmp_path: Path) -> None:
    """`ADR-035` / `SEC-030`: Signing key stays outside guest workspace and produces verifiable
    domain-separated `DOMAIN_RESULT_V1` Ed25519 signatures."""
    key_dir = tmp_path / "supervisor_keys"
    guest_root = tmp_path / "guest_scratch" / "job-01"
    guest_root.mkdir(parents=True)

    now = datetime(2026, 10, 28, 10, 5, 0, tzinfo=UTC)
    signer = ExternalResultSigner.generate(
        key_id="ed25519-worker-test01",
        not_before=now - timedelta(minutes=5),
    )
    signer.save_to_directory(key_dir)
    reloaded = ExternalResultSigner.load_from_directory(key_dir)
    reloaded.assert_outside_guest_workspace(guest_root)

    # Attempt to place signing key inside guest workspace MUST fail closed!
    bad_signer = ExternalResultSigner.generate(
        key_id="ed25519-bad",
        not_before=now - timedelta(minutes=5),
    )
    bad_signer.save_to_directory(guest_root / "leaked_keys")
    with pytest.raises(PermissionError, match="ADR-035"):
        bad_signer.assert_outside_guest_workspace(guest_root)

    unsigned = ResultV1(
        job_id=new_uuid7(now=now),
        lease_epoch=1,
        capability_nonce="nonce_u14_sign_01",
        worker_id=new_uuid7(now=now),
        started_at=now - timedelta(seconds=4),
        ended_at=now,
        exit_code=0,
        termination="exited",
        command_digest="1" * 64,
        image_digest="2" * 64,
        environment_digest="3" * 64,
        source_digest="4" * 64,
        artifact_refs=[],
        resource_usage=SandboxResourceUsage(
            wall_ms=4000,
            max_memory_bytes=64_000_000,
            disk_written_bytes=8192,
            output_bytes=1024,
        ),
        isolation_checks=[
            IsolationCheckResult(check_id="network_none", passed=True, detail="isolated"),
            IsolationCheckResult(check_id="ephemeral_cleanup", passed=True, detail="clean"),
        ],
        signer_key_id=reloaded.key_id,
        signature="00" * 32,
    )
    signed = reloaded.sign_result(unsigned, guest_workspace_root=guest_root)
    ring = KeyRing([reloaded.public_key_record])
    verify_model_ed25519(
        signed,
        keyring=ring,
        domain=DOMAIN_RESULT_V1,
        signed_at=now,
    )
    assert signed.passed_cleanly() is True


def test_adversarial_fork_bomb_oom_timeout_never_certify_tests_passed() -> None:
    """`SEC-013`, `SEC-029`, `Proof over prose`: OOM/fork-bomb, timeout, or failed isolation check
    never evaluates `passed_cleanly() == True` even if `exit_code == 0`."""
    now = datetime(2026, 10, 28, 10, 10, 0, tzinfo=UTC)
    guest_oom = GuestExecutionResult(
        exit_code=137,
        timed_out=False,
        cancelled=False,
        oom_killed=True,
        infrastructure_error=False,
        stdout_bytes=b"fork: retry: Resource temporarily unavailable (pids.max=512)\n",
        stderr_bytes=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        resource_usage=SandboxResourceUsage(
            wall_ms=1200,
            max_memory_bytes=2_147_483_648,
            disk_written_bytes=0,
            output_bytes=64,
        ),
        isolation_checks=(
            IsolationCheckResult(check_id="pids_limit_512", passed=True, detail="enforced"),
        ),
        output_files={},
    )
    res_oom = ResultV1(
        job_id=new_uuid7(now=now),
        lease_epoch=1,
        capability_nonce="nonce_u14_oom",
        worker_id=new_uuid7(now=now),
        started_at=now - timedelta(seconds=2),
        ended_at=now,
        exit_code=guest_oom.exit_code,
        termination="oom",
        command_digest="1" * 64,
        image_digest="2" * 64,
        environment_digest="3" * 64,
        source_digest="4" * 64,
        artifact_refs=[],
        resource_usage=guest_oom.resource_usage,
        isolation_checks=list(guest_oom.isolation_checks),
        signer_key_id="ed25519-k1",
        signature=hashlib.sha256(b"sig").hexdigest(),
    )
    assert res_oom.passed_cleanly() is False

    # Even exit_code=0 with a failed isolation check (`ephemeral_cleanup=False`) MUST be False
    res_bad_iso = ResultV1(
        job_id=new_uuid7(now=now),
        lease_epoch=1,
        capability_nonce="nonce_u14_bad_iso",
        worker_id=new_uuid7(now=now),
        started_at=now - timedelta(seconds=2),
        ended_at=now,
        exit_code=0,
        termination="exited",
        command_digest="1" * 64,
        image_digest="2" * 64,
        environment_digest="3" * 64,
        source_digest="4" * 64,
        artifact_refs=[],
        resource_usage=guest_oom.resource_usage,
        isolation_checks=[
            IsolationCheckResult(check_id="ephemeral_cleanup", passed=False, detail="residue"),
        ],
        signer_key_id="ed25519-k1",
        signature=hashlib.sha256(b"sig").hexdigest(),
    )
    assert res_bad_iso.passed_cleanly() is False
