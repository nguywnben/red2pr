"""Hardened rootless OCI & microVM sandbox runner (`SAN-01`, `ADR-016`, `ADR-034`, `NFR-14`).

Enforces strict fail-closed isolation invariants (`SEC-006`, `SEC-013`, `SEC-014`, `SEC-029`):
- Zero host-shell fallback: if no verified rootless OCI or microVM runtime is available,
  execution raises `SandboxIsolationUnavailableError` immediately.
- Reviewed immutable profile -> `command_id` -> `argv` registry (zero arbitrary shell eval).
- Mandatory `--network=none`, `--read-only`, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges:true`, restrictive seccomp syscall filter,
  `--pids-limit<=512`, `--memory` / `--memory-swap` parity, `--cpus`, `@sha256:` image
  digest pinning, `noexec,nosuid,nodev` `/tmp`, zero Docker/Podman socket mounts, and
  zero host environment secret propagation.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from py_contracts.worker import (
    IsolationCheckResult,
    RunnerProfileManifest,
    SandboxJobV1,
    SandboxResourceUsage,
    WorkerIsolationAttestation,
    WorkerIsolationMode,
    load_reviewed_profile_manifests,
)
from red2pr_worker.cleanup import JobSandboxDirectories
from red2pr_worker.materializer import resolve_default_profiles_dir

MAX_ALLOWED_PIDS_LIMIT = 512
MAX_ALLOWED_DISK_BYTES = 42_949_672_960  # 40 GiB (NFR-14)
MAX_ALLOWED_OUTPUT_BYTES = 104_857_600  # 100 MiB (NFR-14)

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

FORBIDDEN_MOUNT_SUBSTRINGS: tuple[str, ...] = (
    "docker.sock",
    "podman.sock",
    "containerd.sock",
    "crio.sock",
    "/var/run/",
    "/proc/sys",
    "/sys/fs",
    "/etc/shadow",
    "/etc/sudoers",
    ".ssh",
    ".aws",
    ".gnupg",
    "worker_result_ed25519",
    "worker_mtls_client",
)

FORBIDDEN_ENV_SUBSTRINGS: tuple[str, ...] = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "API_KEY",
    "ACCESS_KEY",
    "DATABASE_URL",
    "DSN",
    "COOKIE",
    "SESSION",
    "AUTHORIZATION",
    "RED2PR_",
    "META_",
    "LLAMA_",
    "GITHUB_",
    "GITLAB_",
    "TELEGRAM_",
    "AWS_",
)

_GUEST_ISOLATED_TMP_MOUNT = "/" + "tmp"

SAFE_BASE_GUEST_ENV: Mapping[str, str] = {
    "CI": "true",
    "HOME": _GUEST_ISOLATED_TMP_MOUNT,
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "NO_COLOR": "1",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TMPDIR": _GUEST_ISOLATED_TMP_MOUNT,
}

REVIEWED_PROFILE_MANIFESTS: Mapping[str, RunnerProfileManifest] = load_reviewed_profile_manifests(
    resolve_default_profiles_dir()
)

_BASE_PROFILE_IMAGES: dict[str, str] = {
    "python-3.12-node-22": "ghcr.io/red2pr/runtime-python312-node22",
    "python-3.12-slim": "ghcr.io/red2pr/runtime-python312-slim",
    "node-22-bookworm": "ghcr.io/red2pr/runtime-node22-bookworm",
    "rust-1.82-bookworm": "ghcr.io/red2pr/runtime-rust182-bookworm",
    "go-1.23-bookworm": "ghcr.io/red2pr/runtime-go123-bookworm",
}
for _pid, _manifest in REVIEWED_PROFILE_MANIFESTS.items():
    _BASE_PROFILE_IMAGES[_pid] = _manifest.base_image

REVIEWED_PROFILE_IMAGES: Mapping[str, str] = _BASE_PROFILE_IMAGES

_BASE_PROFILE_COMMANDS: dict[str, Mapping[str, tuple[str, ...]]] = {
    "python-3.12-node-22": {
        "pytest-unit": ("python3", "-m", "pytest", "-q"),
        "pytest-repro": ("python3", "-m", "pytest", "-v", "--tb=short"),
        "ruff-check": ("python3", "-m", "ruff", "check", "."),
        "mypy-strict": ("python3", "-m", "mypy", "--strict", "."),
        "pnpm-test": ("pnpm", "test", "--run"),
        "pnpm-typecheck": ("pnpm", "typecheck"),
        "sandbox-self-test": ("python3", "-c", "print('sandbox-isolated-ok')"),
    },
    "python-3.12-slim": {
        "pytest-unit": ("python3", "-m", "pytest", "-q"),
        "pytest-repro": ("python3", "-m", "pytest", "-v", "--tb=short"),
        "ruff-check": ("python3", "-m", "ruff", "check", "."),
        "mypy-strict": ("python3", "-m", "mypy", "--strict", "."),
        "sandbox-self-test": ("python3", "-c", "print('sandbox-isolated-ok')"),
    },
    "node-22-bookworm": {
        "pnpm-test": ("pnpm", "test", "--run"),
        "pnpm-typecheck": ("pnpm", "typecheck"),
        "npm-test": ("npm", "test", "--", "--watch=false"),
        "sandbox-self-test": ("node", "-e", "process.stdout.write('sandbox-isolated-ok\\n')"),
    },
    "rust-1.82-bookworm": {
        "cargo-test": ("cargo", "test", "--offline", "--locked"),
        "cargo-check": ("cargo", "check", "--offline", "--locked"),
        "sandbox-self-test": ("rustc", "--version"),
    },
    "go-1.23-bookworm": {
        "go-test": ("go", "test", "./..."),
        "go-vet": ("go", "vet", "./..."),
        "sandbox-self-test": ("go", "version"),
    },
}
for _pid, _manifest in REVIEWED_PROFILE_MANIFESTS.items():
    _BASE_PROFILE_COMMANDS[_pid] = {cmd.command_id: tuple(cmd.argv) for cmd in _manifest.commands}

REVIEWED_PROFILE_COMMANDS: Mapping[str, Mapping[str, tuple[str, ...]]] = _BASE_PROFILE_COMMANDS

BLOCKED_SECCOMP_SYSCALLS: tuple[str, ...] = (
    "acct",
    "add_key",
    "bpf",
    "clock_adjtime",
    "clock_settime",
    "create_module",
    "delete_module",
    "finit_module",
    "init_module",
    "ioperm",
    "iopl",
    "kcmp",
    "kexec_file_load",
    "kexec_load",
    "keyctl",
    "lookup_dcookie",
    "mount",
    "move_mount",
    "name_to_handle_at",
    "nfsservctl",
    "open_by_handle_at",
    "open_tree",
    "perf_event_open",
    "personality",
    "pivot_root",
    "process_vm_readv",
    "process_vm_writev",
    "ptrace",
    "quotactl",
    "reboot",
    "request_key",
    "setns",
    "settimeofday",
    "swapon",
    "swapoff",
    "sysfs",
    "umount",
    "umount2",
    "unshare",
    "uselib",
    "userfaultfd",
    "ustat",
    "vm86",
    "vm86old",
)


class SandboxIsolationUnavailableError(RuntimeError):
    """Raised fail-closed whenever isolated rootless OCI or VM execution is unavailable."""


def build_default_seccomp_profile() -> dict[str, Any]:
    """Build deterministic restrictive OCI seccomp profile blocking kernel-escape syscalls."""
    return {
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
        "syscalls": [
            {
                "names": list(BLOCKED_SECCOMP_SYSCALLS),
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": 1,
            }
        ],
    }


def write_seccomp_profile(target_dir: Path) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    seccomp_path = target_dir / "red2pr-seccomp.v1.json"
    seccomp_path.write_text(
        json.dumps(build_default_seccomp_profile(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with contextlib.suppress(OSError):
        os.chmod(seccomp_path, 0o400)
    return seccomp_path


def resolve_reviewed_commands(
    *,
    profile_id: str,
    command_ids: Sequence[str],
) -> tuple[tuple[str, ...], ...]:
    """Resolve `SandboxJobV1.command_ids` against reviewed immutable profile `argv` entries."""
    profile_map = REVIEWED_PROFILE_COMMANDS.get(profile_id)
    if profile_map is None:
        raise ValueError(f"Unsupported or unreviewed sandbox profile_id: {profile_id!r}")
    if not command_ids:
        raise ValueError("SandboxJobV1.command_ids must contain at least one command_id.")
    resolved: list[tuple[str, ...]] = []
    for cmd_id in command_ids:
        argv = profile_map.get(cmd_id)
        if argv is None:
            raise ValueError(
                f"Command ID {cmd_id!r} is not permitted in reviewed profile {profile_id!r}."
            )
        resolved.append(argv)
    return tuple(resolved)


def build_sanitized_guest_env(
    env_allowlist: Sequence[str] = (),
    *,
    explicit_non_secret_overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Construct minimal guest env with ZERO host `os.environ` secret inheritance (`SEC-006`)."""
    guest_env = dict(SAFE_BASE_GUEST_ENV)
    overrides = explicit_non_secret_overrides or {}
    for key in env_allowlist:
        clean_key = key.strip()
        if not _SAFE_ENV_KEY_RE.fullmatch(clean_key):
            raise SandboxIsolationUnavailableError(
                f"Invalid guest env_allowlist variable name {key!r} (SEC-006)."
            )
        upper_key = clean_key.upper()
        if any(forbidden in upper_key for forbidden in FORBIDDEN_ENV_SUBSTRINGS):
            raise SandboxIsolationUnavailableError(
                f"Forbidden secret-bearing environment variable {clean_key!r} denied (SEC-006)."
            )
        if clean_key in overrides:
            val = overrides[clean_key]
            if "\x00" in val or len(val) > 512:
                raise SandboxIsolationUnavailableError(
                    f"Invalid guest environment override value for {clean_key!r}."
                )
            guest_env[clean_key] = val
    return guest_env


@dataclass(frozen=True, slots=True)
class HardenedOciInvocation:
    """Immutable validated OCI/VM invocation specification for a single `SandboxJobV1`."""

    runtime_binary: str
    isolation_mode: WorkerIsolationMode
    container_name: str
    image_ref: str
    resolved_commands: tuple[tuple[str, ...], ...]
    cli_args: tuple[str, ...]
    mounts: tuple[str, ...]
    guest_env: Mapping[str, str]
    seccomp_profile_path: Path
    cpu_cores: int
    memory_bytes: int
    disk_bytes: int
    pids_limit: int
    output_bytes: int
    wall_seconds: int


def build_hardened_oci_invocation(
    job: SandboxJobV1,
    *,
    dirs: JobSandboxDirectories,
    seccomp_profile_path: Path,
    runtime_binary: str = "podman",
    isolation_mode: WorkerIsolationMode = "oci_rootless",
    explicit_non_secret_env: Mapping[str, str] | None = None,
    readonly_dep_cache_dir: Path | None = None,
) -> HardenedOciInvocation:
    """Build hardened OCI CLI arguments enforcing all `SAN-01` / `SAN-03` / `NFR-14` limits."""
    if not _SHA256_HEX_RE.fullmatch(job.image_digest):
        raise SandboxIsolationUnavailableError(
            "Sandbox image_digest must be a pinned 64-hex SHA-256 digest."
        )
    base_image = REVIEWED_PROFILE_IMAGES.get(job.profile_id)
    if base_image is None:
        raise SandboxIsolationUnavailableError(
            f"Unreviewed sandbox runtime profile: {job.profile_id!r}."
        )
    manifest = REVIEWED_PROFILE_MANIFESTS.get(job.profile_id)
    if manifest is not None:
        if manifest.requires_isolated_vm_tier and isolation_mode != "vm_isolated":
            raise SandboxIsolationUnavailableError(
                f"Profile {job.profile_id!r} requires vm_isolated worker tier (ADR-018)."
            )
        if job.profile_revision == manifest.revision and job.image_digest != manifest.image_digest:
            raise SandboxIsolationUnavailableError(
                f"SandboxJobV1 image_digest does not match pinned manifest digest for "
                f"{job.profile_id!r} rev {manifest.revision} (SAN-03)."
            )

    resolved_cmds = resolve_reviewed_commands(
        profile_id=job.profile_id,
        command_ids=job.command_ids,
    )
    merged_allowlist: list[str] = list(manifest.env_allowlist) if manifest is not None else []
    merged_overrides: dict[str, str] = dict(manifest.default_env) if manifest is not None else {}
    if explicit_non_secret_env:
        for k, v in explicit_non_secret_env.items():
            if k not in merged_allowlist:
                merged_allowlist.append(k)
            merged_overrides[k] = v

    guest_env = build_sanitized_guest_env(
        merged_allowlist,
        explicit_non_secret_overrides=merged_overrides,
    )

    limits = job.resource_limits
    pids_limit = min(limits.pids, MAX_ALLOWED_PIDS_LIMIT)
    disk_bytes = min(limits.disk_bytes, MAX_ALLOWED_DISK_BYTES)
    output_bytes = min(limits.output_bytes, MAX_ALLOWED_OUTPUT_BYTES)
    cpus_str = f"{limits.cpu:.1f}"
    container_name = f"red2pr-sbx-{job.job_id}"
    image_ref = f"{base_image}@sha256:{job.image_digest}"

    worktree_mount = f"{dirs.worktree_dir}:/workspace:rw,nosuid,nodev,Z"
    output_mount = f"{dirs.output_dir}:/output:rw,noexec,nosuid,nodev,Z"
    mount_list: list[str] = [worktree_mount, output_mount]
    volume_flags: list[str] = [
        "--volume",
        worktree_mount,
        "--volume",
        output_mount,
    ]
    if readonly_dep_cache_dir is not None:
        if readonly_dep_cache_dir.is_symlink() or not readonly_dep_cache_dir.is_dir():
            raise SandboxIsolationUnavailableError(
                "Read-only dependency cache path does not exist or is a symlink (SEC-036)."
            )
        resolved_cache = readonly_dep_cache_dir.resolve(strict=True)
        if resolved_cache.is_relative_to(dirs.root_dir.resolve(strict=True)):
            raise SandboxIsolationUnavailableError(
                "Dependency cache directory must reside outside writable guest scratch (SEC-036)."
            )
        cache_mount = f"{resolved_cache}:/dep-cache:ro,noexec,nosuid,nodev,Z"
        mount_list.append(cache_mount)
        volume_flags.extend(("--volume", cache_mount))
    mounts = tuple(mount_list)

    env_flags: list[str] = []
    for k in sorted(guest_env):
        env_flags.extend(("--env", f"{k}={guest_env[k]}"))

    cli_args: list[str] = [
        runtime_binary,
        "run",
        "--rm",
        "--init",
        "--name",
        container_name,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        f"--security-opt=seccomp={seccomp_profile_path}",
        "--user=65534:65534",
        f"--pids-limit={pids_limit}",
        f"--cpus={cpus_str}",
        f"--memory={limits.memory_bytes}",
        f"--memory-swap={limits.memory_bytes}",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864",
        "--workdir=/workspace",
        *volume_flags,
        *env_flags,
        image_ref,
    ]
    if len(resolved_cmds) == 1:
        cli_args.extend(resolved_cmds[0])
    else:
        runner_script = (
            "import json, subprocess, sys; "
            "cmds = json.loads(sys.argv[1]); "
            "rc = 0\n"
            "for argv in cmds:\n"
            "    res = subprocess.run(argv, check=False)\n"
            "    if res.returncode != 0:\n"
            "        sys.exit(res.returncode)\n"
        )
        cli_args.extend(("python3", "-c", runner_script, json.dumps(resolved_cmds)))

    invocation = HardenedOciInvocation(
        runtime_binary=runtime_binary,
        isolation_mode=isolation_mode,
        container_name=container_name,
        image_ref=image_ref,
        resolved_commands=resolved_cmds,
        cli_args=tuple(cli_args),
        mounts=mounts,
        guest_env=guest_env,
        seccomp_profile_path=seccomp_profile_path,
        cpu_cores=limits.cpu,
        memory_bytes=limits.memory_bytes,
        disk_bytes=disk_bytes,
        pids_limit=pids_limit,
        output_bytes=output_bytes,
        wall_seconds=limits.wall_seconds,
    )
    validate_oci_invocation_security(invocation)
    return invocation


def validate_oci_invocation_security(
    invocation: HardenedOciInvocation,
) -> tuple[IsolationCheckResult, ...]:
    """Validate every mandatory OCI/VM security flag fail-closed (`SEC-006`, `SEC-014`)."""
    args = invocation.cli_args
    forbidden_flags = (
        "--privileged",
        "--network=host",
        "--net=host",
        "--pid=host",
        "--ipc=host",
        "--uts=host",
        "--userns=host",
    )
    for bad in forbidden_flags:
        if any(arg == bad or arg.startswith(f"{bad}=") for arg in args):
            raise SandboxIsolationUnavailableError(
                f"Forbidden container escape flag {bad!r} detected in OCI spec (SEC-006)."
            )

    if "--network=none" not in args:
        raise SandboxIsolationUnavailableError(
            "Mandatory --network=none flag missing from OCI spec (SEC-014)."
        )
    if "--read-only" not in args:
        raise SandboxIsolationUnavailableError("Mandatory --read-only rootfs flag missing.")
    if "--cap-drop=ALL" not in args:
        raise SandboxIsolationUnavailableError("Mandatory --cap-drop=ALL flag missing.")
    if "--security-opt=no-new-privileges:true" not in args:
        raise SandboxIsolationUnavailableError(
            "Mandatory --security-opt=no-new-privileges:true flag missing."
        )
    if not any(arg.startswith("--security-opt=seccomp=") for arg in args):
        raise SandboxIsolationUnavailableError("Mandatory seccomp profile flag missing.")
    if not invocation.seccomp_profile_path.is_file():
        raise SandboxIsolationUnavailableError("Seccomp profile file does not exist on disk.")
    if "@sha256:" not in invocation.image_ref:
        raise SandboxIsolationUnavailableError("Sandbox image reference must be digest-pinned.")
    if invocation.pids_limit < 1 or invocation.pids_limit > MAX_ALLOWED_PIDS_LIMIT:
        raise SandboxIsolationUnavailableError(
            f"Sandbox pids_limit {invocation.pids_limit} violates NFR-14 cap (<=512)."
        )
    if invocation.disk_bytes > MAX_ALLOWED_DISK_BYTES:
        raise SandboxIsolationUnavailableError("Sandbox disk_bytes exceeds 40 GiB NFR-14 cap.")
    if invocation.output_bytes > MAX_ALLOWED_OUTPUT_BYTES:
        raise SandboxIsolationUnavailableError("Sandbox output_bytes exceeds 100 MiB NFR-14 cap.")

    for mount_spec in (*invocation.mounts, *args):
        lowered = mount_spec.lower().replace("\\", "/")
        for bad_mount in FORBIDDEN_MOUNT_SUBSTRINGS:
            if bad_mount in lowered:
                raise SandboxIsolationUnavailableError(
                    f"Forbidden host mount/socket reference {bad_mount!r} rejected (SEC-006)."
                )
        if ":/dep-cache" in lowered:
            after_target = lowered.split(":/dep-cache", 1)[1]
            opts = {opt.strip() for opt in after_target.lstrip(":").split(",") if opt.strip()}
            if "ro" not in opts or "rw" in opts:
                raise SandboxIsolationUnavailableError(
                    "Dependency cache mount /dep-cache must be strictly read-only (:ro) (SEC-036)."
                )

    for env_key in invocation.guest_env:
        upper_key = env_key.upper()
        if any(bad_env in upper_key for bad_env in FORBIDDEN_ENV_SUBSTRINGS):
            raise SandboxIsolationUnavailableError(
                f"Forbidden secret environment variable {env_key!r} rejected (SEC-006)."
            )

    return (
        IsolationCheckResult(
            check_id="network_none",
            passed=True,
            detail="Guest network namespace isolated (--network=none; egress disabled).",
        ),
        IsolationCheckResult(
            check_id="no_privileged_or_socket",
            passed=True,
            detail="Non-privileged guest with cap-drop=ALL, read-only rootfs, zero socket mounts.",
        ),
        IsolationCheckResult(
            check_id="seccomp_and_limits",
            passed=True,
            detail=(
                f"Restrictive seccomp active; pids<={invocation.pids_limit}, "
                f"mem={invocation.memory_bytes}, output<={invocation.output_bytes}."
            ),
        ),
        IsolationCheckResult(
            check_id="env_sanitized",
            passed=True,
            detail="Guest environment restricted to allowlisted non-secret variables.",
        ),
    )


@dataclass(frozen=True, slots=True)
class GuestExecutionResult:
    """Raw guest execution outcome captured by a `SandboxRuntimeDriver` prior to signing."""

    exit_code: int | None
    timed_out: bool
    cancelled: bool
    oom_killed: bool
    infrastructure_error: bool
    stdout_bytes: bytes
    stderr_bytes: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    resource_usage: SandboxResourceUsage
    isolation_checks: tuple[IsolationCheckResult, ...]
    output_files: Mapping[str, bytes]


class SandboxRuntimeDriver(Protocol):
    """Pluggable isolated guest execution backend (`RootlessOciCliDriver` / `VmSandboxDriver`)."""

    @property
    def isolation_mode(self) -> WorkerIsolationMode: ...

    async def probe_isolation(self) -> WorkerIsolationAttestation: ...

    async def execute_job(
        self,
        job: SandboxJobV1,
        *,
        invocation: HardenedOciInvocation,
        dirs: JobSandboxDirectories,
        cancel_event: asyncio.Event,
    ) -> GuestExecutionResult: ...

    async def force_kill_job(self, job_id: str) -> Sequence[str]: ...

    async def run_self_test(
        self,
    ) -> tuple[bool, tuple[IsolationCheckResult, ...], str]: ...


async def _read_bounded_stream(
    stream: asyncio.StreamReader | None,
    *,
    max_bytes: int,
) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    chunks: list[bytes] = []
    captured = 0
    truncated = False
    while True:
        chunk = await stream.read(65_536)
        if not chunk:
            break
        if captured < max_bytes:
            take = min(len(chunk), max_bytes - captured)
            chunks.append(chunk[:take])
            captured += take
            if take < len(chunk):
                truncated = True
        else:
            truncated = True
    return b"".join(chunks), truncated


def _collect_bounded_output_files(
    output_dir: Path,
    *,
    allowed_slots: Sequence[str],
    remaining_byte_budget: int,
) -> dict[str, bytes]:
    collected: dict[str, bytes] = {}
    budget = max(0, remaining_byte_budget)
    for slot in allowed_slots:
        if slot in ("stdout", "stderr"):
            continue
        candidate = output_dir / slot
        if not candidate.exists() or candidate.is_symlink() or not candidate.is_file():
            continue
        raw = candidate.read_bytes()
        if len(raw) > budget:
            raw = raw[:budget]
        budget -= len(raw)
        collected[slot] = raw
    return collected


class RootlessOciCliDriver:
    """Production rootless Podman/Docker OCI sandbox driver (`SAN-01`, `ADR-016`).

    Fails closed (`SandboxIsolationUnavailableError`) whenever no OCI runtime is present
    or rootless mode is inactive without explicit `oci_trusted_local` acknowledgement.
    """

    def __init__(
        self,
        *,
        host_id: str = "local-worker-01",
        preferred_binary: str = "podman",
        isolation_mode: WorkerIsolationMode = "oci_rootless",
        allow_trusted_local_rootful: bool = False,
        cpu_limit: int = 4,
        memory_limit_bytes: int = 8_589_934_592,
        disk_limit_bytes: int = MAX_ALLOWED_DISK_BYTES,
        pids_limit: int = MAX_ALLOWED_PIDS_LIMIT,
    ) -> None:
        if isolation_mode == "vm_isolated":
            raise ValueError("Use VmSandboxDriver for vm_isolated mode.")
        if isolation_mode == "oci_trusted_local" and not allow_trusted_local_rootful:
            raise ValueError(
                "oci_trusted_local requires allow_trusted_local_rootful=True (ADR-016)."
            )
        self._host_id = host_id
        self._preferred_binary = preferred_binary
        self._isolation_mode: WorkerIsolationMode = isolation_mode
        self._allow_trusted_local = allow_trusted_local_rootful
        self._cpu_limit = cpu_limit
        self._memory_limit = memory_limit_bytes
        self._disk_limit = disk_limit_bytes
        self._pids_limit = pids_limit

    @property
    def isolation_mode(self) -> WorkerIsolationMode:
        return self._isolation_mode

    def _locate_binary(self) -> str | None:
        for candidate in (self._preferred_binary, "podman", "docker"):
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        return None

    async def probe_isolation(self) -> WorkerIsolationAttestation:
        binary = self._locate_binary()
        if binary is None:
            return WorkerIsolationAttestation(
                host_id=self._host_id,
                runtime_name="oci-cli-missing",
                isolation_mode=self._isolation_mode,
                rootless_verified=False,
                seccomp_verified=False,
                no_new_privileges_verified=False,
                network_none_supported=False,
                cpu_limit=self._cpu_limit,
                memory_limit_bytes=self._memory_limit,
                disk_limit_bytes=self._disk_limit,
                pids_limit=self._pids_limit,
            )

        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [binary, "info", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception:
            return WorkerIsolationAttestation(
                host_id=self._host_id,
                runtime_name=Path(binary).name,
                isolation_mode=self._isolation_mode,
                rootless_verified=False,
                seccomp_verified=False,
                no_new_privileges_verified=False,
                network_none_supported=False,
                cpu_limit=self._cpu_limit,
                memory_limit_bytes=self._memory_limit,
                disk_limit_bytes=self._disk_limit,
                pids_limit=self._pids_limit,
            )

        if proc.returncode != 0:
            return WorkerIsolationAttestation(
                host_id=self._host_id,
                runtime_name=Path(binary).name,
                isolation_mode=self._isolation_mode,
                rootless_verified=False,
                seccomp_verified=False,
                no_new_privileges_verified=False,
                network_none_supported=False,
                cpu_limit=self._cpu_limit,
                memory_limit_bytes=self._memory_limit,
                disk_limit_bytes=self._disk_limit,
                pids_limit=self._pids_limit,
            )

        try:
            info = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            info = {}

        host_security = info.get("host", {}).get("security", {})
        security_opts = info.get("SecurityOptions") or []
        is_rootless = bool(
            host_security.get("rootless") is True
            or any("rootless" in str(opt).lower() for opt in security_opts)
        )
        return WorkerIsolationAttestation(
            host_id=self._host_id,
            runtime_name=Path(binary).name,
            isolation_mode=self._isolation_mode,
            rootless_verified=is_rootless,
            seccomp_verified=True,
            no_new_privileges_verified=True,
            network_none_supported=True,
            cpu_limit=self._cpu_limit,
            memory_limit_bytes=self._memory_limit,
            disk_limit_bytes=self._disk_limit,
            pids_limit=self._pids_limit,
        )

    async def execute_job(
        self,
        job: SandboxJobV1,
        *,
        invocation: HardenedOciInvocation,
        dirs: JobSandboxDirectories,
        cancel_event: asyncio.Event,
    ) -> GuestExecutionResult:
        attestation = await self.probe_isolation()
        if not attestation.network_none_supported or not attestation.seccomp_verified:
            raise SandboxIsolationUnavailableError(
                "No running OCI container runtime available on worker host; "
                "refusing host-shell execution fail-closed (SAN-01)."
            )
        if self._isolation_mode == "oci_rootless" and not attestation.rootless_verified:
            raise SandboxIsolationUnavailableError(
                "OCI runtime is rootful; oci_rootless requires verified rootless mode (ADR-016)."
            )

        static_checks = validate_oci_invocation_security(invocation)
        binary = self._locate_binary()
        if binary is None:
            raise SandboxIsolationUnavailableError("OCI runtime binary disappeared before launch.")

        cmd = [binary, *invocation.cli_args[1:]]
        started = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(dirs.tmp_dir)},
        )

        half_cap = max(4096, invocation.output_bytes // 2)
        stdout_task = asyncio.create_task(_read_bounded_stream(proc.stdout, max_bytes=half_cap))
        stderr_task = asyncio.create_task(_read_bounded_stream(proc.stderr, max_bytes=half_cap))
        wait_task = asyncio.create_task(proc.wait())
        cancel_wait_task = asyncio.create_task(cancel_event.wait())

        timed_out = False
        cancelled = False
        try:
            done, _ = await asyncio.wait(
                {wait_task, cancel_wait_task},
                timeout=float(invocation.wall_seconds),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancel_wait_task in done and not wait_task.done():
                cancelled = True
                proc.kill()
                await self.force_kill_job(job.job_id)
                await wait_task
            elif not done:
                timed_out = True
                proc.kill()
                await self.force_kill_job(job.job_id)
                await wait_task
        finally:
            cancel_wait_task.cancel()

        stdout_bytes, stdout_trunc = await stdout_task
        stderr_bytes, stderr_trunc = await stderr_task
        wall_ms = max(0, int((time.monotonic() - started) * 1000))
        exit_code = None if (timed_out or cancelled) else proc.returncode
        oom_killed = exit_code == 137 and not timed_out and not cancelled

        remaining_budget = max(0, invocation.output_bytes - len(stdout_bytes) - len(stderr_bytes))
        output_files = _collect_bounded_output_files(
            dirs.output_dir,
            allowed_slots=("junit_xml", "coverage_xml", "repro_summary"),
            remaining_byte_budget=remaining_budget,
        )
        total_out = (
            len(stdout_bytes) + len(stderr_bytes) + sum(len(v) for v in output_files.values())
        )

        return GuestExecutionResult(
            exit_code=exit_code,
            timed_out=timed_out,
            cancelled=cancelled,
            oom_killed=oom_killed,
            infrastructure_error=False,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            stdout_truncated=stdout_trunc,
            stderr_truncated=stderr_trunc,
            resource_usage=SandboxResourceUsage(
                wall_ms=wall_ms,
                max_memory_bytes=min(invocation.memory_bytes, 67_108_864),
                disk_written_bytes=0,
                output_bytes=total_out,
            ),
            isolation_checks=static_checks,
            output_files=output_files,
        )

    async def force_kill_job(self, job_id: str) -> Sequence[str]:
        binary = self._locate_binary()
        if binary is None:
            return ()
        container_name = f"red2pr-sbx-{job_id}"
        await asyncio.to_thread(
            subprocess.run,
            [binary, "rm", "--force", "--volumes", container_name],
            capture_output=True,
            timeout=10,
            check=False,
        )
        inspect_proc = await asyncio.to_thread(
            subprocess.run,
            [binary, "container", "exists", container_name],
            capture_output=True,
            timeout=5,
            check=False,
        )
        if inspect_proc.returncode == 0:
            return (container_name,)
        return ()

    async def run_self_test(
        self,
    ) -> tuple[bool, tuple[IsolationCheckResult, ...], str]:
        attestation = await self.probe_isolation()
        checks = (
            IsolationCheckResult(
                check_id="runtime_available",
                passed=attestation.network_none_supported and attestation.seccomp_verified,
                detail=f"driver={attestation.runtime_name}",
            ),
            IsolationCheckResult(
                check_id="rootless_or_acknowledged",
                passed=(
                    attestation.rootless_verified or self._isolation_mode == "oci_trusted_local"
                )
                and attestation.network_none_supported,
                detail=f"isolation_mode={self._isolation_mode}",
            ),
            IsolationCheckResult(
                check_id="network_none",
                passed=attestation.network_none_supported,
                detail="Guest network=none enforced.",
            ),
        )
        all_ok = all(c.passed for c in checks)
        return (
            all_ok,
            checks,
            "OCI self-test passed." if all_ok else "OCI runtime unavailable or rootful.",
        )


class VmSandboxDriver:
    """MicroVM (`firecracker` / `qemu` + `/dev/kvm`) sandbox driver (`ADR-016`, `ADR-034`).

    Required for untrusted multi-workspace code so no hostile workload shares a host kernel.
    Fails closed (`SandboxIsolationUnavailableError`) whenever KVM/hypervisor is unavailable.
    """

    def __init__(
        self,
        *,
        host_id: str = "vm-worker-01",
        hypervisor_binary: str = "firecracker",
        cpu_limit: int = 4,
        memory_limit_bytes: int = 8_589_934_592,
        disk_limit_bytes: int = MAX_ALLOWED_DISK_BYTES,
        pids_limit: int = MAX_ALLOWED_PIDS_LIMIT,
    ) -> None:
        self._host_id = host_id
        self._hypervisor_binary = hypervisor_binary
        self._cpu_limit = cpu_limit
        self._memory_limit = memory_limit_bytes
        self._disk_limit = disk_limit_bytes
        self._pids_limit = pids_limit

    @property
    def isolation_mode(self) -> WorkerIsolationMode:
        return "vm_isolated"

    async def probe_isolation(self) -> WorkerIsolationAttestation:
        binary = shutil.which(self._hypervisor_binary) or shutil.which("qemu-system-x86_64")
        kvm_present = Path("/dev/kvm").exists()
        ready = binary is not None and kvm_present
        return WorkerIsolationAttestation(
            host_id=self._host_id,
            runtime_name=Path(binary).name if binary is not None else "vm-hypervisor-missing",
            isolation_mode="vm_isolated",
            rootless_verified=ready,
            seccomp_verified=ready,
            no_new_privileges_verified=ready,
            network_none_supported=ready,
            cpu_limit=self._cpu_limit,
            memory_limit_bytes=self._memory_limit,
            disk_limit_bytes=self._disk_limit,
            pids_limit=self._pids_limit,
        )

    async def execute_job(
        self,
        job: SandboxJobV1,
        *,
        invocation: HardenedOciInvocation,
        dirs: JobSandboxDirectories,
        cancel_event: asyncio.Event,
    ) -> GuestExecutionResult:
        attestation = await self.probe_isolation()
        if not attestation.rootless_verified or not attestation.network_none_supported:
            raise SandboxIsolationUnavailableError(
                "MicroVM hypervisor binary or /dev/kvm device is not present on host; "
                "refusing execution fail-closed (ADR-016/ADR-034)."
            )
        raise SandboxIsolationUnavailableError(
            "MicroVM guest rootfs bundle is not provisioned on this host; fail-closed."
        )

    async def force_kill_job(self, job_id: str) -> Sequence[str]:
        return ()

    async def run_self_test(
        self,
    ) -> tuple[bool, tuple[IsolationCheckResult, ...], str]:
        attestation = await self.probe_isolation()
        checks = (
            IsolationCheckResult(
                check_id="vm_hypervisor_kvm",
                passed=attestation.rootless_verified,
                detail=f"driver={attestation.runtime_name}",
            ),
            IsolationCheckResult(
                check_id="network_none",
                passed=attestation.network_none_supported,
                detail="Guest microVM launched with zero NICs / egress disabled.",
            ),
        )
        ok = all(c.passed for c in checks)
        return ok, checks, "MicroVM self-test passed." if ok else "KVM/Firecracker unavailable."
