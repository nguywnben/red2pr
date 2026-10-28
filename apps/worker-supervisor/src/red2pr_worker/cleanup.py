"""Ephemeral sandbox workspace preparation, safe extraction, and verified teardown.

Implements `SAN-01`, `T-SAN-01-P/N`, `SEC-007`, `SEC-026`, `SEC-029`, and `SEC-036`:
- Symlink-free per-job scratch hierarchy (`worktree`, `tmp`, `output`).
- Safe source archive extraction (`<=10k` files, `<=500 MiB`, rejecting symlinks/hardlinks,
  special device nodes, and path traversal).
- Post-job container/VM termination and non-following (`lstat`/`scandir`) recursive cleanup
  that unlinks guest-planted symlinks without ever touching or chmod'ing host targets,
  followed by hard zero-residue verification.
"""

from __future__ import annotations

import contextlib
import io
import os
import posixpath
import re
import stat
import tarfile
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from py_contracts.worker import IsolationCheckResult

MAX_SOURCE_ARCHIVE_FILES = 10_000
MAX_SOURCE_ARCHIVE_BYTES = 524_288_000  # 500 MiB (SEC-026)

_SAFE_JOB_ID_RE = re.compile(r"^[0-9A-Za-z_-]{8,64}$")
_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class UnsafeSourceArchiveError(ValueError):
    """Raised when a repository snapshot archive violates traversal/symlink/size guards."""


@dataclass(frozen=True, slots=True)
class JobSandboxDirectories:
    """Isolated per-job host scratch directories mounted into a single sandbox run."""

    job_id: str
    root_dir: Path
    worktree_dir: Path
    tmp_dir: Path
    output_dir: Path


@dataclass(frozen=True, slots=True)
class CleanupVerificationResult:
    """Deterministic post-job workspace & runtime cleanup verification outcome."""

    passed: bool
    residual_paths: tuple[str, ...]
    residual_sandboxes: tuple[str, ...]
    symlinks_unlinked: int
    detail: str

    def to_isolation_check(self) -> IsolationCheckResult:
        return IsolationCheckResult(
            check_id="ephemeral_cleanup",
            passed=self.passed,
            detail=self.detail[:512],
        )


def _chmod_owner_rwx(path: Path, *, is_dir: bool) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700 if is_dir else 0o600)


def _assert_no_symlink_ancestors(base_dir: Path) -> None:
    current = base_dir
    checked: list[Path] = []
    while True:
        checked.append(current)
        if current.parent == current:
            break
        current = current.parent
    for item in reversed(checked):
        if item.exists() and item.is_symlink():
            raise UnsafeSourceArchiveError(
                f"Sandbox scratch ancestor {item.name!r} is a symbolic link (SEC-007)."
            )


def _normalize_archive_member_path(raw_name: str) -> str | None:
    replaced = raw_name.replace("\\", "/").strip()
    if not replaced or replaced == ".":
        return None
    if "\x00" in replaced or replaced.startswith("/") or _WIN_DRIVE_RE.match(replaced):
        raise UnsafeSourceArchiveError(
            "Source archive contains absolute or drive-prefixed member path (SEC-007)."
        )
    parts = [seg for seg in replaced.split("/") if seg not in ("", ".")]
    if not parts:
        return None
    if any(seg == ".." for seg in parts):
        raise UnsafeSourceArchiveError(
            "Source archive contains '..' path traversal component (SEC-007)."
        )
    normalized = posixpath.normpath("/".join(parts))
    if normalized.startswith("..") or normalized.startswith("/"):
        raise UnsafeSourceArchiveError("Normalized archive path escapes worktree root (SEC-007).")
    return normalized


def safe_extract_source_archive(
    archive_bytes: bytes,
    *,
    worktree_dir: Path,
    max_files: int = MAX_SOURCE_ARCHIVE_FILES,
    max_total_bytes: int = MAX_SOURCE_ARCHIVE_BYTES,
) -> int:
    """Safely extract `.tar` / `.tar.gz` repository bytes into `worktree_dir` (`SEC-007`)."""
    if max_files < 1 or max_total_bytes < 1:
        raise ValueError("Archive extraction limits must be positive.")

    worktree_resolved = worktree_dir.resolve(strict=True)
    extracted_files = 0
    extracted_bytes = 0

    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tf:
            for member in tf.getmembers():
                rel_path = _normalize_archive_member_path(member.name)
                if rel_path is None:
                    continue
                if member.issym() or member.islnk():
                    raise UnsafeSourceArchiveError(
                        f"Source archive member {rel_path!r} is a symlink or hardlink "
                        "(SEC-007/SEC-036)."
                    )
                if member.isfifo() or member.ischr() or member.isblk() or member.isdev():
                    raise UnsafeSourceArchiveError(
                        f"Source archive member {rel_path!r} is a forbidden special file."
                    )

                target = (worktree_resolved / rel_path).resolve(strict=False)
                try:
                    target.relative_to(worktree_resolved)
                except ValueError as exc:
                    raise UnsafeSourceArchiveError(
                        f"Archive member {rel_path!r} resolves outside worktree."
                    ) from exc

                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise UnsafeSourceArchiveError(
                        f"Unsupported archive entry type for {rel_path!r}."
                    )

                extracted_files += 1
                if extracted_files > max_files:
                    raise UnsafeSourceArchiveError(
                        f"Source archive exceeds maximum file count ({max_files}) (SEC-026)."
                    )
                if member.size < 0 or extracted_bytes + member.size > max_total_bytes:
                    raise UnsafeSourceArchiveError(
                        f"Source archive exceeds maximum byte cap ({max_total_bytes}) (SEC-026)."
                    )

                target.parent.mkdir(parents=True, exist_ok=True)
                reader = tf.extractfile(member)
                if reader is None:
                    raise UnsafeSourceArchiveError(f"Failed to read archive member {rel_path!r}.")
                with reader, target.open("wb") as out_f:
                    remaining = member.size
                    while True:
                        chunk = reader.read(65_536)
                        if not chunk:
                            break
                        extracted_bytes += len(chunk)
                        if extracted_bytes > max_total_bytes or len(chunk) > remaining + 65_536:
                            raise UnsafeSourceArchiveError(
                                "Source archive stream exceeded declared/max byte cap (SEC-026)."
                            )
                        remaining -= len(chunk)
                        out_f.write(chunk)
    except tarfile.TarError as exc:
        raise UnsafeSourceArchiveError("Malformed tar source archive.") from exc

    return extracted_files


def _remove_tree_no_follow(root: Path) -> tuple[int, list[str]]:
    """Recursively remove `root` without following any symlinks (`SEC-007`, `SEC-029`)."""
    symlinks_removed = 0
    errors: list[str] = []

    if not root.exists() and not root.is_symlink():
        return 0, []

    if root.is_symlink():
        try:
            os.unlink(root)
            return 1, []
        except OSError as exc:
            return 0, [f"{root}: {exc}"]

    def _sweep_dir(dir_path: Path) -> None:
        nonlocal symlinks_removed
        with contextlib.suppress(OSError):
            os.chmod(dir_path, stat.S_IRWXU)

        try:
            with os.scandir(dir_path) as it:
                entries = list(it)
        except OSError as exc:
            errors.append(f"scandir:{dir_path.name}:{exc}")
            return

        for entry in entries:
            entry_path = Path(entry.path)
            try:
                is_link = entry.is_symlink()
            except OSError:
                is_link = entry_path.is_symlink()

            if is_link:
                try:
                    os.unlink(entry_path)
                    symlinks_removed += 1
                except OSError:
                    try:
                        os.rmdir(entry_path)
                        symlinks_removed += 1
                    except OSError as exc:
                        errors.append(f"unlink_symlink:{entry.name}:{exc}")
                continue

            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False

            if is_dir:
                _sweep_dir(entry_path)
                try:
                    os.rmdir(entry_path)
                except OSError as exc:
                    errors.append(f"rmdir:{entry.name}:{exc}")
            else:
                with contextlib.suppress(OSError):
                    os.chmod(entry_path, stat.S_IRUSR | stat.S_IWUSR)
                try:
                    os.unlink(entry_path)
                except OSError as exc:
                    errors.append(f"unlink:{entry.name}:{exc}")

    _sweep_dir(root)
    try:
        os.rmdir(root)
    except OSError as exc:
        errors.append(f"rmdir_root:{root.name}:{exc}")

    return symlinks_removed, errors


class EphemeralWorkspaceCleaner:
    """Manages isolated per-job host scratch directories and verifies zero residue."""

    def __init__(self, base_scratch_dir: Path) -> None:
        _assert_no_symlink_ancestors(base_scratch_dir)
        base_scratch_dir.mkdir(parents=True, exist_ok=True)
        _chmod_owner_rwx(base_scratch_dir, is_dir=True)
        self._base_dir = base_scratch_dir.resolve(strict=True)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def prepare_job_directories(self, job_id: str) -> JobSandboxDirectories:
        clean_id = job_id.strip()
        if not _SAFE_JOB_ID_RE.fullmatch(clean_id):
            raise ValueError(f"Unsafe sandbox job_id for filesystem path: {job_id!r}")
        _assert_no_symlink_ancestors(self._base_dir)

        job_root = self._base_dir / f"job-{clean_id}"
        if job_root.exists() or job_root.is_symlink():
            _remove_tree_no_follow(job_root)

        worktree = job_root / "worktree"
        tmp_dir = job_root / "tmp"
        output_dir = job_root / "output"
        for d in (job_root, worktree, tmp_dir, output_dir):
            d.mkdir(parents=True, exist_ok=False)
            _chmod_owner_rwx(d, is_dir=True)

        return JobSandboxDirectories(
            job_id=clean_id,
            root_dir=job_root,
            worktree_dir=worktree,
            tmp_dir=tmp_dir,
            output_dir=output_dir,
        )

    async def teardown_and_verify(
        self,
        dirs: JobSandboxDirectories,
        *,
        kill_runtime: Callable[[], Awaitable[Sequence[str]]] | None = None,
    ) -> CleanupVerificationResult:
        residual_sandboxes: list[str] = []
        runtime_error: str | None = None
        if kill_runtime is not None:
            try:
                lingering = await kill_runtime()
                residual_sandboxes.extend(str(item) for item in lingering)
            except Exception as exc:
                runtime_error = f"runtime_kill_error:{type(exc).__name__}"

        symlinks_unlinked, fs_errors = _remove_tree_no_follow(dirs.root_dir)
        residual_paths: list[str] = []
        if dirs.root_dir.exists() or dirs.root_dir.is_symlink():
            residual_paths.append(dirs.root_dir.name)
            try:
                with os.scandir(dirs.root_dir) as it:
                    for entry in it:
                        residual_paths.append(f"{dirs.root_dir.name}/{entry.name}")
            except OSError:
                pass

        passed = (
            len(residual_paths) == 0
            and len(residual_sandboxes) == 0
            and len(fs_errors) == 0
            and runtime_error is None
        )
        if passed:
            detail = (
                f"Ephemeral workspace and sandbox cleanly destroyed "
                f"(symlinks_unlinked={symlinks_unlinked}, residuals=0)."
            )
        else:
            parts = []
            if residual_paths:
                parts.append(f"residual_paths={len(residual_paths)}")
            if residual_sandboxes:
                parts.append(f"residual_sandboxes={len(residual_sandboxes)}")
            if fs_errors:
                parts.append(f"fs_errors={fs_errors[0][:120]}")
            if runtime_error:
                parts.append(runtime_error)
            detail = "Cleanup verification failed: " + "; ".join(parts)

        return CleanupVerificationResult(
            passed=passed,
            residual_paths=tuple(residual_paths),
            residual_sandboxes=tuple(residual_sandboxes),
            symlinks_unlinked=symlinks_unlinked,
            detail=detail,
        )
