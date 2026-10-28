"""Bomb-safe streaming CI archive inspector & extractor (`U13`, `NFR-14`, `SEC-007`, `SEC-036`).

Enforces strict pre-write archive hygiene on untrusted `.zip` and `.tar*` CI artifacts:
- Compressed archive size `<= 100 MiB` (`NFR-14`).
- Expanded total payload `<= 500 MiB` (`NFR-14`), read in `64 KiB` streaming chunks.
- Extracted entry count `<= 10,000` (`NFR-14`).
- Compression-ratio bomb halt (`ratio > 100:1` once expanded bytes exceed `1 MiB`).
- Rejects `..` path traversal, leading `/` or `\\`, Windows drive prefixes (`C:`), UNC paths,
  control characters, symbolic links, hard links, FIFOs, sockets, and block/char device nodes
  BEFORE creating directories or writing bytes (`SEC-007`, `SEC-036`).
"""

from __future__ import annotations

import io
import os
import posixpath
import re
import shutil
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from red2pr_control.core.errors import BadRequestError

MAX_ARCHIVE_COMPRESSED_BYTES: Final[int] = 100 * 1024 * 1024  # 100 MiB (NFR-14)
MAX_ARCHIVE_EXPANDED_BYTES: Final[int] = 500 * 1024 * 1024  # 500 MiB (NFR-14)
MAX_ARCHIVE_FILE_COUNT: Final[int] = 10_000  # 10,000 files (NFR-14)
MAX_ARCHIVE_FILES: Final[int] = MAX_ARCHIVE_FILE_COUNT
MAX_COMPRESSION_RATIO: Final[float] = 100.0
RATIO_CHECK_MIN_EXPANDED_BYTES: Final[int] = 1024 * 1024  # 1 MiB threshold
STREAM_CHUNK_BYTES: Final[int] = 65_536

_DRIVE_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:")
_CONTROL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")


class ArchiveSecurityError(BadRequestError):
    """Raised when an untrusted CI archive violates NFR-14, SEC-007, or SEC-036."""

    def __init__(self, *, code: str, detail: str) -> None:
        super().__init__(code=code, detail=detail)


ArchiveHazardError = ArchiveSecurityError


@dataclass(frozen=True, slots=True)
class ExtractedArchiveMember:
    """Verified regular file entry inspected or extracted from an archive."""

    safe_rel_path: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ArchiveInspectionResult:
    """Deterministic summary of a bomb-checked archive."""

    archive_format: str
    compressed_bytes: int
    expanded_bytes: int
    file_count: int
    members: tuple[ExtractedArchiveMember, ...]

    @property
    def extracted_file_count(self) -> int:
        return self.file_count


ArchiveInspectionSummary = ArchiveInspectionResult


def validate_safe_archive_member_path(raw_name: str) -> str | None:
    """Validate and canonicalize an archive entry path (`SEC-007`).

    Returns `None` for benign directory-only entries (`""` or `"."`), or raises
    `ArchiveSecurityError` on any traversal, absolute path, drive prefix, or control char.
    """
    if not raw_name or _CONTROL_CHAR_RE.search(raw_name):
        raise ArchiveSecurityError(
            code="archive_path_traversal",
            detail="Archive entry name is empty or contains forbidden control characters.",
        )

    if raw_name.startswith(("/", "\\")) or _DRIVE_PREFIX_RE.match(raw_name):
        raise ArchiveSecurityError(
            code="archive_path_traversal",
            detail=f"Archive entry '{raw_name[:80]}' uses an absolute or drive-prefixed path.",
        )

    if "\\" in raw_name:
        raise ArchiveSecurityError(
            code="archive_path_traversal",
            detail=f"Archive entry '{raw_name[:80]}' contains forbidden backslash separators.",
        )

    stripped = raw_name.rstrip("/")
    if not stripped or stripped == ".":
        return None

    segments = stripped.split("/")
    for seg in segments:
        if seg in ("", "."):
            continue
        if seg == ".." or _DRIVE_PREFIX_RE.match(seg):
            raise ArchiveSecurityError(
                code="archive_path_traversal",
                detail=f"Archive entry '{raw_name[:80]}' attempts parent directory traversal.",
            )

    normalized = posixpath.normpath(stripped)
    if (
        normalized in ("", ".", "..")
        or normalized.startswith("../")
        or normalized.startswith("/")
        or "/../" in f"/{normalized}/"
    ):
        raise ArchiveSecurityError(
            code="archive_path_traversal",
            detail=f"Archive entry '{raw_name[:80]}' escapes archive extraction root.",
        )
    return normalized


normalize_safe_archive_member_path = validate_safe_archive_member_path


def _resolve_confined_destination(resolved_root: Path, safe_rel_path: str) -> Path:
    candidate = (resolved_root / Path(*safe_rel_path.split("/"))).resolve()
    if candidate == resolved_root or not candidate.is_relative_to(resolved_root):
        raise ArchiveSecurityError(
            code="archive_path_traversal",
            detail=f"Resolved extraction target for '{safe_rel_path[:80]}' escapes root.",
        )
    return candidate


def _check_ratio_and_budget(
    *,
    total_expanded: int,
    compressed_reference: int,
    max_expanded_bytes: int,
    max_ratio: float,
) -> None:
    if total_expanded > max_expanded_bytes:
        raise ArchiveSecurityError(
            code="archive_expanded_limit_exceeded",
            detail=(
                f"Archive expanded payload exceeds {max_expanded_bytes} bytes ceiling (NFR-14)."
            ),
        )
    if total_expanded >= RATIO_CHECK_MIN_EXPANDED_BYTES:
        denom = max(1, compressed_reference)
        if (total_expanded / denom) > max_ratio:
            raise ArchiveSecurityError(
                code="archive_compression_bomb",
                detail=(
                    f"Archive expansion ratio ({total_expanded / denom:.1f}:1) exceeds "
                    f"maximum safe compression ratio ({max_ratio:.0f}:1) (SEC-036)."
                ),
            )


def _inspect_zip(
    raw_bytes: bytes,
    *,
    dest_dir: Path | None,
    max_expanded_bytes: int,
    max_files: int,
    max_ratio: float,
) -> ArchiveInspectionResult:
    resolved_root = dest_dir.resolve() if dest_dir is not None else None
    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes), mode="r") as zf:
            return _inspect_open_zip(
                zf,
                compressed_bytes=len(raw_bytes),
                resolved_root=resolved_root,
                max_expanded_bytes=max_expanded_bytes,
                max_files=max_files,
                max_ratio=max_ratio,
            )
    except (zipfile.BadZipFile, OSError, EOFError) as exc:
        raise ArchiveSecurityError(
            code="archive_corrupt",
            detail="Malformed or truncated ZIP archive.",
        ) from exc


def _inspect_open_zip(
    zf: zipfile.ZipFile,
    *,
    compressed_bytes: int,
    resolved_root: Path | None,
    max_expanded_bytes: int,
    max_files: int,
    max_ratio: float,
) -> ArchiveInspectionResult:
    if True:
        infos = zf.infolist()
        total_expanded = 0
        total_compressed_seen = 0
        file_count = 0
        members: list[ExtractedArchiveMember] = []

        # Pass 1: Pre-validate ALL headers before writing a single byte (SEC-007, SEC-036)
        planned_entries: list[tuple[zipfile.ZipInfo, str | None, bool]] = []
        for info in infos:
            is_dir = info.is_dir()
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if unix_mode != 0:
                file_type = stat.S_IFMT(unix_mode)
                if file_type == stat.S_IFLNK:
                    raise ArchiveSecurityError(
                        code="archive_forbidden_entry_type",
                        detail=(f"ZIP entry '{info.filename[:80]}' is a symbolic link (SEC-036)."),
                    )
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ArchiveSecurityError(
                        code="archive_forbidden_entry_type",
                        detail=(
                            f"ZIP entry '{info.filename[:80]}' uses forbidden special file mode "
                            f"{oct(file_type)} (SEC-036)."
                        ),
                    )

            safe_rel = validate_safe_archive_member_path(info.filename)
            if not is_dir and safe_rel is not None:
                file_count += 1
                if file_count > max_files:
                    raise ArchiveSecurityError(
                        code="archive_file_count_exceeded",
                        detail=f"Archive exceeds {max_files} extracted files limit (NFR-14).",
                    )
                if info.file_size > max_expanded_bytes:
                    raise ArchiveSecurityError(
                        code="archive_expanded_limit_exceeded",
                        detail=(
                            f"ZIP entry '{safe_rel[:80]}' declared size exceeds "
                            f"{max_expanded_bytes} bytes (NFR-14)."
                        ),
                    )
            planned_entries.append((info, safe_rel, is_dir))

        # Pass 2: Stream-read (and optionally write) with live byte & ratio accounting
        for info, safe_rel, is_dir in planned_entries:
            if is_dir or safe_rel is None:
                if resolved_root is not None and safe_rel is not None:
                    dir_path = _resolve_confined_destination(resolved_root, safe_rel)
                    dir_path.mkdir(parents=True, exist_ok=True)
                continue

            total_compressed_seen += max(1, info.compress_size)
            member_bytes = 0
            out_path: Path | None = None
            if resolved_root is not None:
                out_path = _resolve_confined_destination(resolved_root, safe_rel)
                out_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                with zf.open(info, mode="r") as src_stream:
                    if out_path is not None:
                        with out_path.open("wb") as dst_file:
                            while True:
                                chunk = src_stream.read(STREAM_CHUNK_BYTES)
                                if not chunk:
                                    break
                                member_bytes += len(chunk)
                                total_expanded += len(chunk)
                                _check_ratio_and_budget(
                                    total_expanded=total_expanded,
                                    compressed_reference=min(
                                        compressed_bytes, max(1, total_compressed_seen)
                                    ),
                                    max_expanded_bytes=max_expanded_bytes,
                                    max_ratio=max_ratio,
                                )
                                dst_file.write(chunk)
                    else:
                        while True:
                            chunk = src_stream.read(STREAM_CHUNK_BYTES)
                            if not chunk:
                                break
                            member_bytes += len(chunk)
                            total_expanded += len(chunk)
                            _check_ratio_and_budget(
                                total_expanded=total_expanded,
                                compressed_reference=min(
                                    compressed_bytes, max(1, total_compressed_seen)
                                ),
                                max_expanded_bytes=max_expanded_bytes,
                                max_ratio=max_ratio,
                            )
            except ArchiveSecurityError:
                raise
            except (zipfile.BadZipFile, OSError, EOFError, RuntimeError) as exc:
                raise ArchiveSecurityError(
                    code="archive_corrupt",
                    detail=f"Failed reading ZIP entry '{safe_rel[:80]}': corrupt stream.",
                ) from exc

            members.append(ExtractedArchiveMember(safe_rel_path=safe_rel, size_bytes=member_bytes))

        return ArchiveInspectionResult(
            archive_format="zip",
            compressed_bytes=compressed_bytes,
            expanded_bytes=total_expanded,
            file_count=file_count,
            members=tuple(members),
        )


def _inspect_tar(
    raw_bytes: bytes,
    *,
    dest_dir: Path | None,
    max_expanded_bytes: int,
    max_files: int,
    max_ratio: float,
) -> ArchiveInspectionResult:
    resolved_root = dest_dir.resolve() if dest_dir is not None else None
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:*") as tf:
            total_expanded = 0
            file_count = 0
            members_out: list[ExtractedArchiveMember] = []
            planned: list[tuple[tarfile.TarInfo, str | None]] = []

            # Pass 1: Pre-validate ALL tar headers before touching disk (SEC-007, SEC-036)
            try:
                tar_members = tf.getmembers()
            except (tarfile.TarError, OSError, EOFError) as exc:
                raise ArchiveSecurityError(
                    code="archive_corrupt",
                    detail="Corrupt TAR member header table.",
                ) from exc

            for member in tar_members:
                if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
                    continue
                if (
                    member.issym()
                    or member.islnk()
                    or member.isfifo()
                    or member.ischr()
                    or member.isblk()
                    or member.isdev()
                ):
                    raise ArchiveSecurityError(
                        code="archive_forbidden_entry_type",
                        detail=(
                            f"TAR entry '{member.name[:80]}' is a symlink, hardlink, or special "
                            "device/FIFO node (SEC-036)."
                        ),
                    )
                if not (member.isfile() or member.isdir()):
                    raise ArchiveSecurityError(
                        code="archive_forbidden_entry_type",
                        detail=f"TAR entry '{member.name[:80]}' has unsupported member type.",
                    )

                safe_rel = validate_safe_archive_member_path(member.name)
                if member.isfile() and safe_rel is not None:
                    file_count += 1
                    if file_count > max_files:
                        raise ArchiveSecurityError(
                            code="archive_file_count_exceeded",
                            detail=f"Archive exceeds {max_files} extracted files limit (NFR-14).",
                        )
                    if member.size < 0 or member.size > max_expanded_bytes:
                        raise ArchiveSecurityError(
                            code="archive_expanded_limit_exceeded",
                            detail=(
                                f"TAR entry '{safe_rel[:80]}' declared size exceeds "
                                f"{max_expanded_bytes} bytes (NFR-14)."
                            ),
                        )
                planned.append((member, safe_rel))

            # Pass 2: Stream-extract regular files with live byte & ratio accounting
            for member, safe_rel in planned:
                if member.isdir() or safe_rel is None:
                    if resolved_root is not None and safe_rel is not None:
                        dir_path = _resolve_confined_destination(resolved_root, safe_rel)
                        dir_path.mkdir(parents=True, exist_ok=True)
                    continue

                extracted_stream = tf.extractfile(member)
                if extracted_stream is None:
                    continue

                member_bytes = 0
                out_path: Path | None = None
                if resolved_root is not None:
                    out_path = _resolve_confined_destination(resolved_root, safe_rel)
                    out_path.parent.mkdir(parents=True, exist_ok=True)

                with extracted_stream:
                    if out_path is not None:
                        with out_path.open("wb") as dst_file:
                            while True:
                                chunk = extracted_stream.read(STREAM_CHUNK_BYTES)
                                if not chunk:
                                    break
                                member_bytes += len(chunk)
                                total_expanded += len(chunk)
                                _check_ratio_and_budget(
                                    total_expanded=total_expanded,
                                    compressed_reference=len(raw_bytes),
                                    max_expanded_bytes=max_expanded_bytes,
                                    max_ratio=max_ratio,
                                )
                                dst_file.write(chunk)
                    else:
                        while True:
                            chunk = extracted_stream.read(STREAM_CHUNK_BYTES)
                            if not chunk:
                                break
                            member_bytes += len(chunk)
                            total_expanded += len(chunk)
                            _check_ratio_and_budget(
                                total_expanded=total_expanded,
                                compressed_reference=len(raw_bytes),
                                max_expanded_bytes=max_expanded_bytes,
                                max_ratio=max_ratio,
                            )

                members_out.append(
                    ExtractedArchiveMember(safe_rel_path=safe_rel, size_bytes=member_bytes)
                )

            return ArchiveInspectionResult(
                archive_format="tar",
                compressed_bytes=len(raw_bytes),
                expanded_bytes=total_expanded,
                file_count=file_count,
                members=tuple(members_out),
            )
    except ArchiveSecurityError:
        raise
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ArchiveSecurityError(
            code="archive_corrupt",
            detail="Malformed or unsupported TAR archive.",
        ) from exc


def inspect_and_extract_archive(
    raw_bytes: bytes,
    *,
    filename: str | None = None,
    dest_dir: Path | None = None,
    format_hint: str | None = None,
    max_compressed_bytes: int = MAX_ARCHIVE_COMPRESSED_BYTES,
    max_expanded_bytes: int = MAX_ARCHIVE_EXPANDED_BYTES,
    max_files: int = MAX_ARCHIVE_FILE_COUNT,
    max_ratio: float = MAX_COMPRESSION_RATIO,
) -> ArchiveInspectionResult:
    """Validate and optionally extract an untrusted `.zip` or `.tar*` archive safely.

    If `dest_dir` is supplied and any security or budget violation occurs mid-stream,
    all partially extracted contents inside `dest_dir` are scrubbed before raising.
    """
    if len(raw_bytes) > max_compressed_bytes:
        raise ArchiveSecurityError(
            code="archive_compressed_limit_exceeded",
            detail=(
                f"Compressed archive size ({len(raw_bytes)} bytes) exceeds "
                f"{max_compressed_bytes} bytes ceiling (NFR-14)."
            ),
        )
    if not raw_bytes:
        raise ArchiveSecurityError(
            code="archive_corrupt",
            detail="Archive payload is empty.",
        )

    staging_subdir: Path | None = None
    if dest_dir is not None:
        dest_dir.mkdir(parents=True, exist_ok=True)
        staging_subdir = dest_dir / f".extract_stage_{os.urandom(6).hex()}"
        staging_subdir.mkdir(parents=True, exist_ok=False)

    try:
        hint = (format_hint or filename or "").strip().lower()
        is_zip_magic = raw_bytes[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
        if hint == "zip" or (hint == "" and is_zip_magic) or hint.endswith(".zip"):
            result = _inspect_zip(
                raw_bytes,
                dest_dir=staging_subdir,
                max_expanded_bytes=max_expanded_bytes,
                max_files=max_files,
                max_ratio=max_ratio,
            )
        else:
            result = _inspect_tar(
                raw_bytes,
                dest_dir=staging_subdir,
                max_expanded_bytes=max_expanded_bytes,
                max_files=max_files,
                max_ratio=max_ratio,
            )

        if staging_subdir is not None and dest_dir is not None:
            for item in staging_subdir.iterdir():
                target = dest_dir / item.name
                if target.exists():
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                shutil.move(str(item), str(target))
            shutil.rmtree(staging_subdir, ignore_errors=True)
        return result
    except Exception:
        if staging_subdir is not None:
            shutil.rmtree(staging_subdir, ignore_errors=True)
        raise
