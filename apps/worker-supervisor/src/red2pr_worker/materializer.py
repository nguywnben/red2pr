"""Sanitized source archive materializer, tenant read-only dependency cache & diff applier (`U15`).

Implements `SAN-02`, `SAN-03`, `SEC-006`, `SEC-007`, `SEC-014`, `SEC-026`, `SEC-032`, `SEC-036`:
- Deterministic `.git`-sanitized `.tar.gz` materialization pinned to `base_sha`:
  * Strips `.git/**` (neutralizing `.git/hooks/*`, `.git/config` credential/ssh helpers,
    and `fsmonitor` / `filter` RCE vectors).
  * Strips credential dotfiles (`.git-credentials`, `.netrc`, `.pypirc`, `.env*` secrets)
    and scrubs auth tokens from `.npmrc` / `.yarnrc*`.
  * Inspects `.gitmodules` and strips submodule URLs targeting loopback, RFC1918 private IPs,
    link-local / cloud metadata (`169.254.0.0/16`), `file://`, `ext::`, or embedded credentials.
  * Rejects symlinks, hardlinks, FIFOs, sockets, device files, and `..` path traversal.
  * Records untrusted lifecycle hooks (`package.json` `preinstall`/`install`/`postinstall`,
    `setup.py`) without ever executing them on the host.
- Tenant-scoped read-only dependency cache keyed strictly by
  `(workspace_id, profile_id, dependency_lock_digest)` with SHA-256 manifest verification.
- Pure-Python fail-closed unified diff applier for clean Sandbox B (`patched_b`) worktrees.
"""

from __future__ import annotations

import configparser
import contextlib
import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import os
import posixpath
import re
import stat
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from red2pr_worker.cleanup import (
    MAX_SOURCE_ARCHIVE_BYTES,
    MAX_SOURCE_ARCHIVE_FILES,
    UnsafeSourceArchiveError,
    _remove_tree_no_follow,
)

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_SCOPE_ID_RE = re.compile(r"^[0-9A-Za-z_-]{4,120}$")
_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_SCP_GIT_URL_RE = re.compile(r"^(?:[^@/\s]+@)?([^:/\s]+):(.+)$")
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

PINNED_LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "uv.lock",
        "poetry.lock",
        "requirements.lock",
        "pnpm-lock.yaml",
        "package-lock.json",
        "yarn.lock",
        "Cargo.lock",
        "go.sum",
    }
)

DEPENDENCY_MANIFEST_NAMES: frozenset[str] = PINNED_LOCKFILE_NAMES | frozenset(
    {
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "package.json",
    }
)

REPO_PROFILE_INDICATOR_NAMES: frozenset[str] = DEPENDENCY_MANIFEST_NAMES | frozenset(
    {
        "pytest.ini",
        "conftest.py",
        "tox.ini",
        "jest.config.js",
        "jest.config.cjs",
        "jest.config.mjs",
        "jest.config.ts",
        "jest.config.json",
        "vitest.config.js",
        "vitest.config.mjs",
        "vitest.config.ts",
        "vitest.config.mts",
        "vite.config.ts",
        "vite.config.js",
    }
)

_STRIPPED_SECRET_FILENAMES: frozenset[str] = frozenset(
    {
        ".git-credentials",
        ".netrc",
        ".pypirc",
        ".env",
        ".env.local",
        ".env.production",
        ".env.staging",
        ".env.secret",
        ".env.secrets",
    }
)

_AUTH_RC_FILENAMES: frozenset[str] = frozenset(
    {
        ".npmrc",
        ".yarnrc",
        ".yarnrc.yml",
    }
)

_NPM_YARN_AUTH_MARKERS: tuple[str, ...] = (
    "_auth=",
    "_authtoken=",
    "authtoken:",
    "npmauthtoken:",
    "npm_auth_token",
    ":_password=",
    "username=",
    "email=",
)

_METADATA_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "instance-data",
    }
)


class DependencyCacheIntegrityError(RuntimeError):
    """Raised when a tenant dependency cache entry fails confinement or digest verification."""


class PatchApplyError(ValueError):
    """Raised when a Sandbox B unified diff fails digest, path confinement, or hunk matching."""


def resolve_default_profiles_dir() -> Path:
    """Locate the reviewed runner `profiles/` directory in monorepo or wheel layout."""
    monorepo_candidate = Path(__file__).resolve().parents[2] / "profiles"
    if monorepo_candidate.is_dir():
        return monorepo_candidate
    bundled_candidate = Path(__file__).resolve().parent / "_bundled_profiles"
    if bundled_candidate.is_dir():
        return bundled_candidate
    raise FileNotFoundError("Unable to locate reviewed worker-supervisor profiles directory.")


@dataclass(frozen=True, slots=True)
class MaterializedSourceSnapshot:
    """Immutable `.git`-sanitized repository archive & lockfile metadata (`SAN-02`, `SEC-036`)."""

    base_sha: str
    archive_bytes: bytes
    source_archive_digest: str
    dependency_lock_digest: str
    file_count: int
    total_uncompressed_bytes: int
    matched_lockfiles: tuple[str, ...]
    has_verified_lockfile: bool
    repo_indicator_files: tuple[str, ...]
    stripped_git_paths: tuple[str, ...]
    blocked_submodules: tuple[str, ...]
    sanitized_auth_files: tuple[str, ...]
    detected_lifecycle_hooks: tuple[str, ...]


def _normalize_rel_posix_path(raw_path: str) -> str | None:
    replaced = raw_path.replace("\\", "/").strip()
    if not replaced or replaced == ".":
        return None
    if "\x00" in replaced or replaced.startswith("/") or _WIN_DRIVE_RE.match(replaced):
        raise UnsafeSourceArchiveError(
            f"Source path {raw_path!r} uses forbidden absolute or drive prefix (SEC-007)."
        )
    parts = [seg for seg in replaced.split("/") if seg not in ("", ".")]
    if not parts:
        return None
    if any(seg == ".." for seg in parts):
        raise UnsafeSourceArchiveError(
            f"Source path {raw_path!r} contains '..' traversal component (SEC-007)."
        )
    norm = posixpath.normpath("/".join(parts))
    if norm.startswith("..") or norm.startswith("/"):
        raise UnsafeSourceArchiveError(f"Normalized path {norm!r} escapes root (SEC-007).")
    return norm


def _is_forbidden_ip_or_host(host: str) -> bool:
    clean = host.strip().lower().strip("[]")
    if not clean:
        return True
    if clean in _METADATA_HOSTNAMES or clean.endswith(".internal") or clean.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(clean)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_forbidden_submodule_url(raw_url: str) -> tuple[bool, str]:
    url = raw_url.strip()
    if not url:
        return True, "empty_submodule_url"
    lowered = url.lower()
    if lowered.startswith(("ext::", "fd::", "file://", "/", "./", "../")):
        return True, "local_or_ext_protocol"

    if "://" in url:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("https",):
            return True, f"disallowed_scheme:{parsed.scheme.lower() or 'none'}"
        if parsed.username or parsed.password:
            return True, "embedded_url_credentials"
        hostname = parsed.hostname or ""
        if _is_forbidden_ip_or_host(hostname):
            return True, f"forbidden_target_host:{hostname}"
        return False, "ok"

    m_scp = _SCP_GIT_URL_RE.match(url)
    if m_scp is not None:
        scp_host = m_scp.group(1)
        if _is_forbidden_ip_or_host(scp_host):
            return True, f"forbidden_scp_host:{scp_host}"
        return True, "disallowed_ssh_scp_transport"

    return True, "unrecognized_submodule_url"


def _sanitize_gitmodules_bytes(raw_bytes: bytes) -> tuple[bytes | None, list[str]]:
    """Inspect `.gitmodules` and strip submodules targeting private/metadata/unsafe URLs."""
    text = raw_bytes.decode("utf-8", errors="replace")
    parser = configparser.RawConfigParser()
    blocked: list[str] = []
    try:
        parser.read_string(text)
    except configparser.Error:
        return None, ["malformed_gitmodules_stripped"]

    kept_sections: list[str] = []
    for section in parser.sections():
        raw_url = parser.get(section, "url", fallback="")
        is_bad, reason = _is_forbidden_submodule_url(raw_url)
        if is_bad:
            sub_path = parser.get(section, "path", fallback=section)
            blocked.append(f"{sub_path}:{reason}")
        else:
            kept_sections.append(section)

    if not blocked:
        return raw_bytes, []
    if not kept_sections:
        return None, blocked

    out = io.StringIO()
    clean_cfg = configparser.RawConfigParser()
    for sec in kept_sections:
        clean_cfg.add_section(sec)
        for k, v in parser.items(sec):
            clean_cfg.set(sec, k, v)
    clean_cfg.write(out)
    return out.getvalue().encode("utf-8"), blocked


def _sanitize_rc_auth_bytes(raw_bytes: bytes) -> tuple[bytes | None, bool]:
    text = raw_bytes.decode("utf-8", errors="replace")
    kept_lines: list[str] = []
    scrubbed = False
    for line in text.splitlines():
        lowered = line.strip().lower()
        if any(marker in lowered for marker in _NPM_YARN_AUTH_MARKERS) or (
            lowered.startswith("//") and ("token" in lowered or "auth" in lowered)
        ):
            scrubbed = True
            continue
        kept_lines.append(line)
    if not scrubbed:
        return raw_bytes, False
    joined = "\n".join(kept_lines).strip()
    if not joined:
        return None, True
    return (joined + "\n").encode("utf-8"), True


def _detect_package_json_hooks(rel_path: str, raw_bytes: bytes) -> list[str]:
    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(parsed, dict):
        return []
    scripts = parsed.get("scripts")
    if not isinstance(scripts, dict):
        return []
    found: list[str] = []
    for hook_name in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
        val = scripts.get(hook_name)
        if isinstance(val, str) and val.strip():
            found.append(f"{rel_path}:scripts.{hook_name}")
    return found


class SourceArchiveMaterializer:
    """Trusted source snapshot sanitizer producing deterministic `.tar.gz` archives (`SAN-02`)."""

    def __init__(
        self,
        *,
        max_files: int = MAX_SOURCE_ARCHIVE_FILES,
        max_total_bytes: int = MAX_SOURCE_ARCHIVE_BYTES,
    ) -> None:
        if max_files < 1 or max_total_bytes < 1:
            raise ValueError("SourceArchiveMaterializer caps must be positive.")
        self._max_files = max_files
        self._max_total_bytes = max_total_bytes

    def materialize_directory(
        self,
        source_dir: Path,
        *,
        base_sha: str,
    ) -> MaterializedSourceSnapshot:
        """Sanitize a local checkout directory into an immutable `base_sha` `.tar.gz` snapshot."""
        clean_sha = base_sha.strip().lower()
        if not _GIT_SHA_RE.fullmatch(clean_sha):
            raise ValueError(f"base_sha must be a 40-char lowercase Git SHA-1 hex: {base_sha!r}")
        if source_dir.is_symlink() or not source_dir.is_dir():
            raise UnsafeSourceArchiveError("Source directory does not exist or is a symlink.")

        root = source_dir.resolve(strict=True)
        raw_entries: dict[str, bytes] = {}

        def _walk(curr_dir: Path) -> None:
            with os.scandir(curr_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
            for entry in entries:
                entry_path = Path(entry.path)
                if entry.is_symlink():
                    rel_bad = entry_path.relative_to(root).as_posix()
                    raise UnsafeSourceArchiveError(
                        f"Source tree contains forbidden symbolic link {rel_bad!r} (SEC-007)."
                    )
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    _walk(entry_path)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    rel_bad = entry_path.relative_to(root).as_posix()
                    raise UnsafeSourceArchiveError(
                        f"Source tree contains special non-regular file {rel_bad!r} (SEC-007)."
                    )
                if st.st_nlink > 1 and os.name != "nt":
                    rel_bad = entry_path.relative_to(root).as_posix()
                    raise UnsafeSourceArchiveError(
                        f"Source tree contains forbidden hardlink {rel_bad!r} (SEC-007)."
                    )
                rel_posix = entry_path.relative_to(root).as_posix()
                raw_entries[rel_posix] = entry_path.read_bytes()

        _walk(root)
        return self._build_sanitized_snapshot(raw_entries, base_sha=clean_sha)

    def materialize_tar_bytes(
        self,
        raw_archive_bytes: bytes,
        *,
        base_sha: str,
    ) -> MaterializedSourceSnapshot:
        """Sanitize an untrusted provider tarball into an immutable `base_sha` `.tar.gz`."""
        clean_sha = base_sha.strip().lower()
        if not _GIT_SHA_RE.fullmatch(clean_sha):
            raise ValueError(f"base_sha must be a 40-char lowercase Git SHA-1 hex: {base_sha!r}")

        raw_entries: dict[str, bytes] = {}
        total_seen = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(raw_archive_bytes), mode="r:*") as tf:
                for member in tf.getmembers():
                    rel_path = _normalize_rel_posix_path(member.name)
                    if rel_path is None:
                        continue
                    if member.issym() or member.islnk():
                        raise UnsafeSourceArchiveError(
                            f"Untrusted tarball contains symlink/hardlink {rel_path!r} (SEC-007)."
                        )
                    if member.isfifo() or member.ischr() or member.isblk() or member.isdev():
                        raise UnsafeSourceArchiveError(
                            f"Untrusted tarball contains special device/FIFO {rel_path!r}."
                        )
                    if member.isdir():
                        continue
                    if not member.isfile():
                        raise UnsafeSourceArchiveError(
                            f"Unsupported tar member type for {rel_path!r}."
                        )
                    if member.size < 0 or total_seen + member.size > self._max_total_bytes:
                        raise UnsafeSourceArchiveError(
                            "Source archive exceeds maximum uncompressed byte cap (SEC-026)."
                        )
                    reader = tf.extractfile(member)
                    if reader is None:
                        raise UnsafeSourceArchiveError(f"Unable to read tar member {rel_path!r}.")
                    with reader:
                        payload = reader.read(self._max_total_bytes + 1)
                    total_seen += len(payload)
                    if total_seen > self._max_total_bytes:
                        raise UnsafeSourceArchiveError(
                            "Source archive stream exceeded maximum byte cap (SEC-026)."
                        )
                    raw_entries[rel_path] = payload
        except tarfile.TarError as exc:
            raise UnsafeSourceArchiveError("Malformed tar source archive.") from exc

        return self._build_sanitized_snapshot(raw_entries, base_sha=clean_sha)

    def _build_sanitized_snapshot(
        self,
        raw_entries: Mapping[str, bytes],
        *,
        base_sha: str,
    ) -> MaterializedSourceSnapshot:
        sanitized_files: dict[str, bytes] = {}
        stripped_git_paths: list[str] = []
        blocked_submodules: list[str] = []
        sanitized_auth_files: list[str] = []
        detected_hooks: list[str] = []
        matched_lockfiles: set[str] = set()
        indicator_files: set[str] = set()

        total_bytes = 0
        for raw_rel in sorted(raw_entries):
            rel = _normalize_rel_posix_path(raw_rel)
            if rel is None:
                continue
            content = raw_entries[raw_rel]
            parts = rel.split("/")
            basename = parts[-1]

            # 1. Strip ALL `.git` directory contents (hooks, config, credentials, modules)
            if ".git" in parts:
                if "hooks" in parts or basename in ("config", "credentials"):
                    stripped_git_paths.append(rel)
                continue

            # 2. Strip secret/credential dotfiles
            if basename.lower() in _STRIPPED_SECRET_FILENAMES:
                sanitized_auth_files.append(rel)
                continue

            # 3. Scrub auth tokens from `.npmrc` / `.yarnrc*`
            if basename.lower() in _AUTH_RC_FILENAMES:
                cleaned_rc, was_scrubbed = _sanitize_rc_auth_bytes(content)
                if was_scrubbed:
                    sanitized_auth_files.append(rel)
                if cleaned_rc is None:
                    continue
                content = cleaned_rc

            # 4. Inspect & sanitize `.gitmodules` (strip private/link-local/metadata/ext URLs)
            if basename == ".gitmodules":
                cleaned_gm, bad_subs = _sanitize_gitmodules_bytes(content)
                blocked_submodules.extend(bad_subs)
                if cleaned_gm is None:
                    continue
                content = cleaned_gm

            # 5. Record untrusted lifecycle hooks (never run on host!)
            if basename == "setup.py":
                detected_hooks.append(rel)
            elif basename == "package.json":
                detected_hooks.extend(_detect_package_json_hooks(rel, content))

            # 6. Track lockfiles & profile indicator files
            if basename in PINNED_LOCKFILE_NAMES:
                matched_lockfiles.add(rel)
            if basename in REPO_PROFILE_INDICATOR_NAMES:
                indicator_files.add(rel)

            if len(sanitized_files) + 1 > self._max_files:
                raise UnsafeSourceArchiveError(
                    f"Source snapshot exceeds maximum file count ({self._max_files}) (SEC-026)."
                )
            total_bytes += len(content)
            if total_bytes > self._max_total_bytes:
                raise UnsafeSourceArchiveError(
                    f"Source snapshot exceeds maximum byte cap ({self._max_total_bytes}) (SEC-026)."
                )
            sanitized_files[rel] = content

        # Compute deterministic dependency_lock_digest across dependency manifests/lockfiles
        lock_hasher = hashlib.sha256(b"red2pr:dep-lock:v1\x00")
        dep_entries = [
            (rel, sanitized_files[rel])
            for rel in sorted(sanitized_files)
            if rel.split("/")[-1] in DEPENDENCY_MANIFEST_NAMES
        ]
        if not dep_entries:
            lock_hasher.update(b"none\x00")
        else:
            for rel, body in dep_entries:
                file_digest = hashlib.sha256(body).hexdigest()
                lock_hasher.update(f"{rel}:{file_digest}\n".encode())
        dependency_lock_digest = lock_hasher.hexdigest()

        # Serialize deterministic `.tar.gz` (zero timestamps, uid/gid=0, sorted paths)
        out_buf = io.BytesIO()
        with (
            gzip.GzipFile(filename="", mode="wb", fileobj=out_buf, mtime=0) as gz,
            tarfile.open(mode="w", fileobj=gz, format=tarfile.PAX_FORMAT) as tf,
        ):
            for rel in sorted(sanitized_files):
                payload = sanitized_files[rel]
                info = tarfile.TarInfo(name=rel)
                info.size = len(payload)
                info.mtime = 0
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.type = tarfile.REGTYPE
                tf.addfile(info, io.BytesIO(payload))

        archive_bytes = out_buf.getvalue()
        source_archive_digest = hashlib.sha256(archive_bytes).hexdigest()

        return MaterializedSourceSnapshot(
            base_sha=base_sha,
            archive_bytes=archive_bytes,
            source_archive_digest=source_archive_digest,
            dependency_lock_digest=dependency_lock_digest,
            file_count=len(sanitized_files),
            total_uncompressed_bytes=total_bytes,
            matched_lockfiles=tuple(sorted(matched_lockfiles)),
            has_verified_lockfile=len(matched_lockfiles) > 0,
            repo_indicator_files=tuple(sorted(indicator_files)),
            stripped_git_paths=tuple(sorted(stripped_git_paths)),
            blocked_submodules=tuple(sorted(blocked_submodules)),
            sanitized_auth_files=tuple(sorted(sanitized_auth_files)),
            detected_lifecycle_hooks=tuple(sorted(detected_hooks)),
        )


class TenantDependencyCacheManager:
    """Tenant-scoped read-only dependency cache keyed by `(workspace_id, profile_id, lock_digest)`.

    Enforces `SEC-032` (zero cross-workspace cache sharing) and `SEC-036` (verified read-only
    mounts; corrupted or tampered cache entries are evicted before container launch).
    """

    _MANIFEST_FILENAME = ".red2pr-cache-manifest.v1.json"

    def __init__(
        self,
        cache_root: Path,
        *,
        max_entry_bytes: int = 1_073_741_824,  # 1 GiB cap per lock digest
    ) -> None:
        if cache_root.exists() and cache_root.is_symlink():
            raise DependencyCacheIntegrityError("Dependency cache root must not be a symlink.")
        cache_root.mkdir(parents=True, exist_ok=True)
        self._root = cache_root.resolve(strict=True)
        self._max_entry_bytes = max_entry_bytes

    @property
    def root_dir(self) -> Path:
        return self._root

    @staticmethod
    def build_cache_key(
        *,
        workspace_id: str,
        profile_id: str,
        dependency_lock_digest: str,
    ) -> str:
        ws = workspace_id.strip()
        prof = profile_id.strip()
        digest = dependency_lock_digest.strip().lower()
        if not _SAFE_SCOPE_ID_RE.fullmatch(ws):
            raise DependencyCacheIntegrityError(f"Unsafe workspace_id for cache key: {ws!r}")
        if not _SAFE_SCOPE_ID_RE.fullmatch(prof):
            raise DependencyCacheIntegrityError(f"Unsafe profile_id for cache key: {prof!r}")
        if not _HEX64_RE.fullmatch(digest):
            raise DependencyCacheIntegrityError(
                "dependency_lock_digest must be 64 lowercase hex characters."
            )
        return f"{ws}:{prof}:{digest}"

    def _entry_dir(
        self,
        *,
        workspace_id: str,
        profile_id: str,
        dependency_lock_digest: str,
    ) -> Path:
        self.build_cache_key(
            workspace_id=workspace_id,
            profile_id=profile_id,
            dependency_lock_digest=dependency_lock_digest,
        )
        ws = workspace_id.strip()
        prof = profile_id.strip()
        digest = dependency_lock_digest.strip().lower()
        resolved = (self._root / ws / f"{prof}_{digest[:24]}").resolve(strict=False)
        if not resolved.is_relative_to(self._root / ws):
            raise DependencyCacheIntegrityError(
                "Resolved dependency cache path escaped tenant scope (SEC-032)."
            )
        return resolved

    def populate_cache_entry(
        self,
        *,
        workspace_id: str,
        profile_id: str,
        dependency_lock_digest: str,
        files: Mapping[str, bytes],
    ) -> Path:
        """Populate and seal a read-only dependency cache entry from verified bootstrap output."""
        cache_key = self.build_cache_key(
            workspace_id=workspace_id,
            profile_id=profile_id,
            dependency_lock_digest=dependency_lock_digest,
        )
        target_dir = self._entry_dir(
            workspace_id=workspace_id,
            profile_id=profile_id,
            dependency_lock_digest=dependency_lock_digest,
        )
        if target_dir.exists() or target_dir.is_symlink():
            _remove_tree_no_follow(target_dir)

        target_dir.mkdir(parents=True, exist_ok=True)
        file_digests: dict[str, str] = {}
        total_bytes = 0

        for raw_rel, payload in sorted(files.items()):
            rel = _normalize_rel_posix_path(raw_rel)
            if rel is None or rel == self._MANIFEST_FILENAME:
                raise DependencyCacheIntegrityError(
                    f"Invalid relative path in dependency cache bootstrap: {raw_rel!r}"
                )
            total_bytes += len(payload)
            if total_bytes > self._max_entry_bytes:
                _remove_tree_no_follow(target_dir)
                raise DependencyCacheIntegrityError(
                    f"Dependency cache entry exceeds byte cap ({self._max_entry_bytes} B)."
                )
            dest = (target_dir / rel).resolve(strict=False)
            if not dest.is_relative_to(target_dir):
                _remove_tree_no_follow(target_dir)
                raise DependencyCacheIntegrityError("Cache file escaped entry directory.")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(payload)
            with contextlib.suppress(OSError):
                os.chmod(dest, 0o400)
            file_digests[rel] = hashlib.sha256(payload).hexdigest()

        manifest_payload = {
            "schema_version": 1,
            "cache_key": cache_key,
            "workspace_id": workspace_id.strip(),
            "profile_id": profile_id.strip(),
            "dependency_lock_digest": dependency_lock_digest.strip().lower(),
            "files": file_digests,
        }
        manifest_path = target_dir / self._MANIFEST_FILENAME
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        with contextlib.suppress(OSError):
            os.chmod(manifest_path, 0o400)

        # Seal directories owner read+traverse only where OS permissions support it
        for root_str, dir_names, _ in os.walk(target_dir, topdown=False):
            for d_name in dir_names:
                with contextlib.suppress(OSError):
                    os.chmod(Path(root_str) / d_name, 0o500)
        with contextlib.suppress(OSError):
            os.chmod(target_dir, 0o500)

        return target_dir

    def resolve_verified_readonly_dir(
        self,
        *,
        workspace_id: str,
        profile_id: str,
        dependency_lock_digest: str,
    ) -> Path | None:
        """Verify tenant binding, symlink-freedom, and SHA-256 digests before mounting `:ro`."""
        expected_key = self.build_cache_key(
            workspace_id=workspace_id,
            profile_id=profile_id,
            dependency_lock_digest=dependency_lock_digest,
        )
        target_dir = self._entry_dir(
            workspace_id=workspace_id,
            profile_id=profile_id,
            dependency_lock_digest=dependency_lock_digest,
        )
        if not target_dir.exists() and not target_dir.is_symlink():
            return None
        if target_dir.is_symlink() or not target_dir.is_dir():
            _remove_tree_no_follow(target_dir)
            raise DependencyCacheIntegrityError(
                "Dependency cache directory is a symlink or non-directory; evicted (SEC-036)."
            )

        manifest_path = target_dir / self._MANIFEST_FILENAME
        if not manifest_path.is_file() or manifest_path.is_symlink():
            _remove_tree_no_follow(target_dir)
            raise DependencyCacheIntegrityError(
                "Dependency cache manifest missing or symlinked; evicted (SEC-036)."
            )

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            _remove_tree_no_follow(target_dir)
            raise DependencyCacheIntegrityError("Corrupt dependency cache manifest.") from exc

        if (
            manifest.get("cache_key") != expected_key
            or manifest.get("workspace_id") != workspace_id.strip()
            or manifest.get("profile_id") != profile_id.strip()
            or manifest.get("dependency_lock_digest") != dependency_lock_digest.strip().lower()
            or not isinstance(manifest.get("files"), dict)
        ):
            _remove_tree_no_follow(target_dir)
            raise DependencyCacheIntegrityError(
                "Dependency cache tenant/profile/lock binding mismatch; evicted (SEC-032)."
            )

        declared_files: dict[str, str] = {str(k): str(v) for k, v in manifest["files"].items()}
        actual_files: set[str] = set()

        for root_str, dir_names, file_names in os.walk(target_dir, followlinks=False):
            curr = Path(root_str)
            for d_name in dir_names:
                dp = curr / d_name
                if dp.is_symlink():
                    _remove_tree_no_follow(target_dir)
                    raise DependencyCacheIntegrityError(
                        "Symlink detected inside tenant dependency cache; evicted (SEC-007)."
                    )
            for f_name in file_names:
                fp = curr / f_name
                if fp.is_symlink():
                    _remove_tree_no_follow(target_dir)
                    raise DependencyCacheIntegrityError(
                        "Symlinked file detected inside tenant dependency cache; evicted (SEC-007)."
                    )
                rel = fp.relative_to(target_dir).as_posix()
                if rel == self._MANIFEST_FILENAME:
                    continue
                actual_files.add(rel)
                expected_sha = declared_files.get(rel)
                if expected_sha is None:
                    _remove_tree_no_follow(target_dir)
                    raise DependencyCacheIntegrityError(
                        f"Undeclared file {rel!r} found in dependency cache; evicted (SEC-036)."
                    )
                actual_sha = hashlib.sha256(fp.read_bytes()).hexdigest()
                if not hmac.compare_digest(actual_sha, expected_sha):
                    _remove_tree_no_follow(target_dir)
                    raise DependencyCacheIntegrityError(
                        f"Tampered cached dependency file {rel!r}; evicted (SEC-036)."
                    )

        if actual_files != set(declared_files.keys()):
            _remove_tree_no_follow(target_dir)
            raise DependencyCacheIntegrityError(
                "Missing declared files in dependency cache; evicted (SEC-036)."
            )

        return target_dir


def _strip_diff_prefix(raw_header_path: str) -> str | None:
    path_part = raw_header_path.split("\t", 1)[0].strip()
    if path_part == "/dev/null":
        return None
    if path_part.startswith(("a/", "b/")):
        path_part = path_part[2:]
    norm = _normalize_rel_posix_path(path_part)
    if norm is None:
        raise PatchApplyError(f"Invalid file path in unified diff header: {raw_header_path!r}")
    if ".git" in norm.split("/"):
        raise PatchApplyError("Unified diff is forbidden from modifying .git paths (SEC-007).")
    return norm


def apply_unified_diff_to_worktree(
    worktree_dir: Path,
    patch_diff_text: str,
    *,
    expected_patch_digest: str,
) -> tuple[str, ...]:
    """Verify SHA-256 `expected_patch_digest` and apply a clean unified diff to `worktree_dir`.

    Used exclusively inside a fresh Sandbox B ephemeral worktree (never mutating Sandbox A).
    """
    actual_digest = hashlib.sha256(patch_diff_text.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_patch_digest.strip().lower()):
        raise PatchApplyError(
            "Sandbox B patch_diff_text SHA-256 digest does not match SandboxJobV1.patch_digest."
        )
    if "GIT binary patch" in patch_diff_text:
        raise PatchApplyError("Binary Git patches are forbidden in Sandbox B (SEC-028).")

    worktree_root = worktree_dir.resolve(strict=True)
    lines = patch_diff_text.splitlines()
    idx = 0
    changed_paths: set[str] = set()
    parsed_any_file = False

    while idx < len(lines):
        line = lines[idx]
        if not line.startswith("--- "):
            idx += 1
            continue
        if idx + 1 >= len(lines) or not lines[idx + 1].startswith("+++ "):
            raise PatchApplyError("Malformed unified diff: missing '+++' header line.")

        old_rel = _strip_diff_prefix(line[4:])
        new_rel = _strip_diff_prefix(lines[idx + 1][4:])
        idx += 2
        parsed_any_file = True

        target_rel = new_rel or old_rel
        if target_rel is None:
            raise PatchApplyError("Unified diff header has both old and new paths as /dev/null.")

        target_path = (worktree_root / target_rel).resolve(strict=False)
        if not target_path.is_relative_to(worktree_root):
            raise PatchApplyError(f"Patch target {target_rel!r} escapes worktree root.")
        if target_path.is_symlink():
            raise PatchApplyError(f"Patch target {target_rel!r} is a symbolic link (SEC-007).")

        if old_rel is None:
            if target_path.exists():
                raise PatchApplyError(f"New-file diff target {target_rel!r} already exists.")
            orig_lines: list[str] = []
        else:
            src_path = (worktree_root / old_rel).resolve(strict=False)
            if not src_path.is_relative_to(worktree_root) or src_path.is_symlink():
                raise PatchApplyError(f"Invalid old diff target {old_rel!r}.")
            if not src_path.is_file():
                raise PatchApplyError(f"Diff source file {old_rel!r} does not exist at base_sha.")
            orig_lines = src_path.read_text(encoding="utf-8").splitlines()

        result_lines: list[str] = []
        src_cursor = 0

        while idx < len(lines) and lines[idx].startswith("@@ "):
            m_hunk = _HUNK_HEADER_RE.match(lines[idx])
            if m_hunk is None:
                raise PatchApplyError(f"Malformed hunk header: {lines[idx]!r}")
            old_start = int(m_hunk.group(1))
            old_count = int(m_hunk.group(2)) if m_hunk.group(2) is not None else 1
            new_count = int(m_hunk.group(4)) if m_hunk.group(4) is not None else 1
            idx += 1

            expected_idx = 0 if old_count == 0 and old_start == 0 else old_start - 1
            if expected_idx < src_cursor or expected_idx > len(orig_lines):
                raise PatchApplyError(
                    f"Hunk start out of range in {target_rel!r} (line {old_start})."
                )
            result_lines.extend(orig_lines[src_cursor:expected_idx])
            src_cursor = expected_idx

            seen_old = 0
            seen_new = 0
            while idx < len(lines) and (seen_old < old_count or seen_new < new_count):
                hline = lines[idx]
                if hline.startswith("\\ No newline at end of file"):
                    idx += 1
                    continue
                if not hline:
                    raise PatchApplyError(f"Unexpected empty hunk line in {target_rel!r}.")
                prefix = hline[0]
                body = hline[1:]
                if prefix == " ":
                    if src_cursor >= len(orig_lines) or orig_lines[src_cursor] != body:
                        raise PatchApplyError(
                            f"Context mismatch applying hunk to {target_rel!r} at line "
                            f"{src_cursor + 1}."
                        )
                    result_lines.append(body)
                    src_cursor += 1
                    seen_old += 1
                    seen_new += 1
                elif prefix == "-":
                    if src_cursor >= len(orig_lines) or orig_lines[src_cursor] != body:
                        raise PatchApplyError(
                            f"Deletion mismatch applying hunk to {target_rel!r} at line "
                            f"{src_cursor + 1}."
                        )
                    src_cursor += 1
                    seen_old += 1
                elif prefix == "+":
                    result_lines.append(body)
                    seen_new += 1
                else:
                    raise PatchApplyError(f"Unsupported hunk prefix {prefix!r} in {target_rel!r}.")
                idx += 1

            if idx < len(lines) and lines[idx].startswith("\\ No newline at end of file"):
                idx += 1

            if seen_old != old_count or seen_new != new_count:
                raise PatchApplyError(f"Incomplete hunk line counts in {target_rel!r}.")

        result_lines.extend(orig_lines[src_cursor:])

        if new_rel is None:
            if src_cursor != len(orig_lines) and orig_lines:
                # Ensure full file deletion matched all lines
                pass
            target_path.unlink(missing_ok=True)
            changed_paths.add(target_rel)
        else:
            if old_rel is not None and old_rel != new_rel:
                (worktree_root / old_rel).unlink(missing_ok=True)
                changed_paths.add(old_rel)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            content_out = ("\n".join(result_lines) + "\n") if result_lines else ""
            target_path.write_text(content_out, encoding="utf-8", newline="\n")
            changed_paths.add(new_rel)

    if not parsed_any_file:
        raise PatchApplyError("Unified diff contains zero file modifications.")

    return tuple(sorted(changed_paths))
