"""Canonical path/branch normalization, glob matching, and protected-path guards (`U12`).

Implements `REP-03`, `SEC-007`, and `SEC-009`:
- Strict repository-relative POSIX path canonicalization rejecting traversal (`..`, `.`),
  null/control bytes, leading slashes, empty `//` segments, and Windows drive prefixes.
- Deterministic segment-aware glob matching (`**`, `*`, `?`) where security, denylist, and
  protected-path globs evaluate case-insensitively (`.casefold()`) so mixed-case path tricks
  (`.GitHub/Workflows/CI.yml`, `.ENV`) never bypass policy enforcement.
- Non-waivable hard-denied VCS/secret globs (`SEC-007`), `SEC-009` protected CI/lockfile/auth/
  deploy/migration globs (always escalating to mandatory human approval), and gated test/config
  path classifiers (`AGENTS.md` Principle 3).
"""

from __future__ import annotations

import functools
import re
import unicodedata
from dataclasses import dataclass

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_INVALID_GIT_REF_CHARS_RE = re.compile(r"[\x00-\x20\x7f~^:?*\[\]\\]")

HARD_DENIED_PATH_GLOBS: tuple[str, ...] = (
    ".git/**",
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/id_rsa*",
    "**/id_ed25519*",
    "secrets/**",
    "**/secrets/**",
)

PROTECTED_SENSITIVE_PATH_GLOBS: tuple[str, ...] = (
    ".github/workflows/**",
    ".github/actions/**",
    ".gitlab-ci.yml",
    ".gitlab/ci/**",
    "uv.lock",
    "**/uv.lock",
    "poetry.lock",
    "**/poetry.lock",
    "Pipfile.lock",
    "**/Pipfile.lock",
    "pnpm-lock.yaml",
    "**/pnpm-lock.yaml",
    "package-lock.json",
    "**/package-lock.json",
    "yarn.lock",
    "**/yarn.lock",
    "Cargo.lock",
    "**/Cargo.lock",
    "go.sum",
    "**/go.sum",
    "Gemfile.lock",
    "**/Gemfile.lock",
    "composer.lock",
    "**/composer.lock",
    "auth/**",
    "**/auth/**",
    "iam/**",
    "**/iam/**",
    "security/**",
    "**/security/**",
    "Dockerfile",
    "Dockerfile.*",
    "**/Dockerfile",
    "**/Dockerfile.*",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "**/docker-compose*.yml",
    "**/docker-compose*.yaml",
    "deploy/**",
    "**/deploy/**",
    "infra/**",
    "**/infra/**",
    "terraform/**",
    "**/*.tf",
    "k8s/**",
    "**/k8s/**",
    "helm/**",
    "**/helm/**",
    "alembic/**",
    "**/alembic/**",
    "migrations/**",
    "**/migrations/**",
    "AGENTS.md",
    "**/AGENTS.md",
    "CODEOWNERS",
    ".github/CODEOWNERS",
    ".gitlab/CODEOWNERS",
)

TEST_FILE_GLOBS: tuple[str, ...] = (
    "tests/**",
    "**/tests/**",
    "test/**",
    "**/test/**",
    "__tests__/**",
    "**/__tests__/**",
    "test_*.py",
    "**/test_*.py",
    "*_test.py",
    "**/*_test.py",
    "*_test.go",
    "**/*_test.go",
    "*.test.ts",
    "**/*.test.ts",
    "*.test.tsx",
    "**/*.test.tsx",
    "*.spec.ts",
    "**/*.spec.ts",
    "*.spec.tsx",
    "**/*.spec.tsx",
    "*.test.js",
    "**/*.test.js",
    "*.spec.js",
    "**/*.spec.js",
)

CONFIG_FILE_GLOBS: tuple[str, ...] = (
    "pyproject.toml",
    "**/pyproject.toml",
    "package.json",
    "**/package.json",
    "tsconfig*.json",
    "**/tsconfig*.json",
    "Cargo.toml",
    "**/Cargo.toml",
    "go.mod",
    "**/go.mod",
    "Makefile",
    "**/Makefile",
    "tox.ini",
    "**/tox.ini",
    "pytest.ini",
    "**/pytest.ini",
    ".ruff.toml",
    "ruff.toml",
)


class PathCanonicalizationError(ValueError):
    """Raised when a path, branch ref, or glob violates canonical repository safety rules."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def canonicalize_repo_path(raw_path: str) -> str:
    """Normalize a repo-relative file path or raise `PathCanonicalizationError` (`SEC-007`)."""
    if not isinstance(raw_path, str):
        raise PathCanonicalizationError("invalid_path_type", "Path must be a UTF-8 string.")
    if "\\" in raw_path:
        raise PathCanonicalizationError(
            "path_backslash_forbidden",
            "Repository file path must use POSIX '/' separators without backslashes.",
        )
    normalized = unicodedata.normalize("NFC", raw_path).strip()
    if not normalized or len(normalized) > 512:
        raise PathCanonicalizationError(
            "invalid_path_length",
            "Repository file path must be between 1 and 512 characters.",
        )
    if _CONTROL_CHAR_RE.search(normalized) is not None:
        raise PathCanonicalizationError(
            "path_control_char",
            "Repository file path must not contain null or control characters.",
        )
    if normalized.startswith("/") or normalized.endswith("/"):
        raise PathCanonicalizationError(
            "path_absolute_or_directory",
            "Repository file path must be a relative file path without leading or trailing '/'.",
        )
    if _WINDOWS_DRIVE_RE.match(normalized) is not None:
        raise PathCanonicalizationError(
            "path_drive_prefix",
            "Repository file path must not start with a Windows drive prefix.",
        )

    segments = normalized.split("/")
    for seg in segments:
        if seg == "":
            raise PathCanonicalizationError(
                "path_empty_segment",
                "Repository file path must not contain empty '//' segments.",
            )
        if seg in {".", ".."}:
            raise PathCanonicalizationError(
                "path_traversal_segment",
                "Repository file path must not contain '.' or '..' traversal segments.",
            )
    return normalized


def canonicalize_glob_pattern(raw_pattern: str) -> str:
    """Validate and normalize a repository path or branch glob pattern (`SEC-007`)."""
    if not isinstance(raw_pattern, str):
        raise PathCanonicalizationError("invalid_glob_type", "Glob pattern must be a string.")
    if "\\" in raw_pattern:
        raise PathCanonicalizationError(
            "glob_backslash_forbidden",
            "Glob pattern must use POSIX '/' separators without backslashes.",
        )
    normalized = unicodedata.normalize("NFC", raw_pattern).strip()
    if not normalized or len(normalized) > 256:
        raise PathCanonicalizationError(
            "invalid_glob_length",
            "Glob pattern must be between 1 and 256 characters.",
        )
    if _CONTROL_CHAR_RE.search(normalized) is not None:
        raise PathCanonicalizationError(
            "glob_control_char",
            "Glob pattern must not contain null or control characters.",
        )
    if normalized.startswith("/") or _WINDOWS_DRIVE_RE.match(normalized) is not None:
        raise PathCanonicalizationError(
            "glob_root_or_drive_prefix",
            "Glob pattern must be relative without leading '/' or drive prefixes.",
        )
    segments = normalized.split("/")
    for seg in segments:
        if seg == "":
            raise PathCanonicalizationError(
                "glob_empty_segment",
                "Glob pattern must not contain empty '//' segments.",
            )
        if seg in {".", ".."}:
            raise PathCanonicalizationError(
                "glob_traversal_segment",
                "Glob pattern must not contain '.' or '..' traversal segments.",
            )
    return normalized


def canonicalize_branch_ref(raw_ref: str) -> str:
    """Canonicalize a Git branch ref (stripping `refs/heads/` while keeping tag/PR namespaces)."""
    if not isinstance(raw_ref, str):
        raise PathCanonicalizationError("invalid_branch_type", "Branch ref must be a string.")
    normalized = unicodedata.normalize("NFC", raw_ref).strip()
    if not normalized or len(normalized) > 120:
        raise PathCanonicalizationError(
            "invalid_branch_length",
            "Branch ref must be between 1 and 120 characters.",
        )
    if normalized.startswith("refs/heads/"):
        normalized = normalized.removeprefix("refs/heads/")
    elif normalized.startswith("refs/"):
        raise PathCanonicalizationError(
            "non_branch_git_ref",
            f"Git reference '{normalized}' is not a branch under refs/heads/.",
        )
    if (
        not normalized
        or normalized.startswith("/")
        or normalized.endswith("/")
        or normalized.endswith(".lock")
        or ".." in normalized
        or "//" in normalized
        or "@{" in normalized
        or _INVALID_GIT_REF_CHARS_RE.search(normalized) is not None
    ):
        raise PathCanonicalizationError(
            "invalid_branch_ref",
            "Branch name violates Git reference safety constraints.",
        )
    return normalized


def _glob_to_regex_source(canonical_glob: str) -> str:
    """Translate a canonical POSIX glob (`**`, `*`, `?`) into an anchored regex string."""
    parts: list[str] = ["^"]
    idx = 0
    length = len(canonical_glob)

    while idx < length:
        if canonical_glob.startswith("**/", idx):
            parts.append("(?:.+/)?")
            idx += 3
            continue
        if canonical_glob.startswith("/**", idx) and idx + 3 == length:
            parts.append("/.+")
            idx += 3
            continue
        if canonical_glob.startswith("/**/", idx):
            parts.append("/(?:.+/)?")
            idx += 4
            continue
        if canonical_glob.startswith("**", idx):
            parts.append(".*")
            idx += 2
            continue
        ch = canonical_glob[idx]
        if ch == "*":
            parts.append("[^/]*")
        elif ch == "?":
            parts.append("[^/]")
        else:
            parts.append(re.escape(ch))
        idx += 1

    parts.append("$")
    return "".join(parts)


@functools.lru_cache(maxsize=1024)
def compile_canonical_glob(pattern: str, *, case_insensitive: bool = False) -> re.Pattern[str]:
    """Compile a canonical glob pattern into a cached anchored regular expression."""
    canonical = canonicalize_glob_pattern(pattern)
    target_glob = canonical.casefold() if case_insensitive else canonical
    regex_src = _glob_to_regex_source(target_glob)
    return re.compile(regex_src, re.DOTALL)


def glob_matches(
    pattern: str,
    candidate: str,
    *,
    case_insensitive: bool = False,
) -> bool:
    """Return `True` if `candidate` (already canonicalized) matches `pattern`."""
    compiled = compile_canonical_glob(pattern, case_insensitive=case_insensitive)
    probe = candidate.casefold() if case_insensitive else candidate
    return compiled.fullmatch(probe) is not None


def first_matching_glob(
    patterns: tuple[str, ...] | list[str],
    candidate: str,
    *,
    case_insensitive: bool = False,
) -> str | None:
    """Return the first pattern in `patterns` matching `candidate`, or `None`."""
    for pat in patterns:
        if glob_matches(pat, candidate, case_insensitive=case_insensitive):
            return pat
    return None


@dataclass(frozen=True, slots=True)
class BuiltinPathClassification:
    """Built-in security & governance classification for a canonical repository file path."""

    hard_denied_rule: str | None
    protected_sensitive_rule: str | None
    test_file_rule: str | None
    config_file_rule: str | None


def classify_builtin_repo_path(canonical_path: str) -> BuiltinPathClassification:
    """Evaluate a canonical path against built-in case-insensitive security & governance globs."""
    return BuiltinPathClassification(
        hard_denied_rule=first_matching_glob(
            HARD_DENIED_PATH_GLOBS, canonical_path, case_insensitive=True
        ),
        protected_sensitive_rule=first_matching_glob(
            PROTECTED_SENSITIVE_PATH_GLOBS, canonical_path, case_insensitive=True
        ),
        test_file_rule=first_matching_glob(TEST_FILE_GLOBS, canonical_path, case_insensitive=True),
        config_file_rule=first_matching_glob(
            CONFIG_FILE_GLOBS, canonical_path, case_insensitive=True
        ),
    )
