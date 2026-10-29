"""Deterministic diff inspection for FIX-01 (no model-authored verdicts)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath


class IntegrityDisposition(StrEnum):
    ACCEPT = "accept"
    HUMAN_REVIEW = "human_review"
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class IntegrityFinding:
    code: str
    path: str
    detail: str


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    disposition: IntegrityDisposition
    findings: tuple[IntegrityFinding, ...]
    changed_paths: tuple[str, ...]
    added_lines: int
    removed_lines: int


_TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__)(?:/|$)|(?:^|/)[^/]+\.(?:test|spec)\.[^/]+$",
    re.IGNORECASE,
)
_SUPPRESSION_RE = re.compile(
    r"(?:pytest\.mark\.(?:skip|skipif|xfail)|\b(?:skip|skipif|xfail)\s*=|"
    r"\.(?:skip|skipIf|todo|only)\s*\(|\bit\.(?:only|skip|todo)\b|"
    r"\b(?:describe|test)\.only\s*\()",
    re.IGNORECASE,
)
_ASSERTION_RE = re.compile(
    r"\bassert\b|\bexpect\s*\(|\b(?:assertThat|should|toBe|toEqual|toThrow|toStrictEqual)\b"
)
_TEST_DECLARATION_RE = re.compile(
    r"(?:^\s*(?:async\s+)?def\s+test_|\b(?:it|test)\s*\(|\b(?:describe|suite)\s*\()"
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|/)(?:\.github/workflows/|\.gitlab-ci\.yml$|(?:\.ruff|ruff|mypy|eslint|tsconfig|"
    r"pyproject\.toml$|package\.json$|pnpm-lock\.yaml$|uv\.lock$|requirements[^/]*\.txt$|"
    r"Dockerfile|.*\.tf$|.*\.ya?ml$|migrations?/|alembic/versions/|.*auth.*|.*deploy.*))",
    re.IGNORECASE,
)
_GATE_WEAKENING_RE = re.compile(
    r"(?:ignore_errors\s*=\s*true|noqa\s*(?:#|$)|eslint-disable|type:\s*ignore|"
    r"strict\s*=\s*false|strictNullChecks\s*[:=]\s*false|skipLibCheck\s*[:=]\s*true|"
    r"continue-on-error\s*:\s*true|\|\|\s*true|exit\s+0|--passWithNoTests|"
    r"(?:run|script)\s*:\s*(?:true|:|echo\s+['\"]?(?:ok|pass))\s*$)",
    re.IGNORECASE,
)
_TEST_ASSERTION_NAMES = frozenset(
    {"assert", "expect", "toBe", "toEqual", "toThrow", "toStrictEqual"}
)


def _safe_path(path: str) -> bool:
    if not path or "\x00" in path or "\\" in path:
        return False
    candidate = PurePosixPath(path)
    return (
        not candidate.is_absolute()
        and bool(candidate.parts)
        and all(part not in {"", ".", ".."} for part in candidate.parts)
    )


def _parse_changed_lines(
    diff_text: str,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], set[str]]:
    current_path = ""
    added: list[tuple[str, str]] = []
    removed: list[tuple[str, str]] = []
    diff_paths: set[str] = set()
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_path = line[6:]
        elif line.startswith("+++ "):
            current_path = line[4:]
        elif line.startswith("diff --git "):
            match = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            if match:
                current_path = match.group(2)
                diff_paths.add(current_path)
        elif line.startswith("+") and not line.startswith("+++"):
            added.append((current_path, line[1:]))
        elif line.startswith("-") and not line.startswith("---"):
            removed.append((current_path, line[1:]))
    return added, removed, diff_paths


class DiffIntegrityGuard:
    """Reject anti-cheat edits and require a human for sensitive paths/legitimate test edits."""

    def inspect(
        self,
        diff_text: str,
        *,
        changed_paths: list[str] | tuple[str, ...],
        allowed_paths: tuple[str, ...] | None = None,
        max_diff_lines: int = 2000,
        max_diff_bytes: int = 262_144,
    ) -> IntegrityReport:
        paths = tuple(sorted(set(changed_paths)))
        findings: list[IntegrityFinding] = []
        for path in paths:
            if not _safe_path(path):
                findings.append(
                    IntegrityFinding(
                        "unsafe_path",
                        path[:240],
                        "Path escapes repository root or is malformed.",
                    )
                )

        added, removed, diff_paths = _parse_changed_lines(diff_text)
        if set(paths) != diff_paths:
            findings.append(
                IntegrityFinding(
                    "diff_path_mismatch",
                    "",
                    "Declared paths do not exactly match paths present in the diff.",
                )
            )
        if allowed_paths is not None and not set(paths).issubset(set(allowed_paths)):
            findings.append(
                IntegrityFinding(
                    "path_out_of_scope",
                    "",
                    "Diff includes paths outside the approved allowlist.",
                )
            )
        if (
            len(diff_text.encode("utf-8")) > max_diff_bytes
            or len(added) + len(removed) > max_diff_lines
        ):
            findings.append(
                IntegrityFinding(
                    "diff_size_limit",
                    "",
                    "Diff exceeds its configured byte or line limit.",
                )
            )
        deleted_paths: set[str] = set()
        current_path = ""
        for line in diff_text.splitlines():
            if line.startswith("diff --git "):
                match = re.match(r"diff --git a/(.+?) b/(.+)$", line)
                current_path = match.group(1) if match else ""
            elif line.startswith("deleted file mode ") and current_path:
                deleted_paths.add(current_path)
        for path in paths:
            if path in deleted_paths and _TEST_PATH_RE.search(path):
                findings.append(
                    IntegrityFinding("deleted_test", path, "Deleting a test file is prohibited.")
                )

        for path, line in added:
            if _SUPPRESSION_RE.search(line):
                findings.append(
                    IntegrityFinding(
                        "test_suppression",
                        path,
                        "Added skip, xfail, todo, or focused-only test suppression.",
                    )
                )
            if _GATE_WEAKENING_RE.search(line):
                findings.append(
                    IntegrityFinding(
                        "gate_weakening",
                        path,
                        "Added a pattern that disables or weakens a verification gate.",
                    )
                )

        removed_assertions = [
            (path, line)
            for path, line in removed
            if _TEST_PATH_RE.search(path) and _ASSERTION_RE.search(line)
        ]
        added_assertions = [
            (path, line)
            for path, line in added
            if _TEST_PATH_RE.search(path) and _ASSERTION_RE.search(line)
        ]
        if removed_assertions and len(added_assertions) < len(removed_assertions):
            path = removed_assertions[0][0]
            findings.append(
                IntegrityFinding(
                    "removed_test_assertion",
                    path,
                    "Removing test assertions requires independent human review.",
                )
            )
        removed_tests = [
            (path, line)
            for path, line in removed
            if _TEST_PATH_RE.search(path) and _TEST_DECLARATION_RE.search(line)
        ]
        added_tests = [
            (path, line)
            for path, line in added
            if _TEST_PATH_RE.search(path) and _TEST_DECLARATION_RE.search(line)
        ]
        if removed_tests and len(added_tests) < len(removed_tests):
            findings.append(
                IntegrityFinding(
                    "removed_test_case",
                    removed_tests[0][0],
                    "Removing test cases is prohibited without preserving the original intent.",
                )
            )

        for path in paths:
            if _SENSITIVE_PATH_RE.search(path):
                findings.append(
                    IntegrityFinding(
                        "sensitive_path",
                        path,
                        "Sensitive workflow, policy, dependency, auth, deployment, or migration "
                        "change requires human review.",
                    )
                )
            elif (
                _TEST_PATH_RE.search(path)
                and any(item_path == path for item_path, _ in (*added, *removed))
                and not any(
                    f.path == path
                    and f.code in {"deleted_test", "test_suppression", "removed_test_assertion"}
                    for f in findings
                )
            ):
                findings.append(
                    IntegrityFinding(
                        "test_change",
                        path,
                        "Test changes require explanation and independent human review.",
                    )
                )

        if any(
            item.code
            in {
                "unsafe_path",
                "diff_path_mismatch",
                "path_out_of_scope",
                "diff_size_limit",
                "deleted_test",
                "removed_test_case",
                "test_suppression",
                "gate_weakening",
            }
            for item in findings
        ):
            disposition = IntegrityDisposition.REJECT
        elif findings:
            disposition = IntegrityDisposition.HUMAN_REVIEW
        else:
            disposition = IntegrityDisposition.ACCEPT
        return IntegrityReport(
            disposition=disposition,
            findings=tuple(findings),
            changed_paths=paths,
            added_lines=len(added),
            removed_lines=len(removed),
        )
