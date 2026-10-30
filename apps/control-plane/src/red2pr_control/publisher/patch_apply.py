"""Apply a previously verified text unified diff to exact provider file snapshots."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import PurePosixPath

from red2pr_control.core.errors import ConflictError

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")


def apply_verified_unified_diff(
    diff_text: str,
    *,
    base_contents: Mapping[str, str | None],
) -> dict[str, str | None]:
    """Return changed file contents; `None` is an explicit deletion.

    Hunk context is checked against provider contents read at the approved base SHA. The parser
    intentionally rejects binary, rename, malformed, overlapping, and path-escaping patches.
    """
    text = diff_text.replace("\r\n", "\n")
    if not text or "GIT binary patch" in text or "\x00" in text:
        raise ConflictError(
            code="publish_patch_unsupported",
            detail="Only non-empty UTF-8 text patches can be published.",
        )
    lines = text.splitlines()
    result: dict[str, str | None] = {}
    i = 0
    while i < len(lines):
        if not lines[i].startswith("--- "):
            if (
                lines[i].startswith(
                    (
                        "diff --git ",
                        "index ",
                        "old mode ",
                        "new mode ",
                        "new file mode ",
                        "deleted file mode ",
                    )
                )
                or not lines[i]
            ):
                i += 1
                continue
            raise _invalid_diff()
        old = lines[i][4:].split("\t", 1)[0]
        i += 1
        if i == len(lines) or not lines[i].startswith("+++ "):
            raise _invalid_diff()
        new = lines[i][4:].split("\t", 1)[0]
        i += 1
        old_path = None if old == "/dev/null" else _clean_path(old)
        new_path = None if new == "/dev/null" else _clean_path(new)
        if old_path is not None and new_path is not None and old_path != new_path:
            raise _invalid_diff()
        path = new_path or old_path
        if path is None or path in result or path not in base_contents:
            raise ConflictError(
                code="publish_patch_base_mismatch",
                detail="Patch paths are duplicate or do not match the approved repository base.",
            )
        base_text = base_contents[path]
        if (old_path is None and base_text is not None) or (
            old_path is not None and base_text is None
        ):
            raise ConflictError(
                code="publish_patch_base_mismatch",
                detail="Patch file existence does not match the approved base revision.",
            )
        original_terminated = bool(base_text and base_text.endswith("\n"))
        source = (base_text or "").replace("\r\n", "\n").splitlines()
        output: list[str] = []
        cursor = 0
        old_consumed = 0
        new_produced = 0
        last_new_count = 0
        while i < len(lines) and lines[i].startswith("@@ "):
            match = _HUNK.fullmatch(lines[i])
            if match is None:
                raise _invalid_diff()
            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) is not None else 1
            new_count = int(match.group(4)) if match.group(4) is not None else 1
            last_new_count = new_count
            target = max(0, old_start - 1)
            if target < cursor or target > len(source):
                raise _invalid_diff()
            output.extend(source[cursor:target])
            cursor = target
            i += 1
            hunk_old = 0
            hunk_new = 0
            while i < len(lines) and not lines[i].startswith(("@@ ", "--- ", "diff --git ")):
                line = lines[i]
                i += 1
                if line.startswith("\\ No newline at end of file"):
                    continue
                if not line or line[0] not in {" ", "+", "-"}:
                    raise _invalid_diff()
                content = line[1:]
                if line[0] in {" ", "-"}:
                    if cursor >= len(source) or source[cursor] != content:
                        raise ConflictError(
                            code="publish_patch_base_mismatch",
                            detail="Patch hunk context does not match the approved base revision.",
                        )
                    cursor += 1
                    hunk_old += 1
                    old_consumed += 1
                if line[0] in {" ", "+"}:
                    output.append(content)
                    hunk_new += 1
                    new_produced += 1
            if hunk_old != old_count or hunk_new != new_count:
                raise _invalid_diff()
        output.extend(source[cursor:])
        if new_path is None:
            if output:
                raise _invalid_diff()
            result[path] = None
        else:
            content = "\n".join(output)
            if output and (original_terminated or last_new_count > 0):
                content += "\n"
            result[path] = content
        if old_consumed > len(source) or new_produced > 131_072:
            raise _invalid_diff()
    if not result:
        raise _invalid_diff()
    if set(result) != set(base_contents):
        raise ConflictError(
            code="publish_patch_base_mismatch",
            detail="Patch paths do not exactly match the verified candidate file scope.",
        )
    return result


def _clean_path(raw_path: str) -> str:
    path = raw_path[2:] if raw_path.startswith(("a/", "b/")) else raw_path
    candidate = PurePosixPath(path)
    if (
        not path
        or "\\" in path
        or "\x00" in path
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise _invalid_diff()
    return path


def _invalid_diff() -> ConflictError:
    return ConflictError(
        code="publish_patch_invalid",
        detail="Verified patch is malformed or cannot be applied without ambiguity.",
    )
