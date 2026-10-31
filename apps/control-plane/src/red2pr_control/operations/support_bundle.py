"""Preview and produce allowlisted redacted support bundles (U26)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from py_contracts.crypto import canonical_json_bytes
from py_contracts.operations import SupportBundleFileId, SupportBundlePreview
from red2pr_control.core.redaction import DEFAULT_REDACTOR


def read_recent_redacted_logs(*, max_lines: int = 200) -> dict[str, object]:
    """Read only the configured owned log file and redact each bounded line."""
    raw_file = os.environ.get("RED2PR_LOG_FILE", "").strip()
    raw_root = os.environ.get("RED2PR_LOG_DIRECTORY", "").strip()
    if not raw_file or not raw_root:
        raise RuntimeError("support_logs_not_configured")
    try:
        root = Path(raw_root).resolve(strict=True)
        target = Path(os.path.abspath(raw_file))
        if not target.is_relative_to(root) or target == root:
            raise RuntimeError("support_logs_not_configured")
        cursor = Path(target.anchor)
        for part in target.parts[1:]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise RuntimeError("support_logs_not_configured")
        if not target.is_file():
            raise RuntimeError("support_logs_not_configured")
        lines: deque[str] = deque(maxlen=max_lines)
        with target.open("r", encoding="utf-8", errors="replace") as stream:
            lines.extend(stream)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("support_logs_not_configured") from exc
    return {
        "lines": [DEFAULT_REDACTOR.redact_text(line.rstrip("\r\n"))[:16_384] for line in lines],
        "line_count": len(lines),
    }


def render_support_bundle_preview(
    file_ids: tuple[SupportBundleFileId, ...], *, now: datetime | None = None
) -> SupportBundlePreview:
    ref_now = now.astimezone(UTC) if now else datetime.now(UTC)
    safe_ids = tuple(dict.fromkeys(file_ids))
    manifest = {
        "schema_version": 1,
        "file_ids": safe_ids,
        "excluded": ["secrets", "repository_source"],
    }
    return SupportBundlePreview(
        manifest_digest=hashlib.sha256(canonical_json_bytes(manifest)).hexdigest(),
        file_ids=safe_ids,
        redacted_file_count=len(safe_ids),
        excluded_secrets=True,
        excluded_repository_source=True,
        expires_at=ref_now + timedelta(minutes=10),
    )


def create_support_bundle(
    file_ids: tuple[SupportBundleFileId, ...], sources: Mapping[str, object]
) -> tuple[bytes, str]:
    """Package only caller-provided allowlisted diagnostics after structural redaction."""
    allowed = set(file_ids)
    normalized: dict[str, object] = {}
    for file_id in allowed:
        if file_id not in sources:
            continue
        value = DEFAULT_REDACTOR.redact_value(sources[file_id])
        normalized[f"{file_id}.json"] = value
    if not normalized:
        raise ValueError("No allowlisted support diagnostics are available.")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, value in sorted(normalized.items()):
            data = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    payload = output.getvalue()
    return payload, hashlib.sha256(payload).hexdigest()
