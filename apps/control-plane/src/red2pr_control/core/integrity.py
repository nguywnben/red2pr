"""Repository operating-contract integrity verifier (AGENTS.md SHA-256 guard)."""

from __future__ import annotations

import hashlib
import pathlib

EXPECTED_AGENTS_MD_LF_SHA256: str = (
    "1fe195214a28f40d3b621a75da55390d8033aadeace35e9aefa4599146b97509"
)
EXPECTED_AGENTS_MD_HEADER: str = "# Red2PR — Agent operating contract"


class IntegrityCheckError(RuntimeError):
    """Raised when a protected repository contract file is missing or modified."""


def verify_agents_md_integrity(
    agents_md_path: pathlib.Path,
    *,
    expected_lf_sha256: str = EXPECTED_AGENTS_MD_LF_SHA256,
) -> str:
    """Verify AGENTS.md exists, preserves its header, and matches its canonical LF SHA-256."""
    if not agents_md_path.is_file():
        raise IntegrityCheckError(f"Protected contract file is missing: {agents_md_path}")

    raw_bytes = agents_md_path.read_bytes()
    normalized_lf = raw_bytes.replace(b"\r\n", b"\n")
    text = normalized_lf.decode("utf-8", errors="strict")
    if not text.startswith(EXPECTED_AGENTS_MD_HEADER):
        raise IntegrityCheckError("AGENTS.md header mismatch")

    actual_digest = hashlib.sha256(normalized_lf).hexdigest()
    if actual_digest != expected_lf_sha256:
        raise IntegrityCheckError(
            f"AGENTS.md SHA-256 mismatch: expected {expected_lf_sha256}, got {actual_digest}"
        )
    return actual_digest
