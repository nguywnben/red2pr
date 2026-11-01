"""Load the externally managed master key ring for control-plane services."""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping
from pathlib import Path

from py_contracts.crypto import MasterKeyRing
from red2pr_control.core.errors import DependencyUnavailableError


def _decode_32byte_key_material(raw: str | bytes) -> bytes:
    if isinstance(raw, bytes):
        if len(raw) == 32:
            return raw
        text_val = raw.decode("ascii", errors="strict").strip()
    else:
        text_val = raw.strip()

    if len(text_val) == 64:
        try:
            decoded_hex = bytes.fromhex(text_val)
            if len(decoded_hex) == 32:
                return decoded_hex
        except ValueError:
            pass

    try:
        padded = text_val + "=" * ((4 - (len(text_val) % 4)) % 4)
        decoded_b64 = base64.b64decode(padded.encode("ascii"), validate=False)
        if len(decoded_b64) == 32:
            return decoded_b64
    except (ValueError, binascii.Error):
        pass

    raise ValueError("Master key material must decode to exactly 32 bytes (256 bits)")


def load_master_key_ring_from_file(
    path: Path | str | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> MasterKeyRing:
    """Load a versioned 256-bit key ring from a file or RED2PR_MASTER_KEY_FILE."""
    effective_env = env if env is not None else os.environ
    resolved_target = (
        Path(path)
        if path is not None
        else (
            Path(effective_env["RED2PR_MASTER_KEY_FILE"])
            if effective_env.get("RED2PR_MASTER_KEY_FILE")
            else None
        )
    )
    if resolved_target is None or not resolved_target.is_file():
        raise DependencyUnavailableError(
            code="master_key_unavailable",
            detail=(
                "External master encryption key file is missing or unconfigured; "
                "cannot unwrap or seal secrets."
            ),
        )

    try:
        raw_bytes = resolved_target.read_bytes()
    except OSError as exc:
        raise DependencyUnavailableError(
            code="master_key_unavailable",
            detail="External master encryption key file could not be read.",
        ) from exc

    if len(raw_bytes) == 32:
        return MasterKeyRing(active_version=1, keys={1: raw_bytes})

    try:
        text_content = raw_bytes.decode("utf-8").strip()
        if text_content.startswith("{"):
            parsed = json.loads(text_content)
            active_ver = int(parsed["active_version"])
            raw_keys = parsed["keys"]
            if not isinstance(raw_keys, Mapping) or not raw_keys:
                raise ValueError("Empty keys mapping")
            keys_map = {
                int(ver_str): _decode_32byte_key_material(str(mat))
                for ver_str, mat in raw_keys.items()
            }
            return MasterKeyRing(active_version=active_ver, keys=keys_map)
        single_key = _decode_32byte_key_material(text_content)
        return MasterKeyRing(active_version=1, keys={1: single_key})
    except Exception as exc:
        raise DependencyUnavailableError(
            code="master_key_unavailable",
            detail="External master encryption key file has invalid format or key length.",
        ) from exc
