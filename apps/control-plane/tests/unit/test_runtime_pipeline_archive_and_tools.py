"""Unit tests for source archive normalization, keyring upsert, and strict Meta tool schemas."""

from __future__ import annotations

import hashlib
import io
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, get_args

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_contracts.crypto import (
    KeyRing,
    MasterKeyRing,
    decrypt_envelope,
    encrypt_envelope,
    export_ed25519_public_key_record,
)
from py_contracts.tools import AgentToolName, build_s20_tool_parameter_schema
from red2pr_control.runtime_pipeline import normalize_source_archive
from red2pr_worker.cleanup import safe_extract_source_archive
from red2pr_worker.materializer import apply_unified_diff_to_worktree


def _build_github_style_pax_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        pax_hdr = tarfile.TarInfo(name="pax_global_header")
        pax_hdr.type = tarfile.XGLTYPE
        pax_bytes = b"52 comment=abcdef0123456789abcdef0123456789abcdef01\n"
        pax_hdr.size = len(pax_bytes)
        tf.addfile(pax_hdr, io.BytesIO(pax_bytes))

        files = {
            "owner-repo-deadbeef/src/calc.py": (
                b"def add(a: int, b: int) -> int:\n    return a - b\n"
            ),
            "owner-repo-deadbeef/tests/test_calc.py": (
                b"from src.calc import add\n\ndef test_add() -> None:\n    assert add(2, 3) == 5\n"
            ),
            "owner-repo-deadbeef/uv.lock": b"version = 1\nrevision = 1\n",
            "owner-repo-deadbeef/.git/config": b"[core]\nrepositoryformatversion = 0\n",
            "owner-repo-deadbeef/.gitmodules": b'[submodule "bad"]\n\turl = http://169.254.169.254/\n',
        }
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            tf.addfile(info, io.BytesIO(data))

        sym = tarfile.TarInfo(name="owner-repo-deadbeef/evil_link")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "/etc/passwd"
        tf.addfile(sym)
    return buf.getvalue()


def test_normalize_source_archive_strips_wrapper_pax_symlinks_and_extracts_cleanly(
    tmp_path: Path,
) -> None:
    raw = _build_github_style_pax_tarball()
    first = normalize_source_archive(raw_tar_bytes=raw, base_sha="a" * 40)
    second = normalize_source_archive(raw_tar_bytes=raw, base_sha="a" * 40)

    assert first.archive_digest == second.archive_digest
    assert first.archive_bytes == second.archive_bytes
    assert first.dependency_lock_digest == second.dependency_lock_digest
    assert set(first.snapshot.list_files()) == {
        "src/calc.py",
        "tests/test_calc.py",
        "uv.lock",
    }

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    extracted_count = safe_extract_source_archive(first.archive_bytes, worktree_dir=worktree)
    assert extracted_count == 3
    assert (worktree / "src" / "calc.py").read_text(encoding="utf-8").endswith("return a - b\n")
    assert not (worktree / ".git").exists()
    assert not (worktree / ".gitmodules").exists()
    assert not (worktree / "evil_link").exists()

    diff = (
        "--- a/src/calc.py\n"
        "+++ b/src/calc.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def add(a: int, b: int) -> int:\n"
        "-    return a - b\n"
        "+    return a + b\n"
    )
    patched_files = apply_unified_diff_to_worktree(
        worktree,
        diff,
        expected_patch_digest=hashlib.sha256(diff.encode("utf-8")).hexdigest(),
    )
    assert patched_files == ("src/calc.py",)
    assert "return a + b" in (worktree / "src" / "calc.py").read_text(encoding="utf-8")


def test_keyring_upsert_replaces_and_propagates_revocation() -> None:
    now = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
    priv = Ed25519PrivateKey.generate()
    rec = export_ed25519_public_key_record(
        private_key=priv,
        key_id="worker-res-01",
        not_before=now,
    )
    ring = KeyRing()
    ring.upsert(rec)
    loaded = ring.get("worker-res-01")
    assert loaded is not None and loaded.revoked_at is None

    revoked = rec.model_copy(update={"revoked_at": now})
    ring.upsert(revoked)
    reloaded = ring.get("worker-res-01")
    assert reloaded is not None and reloaded.revoked_at == now


def _assert_meta_strict_object_node(node: dict[str, Any]) -> None:
    assert "default" not in node
    if node.get("type") == "object" or "properties" in node:
        props = node.get("properties", {})
        assert node.get("additionalProperties") is False
        assert set(node.get("required", [])) == set(props.keys())
        for child in props.values():
            if isinstance(child, dict):
                _assert_meta_strict_object_node(child)
    for key in ("anyOf", "oneOf", "allOf"):
        for branch in node.get(key, []):
            if isinstance(branch, dict):
                _assert_meta_strict_object_node(branch)
    items = node.get("items")
    if isinstance(items, dict):
        _assert_meta_strict_object_node(items)


def test_meta_strict_tool_schemas_have_closed_objects_and_no_defaults() -> None:
    tool_names = get_args(AgentToolName)
    assert len(tool_names) >= 6
    for name in tool_names:
        params = build_s20_tool_parameter_schema(name)
        _assert_meta_strict_object_node(params)


def test_envelope_ciphertext_supports_large_ci_log_and_archive_artifacts() -> None:
    ring = MasterKeyRing(active_version=1, keys={1: b"\x33" * 32})
    aad = {"workspace_id": "ws-01", "sha256": "a" * 64}
    large_log = b"FAILED tests/test_calc.py::test_add - AssertionError\n" * 1024
    envelope = encrypt_envelope(large_log, key_ring=ring, aad_context=aad)
    assert len(envelope.ciphertext_b64) > 4096
    assert decrypt_envelope(envelope, key_ring=ring, aad_context=aad) == large_log
