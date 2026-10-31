#!/usr/bin/env python3
"""Create and verify canonical Red2PR release manifests.

The repository trust root is a development-only key. Production signing identity
and trust-root replacement are release-time responsibilities under ADR-021.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

HEX_256 = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
IMAGE_NAMES = {"control", "worker", "database", "redis", "caddy"}
MINIMUM_PROFILES = {"linux", "macos", "windows"}


class ManifestError(ValueError):
    """A release manifest is malformed or violates the signed contract."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise ManifestError("manifest root must be an object")
    return value


def canonical_json(value: dict[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ManifestError(f"manifest is not canonical JSON data: {exc}") from exc


def key_id_from_pem(pem_bytes: bytes) -> str:
    """Hash the exact PEM trust-root bytes, matching OpenSSL/Pwsh installers."""
    return hashlib.sha256(pem_bytes).hexdigest()


def validate_manifest(manifest: dict[str, Any], *, require_key_id: bool) -> None:
    allowed = {"schema_version", "version", "key_id", "artifacts", "images", "minimums"}
    required = allowed if require_key_id else allowed - {"key_id"}
    if set(manifest) - allowed or required - set(manifest):
        raise ManifestError("manifest has missing or unknown top-level fields")
    if (
        isinstance(manifest["schema_version"], bool)
        or manifest["schema_version"] != 1
        or not isinstance(manifest["schema_version"], int)
    ):
        raise ManifestError("schema_version must be integer 1")
    if not isinstance(manifest["version"], str) or not VERSION.fullmatch(manifest["version"]):
        raise ManifestError("version must be a semantic version")
    if require_key_id and (
        not isinstance(manifest["key_id"], str) or not HEX_256.fullmatch(manifest["key_id"])
    ):
        raise ManifestError("key_id must be a SHA-256 hex digest")

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ManifestError("artifacts must be a non-empty array")
    artifact_names: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"name", "kind", "url", "sha256"}:
            raise ManifestError("artifact fields must be exactly name, kind, url, sha256")
        name, kind, url, digest = (artifact[name] for name in ("name", "kind", "url", "sha256"))
        if (
            not isinstance(name, str)
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
        ):
            raise ManifestError("artifact name must be a plain filename")
        if name in artifact_names:
            raise ManifestError("artifact names must be unique")
        artifact_names.add(name)
        if kind not in {"cli", "installer", "support"}:
            raise ManifestError("artifact kind is unsupported")
        parsed = urlsplit(url) if isinstance(url, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ManifestError("artifact URL must use HTTPS without embedded credentials")
        if parsed.fragment or parsed.query:
            raise ManifestError("artifact URL must not contain a query or fragment")
        if not isinstance(digest, str) or not HEX_256.fullmatch(digest):
            raise ManifestError("artifact sha256 must be a lowercase SHA-256 digest")
    if not any(artifact["kind"] == "cli" for artifact in artifacts):
        raise ManifestError("release manifest must include at least one CLI checksum")

    images = manifest["images"]
    if (
        not isinstance(images, list)
        or {item.get("name") for item in images if isinstance(item, dict)} != IMAGE_NAMES
    ):
        raise ManifestError(
            "images must contain control, worker, database, redis, and caddy images"
        )
    if len(images) != len(IMAGE_NAMES):
        raise ManifestError("images must not contain duplicate entries")
    for image in images:
        if not isinstance(image, dict) or set(image) != {"name", "reference"}:
            raise ManifestError("image fields must be exactly name and reference")
        if (
            image["name"] not in IMAGE_NAMES
            or not isinstance(image["reference"], str)
            or not OCI_DIGEST.fullmatch(image["reference"])
        ):
            raise ManifestError("container image must be pinned by an immutable SHA-256 digest")

    minimums = manifest["minimums"]
    if not isinstance(minimums, dict) or set(minimums) != MINIMUM_PROFILES:
        raise ManifestError("minimums must define linux, macos, and windows profiles")
    expected = {
        "linux": {"architectures", "cpus", "ram_bytes", "disk_bytes"},
        "macos": {"architectures", "major_version", "cpus", "ram_bytes", "disk_bytes"},
        "windows": {"architectures", "build", "cpus", "ram_bytes", "disk_bytes"},
    }
    for profile, fields in expected.items():
        item = minimums[profile]
        if not isinstance(item, dict) or set(item) != fields:
            raise ManifestError(f"{profile} minimum profile has missing or unknown fields")
        if not isinstance(item["architectures"], list) or not item["architectures"]:
            raise ManifestError(f"{profile} architectures must be a non-empty array")
        allowed_architectures = {
            "linux": {"x86_64", "arm64"},
            "macos": {"arm64"},
            "windows": {"x86_64"},
        }[profile]
        if any(arch not in allowed_architectures for arch in item["architectures"]):
            raise ManifestError(f"{profile} profile contains an unsupported architecture")
        if len(set(item["architectures"])) != len(item["architectures"]):
            raise ManifestError(f"{profile} architecture list contains duplicates")
        if any(
            not isinstance(item[field], int) or isinstance(item[field], bool) or item[field] <= 0
            for field in fields - {"architectures"}
        ):
            raise ManifestError(f"{profile} minimum resource values must be positive integers")


def _write_new(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = None
    try:
        descriptor = path.open("xb")
        descriptor.write(content)
    except FileExistsError as exc:
        raise ManifestError(f"refusing to overwrite existing file: {path}") from exc
    finally:
        if descriptor is not None:
            descriptor.close()
    path.chmod(mode)


def sign(input_path: Path, key_path: Path, output_path: Path, signature_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    draft = _load_json(input_path)
    validate_manifest(draft, require_key_id=False)
    try:
        private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ManifestError(f"cannot load Ed25519 signing key: {exc}") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise ManifestError("signing key must be Ed25519")
    public = private.public_key()
    signed = dict(draft)
    signed["key_id"] = key_id_from_pem(
        public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    validate_manifest(signed, require_key_id=True)
    payload = canonical_json(signed)
    signature = private.sign(payload)
    _write_new(output_path, payload, 0o644)
    try:
        _write_new(signature_path, signature, 0o644)
    except ManifestError:
        output_path.unlink(missing_ok=True)
        raise


def verify(
    input_path: Path, signature_path: Path, trust_root_path: Path, revoked_path: Path | None
) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    manifest = _load_json(input_path)
    validate_manifest(manifest, require_key_id=True)
    payload = input_path.read_bytes()
    if payload != canonical_json(manifest):
        raise ManifestError("manifest bytes are not canonical JSON")
    try:
        trust_root = serialization.load_pem_public_key(trust_root_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ManifestError(f"cannot load pinned trust root: {exc}") from exc
    if not isinstance(trust_root, Ed25519PublicKey):
        raise ManifestError("pinned trust root must be Ed25519")
    identifier = key_id_from_pem(trust_root_path.read_bytes())
    if manifest["key_id"] != identifier:
        raise ManifestError("manifest signing key is not the pinned trust root")
    if revoked_path is not None and revoked_path.exists():
        revoked = {
            line.strip()
            for line in revoked_path.read_text(encoding="ascii").splitlines()
            if line.strip() and not line.startswith("#")
        }
        if identifier in revoked:
            raise ManifestError("manifest signing key is revoked")
    try:
        trust_root.verify(signature_path.read_bytes(), payload)
    except (OSError, ValueError, InvalidSignature) as exc:
        raise ManifestError("Ed25519 signature verification failed") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sign_parser = commands.add_parser("sign", help="canonicalize and sign a release manifest")
    sign_parser.add_argument("--input", type=Path, required=True)
    sign_parser.add_argument("--key", type=Path, required=True)
    sign_parser.add_argument("--output", type=Path, required=True)
    sign_parser.add_argument("--signature", type=Path, required=True)
    verify_parser = commands.add_parser(
        "verify", help="verify a signed manifest using an offline trust root"
    )
    verify_parser.add_argument("--input", type=Path, required=True)
    verify_parser.add_argument("--signature", type=Path, required=True)
    verify_parser.add_argument("--trust-root", type=Path, required=True)
    verify_parser.add_argument("--revoked-keys", type=Path)
    validate_parser = commands.add_parser(
        "validate", help="validate manifest structure without trusting it"
    )
    validate_parser.add_argument("--input", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "sign":
            sign(args.input, args.key, args.output, args.signature)
            print("Release manifest signed.")
        elif args.command == "verify":
            verify(args.input, args.signature, args.trust_root, args.revoked_keys)
            print("Release manifest signature verified.")
        else:
            manifest = _load_json(args.input)
            validate_manifest(manifest, require_key_id="key_id" in manifest)
            print("Release manifest structure valid.")
    except (ManifestError, OSError, UnicodeError) as exc:
        print(f"release manifest rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
