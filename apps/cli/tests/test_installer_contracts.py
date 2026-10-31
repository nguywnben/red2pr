from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
SIGNER = ROOT / "deploy" / "security" / "sign_release.py"
SCHEMA_PATH = ROOT / "deploy" / "install" / "release-manifest.schema.json"
SIGNER_SPEC = importlib.util.spec_from_file_location("red2pr_release_signer", SIGNER)
assert SIGNER_SPEC is not None and SIGNER_SPEC.loader is not None
SIGNER_MODULE = importlib.util.module_from_spec(SIGNER_SPEC)
SIGNER_SPEC.loader.exec_module(SIGNER_MODULE)


def _manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "version": "1.0.0-rc.1",
        "artifacts": [
            {
                "name": "red2pr-cli-linux-x86_64.tar.gz",
                "kind": "cli",
                "url": "https://releases.example.invalid/red2pr-cli.tar.gz",
                "sha256": "a" * 64,
            }
        ],
        "images": [
            {
                "name": "control",
                "reference": "registry.example.invalid/red2pr/control@sha256:" + "b" * 64,
            },
            {
                "name": "worker",
                "reference": "registry.example.invalid/red2pr/worker@sha256:" + "c" * 64,
            },
            {
                "name": "database",
                "reference": "registry.example.invalid/postgres@sha256:" + "d" * 64,
            },
            {
                "name": "redis",
                "reference": "registry.example.invalid/redis@sha256:" + "e" * 64,
            },
            {
                "name": "caddy",
                "reference": "registry.example.invalid/caddy@sha256:" + "f" * 64,
            },
        ],
        "minimums": {
            "linux": {
                "architectures": ["x86_64"],
                "cpus": 2,
                "ram_bytes": 4294967296,
                "disk_bytes": 21474836480,
            },
            "macos": {
                "architectures": ["arm64"],
                "major_version": 15,
                "cpus": 4,
                "ram_bytes": 8589934592,
                "disk_bytes": 42949672960,
            },
            "windows": {
                "architectures": ["x86_64"],
                "build": 22000,
                "cpus": 4,
                "ram_bytes": 8589934592,
                "disk_bytes": 42949672960,
            },
        },
    }


def _key_pair(tmp_path: Path, name: str = "release") -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    private_path = tmp_path / f"{name}-private.pem"
    public_path = tmp_path / f"{name}-public.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def _run_signer(*args: str) -> int:
    return SIGNER_MODULE.main(list(args))


def _signed_manifest(tmp_path: Path) -> tuple[Path, Path, Path]:
    private_key, public_key = _key_pair(tmp_path)
    draft = tmp_path / "draft.json"
    final_manifest = tmp_path / "release-manifest.json"
    signature = tmp_path / "release-manifest.sig"
    draft.write_text(json.dumps(_manifest()), encoding="utf-8")
    signed = _run_signer(
        "sign",
        "--input",
        str(draft),
        "--key",
        str(private_key),
        "--output",
        str(final_manifest),
        "--signature",
        str(signature),
    )
    assert signed == 0
    return final_manifest, signature, public_key


def test_release_manifest_schema_is_strict_and_pins_supported_profiles() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    assert {"schema_version", "version", "key_id", "artifacts", "images", "minimums"} <= set(
        schema["required"]
    )
    assert set(schema["properties"]["minimums"]["properties"]) == {"linux", "macos", "windows"}
    assert "@sha256:" in schema["$defs"]["image"]["properties"]["reference"]["pattern"]


def test_release_manifest_sign_and_verify_are_canonical_and_offline(tmp_path: Path) -> None:
    manifest, signature, public_key = _signed_manifest(tmp_path)
    raw = manifest.read_bytes()

    verified = _run_signer(
        "verify",
        "--input",
        str(manifest),
        "--signature",
        str(signature),
        "--trust-root",
        str(public_key),
    )

    assert verified == 0
    assert raw.endswith(b"\n")
    assert json.loads(raw)["key_id"]


def test_tampered_manifest_and_signature_are_rejected(tmp_path: Path) -> None:
    manifest, signature, public_key = _signed_manifest(tmp_path)
    manifest.write_bytes(manifest.read_bytes().replace(b"1.0.0-rc.1", b"1.0.0-rc.2"))

    verified = _run_signer(
        "verify",
        "--input",
        str(manifest),
        "--signature",
        str(signature),
        "--trust-root",
        str(public_key),
    )

    assert verified != 0


def test_revoked_or_unpinned_signing_key_is_rejected(tmp_path: Path) -> None:
    manifest, signature, public_key = _signed_manifest(tmp_path)
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    revoked = tmp_path / "revoked.txt"
    revoked.write_text(doc["key_id"] + "\n", encoding="ascii")

    denied = _run_signer(
        "verify",
        "--input",
        str(manifest),
        "--signature",
        str(signature),
        "--trust-root",
        str(public_key),
        "--revoked-keys",
        str(revoked),
    )
    wrong_key = _key_pair(tmp_path, "wrong")[1]
    unpinned = _run_signer(
        "verify",
        "--input",
        str(manifest),
        "--signature",
        str(signature),
        "--trust-root",
        str(wrong_key),
    )

    assert denied != 0
    assert unpinned != 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda doc: doc.update(extra="forbidden"),
        lambda doc: doc["images"][0].update(reference="registry.invalid/red2pr/control:latest"),
        lambda doc: doc["artifacts"][0].update(url="http://releases.invalid/a.tar.gz"),
        lambda doc: doc["artifacts"][0].update(sha256="not-a-digest"),
        lambda doc: doc["artifacts"][0].update(kind="support"),
        lambda doc: doc.update(schema_version=True),
        lambda doc: doc["minimums"]["windows"].update(architectures=["arm64"]),
        lambda doc: doc["artifacts"].append(dict(doc["artifacts"][0])),
    ],
)
def test_signer_rejects_invalid_release_manifest(tmp_path: Path, mutation) -> None:
    private_key, _ = _key_pair(tmp_path)
    doc = _manifest()
    mutation(doc)
    draft = tmp_path / "invalid.json"
    draft.write_text(json.dumps(doc), encoding="utf-8")

    result = _run_signer(
        "sign",
        "--input",
        str(draft),
        "--key",
        str(private_key),
        "--output",
        str(tmp_path / "manifest.json"),
        "--signature",
        str(tmp_path / "manifest.sig"),
    )

    assert result != 0
    assert not (tmp_path / "manifest.json").exists()


def test_compose_topologies_keep_state_private_and_images_digest_pinned() -> None:
    local = yaml.safe_load((ROOT / "deploy/compose/compose.local.yml").read_text(encoding="utf-8"))
    server = yaml.safe_load(
        (ROOT / "deploy/compose/compose.server.yml").read_text(encoding="utf-8")
    )
    distributed = yaml.safe_load(
        (ROOT / "deploy/compose/compose.distributed-worker.yml").read_text(encoding="utf-8")
    )

    assert local["services"]["control"]["ports"][0].startswith("127.0.0.1:")
    assert local["services"]["database"]["networks"]["data"]["aliases"]
    assert local["networks"]["data"]["internal"] is True
    assert server["services"]["caddy"]["ports"] == [
        "${RED2PR_HTTP_PORT:-80}:80",
        "${RED2PR_HTTPS_PORT:-443}:443",
        "${RED2PR_HTTPS_PORT:-443}:443/udp",
    ]
    assert set(distributed["services"]) == {"worker"}

    for document in (local, server, distributed):
        for service in document["services"].values():
            assert service.get("privileged") is not True
            assert "/var/run/docker.sock" not in json.dumps(service)
            assert service.get("cap_drop") == ["ALL"]
            assert service.get("security_opt") == ["no-new-privileges:true"]
            assert "@sha256:" in service["image"]


def test_systemd_units_run_unprivileged_without_host_container_socket() -> None:
    control = (ROOT / "deploy/systemd/red2pr-control.service").read_text(encoding="utf-8")
    worker = (ROOT / "deploy/systemd/red2pr-worker.service").read_text(encoding="utf-8")

    for unit in (control, worker):
        assert "User=red2pr" in unit
        assert "NoNewPrivileges=true" in unit
        assert "ProtectSystem=strict" in unit
        assert "docker.sock" not in unit
    assert "red2pr-control" in control
    assert "red2pr-worker" in worker


def test_installers_expose_non_destructive_modes_and_signed_manifest_gate() -> None:
    posix = (ROOT / "deploy/install/install.sh").read_text(encoding="utf-8")
    powershell = (ROOT / "deploy/install/install.ps1").read_text(encoding="utf-8")

    for option in (
        "local",
        "server",
        "worker",
        "--data-dir",
        "--dry-run",
        "--verify-only",
        "--resume",
    ):
        assert option in posix
    for option in ("local", "server", "worker", "DataDir", "DryRun", "VerifyOnly", "Resume"):
        assert option in powershell
    assert "install-state.json" in posix
    assert "install-state.json" in powershell
    assert "container runtime is installed but not ready" in posix
    assert "one or more required host ports are already in use" in posix
    assert "sha256sum" not in posix
    assert "OpenSSL 3 is required" in posix
    assert "sys.version_info >= (3, 12)" in posix
    assert "ConvertFrom-Json -AsHashtable" not in powershell
    assert "unrelated installer checkpoint already exists" in powershell
    assert posix.index("verify") < posix.index("podman")
    assert powershell.index("Verify-Release") < powershell.index("& wsl.exe @arguments")


def test_protected_agent_contract_hash_is_present_in_release_checks() -> None:
    digest = hashlib.sha256((ROOT / "AGENTS.md").read_bytes()).hexdigest()
    assert digest == "1fe195214a28f40d3b621a75da55390d8033aadeace35e9aefa4599146b97509"
