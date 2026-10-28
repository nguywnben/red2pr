"""External host-side Ed25519 ResultV1 signer (`ADR-035`, `SEC-030`).

Signing keys live strictly in the Z3 worker supervisor process/filesystem outside
the guest OCI container or microVM. Guest code never receives signing key material.
"""

from __future__ import annotations

import contextlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from py_contracts.crypto import (
    DOMAIN_RESULT_V1,
    PublicKeyRecord,
    export_ed25519_public_key_record,
    sign_model_ed25519,
)
from py_contracts.worker import ResultV1

_PRIVATE_KEY_FILENAME = "worker_result_ed25519.key"
_PUBLIC_RECORD_FILENAME = "worker_result_ed25519.pub.json"


def _enforce_owner_only_permissions(path: Path, *, is_dir: bool = False) -> None:
    mode = 0o700 if is_dir else 0o600
    with contextlib.suppress(OSError):
        os.chmod(path, mode)


def _is_path_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


class ExternalResultSigner:
    """Host-supervisor-only Ed25519 signer for canonical `ResultV1` payloads (`ADR-035`)."""

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        public_record: PublicKeyRecord,
        key_path: Path | None = None,
    ) -> None:
        self._private_key = private_key
        self._public_record = public_record
        self._key_path = key_path

    @property
    def key_id(self) -> str:
        return self._public_record.key_id

    @property
    def public_key_record(self) -> PublicKeyRecord:
        return self._public_record

    @property
    def key_path(self) -> Path | None:
        return self._key_path

    @classmethod
    def generate(
        cls,
        *,
        key_id: str,
        trust_domain: str = "worker-supervisor",
        not_before: datetime | None = None,
    ) -> ExternalResultSigner:
        ref_now = not_before.astimezone(UTC) if not_before is not None else datetime.now(tz=UTC)
        priv = Ed25519PrivateKey.generate()
        pub_record = export_ed25519_public_key_record(
            private_key=priv,
            key_id=key_id,
            not_before=ref_now,
            trust_domain=trust_domain,
        )
        return cls(private_key=priv, public_record=pub_record)

    def save_to_directory(self, state_dir: Path) -> Path:
        state_dir.mkdir(parents=True, exist_ok=True)
        _enforce_owner_only_permissions(state_dir, is_dir=True)
        key_file = state_dir / _PRIVATE_KEY_FILENAME
        pub_file = state_dir / _PUBLIC_RECORD_FILENAME

        raw_priv = self._private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        key_file.write_bytes(raw_priv)
        _enforce_owner_only_permissions(key_file, is_dir=False)

        pub_file.write_text(
            json.dumps(self._public_record.model_dump(mode="json"), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        _enforce_owner_only_permissions(pub_file, is_dir=False)
        self._key_path = key_file
        return key_file

    @classmethod
    def load_from_directory(cls, state_dir: Path) -> ExternalResultSigner:
        key_file = state_dir / _PRIVATE_KEY_FILENAME
        pub_file = state_dir / _PUBLIC_RECORD_FILENAME
        raw_priv = key_file.read_bytes()
        priv = Ed25519PrivateKey.from_private_bytes(raw_priv)
        pub_record = PublicKeyRecord.model_validate_json(pub_file.read_text(encoding="utf-8"))
        return cls(private_key=priv, public_record=pub_record, key_path=key_file)

    def assert_outside_guest_workspace(self, guest_workspace_root: Path) -> None:
        """Verify signing key material is never inside or beneath guest mounts (`ADR-035`)."""
        if self._key_path is not None and _is_path_within(self._key_path, guest_workspace_root):
            raise PermissionError(
                "ADR-035 violation: worker Ed25519 signing key resides inside guest workspace."
            )

    def sign_result(
        self,
        result: ResultV1,
        *,
        guest_workspace_root: Path | None = None,
    ) -> ResultV1:
        """Return a signed copy of `ResultV1` under `DOMAIN_RESULT_V1` (`SEC-030`)."""
        if guest_workspace_root is not None:
            self.assert_outside_guest_workspace(guest_workspace_root)
        return sign_model_ed25519(
            result,
            private_key=self._private_key,
            key_id=self._public_record.key_id,
            domain=DOMAIN_RESULT_V1,
        )
