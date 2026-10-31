"""Streaming authenticated encryption for a database backup payload."""

from __future__ import annotations

import os
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from py_contracts.crypto import MasterKeyRing

_MAGIC = b"R2PRDB01"
_HEADER = struct.Struct(">8sI12s12s48s")
_CHUNK = 1024 * 1024
_TAG_SIZE = 16


def _aad(backup_id: str, version: int) -> bytes:
    return b"red2pr:backup-db:v1\x00" + backup_id.encode("ascii") + struct.pack(">I", version)


class BackupEncryptor:
    """Wrap a random data key and stream a GCM ciphertext to an owned file."""

    def __init__(self, output: BinaryIO, *, keys: MasterKeyRing, backup_id: str) -> None:
        self._output = output
        self.version = keys.active_version
        key = keys.get(self.version)
        if key is None:
            raise ValueError("backup_encryption_key_missing")
        nonce, wrap_nonce, data_key = os.urandom(12), os.urandom(12), os.urandom(32)
        aad = _aad(backup_id, self.version)
        wrapped = AESGCM(key).encrypt(wrap_nonce, data_key, aad)
        header = _HEADER.pack(_MAGIC, self.version, nonce, wrap_nonce, wrapped)
        output.write(header)
        self._encryptor = Cipher(algorithms.AES(data_key), modes.GCM(nonce)).encryptor()
        self._encryptor.authenticate_additional_data(aad + header)

    def update(self, plaintext: bytes) -> None:
        self._output.write(self._encryptor.update(plaintext))

    def finish(self) -> None:
        self._output.write(self._encryptor.finalize())
        self._output.write(self._encryptor.tag)


def decrypt_backup_chunks(
    path: Path, *, keys: MasterKeyRing, backup_id: str, expected_version: int
) -> Iterator[bytes]:
    """Yield plaintext only for staging; caller must consume through tag verification."""
    with path.open("rb") as source:
        header = source.read(_HEADER.size)
        if len(header) != _HEADER.size or path.stat().st_size < _HEADER.size + _TAG_SIZE:
            raise ValueError("backup_payload_invalid")
        magic, version, nonce, wrap_nonce, wrapped = _HEADER.unpack(header)
        if magic != _MAGIC or version != expected_version:
            raise ValueError("backup_payload_invalid")
        key = keys.get(version)
        if key is None:
            raise ValueError("backup_encryption_key_missing")
        aad = _aad(backup_id, version)
        try:
            data_key = AESGCM(key).decrypt(wrap_nonce, wrapped, aad)
        except InvalidTag as exc:
            raise ValueError("backup_payload_integrity_failed") from exc
        source.seek(-_TAG_SIZE, os.SEEK_END)
        tag = source.read(_TAG_SIZE)
        remaining = path.stat().st_size - _HEADER.size - _TAG_SIZE
        source.seek(_HEADER.size)
        decryptor = Cipher(algorithms.AES(data_key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(aad + header)
        while remaining:
            chunk = source.read(min(_CHUNK, remaining))
            if not chunk:
                raise ValueError("backup_payload_invalid")
            remaining -= len(chunk)
            yield decryptor.update(chunk)
        try:
            yield decryptor.finalize()
        except InvalidTag as exc:
            raise ValueError("backup_payload_integrity_failed") from exc
