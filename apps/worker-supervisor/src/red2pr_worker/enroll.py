"""One-time enrollment token CSR exchange and TLS 1.3 mTLS client builder (`S-21`, `W-04`)."""

from __future__ import annotations

import contextlib
import json
import os
import ssl
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from py_contracts.crypto import (
    build_worker_spiffe_uri,
    generate_worker_csr,
    verify_worker_client_certificate,
)
from py_contracts.worker import (
    WORKER_PROTOCOL_V1,
    WorkerEnrollHandshakeRequest,
    WorkerEnrollHandshakeResponse,
    WorkerIsolationAttestation,
    WorkerIsolationMode,
)
from red2pr_worker.signer import ExternalResultSigner

_CREDENTIALS_META_FILE = "worker_mtls_credentials.json"
_CLIENT_KEY_FILE = "worker_mtls_client.key.pem"
_CLIENT_CERT_FILE = "worker_mtls_client.cert.pem"
_CA_CERT_FILE = "worker_mtls_ca.cert.pem"


class WorkerEnrollmentError(RuntimeError):
    """Raised when worker preflight attestation or mTLS enrollment fails."""


def _chmod_owner_only(path: Path, *, is_dir: bool = False) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700 if is_dir else 0o600)


def validate_attestation_fail_closed(attestation: WorkerIsolationAttestation) -> None:
    """Enforce fail-closed isolation attestation prior to enrollment or job polling."""
    if not attestation.network_none_supported:
        raise WorkerEnrollmentError(
            "Guest network=none egress isolation is unsupported; refusing enrollment (SEC-014)."
        )
    if not attestation.seccomp_verified:
        raise WorkerEnrollmentError(
            "Restrictive seccomp/hypervisor syscall filter is unverified; refusing enrollment."
        )
    if not attestation.no_new_privileges_verified:
        raise WorkerEnrollmentError(
            "no-new-privileges confinement is unverified; refusing enrollment (SEC-006)."
        )
    if (
        attestation.isolation_mode in ("oci_rootless", "vm_isolated")
        and not attestation.rootless_verified
    ):
        raise WorkerEnrollmentError(
            f"Isolation mode {attestation.isolation_mode!r} requires verified rootless/VM backend."
        )


@dataclass(frozen=True, slots=True)
class MtlsWorkerCredentials:
    """Short-lived mTLS X.509 worker identity issued by the control plane (`S-21`)."""

    worker_id: str
    spiffe_id: str
    cert_serial: str
    cert_fingerprint_sha256: str
    cert_expires_at: datetime
    client_key_pem: str
    client_cert_pem: str
    ca_cert_pem: str
    signer_key_id: str
    isolation_mode: WorkerIsolationMode
    trust_domain: str

    def save_to_directory(self, state_dir: Path) -> Path:
        state_dir.mkdir(parents=True, exist_ok=True)
        _chmod_owner_only(state_dir, is_dir=True)

        key_path = state_dir / _CLIENT_KEY_FILE
        cert_path = state_dir / _CLIENT_CERT_FILE
        ca_path = state_dir / _CA_CERT_FILE
        meta_path = state_dir / _CREDENTIALS_META_FILE

        key_path.write_text(self.client_key_pem, encoding="utf-8", newline="\n")
        _chmod_owner_only(key_path)
        cert_path.write_text(self.client_cert_pem, encoding="utf-8", newline="\n")
        _chmod_owner_only(cert_path)
        ca_path.write_text(self.ca_cert_pem, encoding="utf-8", newline="\n")
        _chmod_owner_only(ca_path)

        meta = {
            "worker_id": self.worker_id,
            "spiffe_id": self.spiffe_id,
            "cert_serial": self.cert_serial,
            "cert_fingerprint_sha256": self.cert_fingerprint_sha256,
            "cert_expires_at": self.cert_expires_at.astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "signer_key_id": self.signer_key_id,
            "isolation_mode": self.isolation_mode,
            "trust_domain": self.trust_domain,
        }
        meta_path.write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        _chmod_owner_only(meta_path)
        return meta_path

    @classmethod
    def load_from_directory(cls, state_dir: Path) -> MtlsWorkerCredentials:
        meta_raw = json.loads((state_dir / _CREDENTIALS_META_FILE).read_text(encoding="utf-8"))
        exp_str = str(meta_raw["cert_expires_at"])
        if exp_str.endswith("Z"):
            exp_str = exp_str[:-1] + "+00:00"
        return cls(
            worker_id=str(meta_raw["worker_id"]),
            spiffe_id=str(meta_raw["spiffe_id"]),
            cert_serial=str(meta_raw["cert_serial"]),
            cert_fingerprint_sha256=str(meta_raw["cert_fingerprint_sha256"]),
            cert_expires_at=datetime.fromisoformat(exp_str).astimezone(UTC),
            client_key_pem=(state_dir / _CLIENT_KEY_FILE).read_text(encoding="utf-8"),
            client_cert_pem=(state_dir / _CLIENT_CERT_FILE).read_text(encoding="utf-8"),
            ca_cert_pem=(state_dir / _CA_CERT_FILE).read_text(encoding="utf-8"),
            signer_key_id=str(meta_raw["signer_key_id"]),
            isolation_mode=meta_raw["isolation_mode"],
            trust_domain=str(meta_raw["trust_domain"]),
        )


def build_worker_ssl_context(
    credentials: MtlsWorkerCredentials,
    *,
    check_hostname: bool = True,
) -> ssl.SSLContext:
    """Construct a strict `TLS 1.3` mTLS `ssl.SSLContext` pinned to the Worker CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = check_hostname
    ctx.load_verify_locations(cadata=credentials.ca_cert_pem)

    tmp_dir = Path(tempfile.mkdtemp(prefix="red2pr-mtls-"))
    _chmod_owner_only(tmp_dir, is_dir=True)
    cert_file = tmp_dir / "client.crt"
    key_file = tmp_dir / "client.key"
    try:
        cert_file.write_text(credentials.client_cert_pem, encoding="utf-8", newline="\n")
        _chmod_owner_only(cert_file)
        key_file.write_text(credentials.client_key_pem, encoding="utf-8", newline="\n")
        _chmod_owner_only(key_file)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    finally:
        for candidate in (key_file, cert_file):
            with contextlib.suppress(OSError):
                candidate.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            tmp_dir.rmdir()
    return ctx


class WorkerEnroller:
    """Exchanges a one-time enrollment token + PKCS#10 CSR for short-lived mTLS credentials."""

    async def enroll(
        self,
        *,
        client: httpx.AsyncClient,
        enrollment_token: str,
        supported_profiles: Sequence[str],
        signer: ExternalResultSigner,
        attestation: WorkerIsolationAttestation,
        trust_domain: str = "worker-supervisor",
        now: datetime | None = None,
    ) -> MtlsWorkerCredentials:
        validate_attestation_fail_closed(attestation)
        clean_token = enrollment_token.strip()
        if len(clean_token) < 24:
            raise WorkerEnrollmentError("Enrollment token is malformed or too short.")

        csr_pem, key_pem = generate_worker_csr(
            host_id=attestation.host_id,
            trust_domain=trust_domain,
        )
        req_payload = WorkerEnrollHandshakeRequest(
            enrollment_token=clean_token,
            csr_pem=csr_pem,
            signer_public_key=signer.public_key_record,
            attestation=attestation,
            profile_ids=list(supported_profiles),
            protocol_versions=[WORKER_PROTOCOL_V1],
        )

        resp = await client.post(
            "/internal/v1/workers/enroll",
            json=req_payload.model_dump(mode="json"),
        )
        if resp.status_code != 200:
            raise WorkerEnrollmentError(
                f"Worker enrollment rejected by control plane (HTTP {resp.status_code}): "
                f"{resp.text[:300]}"
            )

        handshake = WorkerEnrollHandshakeResponse.model_validate(resp.json())
        verified_cert = verify_worker_client_certificate(
            cert_der_or_pem=handshake.client_cert_pem,
            ca_cert_pem=handshake.ca_cert_pem,
            now=now,
        )
        if verified_cert.worker_id != handshake.worker.id:
            raise WorkerEnrollmentError(
                "Issued client certificate SPIFFE worker_id does not match enrolled worker."
            )
        spiffe_uri = build_worker_spiffe_uri(
            trust_domain=verified_cert.trust_domain,
            worker_id=verified_cert.worker_id,
        )
        return MtlsWorkerCredentials(
            worker_id=handshake.worker.id,
            spiffe_id=spiffe_uri,
            cert_serial=verified_cert.serial_hex,
            cert_fingerprint_sha256=verified_cert.fingerprint_sha256,
            cert_expires_at=verified_cert.not_valid_after,
            client_key_pem=key_pem,
            client_cert_pem=handshake.client_cert_pem,
            ca_cert_pem=handshake.ca_cert_pem,
            signer_key_id=signer.key_id,
            isolation_mode=handshake.worker.isolation_mode,
            trust_domain=verified_cert.trust_domain,
        )
