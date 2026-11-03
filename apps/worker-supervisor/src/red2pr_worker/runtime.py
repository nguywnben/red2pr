"""CLI composition root for the standalone `Z3` worker supervisor (`red2pr-worker`)."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import signal
import socket
import ssl
import sys
import tempfile
import uuid
from pathlib import Path

import httpx

from py_contracts.crypto import (
    CryptoVerificationError,
    build_worker_spiffe_uri,
    verify_worker_client_certificate,
)
from py_contracts.worker import WorkerIsolationMode
from red2pr_worker.enroll import (
    MtlsWorkerCredentials,
    WorkerEnroller,
    WorkerEnrollmentError,
    build_worker_ssl_context,
)
from red2pr_worker.oci_runner import (
    REVIEWED_PROFILE_MANIFESTS,
    RootlessOciCliDriver,
    SandboxIsolationUnavailableError,
    write_seccomp_profile,
)
from red2pr_worker.signer import ExternalResultSigner
from red2pr_worker.supervisor import WorkerSupervisor

WORKER_VERSION = "0.1.0"
_CREDENTIALS_META_NAME = "worker_mtls_credentials.json"
_SECCOMP_PROFILE_NAME = "red2pr-seccomp.v1.json"
_SIGNER_KEY_NAME = "worker_result_ed25519.key"
_SIGNER_PUB_NAME = "worker_result_ed25519.pub.json"


def _default_worker_root() -> Path:
    return Path(tempfile.gettempdir()) / "red2pr-worker"


def _load_or_create_signer(state_dir: Path, *, trust_domain: str) -> ExternalResultSigner:
    key_file = state_dir / _SIGNER_KEY_NAME
    pub_file = state_dir / _SIGNER_PUB_NAME
    if key_file.is_file() and pub_file.is_file():
        return ExternalResultSigner.load_from_directory(state_dir)
    signer = ExternalResultSigner.generate(
        key_id=f"worker-ed25519-{uuid.uuid4().hex[:12]}",
        trust_domain=trust_domain,
    )
    signer.save_to_directory(state_dir)
    return signer


def _load_env_mtls_credentials(
    *,
    signer_key_id: str,
    isolation_mode: WorkerIsolationMode,
) -> MtlsWorkerCredentials | None:
    cert_env = os.environ.get("RED2PR_WORKER_CERT", "").strip()
    key_env = os.environ.get("RED2PR_WORKER_KEY", "").strip()
    ca_env = os.environ.get("RED2PR_WORKER_CA", "").strip()
    if not (cert_env and key_env and ca_env):
        return None
    cert_pem = Path(cert_env).read_text(encoding="utf-8")
    key_pem = Path(key_env).read_text(encoding="utf-8")
    ca_pem = Path(ca_env).read_text(encoding="utf-8")
    verified = verify_worker_client_certificate(
        cert_der_or_pem=cert_pem,
        ca_cert_pem=ca_pem,
    )
    return MtlsWorkerCredentials(
        worker_id=verified.worker_id,
        spiffe_id=build_worker_spiffe_uri(
            trust_domain=verified.trust_domain,
            worker_id=verified.worker_id,
        ),
        cert_serial=verified.serial_hex,
        cert_fingerprint_sha256=verified.fingerprint_sha256,
        cert_expires_at=verified.not_valid_after,
        client_key_pem=key_pem,
        client_cert_pem=cert_pem,
        ca_cert_pem=ca_pem,
        signer_key_id=signer_key_id,
        isolation_mode=isolation_mode,
        trust_domain=verified.trust_domain,
    )


def _verify_local_wiring(
    *,
    state_dir: Path,
    scratch_dir: Path,
    trust_domain: str,
) -> None:
    if not REVIEWED_PROFILE_MANIFESTS:
        raise RuntimeError("Bundled runner profile manifests are missing.")
    state_dir.mkdir(parents=True, exist_ok=True)
    scratch_dir.mkdir(parents=True, exist_ok=True)
    signer = _load_or_create_signer(state_dir, trust_domain=trust_domain)
    signer.assert_outside_guest_workspace(scratch_dir)
    seccomp_path = state_dir / _SECCOMP_PROFILE_NAME
    if not seccomp_path.is_file():
        seccomp_path = write_seccomp_profile(state_dir)
    if not seccomp_path.is_file():
        raise RuntimeError("Failed to materialize worker seccomp profile.")


def _preflight_daemon_config(
    args: argparse.Namespace,
) -> tuple[
    Path, Path, ExternalResultSigner, str, WorkerIsolationMode, MtlsWorkerCredentials | None
]:
    state_dir = Path(args.state_dir).expanduser().resolve()
    scratch_dir = Path(args.scratch_dir).expanduser().resolve()
    _verify_local_wiring(
        state_dir=state_dir,
        scratch_dir=scratch_dir,
        trust_domain=args.trust_domain,
    )
    signer = _load_or_create_signer(state_dir, trust_domain=args.trust_domain)

    control_url = str(args.control_url).strip().rstrip("/")
    if not control_url.startswith("https://"):
        raise WorkerEnrollmentError(
            "RED2PR_CONTROL_URL must use https:// for mTLS worker transport (S-21)."
        )

    isolation_mode: WorkerIsolationMode = (
        "oci_trusted_local" if args.allow_trusted_local_mode else "oci_rootless"
    )
    credentials: MtlsWorkerCredentials | None = None
    if (state_dir / _CREDENTIALS_META_NAME).is_file():
        credentials = MtlsWorkerCredentials.load_from_directory(state_dir)
    else:
        credentials = _load_env_mtls_credentials(
            signer_key_id=signer.key_id,
            isolation_mode=isolation_mode,
        )
    if credentials is None and not str(args.enroll_token).strip():
        raise WorkerEnrollmentError(
            "Worker mTLS credentials are not provisioned. Provide --enroll-token "
            "(RED2PR_WORKER_ENROLL_TOKEN) or mount RED2PR_WORKER_CERT/KEY/CA."
        )
    return state_dir, scratch_dir, signer, control_url, isolation_mode, credentials


async def _run_daemon(
    args: argparse.Namespace,
    *,
    state_dir: Path,
    scratch_dir: Path,
    signer: ExternalResultSigner,
    control_url: str,
    isolation_mode: WorkerIsolationMode,
    credentials: MtlsWorkerCredentials | None,
) -> int:
    driver = RootlessOciCliDriver(
        host_id=args.host_id,
        isolation_mode=isolation_mode,
        allow_trusted_local_rootful=bool(args.allow_trusted_local_mode),
    )

    if credentials is None:
        enroll_token = str(args.enroll_token).strip()
        attestation = await driver.probe_isolation()
        ca_env = os.environ.get("RED2PR_WORKER_CA", "").strip()
        enroll_verify: ssl.SSLContext | bool = True
        if ca_env and Path(ca_env).is_file():
            enroll_ctx = ssl.create_default_context(cafile=ca_env)
            enroll_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            enroll_verify = enroll_ctx
        async with httpx.AsyncClient(
            base_url=control_url,
            verify=enroll_verify,
            timeout=30.0,
        ) as enroll_client:
            credentials = await WorkerEnroller().enroll(
                client=enroll_client,
                enrollment_token=enroll_token,
                supported_profiles=sorted(REVIEWED_PROFILE_MANIFESTS.keys()),
                signer=signer,
                attestation=attestation,
                trust_domain=args.trust_domain,
            )
        credentials.save_to_directory(state_dir)

    supervisor = WorkerSupervisor(
        credentials=credentials,
        signer=signer,
        driver=driver,
        scratch_dir=scratch_dir,
        state_dir=state_dir,
        allow_trusted_local_mode=bool(args.allow_trusted_local_mode),
    )
    ssl_ctx = build_worker_ssl_context(credentials)
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop_event.set)

    async with httpx.AsyncClient(
        base_url=control_url,
        verify=ssl_ctx,
        timeout=60.0,
    ) as client:
        while not stop_event.is_set():
            outcome = await supervisor.poll_and_execute_once(client)
            if supervisor.is_quarantined:
                sys.stderr.write("red2pr-worker: worker supervisor entered quarantine; stopping.\n")
                return 3
            if args.once:
                return 0
            if outcome is None:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop_event.wait(), timeout=args.poll_interval)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    default_root = _default_worker_root()
    parser = argparse.ArgumentParser(
        prog="red2pr-worker",
        description="Start the isolated Red2PR Z3 worker supervisor.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"red2pr-worker {WORKER_VERSION}",
    )
    parser.add_argument(
        "--check-wiring",
        action="store_true",
        help=(
            "Validate bundled runner profiles, Ed25519 signer, "
            "and seccomp profile without network I/O."
        ),
    )
    parser.add_argument(
        "--control-url",
        default=os.environ.get("RED2PR_CONTROL_URL", "https://127.0.0.1:8443"),
        help="Control-plane mTLS base URL (defaults to RED2PR_CONTROL_URL).",
    )
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("RED2PR_WORKER_STATE_DIR", str(default_root / "state")),
        help="Supervisor state directory outside guest workspace mounts.",
    )
    parser.add_argument(
        "--scratch-dir",
        default=os.environ.get("RED2PR_WORKER_SCRATCH_DIR", str(default_root / "scratch")),
        help="Ephemeral per-job guest workspace root directory.",
    )
    parser.add_argument(
        "--enroll-token",
        default=os.environ.get("RED2PR_WORKER_ENROLL_TOKEN", ""),
        help="One-time worker enrollment token (or RED2PR_WORKER_ENROLL_TOKEN).",
    )
    parser.add_argument(
        "--host-id",
        default=os.environ.get("RED2PR_WORKER_HOST_ID", socket.gethostname() or "worker-01"),
        help="Logical worker host identifier reported during enrollment attestation.",
    )
    parser.add_argument(
        "--trust-domain",
        default=os.environ.get("RED2PR_WORKER_TRUST_DOMAIN", "worker.red2pr.internal"),
        help="SPIFFE mTLS worker trust domain.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.environ.get("RED2PR_WORKER_POLL_INTERVAL", "5.0")),
        help="Idle poll interval in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--allow-trusted-local-mode",
        action="store_true",
        default=os.environ.get("RED2PR_WORKER_ALLOW_TRUSTED_LOCAL", "").strip() == "1",
        help="Explicitly allow oci_trusted_local mode on local single-user developer hosts.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll at most one sandbox job cycle and exit.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `red2pr-worker`."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.poll_interval <= 0:
        sys.stderr.write("red2pr-worker: --poll-interval must be > 0.\n")
        return 2

    if args.check_wiring:
        try:
            state_dir = Path(args.state_dir).expanduser().resolve()
            scratch_dir = Path(args.scratch_dir).expanduser().resolve()
            _verify_local_wiring(
                state_dir=state_dir,
                scratch_dir=scratch_dir,
                trust_domain=args.trust_domain,
            )
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            sys.stderr.write(f"red2pr-worker wiring check failed: {exc}\n")
            return 2
        sys.stdout.write(
            f"red2pr-worker {WORKER_VERSION}: wiring verified "
            f"({len(REVIEWED_PROFILE_MANIFESTS)} reviewed profiles).\n"
        )
        return 0

    try:
        state_dir, scratch_dir, signer, control_url, isolation_mode, credentials = (
            _preflight_daemon_config(args)
        )
        return asyncio.run(
            _run_daemon(
                args,
                state_dir=state_dir,
                scratch_dir=scratch_dir,
                signer=signer,
                control_url=control_url,
                isolation_mode=isolation_mode,
                credentials=credentials,
            )
        )
    except (
        CryptoVerificationError,
        OSError,
        PermissionError,
        SandboxIsolationUnavailableError,
        ValueError,
        WorkerEnrollmentError,
    ) as exc:
        sys.stderr.write(f"red2pr-worker: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
