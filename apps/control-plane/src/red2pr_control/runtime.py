"""Production & self-hosted control-plane ASGI composition root (`red2pr-control`)."""

from __future__ import annotations

import argparse
import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from py_contracts.crypto import KeyRing, MasterKeyRing, export_ed25519_public_key_record
from red2pr_control.api.app import create_app
from red2pr_control.core.config import load_config
from red2pr_control.core.egress import EgressPolicyEngine
from red2pr_control.core.keyring import load_master_key_ring_from_file
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.engine import (
    create_app_engine,
    create_session_factory,
    ensure_compatible_event_loop,
)
from red2pr_control.iam.sessions import IamService
from red2pr_control.inference import AgentProfileService, MetaMuseInferenceService
from red2pr_control.inference.budgets import AtomicBudgetLedger
from red2pr_control.integrations import (
    GitHubAppAdapter,
    GitHubIntegrationService,
    GitLabAdapter,
    LocalPollingService,
    MissedEventReconciler,
    WebhookIngestService,
)
from red2pr_control.operations.setup_wizard import (
    DbEndpointAllowlistProvider,
    SetupStepRegistry,
    SetupWizardService,
)
from red2pr_control.orchestrator import (
    DurableTaskQueueService,
    OperationReceiptService,
    WorkerBrokerService,
)
from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine
from red2pr_control.publisher.remote_observer import RemoteCiObserver
from red2pr_control.publisher.saga import PublisherSaga
from red2pr_control.repositories import RepositoryCatalogService
from red2pr_control.runtime_pipeline import RuntimePipelineCoordinator
from red2pr_control.secrets.broker import (
    SecretBroker,
    SecretBrokerProviderVault,
    SecretBrokerTotpVault,
)
from red2pr_control.triage_evidence import TriageEvidenceService
from red2pr_control.triage_evidence.artifact_store import LocalEncryptedArtifactStore
from red2pr_control.triage_evidence.collector import CiRunCollectorService


def _resolve_database_url() -> str:
    direct = os.environ.get("RED2PR_DATABASE_URL", "").strip()
    if direct:
        return direct
    url_file = os.environ.get("RED2PR_DATABASE_URL_FILE", "").strip()
    if url_file:
        return Path(url_file).read_text(encoding="utf-8").strip()
    raise RuntimeError(
        "Configure RED2PR_DATABASE_URL or RED2PR_DATABASE_URL_FILE before starting red2pr-control."
    )


def _resolve_master_key_ring() -> MasterKeyRing:
    if os.environ.get("RED2PR_MASTER_KEY_FILE", "").strip():
        return load_master_key_ring_from_file()
    bootstrap_secret = os.environ.get("RED2PR_BOOTSTRAP_ISSUER_SECRET", "").strip()
    if not bootstrap_secret:
        raise RuntimeError(
            "Configure RED2PR_MASTER_KEY_FILE or RED2PR_BOOTSTRAP_ISSUER_SECRET before starting."
        )
    derived = hashlib.sha256(
        b"red2pr:runtime_master_kek:v1:" + bootstrap_secret.encode("utf-8")
    ).digest()
    return MasterKeyRing(active_version=1, keys={1: derived})


def build_runtime_app(
    *,
    database_url: str | None = None,
    data_dir: Path | None = None,
    pricing_catalog_refresh_enabled: bool = True,
) -> FastAPI:
    """Build a fully wired `FastAPI` control-plane application backed by PostgreSQL."""
    ensure_compatible_event_loop()
    resolved_db_url = database_url or _resolve_database_url()
    key_ring = _resolve_master_key_ring()
    default_data_dir = Path.home() / ".local" / "share" / "red2pr"
    resolved_data_dir = (
        data_dir or Path(os.environ.get("RED2PR_DATA_DIR", str(default_data_dir))).expanduser()
    ).resolve()
    resolved_data_dir.mkdir(parents=True, exist_ok=True)

    cfg = load_config()
    app_engine = create_app_engine(resolved_db_url)
    session_factory = create_session_factory(app_engine)
    redactor = Redactor()
    secret_broker = SecretBroker(key_ring=key_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(secret_broker)
    provider_vault = SecretBrokerProviderVault(secret_broker)

    active_kek = key_ring.get(key_ring.active_version)
    if active_kek is None:
        raise RuntimeError("Active master KEK version is missing from MasterKeyRing.")
    iam_seed = hashlib.sha256(b"red2pr:iam:seed:v1:" + active_kek).digest()
    intent_signing_key = hashlib.sha256(b"red2pr:publisher:intent:v1:" + active_kek).digest()
    manifest_seed = hashlib.sha256(b"red2pr:evidence:manifest:v1:" + active_kek).digest()
    manifest_signer = Ed25519PrivateKey.from_private_bytes(manifest_seed)
    manifest_pub = export_ed25519_public_key_record(
        private_key=manifest_signer,
        key_id="runtime-manifest-key-v1",
        not_before=datetime.now(tz=UTC) - timedelta(days=1),
    )
    manifest_keyring = KeyRing([manifest_pub])
    trust_domain = os.environ.get("RED2PR_EVIDENCE_TRUST_DOMAIN", "worker.red2pr.internal").strip()

    iam = IamService(
        session_factory=session_factory,
        totp_vault=totp_vault,
        iam_seed_key=iam_seed,
        public_base_url=cfg.instance.public_base_url,
        deployment_mode=cfg.instance.deployment_mode,
    )
    step_registry = SetupStepRegistry()
    setup_service = SetupWizardService(
        iam_service=iam,
        step_registry=step_registry,
        redactor=redactor,
    )
    egress_policy = EgressPolicyEngine(
        allowlist_provider=DbEndpointAllowlistProvider(session_factory)
    )
    artifact_store = LocalEncryptedArtifactStore(
        root_dir=resolved_data_dir / "artifacts",
        key_ring=key_ring,
    )
    queue_service = DurableTaskQueueService(
        session_factory=session_factory,
        signing_key=iam.csrf_signing_key,
        redactor=redactor,
    )
    op_receipts = OperationReceiptService(session_factory=session_factory)
    worker_broker = WorkerBrokerService(
        session_factory=session_factory,
        signing_key=iam.csrf_signing_key,
        queue_service=queue_service,
        artifact_store=artifact_store,
        master_key_ring=key_ring,
        redactor=redactor,
    )
    gh_adapter = GitHubAppAdapter(vault=provider_vault, egress_policy=egress_policy)
    gl_adapter = GitLabAdapter(vault=provider_vault, egress_policy=egress_policy)
    integration_service = GitHubIntegrationService(
        session_factory=session_factory,
        signing_key=iam.csrf_signing_key,
        vault=provider_vault,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        redactor=redactor,
    )
    webhook_service = WebhookIngestService(
        session_factory=session_factory,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        integration_service=integration_service,
        redactor=redactor,
    )
    poller = LocalPollingService(
        session_factory=session_factory,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        integration_service=integration_service,
    )
    reconciler = MissedEventReconciler(
        session_factory=session_factory,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        poller=poller,
        integration_service=integration_service,
    )
    catalog_service = RepositoryCatalogService(
        session_factory=session_factory,
        signing_key=iam.csrf_signing_key,
        instance_config=cfg,
        redactor=redactor,
    )
    collector_service = CiRunCollectorService(
        session_factory=session_factory,
        artifact_store=artifact_store,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        redactor=redactor,
    )
    triage_service = TriageEvidenceService(
        session_factory=session_factory,
        signing_key=iam.csrf_signing_key,
        artifact_store=artifact_store,
    )
    budget_ledger = AtomicBudgetLedger(
        session_factory=session_factory,
        redactor=redactor,
    )
    meta_service = MetaMuseInferenceService(
        iam_service=iam,
        secret_broker=secret_broker,
        budget_ledger=budget_ledger,
        egress_policy=egress_policy,
        redactor=redactor,
    )
    agent_profiles = AgentProfileService(
        session_factory=session_factory,
        iam_service=iam,
        meta_inference_service=meta_service,
    )
    state_machine = RepairSessionStateMachine(session_factory=session_factory)
    publisher_saga = PublisherSaga(
        session_factory=session_factory,
        integrations=integration_service,
        artifact_store=artifact_store,
        manifest_keyring=manifest_keyring,
        evidence_trust_domain=trust_domain,
        intent_signing_key=intent_signing_key,
        state_machine=state_machine,
    )
    remote_observer = RemoteCiObserver(
        session_factory=session_factory,
        integrations=integration_service,
        state_machine=state_machine,
    )
    pipeline_coordinator = RuntimePipelineCoordinator(
        session_factory=session_factory,
        queue_service=queue_service,
        collector_service=collector_service,
        state_machine=state_machine,
    )

    app = create_app(
        iam_service=iam,
        setup_wizard_service=setup_service,
        setup_step_registry=step_registry,
        task_queue_service=queue_service,
        operation_receipt_service=op_receipts,
        worker_broker_service=worker_broker,
        github_integration_service=integration_service,
        webhook_ingest_service=webhook_service,
        polling_service=poller,
        reconciler_service=reconciler,
        repository_catalog_service=catalog_service,
        triage_evidence_service=triage_service,
        meta_inference_service=meta_service,
        pricing_catalog_refresh_enabled=pricing_catalog_refresh_enabled,
        agent_profile_service=agent_profiles,
        artifact_store=artifact_store,
        publisher_saga=publisher_saga,
        remote_ci_observer=remote_observer,
        notification_secret_broker=secret_broker,
        relay_secret_broker=secret_broker,
        oidc_secret_broker=secret_broker,
    )
    app.state.pipeline_coordinator = pipeline_coordinator
    app.state.app_engine = app_engine
    return app


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `red2pr-control`."""
    parser = argparse.ArgumentParser(description="Start Red2PR FastAPI control plane.")
    parser.add_argument(
        "--host",
        default=os.environ.get("RED2PR_BIND_HOST", "127.0.0.1"),
        help="Bind host address (defaults to 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("RED2PR_HTTP_PORT", "8080")),
        help="Bind TCP port (defaults to 8080).",
    )
    parser.add_argument(
        "--check-wiring",
        action="store_true",
        help="Verify configuration and build the ASGI application without opening a listener.",
    )
    args = parser.parse_args(argv)
    app = build_runtime_app(pricing_catalog_refresh_enabled=not args.check_wiring)
    if args.check_wiring:
        return 0
    uvicorn.run(app, host=args.host, port=args.port, server_header=False, date_header=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
