from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import os
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from uuid import uuid4

import pgserver
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError

from py_contracts.crypto import (
    DOMAIN_RESULT_V1,
    KeyRing,
    canonical_json_bytes,
    export_ed25519_public_key_record,
    sign_model_ed25519,
)
from py_contracts.evidence import RegressionSuiteSummary
from py_contracts.primitives import new_uuid7
from py_contracts.worker import IsolationCheckResult, ResultV1, SandboxResourceUsage
from red2pr_control.core.errors import ConflictError
from red2pr_control.db.base import (
    AuditLogModel,
    EvidenceManifestModel,
    OutboxEventModel,
    RepairSessionModel,
    VerificationRunModel,
)
from red2pr_control.db.engine import (
    create_admin_engine,
    create_session_factory,
    ensure_compatible_event_loop,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.orchestrator.state_machine import validate_repair_transition
from red2pr_control.verification.diff_integrity import DiffIntegrityGuard, IntegrityDisposition
from red2pr_control.verification.pr_reporter import render_pr_summary
from red2pr_control.verification.service import VerificationService
from red2pr_control.verification.verifier import (
    DeterministicVerifier,
    ExecutionCounts,
    VerificationFacts,
    create_signed_evidence_manifest,
    scan_diff_secrets,
    verify_evidence_manifest,
)

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "{{SECRET_u18_pg_role}}"


@dataclass(frozen=True)
class PgTestUrls:
    admin_url: str
    app_url: str


def _build_role_url(base_uri: str, *, username: str, password: str) -> str:
    parsed = urlparse(base_uri)
    host = parsed.hostname or "127.0.0.1"
    port_part = f":{parsed.port}" if parsed.port else ""
    return urlunparse(
        (
            "postgresql+psycopg",
            f"{username}:{password}@{host}{port_part}",
            parsed.path or "/postgres",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[PgTestUrls]:
    """Provide real PostgreSQL 16 for U18 migration and service integration checks."""
    ensure_compatible_event_loop()
    external_admin = os.environ.get("RED2PR_TEST_ADMIN_DATABASE_URL")
    if external_admin:
        app_url = os.environ.get("RED2PR_TEST_APP_DATABASE_URL") or _build_role_url(
            external_admin,
            username=APP_ROLE_NAME,
            password=APP_ROLE_PASSWORD,
        )
        yield PgTestUrls(admin_url=external_admin, app_url=app_url)
        return

    with (
        tempfile.TemporaryDirectory(prefix="red2pr_u18_pg16_") as tmp_dir,
        pgserver.get_server(tmp_dir, cleanup_mode="delete") as server,
    ):
        raw_uri = server.get_uri()
        parsed = urlparse(raw_uri)
        admin_url = urlunparse(
            (
                "postgresql+psycopg",
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        yield PgTestUrls(
            admin_url=admin_url,
            app_url=_build_role_url(
                raw_uri,
                username=APP_ROLE_NAME,
                password=APP_ROLE_PASSWORD,
            ),
        )


@pytest.fixture
async def migrated_db(pg_urls: PgTestUrls) -> Iterator[PgTestUrls]:
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


def test_ordinary_application_patch_is_accepted() -> None:
    diff = """diff --git a/src/fix.py b/src/fix.py
--- a/src/fix.py
+++ b/src/fix.py
@@ -1 +1 @@
-return broken()
+return fixed()
"""

    result = DiffIntegrityGuard().inspect(diff, changed_paths=["src/fix.py"])

    assert result.disposition is IntegrityDisposition.ACCEPT
    assert result.findings == ()


def test_deleted_test_file_is_rejected_as_test_tampering() -> None:
    diff = """diff --git a/tests/test_regression.py b/tests/test_regression.py
deleted file mode 100644
--- a/tests/test_regression.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def test_regression():
-    assert False
"""

    result = DiffIntegrityGuard().inspect(diff, changed_paths=["tests/test_regression.py"])

    assert result.disposition is IntegrityDisposition.REJECT
    assert "deleted_test" in {finding.code for finding in result.findings}


def test_new_test_suppression_is_rejected() -> None:
    diff = """diff --git a/tests/test_fix.py b/tests/test_fix.py
--- a/tests/test_fix.py
+++ b/tests/test_fix.py
@@ -1 +1,2 @@
+@pytest.mark.skip(reason="green")
 def test_fix():
"""

    result = DiffIntegrityGuard().inspect(diff, changed_paths=["tests/test_fix.py"])

    assert result.disposition is IntegrityDisposition.REJECT
    assert "test_suppression" in {finding.code for finding in result.findings}


def test_gate_weakening_in_sensitive_workflow_is_rejected() -> None:
    diff = """diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1 +1 @@
-run: pytest
+run: true
"""

    result = DiffIntegrityGuard().inspect(diff, changed_paths=[".github/workflows/ci.yml"])

    assert result.disposition is IntegrityDisposition.REJECT
    assert {"sensitive_path", "gate_weakening"} <= {finding.code for finding in result.findings}


def test_other_workflow_edit_requires_human_review() -> None:
    result = DiffIntegrityGuard().inspect(
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n",
        changed_paths=[".github/workflows/ci.yml"],
    )

    assert result.disposition is IntegrityDisposition.HUMAN_REVIEW


def test_path_traversal_is_rejected() -> None:
    result = DiffIntegrityGuard().inspect("", changed_paths=["../outside.py"])

    assert result.disposition is IntegrityDisposition.REJECT
    assert "unsafe_path" in {finding.code for finding in result.findings}


def test_diff_cannot_hide_a_changed_file_outside_declared_paths() -> None:
    diff = """diff --git a/src/hidden.py b/src/hidden.py
--- a/src/hidden.py
+++ b/src/hidden.py
@@ -1 +1 @@
-safe()
+unsafe()
"""

    result = DiffIntegrityGuard().inspect(diff, changed_paths=["src/declared.py"])

    assert result.disposition is IntegrityDisposition.REJECT
    assert "diff_path_mismatch" in {finding.code for finding in result.findings}


def test_diff_outside_policy_allowlist_is_rejected() -> None:
    diff = """diff --git a/src/fix.py b/src/fix.py
--- a/src/fix.py
+++ b/src/fix.py
@@ -1 +1 @@
-broken()
+fixed()
"""

    result = DiffIntegrityGuard().inspect(
        diff, changed_paths=["src/fix.py"], allowed_paths=("src/other.py",)
    )

    assert result.disposition is IntegrityDisposition.REJECT
    assert "path_out_of_scope" in {finding.code for finding in result.findings}


def test_diff_limit_is_enforced() -> None:
    diff = """diff --git a/src/fix.py b/src/fix.py
--- a/src/fix.py
+++ b/src/fix.py
@@ -1 +1,2 @@
+first()
+second()
"""

    result = DiffIntegrityGuard().inspect(
        diff, changed_paths=["src/fix.py"], allowed_paths=("src/fix.py",), max_diff_lines=1
    )

    assert result.disposition is IntegrityDisposition.REJECT
    assert "diff_size_limit" in {finding.code for finding in result.findings}


def test_test_case_removal_is_rejected() -> None:
    diff = """diff --git a/tests/test_case.py b/tests/test_case.py
--- a/tests/test_case.py
+++ b/tests/test_case.py
@@ -1,2 +0,0 @@
-def test_old_case():
-    pass
"""

    result = DiffIntegrityGuard().inspect(diff, changed_paths=["tests/test_case.py"])

    assert result.disposition is IntegrityDisposition.REJECT
    assert "removed_test_case" in {finding.code for finding in result.findings}


def test_adr031_blocks_approval_when_verification_is_not_local() -> None:
    with pytest.raises(ConflictError):
        validate_repair_transition(
            current_state="verifying",
            target_state="policy_gate",
            current_proof_grade="baseline_confirmed",
        )


def build_trusted_verification() -> tuple[DeterministicVerifier, VerificationFacts]:
    private_key = Ed25519PrivateKey.generate()
    key_id = "worker-key-1"
    trust_domain = "worker-test-domain"
    now = datetime.now(tz=UTC)
    public_key = export_ed25519_public_key_record(
        private_key=private_key,
        key_id=key_id,
        not_before=now - timedelta(days=1),
        trust_domain=trust_domain,
    )
    keyring = KeyRing([public_key])
    baseline = ResultV1(
        job_id=str(uuid4()),
        lease_epoch=1,
        capability_nonce="nonce-a",
        worker_id=str(uuid4()),
        started_at=now - timedelta(seconds=4),
        ended_at=now - timedelta(seconds=1),
        exit_code=1,
        termination="exited",
        command_digest="a" * 64,
        image_digest="b" * 64,
        environment_digest="c" * 64,
        source_digest="d" * 64,
        patch_digest=None,
        resource_usage=SandboxResourceUsage(
            wall_ms=3000, max_memory_bytes=1024, disk_written_bytes=0, output_bytes=12
        ),
        artifact_refs=[],
        isolation_checks=[IsolationCheckResult(check_id="network_none", passed=True)],
        signer_key_id=key_id,
        signature="ed25519:placeholder",
    )
    diff = "diff --git a/src/fix.py b/src/fix.py\n"
    diff_digest = hashlib.sha256(diff.encode()).hexdigest()
    patched = baseline.model_copy(
        update={
            "job_id": str(uuid4()),
            "capability_nonce": "nonce-b",
            "started_at": now - timedelta(seconds=4),
            "exit_code": 0,
            "patch_digest": diff_digest,
            "source_digest": "e" * 64,
            "signature": "ed25519:placeholder",
        }
    )
    baseline = sign_model_ed25519(
        baseline, private_key=private_key, key_id=key_id, domain=DOMAIN_RESULT_V1
    )
    patched = sign_model_ed25519(
        patched, private_key=private_key, key_id=key_id, domain=DOMAIN_RESULT_V1
    )
    fingerprint = "f" * 64
    facts = VerificationFacts(
        baseline=baseline,
        patched=patched,
        baseline_trust_domain=trust_domain,
        patched_trust_domain=trust_domain,
        baseline_counts=ExecutionCounts(executed=4, failed=1, skipped=0),
        patched_counts=ExecutionCounts(executed=4, failed=0, skipped=0),
        regression_counts=ExecutionCounts(executed=4, failed=0, skipped=0),
        regression_selection_digest="1" * 64,
        expected_regression_selection_digest="1" * 64,
        expected_failure_fingerprint=fingerprint,
        observed_baseline_fingerprint=fingerprint,
        diff_text=diff,
        changed_paths=("src/fix.py",),
        diff_digest=diff_digest,
        allowed_paths=("src/fix.py",),
        minimum_fidelity="F1_TARGETED",
        fidelity="F2_APPROX",
        security_findings=(),
        workspace_id_matches=True,
        repository_id_matches=True,
        policy_allows_patch=True,
        actor_authorized=True,
        budget_sufficient=True,
    )
    return DeterministicVerifier(keyring=keyring), facts


@pytest.fixture
def trusted_verification() -> tuple[DeterministicVerifier, VerificationFacts]:
    return build_trusted_verification()


def test_all_v01_to_v07_pass_only_with_trusted_red_green_evidence(trusted_verification) -> None:
    verifier, facts = trusted_verification

    decision = verifier.evaluate(facts)

    assert [gate.outcome for gate in decision.gates] == ["pass"] * 7
    assert decision.locally_verified is True
    assert decision.publication_eligible is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("observed_baseline_fingerprint", None),
        ("baseline_counts", ExecutionCounts(executed=0, failed=0, skipped=0)),
        ("patched_counts", ExecutionCounts(executed=0, failed=0, skipped=0)),
        ("regression_counts", ExecutionCounts(executed=0, failed=0, skipped=0)),
        ("regression_counts", ExecutionCounts(executed=4, failed=0, skipped=1)),
        ("security_findings", ("secret_detected",)),
        ("workspace_id_matches", False),
        ("repository_id_matches", False),
        ("policy_allows_patch", False),
        ("actor_authorized", False),
        ("budget_sufficient", False),
        ("cancelled", True),
        ("fidelity", "FX_UNSUPPORTED"),
    ],
)
def test_adversarial_or_incomplete_facts_never_publish(trusted_verification, field, value) -> None:
    verifier, facts = trusted_verification

    decision = verifier.evaluate(replace(facts, **{field: value}))

    assert decision.locally_verified is False
    assert decision.publication_eligible is False


def test_tampered_worker_signature_blocks_green_verdict(trusted_verification) -> None:
    verifier, facts = trusted_verification
    tampered = facts.patched.model_copy(update={"exit_code": 1})

    decision = verifier.evaluate(replace(facts, patched=tampered))

    assert decision.gates[1].outcome == "fail"
    assert decision.publication_eligible is False


def test_secret_scan_returns_location_without_disclosing_secret() -> None:
    token = "ghp_" + "A" * 36
    diff = f"diff --git a/src/config.py b/src/config.py\n+token = '{token}'\n"

    findings = scan_diff_secrets(diff)

    assert findings == ("credential_pattern:src/config.py",)
    assert token not in " ".join(findings)


def _make_signed_manifest_case(
    *,
    workspace_id: str | None = None,
    repository_id: str | None = None,
    repair_id: str | None = None,
    base_sha: str = "1" * 40,
):
    now = datetime.now(tz=UTC)
    worker_key = Ed25519PrivateKey.generate()
    evidence_key = Ed25519PrivateKey.generate()
    worker_id, manifest_id, ci_run_id = (str(uuid4()) for _ in range(3))
    ws_id = workspace_id or str(uuid4())
    repo_id = repository_id or str(uuid4())
    repair_id = repair_id or str(uuid4())
    baseline_id, patched_id = str(uuid4()), str(uuid4())
    worker_key_id, evidence_key_id = "worker-proof-key", "control-evidence-key"
    worker_domain, evidence_domain = "worker-trust-zone", "control-evidence-zone"
    records = [
        export_ed25519_public_key_record(
            private_key=worker_key,
            key_id=worker_key_id,
            not_before=now - timedelta(days=1),
            trust_domain=worker_domain,
        ),
        export_ed25519_public_key_record(
            private_key=evidence_key,
            key_id=evidence_key_id,
            not_before=now - timedelta(days=1),
            trust_domain=evidence_domain,
        ),
    ]
    keyring = KeyRing(records)
    diff_text = "diff --git a/src/fix.py b/src/fix.py\n"
    diff_digest = hashlib.sha256(diff_text.encode()).hexdigest()
    baseline = ResultV1(
        job_id=baseline_id,
        lease_epoch=1,
        capability_nonce="nonce-1",
        worker_id=worker_id,
        started_at=now - timedelta(seconds=5),
        ended_at=now - timedelta(seconds=1),
        exit_code=1,
        termination="exited",
        command_digest="a" * 64,
        image_digest="b" * 64,
        environment_digest="c" * 64,
        source_digest="d" * 64,
        resource_usage=SandboxResourceUsage(
            wall_ms=4000, max_memory_bytes=2, disk_written_bytes=0, output_bytes=0
        ),
        isolation_checks=[IsolationCheckResult(check_id="network_none", passed=True)],
        signer_key_id=worker_key_id,
        signature="ed25519:pending",
    )
    patched = baseline.model_copy(
        update={
            "job_id": patched_id,
            "capability_nonce": "nonce-2",
            "exit_code": 0,
            "source_digest": "e" * 64,
            "patch_digest": diff_digest,
        }
    )
    baseline = sign_model_ed25519(
        baseline, private_key=worker_key, key_id=worker_key_id, domain=DOMAIN_RESULT_V1
    )
    patched = sign_model_ed25519(
        patched, private_key=worker_key, key_id=worker_key_id, domain=DOMAIN_RESULT_V1
    )
    baseline_blob = canonical_json_bytes(baseline.model_dump(mode="json", by_alias=True))
    patched_blob = canonical_json_bytes(patched.model_dump(mode="json", by_alias=True))
    payload = {
        "manifest_id": manifest_id,
        "workspace_id": ws_id,
        "repository_id": repo_id,
        "repair_id": repair_id,
        "source_sha": base_sha,
        "base_sha": base_sha,
        "patched_sha": "2" * 40,
        "diff_digest": diff_digest,
        "ci_run_id": ci_run_id,
        "ci_job_ids": [str(uuid4())],
        "ci_attempt_key": "attempt-1",
        "profile_id": "python-pytest-linux",
        "profile_digest": "3" * 64,
        "image_digest": "b" * 64,
        "dependency_lock_digest": "4" * 64,
        "commands_digest": "a" * 64,
        "environment_digest": "c" * 64,
        "baseline_result_job_id": baseline_id,
        "baseline_result_digest": hashlib.sha256(baseline_blob).hexdigest(),
        "patched_result_job_id": patched_id,
        "patched_result_digest": hashlib.sha256(patched_blob).hexdigest(),
        "failure_fingerprint": "5" * 64,
        "fidelity_grade": "F2_APPROX",
        "regression": RegressionSuiteSummary(
            selection_id="all-required",
            selection_digest="6" * 64,
            passed_count=4,
            failed_count=0,
            skipped_count=0,
            result_job_id=patched_id,
        ),
        "integrity_outcome": "pass",
        "security_outcome": "pass",
        "policy_outcome": "pass",
        "provenance": [],
        "redaction_revision": "v1",
        "artifact_digests": {},
        "created_at": now,
    }
    manifest = create_signed_evidence_manifest(
        payload, private_key=evidence_key, key_id=evidence_key_id
    )
    blobs = {baseline_id: baseline_blob, patched_id: patched_blob}
    return manifest, keyring, blobs, evidence_domain, evidence_key, diff_text


@pytest.fixture
def signed_manifest_case():
    return _make_signed_manifest_case()[:5]


def _facts_for_signed_manifest(
    manifest, blobs: dict[str, bytes], diff_text: str
) -> VerificationFacts:
    baseline = ResultV1.model_validate_json(blobs[manifest.baseline_result_job_id])
    patched = ResultV1.model_validate_json(blobs[manifest.patched_result_job_id])
    regression_count = manifest.regression.passed_count
    return VerificationFacts(
        baseline=baseline,
        patched=patched,
        baseline_trust_domain="worker-trust-zone",
        patched_trust_domain="worker-trust-zone",
        baseline_counts=ExecutionCounts(executed=4, failed=1, skipped=0),
        patched_counts=ExecutionCounts(executed=4, failed=0, skipped=0),
        regression_counts=ExecutionCounts(executed=regression_count, failed=0, skipped=0),
        regression_selection_digest=manifest.regression.selection_digest,
        expected_regression_selection_digest=manifest.regression.selection_digest,
        expected_failure_fingerprint=manifest.failure_fingerprint,
        observed_baseline_fingerprint=manifest.failure_fingerprint,
        diff_text=diff_text,
        changed_paths=("src/fix.py",),
        diff_digest=manifest.diff_digest,
        allowed_paths=("src/fix.py",),
        minimum_fidelity="F1_TARGETED",
        fidelity=manifest.fidelity_grade,
        security_findings=(),
        workspace_id_matches=True,
        repository_id_matches=True,
        policy_allows_patch=True,
        actor_authorized=True,
        budget_sufficient=True,
    )


def test_signed_manifest_validates_worker_results_and_artifact_hashes(signed_manifest_case) -> None:
    manifest, keyring, blobs, evidence_domain, _ = signed_manifest_case

    verify_evidence_manifest(
        manifest,
        keyring=keyring,
        artifact_blobs=blobs,
        expected_signer_trust_domain=evidence_domain,
    )


def test_manifest_rejects_tampered_result_blob(signed_manifest_case) -> None:
    manifest, keyring, blobs, evidence_domain, _ = signed_manifest_case
    blobs[manifest.patched_result_job_id] += b"tampered"

    with pytest.raises(ValueError, match="digest"):
        verify_evidence_manifest(
            manifest,
            keyring=keyring,
            artifact_blobs=blobs,
            expected_signer_trust_domain=evidence_domain,
        )


def test_manifest_rejects_missing_result_blob(signed_manifest_case) -> None:
    manifest, keyring, blobs, evidence_domain, _ = signed_manifest_case
    del blobs[manifest.baseline_result_job_id]

    with pytest.raises(ValueError, match="missing"):
        verify_evidence_manifest(
            manifest,
            keyring=keyring,
            artifact_blobs=blobs,
            expected_signer_trust_domain=evidence_domain,
        )


def test_manifest_rejects_payload_changed_after_signing(signed_manifest_case) -> None:
    manifest, keyring, blobs, evidence_domain, _ = signed_manifest_case
    altered = manifest.model_copy(update={"diff_digest": "9" * 64})

    with pytest.raises(ValueError, match="invalid_signature"):
        verify_evidence_manifest(
            altered,
            keyring=keyring,
            artifact_blobs=blobs,
            expected_signer_trust_domain=evidence_domain,
        )


def test_manifest_rejects_wrong_signer_trust_domain(signed_manifest_case) -> None:
    manifest, keyring, blobs, _, _ = signed_manifest_case

    with pytest.raises(ValueError, match="trust_domain"):
        verify_evidence_manifest(
            manifest,
            keyring=keyring,
            artifact_blobs=blobs,
            expected_signer_trust_domain="worker-trust-zone",
        )


def test_pr_summary_is_manifest_derived_and_redacted(signed_manifest_case) -> None:
    manifest, keyring, blobs, evidence_domain, _ = signed_manifest_case

    body = render_pr_summary(
        manifest,
        keyring=keyring,
        artifact_blobs=blobs,
        expected_signer_trust_domain=evidence_domain,
        authenticated_dashboard_path=f"/w/{manifest.workspace_id}/repairs/{manifest.repair_id}/verification",
    )

    assert "Remote CI has not been evaluated" in body
    assert manifest.diff_digest in body
    assert "ignore all previous instructions" not in body


def test_pr_summary_rejects_external_or_credential_bearing_link(signed_manifest_case) -> None:
    manifest, keyring, blobs, evidence_domain, _ = signed_manifest_case

    with pytest.raises(ValueError, match="same-origin"):
        render_pr_summary(
            manifest,
            keyring=keyring,
            artifact_blobs=blobs,
            expected_signer_trust_domain=evidence_domain,
            authenticated_dashboard_path="https://example.test/private",
        )


async def test_u18_migration_reversibility_rls_and_append_only(migrated_db: PgTestUrls) -> None:
    run_alembic_downgrade(
        migrated_db.admin_url,
        "0013_repair_sessions_diagnostics_steps",
        app_role_name=APP_ROLE_NAME,
    )
    admin_engine = create_admin_engine(migrated_db.admin_url)
    try:
        async with admin_engine.connect() as conn:
            assert await conn.scalar(text("SELECT to_regclass('public.verification_runs')")) is None
    finally:
        await admin_engine.dispose()

    run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    admin_engine = create_admin_engine(migrated_db.admin_url)
    try:
        async with admin_engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT relname FROM pg_class WHERE relname IN "
                    "('verification_runs', 'evidence_manifests') "
                    "AND relrowsecurity AND relforcerowsecurity"
                )
            )
            assert set(rows.scalars()) == {"verification_runs", "evidence_manifests"}
            rows = await conn.execute(
                text(
                    "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal AND tgname IN "
                    "('trg_verification_runs_immutable', 'trg_evidence_manifests_immutable')"
                )
            )
            assert set(rows.scalars()) == {
                "trg_verification_runs_immutable",
                "trg_evidence_manifests_immutable",
            }
            revision = await conn.scalar(
                text(
                    "SELECT revision FROM schema_migrations "
                    "WHERE revision = '0014_verification_runs_and_manifests'"
                )
            )
            assert revision == "0014_verification_runs_and_manifests"
    finally:
        await admin_engine.dispose()


@pytest.mark.asyncio
async def test_u18_verification_persistence_rls_idempotency_and_human_gate(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    helpers_path = Path(__file__).with_name("test_agents_and_state_machine.py")
    helpers_spec = importlib.util.spec_from_file_location("u17_integration_helpers", helpers_path)
    assert helpers_spec is not None and helpers_spec.loader is not None
    helpers = importlib.util.module_from_spec(helpers_spec)
    sys.modules[helpers_spec.name] = helpers
    helpers_spec.loader.exec_module(helpers)

    clock = helpers.ManualClock()
    harness = helpers._build_u17_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "u18-artifacts",
    )
    try:
        (
            owner,
            _csrf,
            _owner_id,
            workspace_id,
            repository_id,
        ) = await helpers._bootstrap_workspace_and_repo(
            harness,
            clock=clock,
            ws_slug="ws-u18-verification",
            ws_name="U18 Verification",
        )
        await owner.aclose()
        base_sha = "1" * 40
        (
            ci_run_id,
            _job_id,
            _artifact_id,
            _fingerprint,
        ) = await helpers._seed_ci_run_job_and_log_artifact(
            harness,
            workspace_id=workspace_id,
            repository_id=repository_id,
            head_sha=base_sha,
            job_name="pytest (ubuntu-latest)",
            ci_failure_log="FAILED tests/test_calc.py::test_add - AssertionError: assert 1 == 2",
            now=clock(),
        )
        repair_id, _budget_id = await helpers._create_repair_session_with_budget(
            harness,
            workspace_id=workspace_id,
            repository_id=repository_id,
            ci_run_id=ci_run_id,
            base_sha=base_sha,
            semantic_key="u18-verifier-integration",
            now=clock(),
        )
        for state in ("authorized", "collecting", "triaging", "reproducing"):
            await harness.state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state=state,
                correlation_id="corr-u18-state-setup",
            )
        await harness.state_machine.transition_session(
            workspace_id=workspace_id,
            repair_id=repair_id,
            target_state="repro_confirmed",
            target_proof_grade="baseline_confirmed",
            correlation_id="corr-u18-state-setup",
        )
        for state in ("patching", "verifying"):
            await harness.state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state=state,
                correlation_id="corr-u18-state-setup",
            )

        verifier, facts = build_trusted_verification()
        facts = replace(facts, actor_authorized=False)
        service = VerificationService(
            session_factory=harness.app_factory,
            verifier=verifier,
            state_machine=harness.state_machine,
            manifest_keyring=KeyRing([]),
            evidence_trust_domain="control-evidence-zone",
        )
        receipt = await service.verify(
            workspace_id=workspace_id,
            repair_id=repair_id,
            verification_id=new_uuid7(now=clock()),
            idempotency_key="u18-verification-attempt-1",
            facts=facts,
            signed_manifest=None,
            evidence_blobs={},
            correlation_id="corr-u18-verification",
            now=clock(),
        )
        assert receipt.status == "blocked"
        assert receipt.proof_grade == "baseline_confirmed"
        assert receipt.idempotent_replay is False
        assert receipt.decision is not None
        assert receipt.decision.publication_eligible is False

        replay = await service.verify(
            workspace_id=workspace_id,
            repair_id=repair_id,
            verification_id=new_uuid7(now=clock()),
            idempotency_key="u18-verification-attempt-1",
            facts=facts,
            signed_manifest=None,
            evidence_blobs={},
            correlation_id="corr-u18-verification-replay",
            now=clock(),
        )
        assert replay.idempotent_replay is True
        assert replay.verification_id == receipt.verification_id
        assert replay.status == "blocked"

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            rows = list(
                (
                    await db.scalars(
                        select(VerificationRunModel).where(
                            VerificationRunModel.repair_id == repair_id
                        )
                    )
                ).all()
            )
            assert len(rows) == 1
            assert rows[0].status == "blocked"
            assert (
                await db.scalar(
                    select(RepairSessionModel.state).where(RepairSessionModel.id == repair_id)
                )
                == "blocked"
            )
            assert (
                await db.scalar(
                    select(OutboxEventModel.id).where(
                        OutboxEventModel.event_type == "repair.verification.completed",
                        OutboxEventModel.correlation_id == "corr-u18-verification",
                    )
                )
                is not None
            )
            assert (
                await db.scalar(
                    select(AuditLogModel.id).where(
                        AuditLogModel.action == "repair.verification.completed",
                        AuditLogModel.target == receipt.verification_id,
                    )
                )
                is not None
            )

        async with harness.app_factory() as unscoped_db, unscoped_db.begin():
            assert await unscoped_db.scalar(select(VerificationRunModel.id)) is None

        with pytest.raises(DBAPIError) as mutation_error:
            async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
                await db.execute(
                    update(VerificationRunModel)
                    .where(VerificationRunModel.id == receipt.verification_id)
                    .values(status="verified")
                )
        assert getattr(mutation_error.value.orig, "sqlstate", None) == "42501"

        async with workspace_rls_session(
            harness.app_factory,
            workspace_id=str(uuid4()),
        ) as other_workspace_db:
            assert await other_workspace_db.scalar(select(VerificationRunModel.id)) is None

        admin_engine = create_admin_engine(migrated_db.admin_url)
        try:
            admin_factory = create_session_factory(admin_engine)
            with pytest.raises(DBAPIError) as immutable_error:
                async with instance_rls_session(admin_factory, mode="instance_admin") as db:
                    await db.execute(
                        update(VerificationRunModel)
                        .where(VerificationRunModel.id == receipt.verification_id)
                        .values(status="verified")
                    )
            assert getattr(immutable_error.value.orig, "sqlstate", None) == "55000"
        finally:
            await admin_engine.dispose()

        success_repair_id, _success_budget_id = await helpers._create_repair_session_with_budget(
            harness,
            workspace_id=workspace_id,
            repository_id=repository_id,
            ci_run_id=ci_run_id,
            base_sha=base_sha,
            semantic_key="u18-verifier-integration-success",
            now=clock(),
        )
        for state in ("authorized", "collecting", "triaging", "reproducing"):
            await harness.state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=success_repair_id,
                target_state=state,
                correlation_id="corr-u18-success-setup",
            )
        await harness.state_machine.transition_session(
            workspace_id=workspace_id,
            repair_id=success_repair_id,
            target_state="repro_confirmed",
            target_proof_grade="baseline_confirmed",
            correlation_id="corr-u18-success-setup",
        )
        for state in ("patching", "verifying"):
            await harness.state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=success_repair_id,
                target_state=state,
                correlation_id="corr-u18-success-setup",
            )

        (
            signed_manifest,
            proof_keyring,
            proof_blobs,
            evidence_domain,
            _evidence_private_key,
            diff_text,
        ) = _make_signed_manifest_case(
            workspace_id=workspace_id,
            repository_id=repository_id,
            repair_id=success_repair_id,
            base_sha=base_sha,
        )
        success_service = VerificationService(
            session_factory=harness.app_factory,
            verifier=DeterministicVerifier(keyring=proof_keyring),
            state_machine=harness.state_machine,
            manifest_keyring=proof_keyring,
            evidence_trust_domain=evidence_domain,
        )
        success_receipt = await success_service.verify(
            workspace_id=workspace_id,
            repair_id=success_repair_id,
            verification_id=new_uuid7(now=clock()),
            idempotency_key="u18-verification-success-1",
            facts=_facts_for_signed_manifest(signed_manifest, proof_blobs, diff_text),
            signed_manifest=signed_manifest,
            evidence_blobs=proof_blobs,
            correlation_id="corr-u18-verification-success",
            now=clock(),
        )
        assert success_receipt.status == "verified"
        assert success_receipt.proof_grade == "locally_verified"
        assert success_receipt.manifest_id == signed_manifest.manifest_id
        assert success_receipt.decision is not None
        assert success_receipt.decision.publication_eligible is True
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            assert (
                await db.scalar(
                    select(RepairSessionModel.state).where(
                        RepairSessionModel.id == success_repair_id
                    )
                )
                == "policy_gate"
            )
            stored_manifest = await db.scalar(
                select(EvidenceManifestModel.id).where(
                    EvidenceManifestModel.verification_run_id == success_receipt.verification_id
                )
            )
            assert stored_manifest == signed_manifest.manifest_id
    finally:
        await harness.app_engine.dispose()
