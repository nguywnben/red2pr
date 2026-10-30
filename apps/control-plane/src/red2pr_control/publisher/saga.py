"""Idempotent internal-only draft publication saga (FIX-03 / S-13 / SEC-015)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import KeyRing, canonical_json_bytes, sha256_canonical_json
from py_contracts.events import EventEnvelope, PublicationEventPayload
from py_contracts.evidence import EvidenceManifestV1
from py_contracts.primitives import new_uuid7
from red2pr_control.core.errors import ConflictError, ForbiddenError, NotFoundError
from red2pr_control.db.base import (
    ApprovalRequestModel,
    ArtifactModel,
    EvidenceManifestModel,
    PatchAttemptModel,
    PublicationRecordModel,
    RepairSessionModel,
    RepositoryModel,
    RepositoryPolicyModel,
    RequiredCheckSetModel,
    SandboxLeaseModel,
    VerificationRunModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.integrations.base import (
    ProviderConnectionContext,
    ProviderDraftReviewRecord,
    SourceProviderAdapter,
)
from red2pr_control.integrations.github_app import GitHubIntegrationService
from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine
from red2pr_control.publisher.patch_apply import apply_verified_unified_diff
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    read_artifact_for_authorized_caller,
)

_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class SealedPublishIntent:
    """Opaque Z2 handoff; the public API and LLM tool registry never accept this object."""

    workspace_id: str
    repair_id: str
    approval_id: str
    patch_digest: str
    policy_revision: int
    correlation_id: str
    signature: str


def seal_internal_publish_intent(
    *,
    workspace_id: str,
    repair_id: str,
    approval_id: str,
    patch_digest: str,
    policy_revision: int,
    correlation_id: str,
    signing_key: bytes,
) -> SealedPublishIntent:
    """Seal a verified internal handoff for trusted post-approval orchestration only."""
    if len(signing_key) < 32 or not _HEX_RE.fullmatch(patch_digest):
        raise ValueError("Publisher intent requires a 256-bit key and a lowercase SHA-256 digest.")
    values = {
        "workspace_id": workspace_id,
        "repair_id": repair_id,
        "approval_id": approval_id,
        "patch_digest": patch_digest,
        "policy_revision": policy_revision,
        "correlation_id": correlation_id,
    }
    signature = hmac.new(signing_key, _canonical(values), hashlib.sha256).hexdigest()
    return SealedPublishIntent(
        workspace_id=workspace_id,
        repair_id=repair_id,
        approval_id=approval_id,
        patch_digest=patch_digest,
        policy_revision=policy_revision,
        correlation_id=correlation_id,
        signature=signature,
    )


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deterministic_branch(run_id: str, repair_id: str, patch_digest: str) -> str:
    attempt_hash = hashlib.sha256(f"{repair_id}:{patch_digest}".encode()).hexdigest()[:16]
    return f"red2pr/{run_id}/{attempt_hash}"


def deterministic_marker(repair_id: str, provider: str, patch_digest: str) -> str:
    effect = hashlib.sha256(f"{repair_id}:{provider}:{patch_digest}".encode()).hexdigest()
    return f"<!-- red2pr-publication:{effect} -->"


def _safe_review_url(raw: str) -> str:
    parsed = urlsplit(raw.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username:
        raise ConflictError(
            code="provider_review_url_invalid", detail="Provider returned an invalid review URL."
        )
    # Provider URLs are display links, never an opaque token/query transport.
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _render_review_body(*, marker: str, patch_digest: str, manifest: EvidenceManifestV1) -> str:
    # The body includes only bounded provenance and a safe marker; never log excerpts or raw diffs.
    return (
        "Automated repair candidate. Please review the diff and provider checks before merging.\n\n"
        f"Local evidence manifest: `{manifest.manifest_id}`\n"
        f"Patch SHA-256: `{patch_digest}`\n\n{marker}"
    )


class PublisherSaga:
    """Persist-before-I/O publisher with deterministic retries and marker reconciliation."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        integrations: GitHubIntegrationService,
        artifact_store: ArtifactStoreProtocol,
        manifest_keyring: KeyRing,
        evidence_trust_domain: str,
        intent_signing_key: bytes,
        state_machine: RepairSessionStateMachine,
    ) -> None:
        if len(intent_signing_key) < 32:
            raise ValueError("Publisher intent signing key must contain at least 256 bits.")
        self._session_factory = session_factory
        self._integrations = integrations
        self._artifact_store = artifact_store
        self._manifest_keyring = manifest_keyring
        self._evidence_trust_domain = evidence_trust_domain
        self._intent_signing_key = intent_signing_key
        self._state_machine = state_machine

    async def publish(self, intent: SealedPublishIntent) -> PublicationRecordModel:
        self._verify_seal(intent)
        now = datetime.now(tz=UTC)
        # Commit the local intent and repair transition before any provider network I/O.
        async with workspace_rls_session(
            self._session_factory, workspace_id=intent.workspace_id
        ) as db:
            (
                repair,
                approval,
                patch,
                _,
                manifest,
                diff_bytes,
                required_set,
            ) = await self._load_and_validate_intent(db, intent, now=now)
            required_digest = (
                required_set.digest
                if required_set is not None
                and sha256_canonical_json(required_set.names_json) == required_set.digest
                else None
            )
            repo = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == intent.workspace_id,
                    RepositoryModel.id == repair.repository_id,
                )
            )
            if repo is None:
                raise NotFoundError(code="repository_not_found", detail="Repository was not found.")
            if repo.policy_revision != intent.policy_revision or repo.mode == "monitor":
                raise ConflictError(
                    code="publication_policy_stale",
                    detail=(
                        "Repository's current policy revision or mode differs from the approved "
                        "intent."
                    ),
                )
            (
                adapter,
                provider_ctx,
                repo_full_name,
            ) = await self._integrations.resolve_publisher_target(
                workspace_id=intent.workspace_id,
                repository_id=repair.repository_id,
            )
            provider = provider_ctx.provider
            publication = await db.scalar(
                select(PublicationRecordModel)
                .where(
                    PublicationRecordModel.workspace_id == intent.workspace_id,
                    PublicationRecordModel.repair_id == repair.id,
                    PublicationRecordModel.provider == provider,
                    PublicationRecordModel.operation == "publish_draft",
                )
                .with_for_update()
            )
            marker = deterministic_marker(repair.id, provider, patch.patch_digest)
            branch = deterministic_branch(repair.ci_run_id, repair.id, patch.patch_digest)
            intent_id = str(new_uuid7(now=now))
            if publication is None:
                if repair.state == "cancel_requested":
                    raise ConflictError(
                        code="publication_cancelled_before_intent",
                        detail="A cancelled repair cannot start a new publication intent.",
                    )
                publication = PublicationRecordModel(
                    id=str(new_uuid7(now=now)),
                    workspace_id=repair.workspace_id,
                    repository_id=repair.repository_id,
                    repair_id=repair.id,
                    approval_request_id=approval.id,
                    provider=provider,
                    operation="publish_draft",
                    intent_id=intent_id,
                    correlation_id=intent.correlation_id,
                    marker=marker,
                    branch=branch,
                    base_sha=repair.base_sha,
                    expected_commit_sha=None,
                    required_check_set_digest=required_digest,
                    target_ref=repair.target_ref,
                    policy_revision=repair.policy_revision,
                    status="intent",
                    created_at=now,
                    updated_at=now,
                )
                db.add(publication)
                await db.flush()
            else:
                self._ensure_replay_binding(
                    publication,
                    intent,
                    marker=marker,
                    branch=branch,
                    required_check_set_digest=required_digest,
                )
                if publication.status == "published":
                    return publication
                if publication.status in {"failed", "unknown"}:
                    raise ConflictError(
                        code="publication_requires_human_review",
                        detail=(
                            "Publication is terminal or ambiguous and requires human "
                            "reconciliation."
                        ),
                    )
            if repair.state == "awaiting_approval":
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=repair.workspace_id,
                    repair_id=repair.id,
                    target_state="publishing",
                    reason_code="approved_publish_intent_persisted",
                    actor="service:publisher",
                    correlation_id=intent.correlation_id,
                )
            publication.status = "pushing"
            publication.updated_at = now
            await db.flush()
            db_data = {
                "workspace_id": repair.workspace_id,
                "publication_id": publication.id,
                "repair_id": repair.id,
                "provider": provider,
                "repository_id": repair.repository_id,
                "repo_full_name": repo_full_name,
                "base_sha": repair.base_sha,
                "target_ref": repair.target_ref,
                "branch": branch,
                "marker": marker,
                "patch_digest": patch.patch_digest,
                "changed_paths": tuple(patch.changed_paths_json),
                "diff_bytes": diff_bytes,
                "manifest": manifest,
                "required_set": required_set,
                "correlation_id": intent.correlation_id,
            }

        return await self._publish_or_reconcile(adapter, provider_ctx, db_data, now=now)

    async def publish_approved(
        self, *, workspace_id: str, approval_id: str, correlation_id: str
    ) -> PublicationRecordModel:
        """Create the sealed publisher handoff from a persisted human decision.

        This is an internal orchestration entry point. Callers cannot provide a diff,
        policy revision, provider target, or signature; all bindings are loaded from the
        approved database record and revalidated by ``publish`` before provider I/O.
        """
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            approval = await db.scalar(
                select(ApprovalRequestModel).where(
                    ApprovalRequestModel.workspace_id == workspace_id,
                    ApprovalRequestModel.id == approval_id,
                )
            )
            if approval is None:
                raise NotFoundError(
                    code="publication_approval_missing",
                    detail="Publication approval was not found.",
                )
            if approval.intent_type != "publish_draft_pr":
                raise ConflictError(
                    code="publication_approval_type_invalid",
                    detail="Approval is not a draft publication request.",
                )
            if approval.status != "approved" or approval.decision != "approve":
                raise ForbiddenError(
                    code="publication_approval_invalid",
                    detail="A persisted approval decision is required before publication.",
                )
            intent = seal_internal_publish_intent(
                workspace_id=workspace_id,
                repair_id=approval.repair_id,
                approval_id=approval.id,
                patch_digest=approval.patch_digest,
                policy_revision=approval.policy_revision,
                correlation_id=correlation_id or approval.correlation_id,
                signing_key=self._intent_signing_key,
            )
        return await self.publish(intent)

    async def reconcile(self, *, workspace_id: str, publication_id: str) -> PublicationRecordModel:
        """Rebuild the sealed internal intent for an already-persisted effect and reconcile it."""
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            publication = await db.scalar(
                select(PublicationRecordModel).where(
                    PublicationRecordModel.workspace_id == workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
            )
            if publication is None:
                raise NotFoundError(
                    code="publication_not_found", detail="Publication was not found."
                )
            approval = await db.scalar(
                select(ApprovalRequestModel).where(
                    ApprovalRequestModel.workspace_id == workspace_id,
                    ApprovalRequestModel.id == publication.approval_request_id,
                    ApprovalRequestModel.repair_id == publication.repair_id,
                )
            )
            if approval is None:
                raise ConflictError(
                    code="publication_approval_missing",
                    detail="Publication approval is no longer available for reconciliation.",
                )
            if publication.status == "published":
                return publication
            intent = seal_internal_publish_intent(
                workspace_id=workspace_id,
                repair_id=publication.repair_id,
                approval_id=approval.id,
                patch_digest=approval.patch_digest,
                policy_revision=publication.policy_revision,
                correlation_id=publication.correlation_id,
                signing_key=self._intent_signing_key,
            )
        return await self.publish(intent)

    async def _load_and_validate_intent(
        self,
        db: AsyncSession,
        intent: SealedPublishIntent,
        *,
        now: datetime,
    ) -> tuple[Any, Any, Any, Any, EvidenceManifestV1, bytes, Any]:
        repair = await db.scalar(
            select(RepairSessionModel)
            .where(
                RepairSessionModel.workspace_id == intent.workspace_id,
                RepairSessionModel.id == intent.repair_id,
            )
            .with_for_update()
        )
        approval = await db.scalar(
            select(ApprovalRequestModel).where(
                ApprovalRequestModel.workspace_id == intent.workspace_id,
                ApprovalRequestModel.id == intent.approval_id,
                ApprovalRequestModel.repair_id == intent.repair_id,
            )
        )
        if repair is None or approval is None:
            raise NotFoundError(
                code="publication_intent_not_found",
                detail="Verified publication intent was not found.",
            )
        if (
            approval.status != "approved"
            or approval.decision != "approve"
            or approval.expires_at <= now
            or approval.patch_digest != intent.patch_digest
            or approval.policy_revision != intent.policy_revision
            or approval.base_sha != repair.base_sha
            or approval.target_ref != repair.target_ref
        ):
            raise ForbiddenError(
                code="publication_approval_invalid",
                detail=(
                    "Publication approval is missing, expired, revoked, or no longer bound to "
                    "the current repair."
                ),
            )
        if repair.proof_grade != "locally_verified" or repair.state not in {
            "awaiting_approval",
            "publishing",
            "publish_reconcile",
            "cancel_requested",
        }:
            raise ConflictError(
                code="publication_local_proof_required",
                detail=(
                    "Only a locally verified repair with an approved publication intent may "
                    "publish."
                ),
            )
        policy = await db.scalar(
            select(RepositoryPolicyModel).where(
                RepositoryPolicyModel.workspace_id == intent.workspace_id,
                RepositoryPolicyModel.repository_id == repair.repository_id,
                RepositoryPolicyModel.revision == intent.policy_revision,
            )
        )
        if (
            policy is None
            or policy.revision != repair.policy_revision
            or policy.paused
            or policy.mode == "monitor"
        ):
            raise ConflictError(
                code="publication_policy_stale",
                detail=(
                    "Current repository policy is paused, monitor-only, or differs from the "
                    "approval."
                ),
            )
        patch = await db.scalar(
            select(PatchAttemptModel).where(
                PatchAttemptModel.workspace_id == intent.workspace_id,
                PatchAttemptModel.repair_id == repair.id,
                PatchAttemptModel.patch_digest == intent.patch_digest,
                PatchAttemptModel.integrity_outcome == "accepted",
            )
        )
        verification = await db.scalar(
            select(VerificationRunModel)
            .where(
                VerificationRunModel.workspace_id == intent.workspace_id,
                VerificationRunModel.repair_id == repair.id,
                VerificationRunModel.patch_digest == intent.patch_digest,
                VerificationRunModel.status == "verified",
                VerificationRunModel.proof_grade == "locally_verified",
            )
            .order_by(VerificationRunModel.created_at.desc())
        )
        manifest_row = await db.scalar(
            select(EvidenceManifestModel)
            .where(
                EvidenceManifestModel.workspace_id == intent.workspace_id,
                EvidenceManifestModel.repair_id == repair.id,
            )
            .order_by(EvidenceManifestModel.created_at.desc())
        )
        if patch is None or verification is None or manifest_row is None:
            raise ConflictError(
                code="publication_evidence_missing",
                detail="Accepted patch, V-01..V-07 verification, or signed manifest is missing.",
            )
        gate_outcomes = {
            str(item.get("id")): str(item.get("outcome"))
            for item in (verification.gates_json or [])
            if isinstance(item, dict)
        }
        required_gates = {f"V-{number:02d}" for number in range(1, 8)}
        if (
            patch.base_sha != repair.base_sha
            or verification.patch_digest != manifest_row.payload_json.get("diff_digest")
            or not required_gates.issubset(gate_outcomes)
            or any(gate_outcomes[gate] != "pass" for gate in required_gates)
            or sha256_canonical_json(manifest_row.payload_json) != manifest_row.manifest_digest
        ):
            raise ConflictError(
                code="publication_evidence_mismatch",
                detail=(
                    "Patch, manifest, and local verification do not share the approved digest "
                    "and base."
                ),
            )
        manifest = EvidenceManifestV1.model_validate(manifest_row.payload_json)
        if (
            manifest.workspace_id != intent.workspace_id
            or manifest.repository_id != repair.repository_id
            or manifest.repair_id != repair.id
            or manifest.base_sha != repair.base_sha
            or manifest.diff_digest != intent.patch_digest
        ):
            raise ConflictError(
                code="publication_manifest_binding_mismatch",
                detail=(
                    "Signed manifest is not bound to the approved workspace, repository, repair, "
                    "base, and diff."
                ),
            )
        artifact_ids = set(manifest.artifact_digests)
        artifacts = (
            (
                await db.scalars(
                    select(ArtifactModel).where(
                        ArtifactModel.workspace_id == intent.workspace_id,
                        ArtifactModel.repository_id == repair.repository_id,
                        ArtifactModel.id.in_(artifact_ids),
                    )
                )
            ).all()
            if artifact_ids
            else []
        )
        blob_by_id = {
            artifact.id: await read_artifact_for_authorized_caller(
                db,
                store=self._artifact_store,
                artifact_row=artifact,
                now=now,
            )
            for artifact in artifacts
        }
        # ResultV1 is durably retained in the fenced sandbox lease, keyed by its job ID.
        # It is not an ArtifactModel row: copying that identifier into an artifact query
        # silently made every valid persisted proof impossible to publish.
        result_digests = {
            manifest.baseline_result_job_id: manifest.baseline_result_digest,
            manifest.patched_result_job_id: manifest.patched_result_digest,
        }
        leases = (
            await db.scalars(
                select(SandboxLeaseModel).where(
                    SandboxLeaseModel.workspace_id == intent.workspace_id,
                    SandboxLeaseModel.repository_id == repair.repository_id,
                    SandboxLeaseModel.repair_id == repair.id,
                    SandboxLeaseModel.job_id.in_(result_digests),
                    SandboxLeaseModel.status == "completed",
                )
            )
        ).all()
        lease_by_job_id = {lease.job_id: lease for lease in leases}
        for job_id, expected_digest in result_digests.items():
            lease = lease_by_job_id.get(job_id)
            if lease is None or lease.result_json is None or lease.result_digest is None:
                raise ConflictError(
                    code="publication_result_missing",
                    detail=(
                        "A signed sandbox result referenced by the evidence manifest is missing."
                    ),
                )
            result_blob = canonical_json_bytes(lease.result_json)
            actual_digest = hashlib.sha256(result_blob).hexdigest()
            if (
                lease.result_json.get("job_id") != job_id
                or sha256_canonical_json(lease.result_json) != lease.result_digest
                or actual_digest != expected_digest
            ):
                raise ConflictError(
                    code="publication_result_digest_mismatch",
                    detail=(
                        "A persisted sandbox result does not match the signed evidence manifest."
                    ),
                )
            blob_by_id[job_id] = result_blob
        from red2pr_control.verification.verifier import verify_evidence_manifest

        verify_evidence_manifest(
            manifest,
            keyring=self._manifest_keyring,
            artifact_blobs=blob_by_id,
            expected_signer_trust_domain=self._evidence_trust_domain,
            now=now,
        )
        diff_artifact = await db.scalar(
            select(ArtifactModel).where(
                ArtifactModel.workspace_id == intent.workspace_id,
                ArtifactModel.repository_id == repair.repository_id,
                ArtifactModel.id == patch.diff_artifact_id,
            )
        )
        if diff_artifact is None:
            raise ConflictError(
                code="publication_diff_missing", detail="Verified patch diff artifact is missing."
            )
        diff_bytes = await read_artifact_for_authorized_caller(
            db, store=self._artifact_store, artifact_row=diff_artifact, now=now
        )
        if hashlib.sha256(diff_bytes).hexdigest() != patch.patch_digest:
            raise ConflictError(
                code="publication_diff_digest_mismatch",
                detail="Patch diff bytes do not match the approved SHA-256 digest.",
            )
        required_set = await db.scalar(
            select(RequiredCheckSetModel).where(
                RequiredCheckSetModel.workspace_id == intent.workspace_id,
                RequiredCheckSetModel.repository_id == repair.repository_id,
                RequiredCheckSetModel.policy_revision == intent.policy_revision,
            )
        )
        if policy is None:
            raise ConflictError(
                code="publication_policy_missing",
                detail="The approved immutable repository policy revision is missing.",
            )
        canonical_names = sorted(policy.required_check_names_json)
        canonical_digest = sha256_canonical_json(canonical_names)
        if required_set is None:
            required_set = RequiredCheckSetModel(
                id=str(new_uuid7(now=now)),
                workspace_id=intent.workspace_id,
                repository_id=repair.repository_id,
                policy_revision=intent.policy_revision,
                names_json=canonical_names,
                digest=canonical_digest,
                created_at=now,
            )
            db.add(required_set)
            await db.flush()
        elif required_set.names_json != canonical_names or required_set.digest != canonical_digest:
            raise ConflictError(
                code="publication_check_set_policy_mismatch",
                detail="The immutable required-check snapshot differs from its policy revision.",
            )
        return repair, approval, patch, verification, manifest, diff_bytes, required_set

    async def _publish_or_reconcile(
        self,
        adapter: SourceProviderAdapter,
        ctx: ProviderConnectionContext,
        data: dict[str, Any],
        *,
        now: datetime,
    ) -> PublicationRecordModel:
        # The target branch and deterministic repair branch are checked independently. An
        # ambiguous commit is identified by exact resulting file bytes; unrelated tips are never
        # overwritten or treated as successful publication.
        try:
            adapter, ctx = await self._require_live_target(ctx, data["repository_id"])
            target_head = await self._branch_head(adapter, ctx, data, now=now, target=True)
            if target_head != data["base_sha"]:
                await self._mark_failed(
                    data["workspace_id"], data["publication_id"], "stale_base_sha"
                )
                return await self._read_publication(data["workspace_id"], data["publication_id"])
            base_contents: dict[str, str | None] = {}
            for path in data["changed_paths"]:
                base_contents[path] = await self._read_file(
                    adapter, ctx, data, path, ref=data["base_sha"], now=now
                )
            files = apply_verified_unified_diff(
                data["diff_bytes"].decode("utf-8"), base_contents=base_contents
            )
            tree_digest = _tree_digest(files)
            branch_head = await self._branch_head(adapter, ctx, data, now=now, target=False)
            if branch_head is None:
                if await self._cancel_requested(data):
                    return await self._read_publication(
                        data["workspace_id"], data["publication_id"]
                    )
                adapter, ctx = await self._require_live_target(ctx, data["repository_id"])
                async with workspace_rls_session(
                    self._session_factory, workspace_id=data["workspace_id"]
                ) as db:
                    await adapter.create_branch(
                        db,
                        ctx,
                        repo_full_name=data["repo_full_name"],
                        branch_name=data["branch"],
                        from_sha=data["base_sha"],
                        now=now,
                    )
                branch_head = data["base_sha"]
            if branch_head == data["base_sha"]:
                # Re-check the base immediately before the branch mutation to catch force-pushes.
                current_target = await self._branch_head(adapter, ctx, data, now=now, target=True)
                if current_target != data["base_sha"]:
                    await self._mark_failed(
                        data["workspace_id"], data["publication_id"], "stale_base_sha"
                    )
                    return await self._read_publication(
                        data["workspace_id"], data["publication_id"]
                    )
                if await self._cancel_requested(data):
                    return await self._read_publication(
                        data["workspace_id"], data["publication_id"]
                    )
                adapter, ctx = await self._require_live_target(ctx, data["repository_id"])
                async with workspace_rls_session(
                    self._session_factory, workspace_id=data["workspace_id"]
                ) as db:
                    commit_sha = await adapter.push_commit(
                        db,
                        ctx,
                        repo_full_name=data["repo_full_name"],
                        branch_name=data["branch"],
                        expected_parent_sha=data["base_sha"],
                        commit_message=f"fix: verified repair {data['marker']}\n\n{data['marker']}",
                        file_changes=files,
                        now=now,
                    )
                if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit_sha):
                    raise ConflictError(
                        code="publisher_commit_unknown",
                        detail="Provider did not return a valid commit SHA.",
                    )
                data["expected_commit_sha"] = commit_sha.lower()
            elif (
                await self._branch_tree_digest(adapter, ctx, data, branch_head, files, now=now)
                == tree_digest
            ):
                # Previous push may have succeeded while its response timed out.
                data["expected_commit_sha"] = branch_head
            else:
                await self._mark_reconciling(data["workspace_id"], data["publication_id"])
                return await self._read_publication(data["workspace_id"], data["publication_id"])

            await self._save_commit_sha(
                data["workspace_id"], data["publication_id"], data["expected_commit_sha"]
            )
            async with workspace_rls_session(
                self._session_factory, workspace_id=data["workspace_id"]
            ) as db:
                existing = await adapter.find_review_by_marker(
                    db,
                    ctx,
                    repo_full_name=data["repo_full_name"],
                    head_branch=data["branch"],
                    marker=data["marker"],
                    now=now,
                )
                review = existing
                if review is None:
                    if await self._cancel_requested(data):
                        return await self._read_publication(
                            data["workspace_id"], data["publication_id"]
                        )
                    adapter, ctx = await self._require_live_target(ctx, data["repository_id"])
                    await self._set_status(data["workspace_id"], data["publication_id"], "creating")
                    review = await adapter.create_draft_review(
                        db,
                        ctx,
                        repo_full_name=data["repo_full_name"],
                        head_branch=data["branch"],
                        base_branch=data["target_ref"].removeprefix("refs/heads/"),
                        title=f"Fix: verified repair for {data['repo_full_name']}",
                        body=_render_review_body(
                            marker=data["marker"],
                            patch_digest=data["patch_digest"],
                            manifest=data["manifest"],
                        ),
                        now=now,
                    )
                if (
                    not review.draft
                    or review.head_sha.lower() != data["expected_commit_sha"].lower()
                    or review.head_branch.removeprefix("refs/heads/") != data["branch"]
                    or review.base_branch.removeprefix("refs/heads/")
                    != data["target_ref"].removeprefix("refs/heads/")
                ):
                    await self._mark_reconciling(data["workspace_id"], data["publication_id"])
                    return await self._read_publication(
                        data["workspace_id"], data["publication_id"]
                    )
                await self._finish_publication(data, review, now=now)
        except Exception:
            # Once provider I/O may have started, persist an ambiguous state. The next invocation
            # must locate the deterministic branch/review before another write is attempted.
            await self._mark_reconciling(data["workspace_id"], data["publication_id"])
        return await self._read_publication(data["workspace_id"], data["publication_id"])

    async def _cancel_requested(self, data: dict[str, Any]) -> bool:
        async with workspace_rls_session(
            self._session_factory, workspace_id=data["workspace_id"]
        ) as db:
            repair = await db.scalar(
                select(RepairSessionModel).where(
                    RepairSessionModel.workspace_id == data["workspace_id"],
                    RepairSessionModel.id == data["repair_id"],
                )
            )
            if repair is None or repair.state != "cancel_requested":
                return False
            await db.execute(
                update(PublicationRecordModel)
                .where(
                    PublicationRecordModel.workspace_id == data["workspace_id"],
                    PublicationRecordModel.id == data["publication_id"],
                )
                .values(
                    status="reconciling",
                    error_code="cancel_requested_during_publish",
                    updated_at=datetime.now(tz=UTC),
                )
            )
            return True

    async def _branch_head(
        self,
        adapter: SourceProviderAdapter,
        ctx: ProviderConnectionContext,
        data: dict[str, Any],
        *,
        now: datetime,
        target: bool,
    ) -> str | None:
        async with workspace_rls_session(
            self._session_factory, workspace_id=data["workspace_id"]
        ) as db:
            try:
                return await adapter.get_branch_head(
                    db,
                    ctx,
                    repo_full_name=data["repo_full_name"],
                    branch_name=data["target_ref"] if target else data["branch"],
                    now=now,
                )
            except Exception as exc:
                if getattr(exc, "code", None) in {"NOT_FOUND", "provider_resource_not_found"}:
                    return None
                raise

    async def _read_file(
        self,
        adapter: SourceProviderAdapter,
        ctx: ProviderConnectionContext,
        data: dict[str, Any],
        path: str,
        *,
        ref: str,
        now: datetime,
    ) -> str | None:
        async with workspace_rls_session(
            self._session_factory, workspace_id=data["workspace_id"]
        ) as db:
            return await adapter.get_file_contents_at_ref(
                db, ctx, repo_full_name=data["repo_full_name"], path=path, ref=ref, now=now
            )

    async def _require_live_target(
        self, ctx: ProviderConnectionContext, repository_id: str
    ) -> tuple[SourceProviderAdapter, ProviderConnectionContext]:
        adapter, live_ctx, _ = await self._integrations.resolve_publisher_target(
            workspace_id=ctx.workspace_id,
            repository_id=repository_id,
        )
        if live_ctx.connection_id != ctx.connection_id or live_ctx.provider != ctx.provider:
            raise ForbiddenError(
                code="publisher_target_changed",
                detail="Provider target changed during publication.",
            )
        return adapter, live_ctx

    async def _branch_tree_digest(
        self,
        adapter: SourceProviderAdapter,
        ctx: ProviderConnectionContext,
        data: dict[str, Any],
        head: str,
        files: dict[str, str | None],
        *,
        now: datetime,
    ) -> str | None:
        # Re-read only the approved changed paths at the candidate head; never infer from an
        # unrelated branch name or trust a review marker without matching its content.
        for path, expected_content in files.items():
            actual = await self._read_file(adapter, ctx, data, path, ref=head, now=now)
            if actual != expected_content:
                return None
        return _tree_digest(files)

    async def _finish_publication(
        self, data: dict[str, Any], review: ProviderDraftReviewRecord, *, now: datetime
    ) -> None:
        safe_url = _safe_review_url(review.html_url)
        async with workspace_rls_session(
            self._session_factory, workspace_id=data["workspace_id"]
        ) as db:
            row = await db.scalar(
                select(PublicationRecordModel)
                .where(
                    PublicationRecordModel.workspace_id == data["workspace_id"],
                    PublicationRecordModel.id == data["publication_id"],
                )
                .with_for_update()
            )
            repair = (
                await db.scalar(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == data["workspace_id"],
                        RepairSessionModel.id == row.repair_id,
                    )
                    .with_for_update()
                )
                if row
                else None
            )
            if row is None or repair is None:
                raise NotFoundError(
                    code="publication_not_found", detail="Publication was not found."
                )
            was_published = row.status == "published"
            row.provider_object_id = review.external_review_id[:128]
            row.provider_number = review.number[:64]
            row.url = safe_url
            row.status = "published"
            row.updated_at = now
            if repair.state in {"publishing", "publish_reconcile"}:
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=repair.workspace_id,
                    repair_id=repair.id,
                    target_state="remote_validating",
                    reason_code="draft_review_confirmed",
                    status_detail=f"Draft {review.number} created at {review.head_sha[:12]}",
                    actor="service:publisher",
                    correlation_id=data["correlation_id"],
                )
            if not was_published:
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=str(new_uuid7(now=now)),
                        type="repair.publication.created",
                        occurred_at=now,
                        workspace_id=repair.workspace_id,
                        repository_id=repair.repository_id,
                        session_id=repair.id,
                        aggregate_id=repair.id,
                        aggregate_version=repair.version,
                        correlation_id=data["correlation_id"],
                        payload=PublicationEventPayload(publication_id=row.id, status="published"),
                    ),
                    now=now,
                )
            await db.flush()

    async def _set_status(self, workspace_id: str, publication_id: str, status: str) -> None:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            await db.execute(
                update(PublicationRecordModel)
                .where(
                    PublicationRecordModel.workspace_id == workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
                .values(status=status, updated_at=datetime.now(tz=UTC))
            )

    async def _save_commit_sha(self, workspace_id: str, publication_id: str, sha: str) -> None:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            await db.execute(
                update(PublicationRecordModel)
                .where(
                    PublicationRecordModel.workspace_id == workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
                .values(expected_commit_sha=sha, status="creating", updated_at=datetime.now(tz=UTC))
            )

    async def _mark_reconciling(self, workspace_id: str, publication_id: str) -> None:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            row = await db.scalar(
                select(PublicationRecordModel)
                .where(
                    PublicationRecordModel.workspace_id == workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
                .with_for_update()
            )
            if row is None:
                return
            row.status = "reconciling"
            row.error_code = "provider_write_ambiguous"
            row.updated_at = datetime.now(tz=UTC)
            repair = await db.scalar(
                select(RepairSessionModel)
                .where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.id == row.repair_id,
                )
                .with_for_update()
            )
            if repair is not None and repair.state == "publishing":
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair.id,
                    target_state="publish_reconcile",
                    reason_code="provider_write_ambiguous",
                    actor="service:publisher",
                    correlation_id=row.correlation_id,
                )

    async def _mark_failed(self, workspace_id: str, publication_id: str, reason: str) -> None:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            row = await db.scalar(
                select(PublicationRecordModel)
                .where(
                    PublicationRecordModel.workspace_id == workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
                .with_for_update()
            )
            if row is not None:
                row.status = "failed"
                row.error_code = reason[:80]
                row.updated_at = datetime.now(tz=UTC)
                repair = await db.scalar(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == workspace_id,
                        RepairSessionModel.id == row.repair_id,
                    )
                    .with_for_update()
                )
                if repair is not None and repair.state in {"publishing", "publish_reconcile"}:
                    await self._state_machine.transition_in_tx(
                        db,
                        workspace_id=workspace_id,
                        repair_id=repair.id,
                        target_state="needs_human",
                        reason_code=reason[:120],
                        actor="service:publisher",
                        correlation_id=row.correlation_id,
                    )

    async def _read_publication(
        self, workspace_id: str, publication_id: str
    ) -> PublicationRecordModel:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            row = await db.scalar(
                select(PublicationRecordModel).where(
                    PublicationRecordModel.workspace_id == workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
            )
            if row is None:
                raise NotFoundError(
                    code="publication_not_found", detail="Publication was not found."
                )
            return row

    def _verify_seal(self, intent: SealedPublishIntent) -> None:
        values = {
            "workspace_id": intent.workspace_id,
            "repair_id": intent.repair_id,
            "approval_id": intent.approval_id,
            "patch_digest": intent.patch_digest,
            "policy_revision": intent.policy_revision,
            "correlation_id": intent.correlation_id,
        }
        expected = hmac.new(
            self._intent_signing_key, _canonical(values), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, intent.signature):
            raise ForbiddenError(
                code="publisher_intent_invalid",
                detail="Only a sealed internal publish intent is accepted.",
            )

    @staticmethod
    def _ensure_replay_binding(
        publication: PublicationRecordModel,
        intent: SealedPublishIntent,
        *,
        marker: str,
        branch: str,
        required_check_set_digest: str | None,
    ) -> None:
        if (
            publication.marker != marker
            or publication.branch != branch
            or publication.policy_revision != intent.policy_revision
            or publication.required_check_set_digest != required_check_set_digest
        ):
            raise ConflictError(
                code="publication_effect_binding_conflict",
                detail="Publication key is already bound to a different approved effect.",
            )


def _tree_digest(files: dict[str, str | None]) -> str:
    return sha256_canonical_json(
        {
            path: (
                hashlib.sha256(content.encode("utf-8")).hexdigest() if content is not None else None
            )
            for path, content in sorted(files.items())
        }
    )
