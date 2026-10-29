"""Deterministic V-01..V-07 evaluation and S-22 manifest validation (FIX-02/FIX-04)."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from py_contracts.crypto import (
    DOMAIN_EVIDENCE_MANIFEST_V1,
    DOMAIN_RESULT_V1,
    CryptoVerificationError,
    KeyRing,
    sha256_canonical_json,
    sign_model_ed25519,
    verify_model_ed25519,
)
from py_contracts.evidence import EvidenceManifestV1
from py_contracts.repairs import GateOutcome, VerificationGateId, VerificationGateResult
from py_contracts.worker import ResultV1
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.verification.diff_integrity import (
    DiffIntegrityGuard,
    IntegrityDisposition,
    IntegrityReport,
)

Fidelity = Literal["F1_TARGETED", "F2_APPROX", "F3_VALIDATED", "FX_UNSUPPORTED"]
_FIDELITY_ORDER: dict[str, int] = {
    "FX_UNSUPPORTED": -1,
    "F1_TARGETED": 0,
    "F2_APPROX": 1,
    "F3_VALIDATED": 2,
}


@dataclass(frozen=True, slots=True)
class ExecutionCounts:
    executed: int
    failed: int
    skipped: int

    def __post_init__(self) -> None:
        if min(self.executed, self.failed, self.skipped) < 0:
            raise ValueError("test counts cannot be negative")
        if self.failed > self.executed or self.skipped > self.executed:
            raise ValueError("failed/skipped counts cannot exceed executed count")


@dataclass(frozen=True, slots=True)
class VerificationFacts:
    baseline: ResultV1
    patched: ResultV1
    baseline_trust_domain: str
    patched_trust_domain: str
    baseline_counts: ExecutionCounts
    patched_counts: ExecutionCounts
    regression_counts: ExecutionCounts
    regression_selection_digest: str
    expected_regression_selection_digest: str
    expected_failure_fingerprint: str
    observed_baseline_fingerprint: str | None
    diff_text: str
    changed_paths: tuple[str, ...]
    diff_digest: str
    allowed_paths: tuple[str, ...]
    minimum_fidelity: Fidelity
    fidelity: Fidelity
    security_findings: tuple[str, ...]
    workspace_id_matches: bool
    repository_id_matches: bool
    policy_allows_patch: bool
    actor_authorized: bool
    budget_sufficient: bool
    cancelled: bool = False
    max_diff_lines: int = 2000
    max_diff_bytes: int = 262_144


@dataclass(frozen=True, slots=True)
class VerificationDecision:
    gates: tuple[VerificationGateResult, ...]
    integrity: IntegrityReport
    baseline_result_digest: str
    patched_result_digest: str
    locally_verified: bool
    reason_codes: tuple[str, ...]

    @property
    def publication_eligible(self) -> bool:
        """FIX-04/ADR-031: only complete V-01..V-07 proof can reach approval/publication."""
        return self.locally_verified and all(gate.outcome == "pass" for gate in self.gates)


def _result_is_trusted(result: ResultV1, *, keyring: KeyRing, trust_domain: str) -> bool:
    try:
        verify_model_ed25519(
            result,
            keyring=keyring,
            domain=DOMAIN_RESULT_V1,
            signed_at=result.ended_at,
            expected_trust_domain=trust_domain,
        )
    except (CryptoVerificationError, ValueError, ValidationError):
        return False
    return True


def _result_digest(result: ResultV1) -> str:
    return sha256_canonical_json(result.model_dump(mode="json", by_alias=True))


def scan_diff_secrets(diff_text: str, *, redactor: Redactor = DEFAULT_REDACTOR) -> tuple[str, ...]:
    """Return safe location-only findings for credential patterns in added diff lines."""
    findings: list[str] = []
    path = "unknown"
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split(" b/", maxsplit=1)
            path = parts[1] if len(parts) == 2 else "unknown"
        elif line.startswith("+") and not line.startswith("+++"):
            if redactor.redact_text(line[1:]) != line[1:]:
                findings.append(f"credential_pattern:{path}")
    return tuple(sorted(set(findings)))


def _gate(
    gate_id: VerificationGateId,
    passes: bool | None,
    evidence_ids: tuple[str, ...],
) -> VerificationGateResult:
    outcome: GateOutcome = "unknown" if passes is None else "pass" if passes else "fail"
    return VerificationGateResult(id=gate_id, outcome=outcome, evidence_ids=list(evidence_ids))


class DeterministicVerifier:
    """Evaluate independently collected executor, diff, policy and test evidence."""

    def __init__(self, *, keyring: KeyRing, diff_guard: DiffIntegrityGuard | None = None) -> None:
        self._keyring = keyring
        self._diff_guard = diff_guard or DiffIntegrityGuard()

    def evaluate(self, facts: VerificationFacts) -> VerificationDecision:
        baseline_trusted = _result_is_trusted(
            facts.baseline, keyring=self._keyring, trust_domain=facts.baseline_trust_domain
        )
        patched_trusted = _result_is_trusted(
            facts.patched, keyring=self._keyring, trust_domain=facts.patched_trust_domain
        )
        integrity = self._diff_guard.inspect(
            facts.diff_text,
            changed_paths=facts.changed_paths,
            allowed_paths=facts.allowed_paths,
            max_diff_lines=facts.max_diff_lines,
            max_diff_bytes=facts.max_diff_bytes,
        )
        baseline_id = facts.baseline.job_id
        patched_id = facts.patched.job_id
        baseline_digest = _result_digest(facts.baseline)
        patched_digest = _result_digest(facts.patched)

        v01 = (
            baseline_trusted
            and facts.baseline.termination == "exited"
            and facts.baseline.exit_code is not None
            and facts.baseline.exit_code != 0
            and facts.baseline_counts.executed > 0
            and facts.baseline_counts.failed > 0
            and facts.observed_baseline_fingerprint is not None
            and hmac.compare_digest(
                facts.expected_failure_fingerprint, facts.observed_baseline_fingerprint
            )
        )
        parity = (
            facts.patched.patch_digest is not None
            and hmac.compare_digest(facts.patched.patch_digest, facts.diff_digest)
            and hmac.compare_digest(facts.baseline.image_digest, facts.patched.image_digest)
            and hmac.compare_digest(
                facts.baseline.environment_digest, facts.patched.environment_digest
            )
            and hmac.compare_digest(facts.baseline.command_digest, facts.patched.command_digest)
        )
        v02 = (
            patched_trusted
            and facts.patched.passed_cleanly()
            and facts.patched_counts.executed > 0
            and facts.patched_counts.failed == 0
            and parity
        )
        v03 = (
            facts.regression_counts.executed > 0
            and facts.regression_counts.failed == 0
            and facts.regression_counts.skipped <= facts.baseline_counts.skipped
            and hmac.compare_digest(
                facts.regression_selection_digest, facts.expected_regression_selection_digest
            )
        )
        v04 = integrity.disposition is IntegrityDisposition.ACCEPT
        v05 = (
            not facts.security_findings
            and not scan_diff_secrets(facts.diff_text)
            and all(
                check.passed
                for result in (facts.baseline, facts.patched)
                for check in result.isolation_checks
            )
        )
        v06 = (
            facts.fidelity in _FIDELITY_ORDER
            and facts.minimum_fidelity in _FIDELITY_ORDER
            and _FIDELITY_ORDER[facts.fidelity] >= _FIDELITY_ORDER[facts.minimum_fidelity]
        )
        v07 = all(
            (
                facts.workspace_id_matches,
                facts.repository_id_matches,
                facts.policy_allows_patch,
                facts.actor_authorized,
                facts.budget_sufficient,
                not facts.cancelled,
            )
        )

        gates = (
            _gate("V-01", v01, (baseline_id,)),
            _gate("V-02", v02, (baseline_id, patched_id)),
            _gate("V-03", v03, (patched_id,)),
            _gate("V-04", v04, ()),
            _gate("V-05", v05, (baseline_id, patched_id)),
            _gate("V-06", v06, (baseline_id, patched_id)),
            _gate("V-07", v07, ()),
        )
        reasons = tuple(
            f"{gate.id.lower().replace('-', '_')}_{gate.outcome}"
            for gate in gates
            if gate.outcome != "pass"
        )
        passed = len(reasons) == 0
        return VerificationDecision(
            gates=gates,
            integrity=integrity,
            baseline_result_digest=baseline_digest,
            patched_result_digest=patched_digest,
            locally_verified=passed,
            reason_codes=reasons,
        )


def sign_evidence_manifest(
    manifest: EvidenceManifestV1,
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> EvidenceManifestV1:
    """Sign the canonical S-22 manifest using the existing domain-separated key contract."""
    return sign_model_ed25519(
        manifest, private_key=private_key, key_id=key_id, domain=DOMAIN_EVIDENCE_MANIFEST_V1
    )


def create_signed_evidence_manifest(
    payload: dict[str, object],
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> EvidenceManifestV1:
    """Validate all S-22 fields before signing; never signs arbitrary unvalidated mappings."""
    parsed_payload = dict(payload)
    parsed_payload["signer_key_id"] = key_id
    parsed_payload["signature"] = "ed25519:pending"
    manifest = EvidenceManifestV1.model_validate(parsed_payload)
    return sign_evidence_manifest(manifest, private_key=private_key, key_id=key_id)


def verify_evidence_manifest(
    manifest: EvidenceManifestV1,
    *,
    keyring: KeyRing,
    artifact_blobs: dict[str, bytes],
    expected_signer_trust_domain: str,
    now: datetime | None = None,
) -> None:
    """Verify signer, result references and every supplied artifact blob; raise on any gap."""
    verify_model_ed25519(
        manifest,
        keyring=keyring,
        domain=DOMAIN_EVIDENCE_MANIFEST_V1,
        signed_at=now or datetime.now(tz=UTC),
        expected_trust_domain=expected_signer_trust_domain,
    )
    baseline_result: ResultV1 | None = None
    patched_result: ResultV1 | None = None
    for job_id, digest_attr in (
        (manifest.baseline_result_job_id, "baseline_result_digest"),
        (manifest.patched_result_job_id, "patched_result_digest"),
    ):
        if job_id not in artifact_blobs:
            raise CryptoVerificationError(
                code="missing_manifest_blob", detail=f"Signed evidence blob {job_id!r} is missing."
            )
        expected = getattr(manifest, digest_attr)
        observed = hashlib.sha256(artifact_blobs[job_id]).hexdigest()
        if not hmac.compare_digest(expected, observed):
            raise CryptoVerificationError(
                code="manifest_blob_digest_mismatch",
                detail=f"Signed evidence blob {job_id!r} does not match its manifest digest.",
            )
        try:
            result = ResultV1.model_validate_json(artifact_blobs[job_id])
        except (ValidationError, ValueError) as exc:
            raise CryptoVerificationError(
                code="invalid_worker_result_blob",
                detail=f"Signed evidence blob {job_id!r} is not a valid ResultV1.",
            ) from exc
        if result.job_id != job_id:
            raise CryptoVerificationError(
                code="manifest_result_reference_mismatch",
                detail=f"Result blob job ID does not match signed reference {job_id!r}.",
            )
        signer_record = keyring.get(result.signer_key_id)
        if signer_record is None or not _result_is_trusted(
            result, keyring=keyring, trust_domain=signer_record.trust_domain or ""
        ):
            raise CryptoVerificationError(
                code="invalid_worker_result_signature",
                detail=f"Worker result {job_id!r} has no valid enrolled signature.",
            )
        if digest_attr == "baseline_result_digest":
            if result.termination != "exited" or result.exit_code in (None, 0):
                raise CryptoVerificationError(
                    code="manifest_baseline_not_red",
                    detail="Signed baseline result does not contain a reproduced failing exit.",
                )
            baseline_result = result
        else:
            if not result.passed_cleanly() or result.patch_digest != manifest.diff_digest:
                raise CryptoVerificationError(
                    code="manifest_patch_not_green",
                    detail="Signed patched result is not green for the manifest diff digest.",
                )
            if (
                result.image_digest != manifest.image_digest
                or result.environment_digest != manifest.environment_digest
            ):
                raise CryptoVerificationError(
                    code="manifest_execution_parity_mismatch",
                    detail="Patched result image/environment does not match the manifest.",
                )
            patched_result = result
    if baseline_result is None or patched_result is None:
        raise CryptoVerificationError(
            code="missing_manifest_result",
            detail="Both signed baseline and patch results are required.",
        )
    if (
        baseline_result.image_digest != patched_result.image_digest
        or baseline_result.environment_digest != patched_result.environment_digest
        or baseline_result.command_digest != patched_result.command_digest
    ):
        raise CryptoVerificationError(
            code="manifest_execution_parity_mismatch",
            detail=(
                "Baseline and patched result do not share the required execution profile parity."
            ),
        )
    if (
        manifest.integrity_outcome != "pass"
        or manifest.security_outcome != "pass"
        or manifest.policy_outcome != "pass"
        or manifest.regression.passed_count <= 0
        or manifest.regression.failed_count != 0
        or manifest.fidelity_grade == "FX_UNSUPPORTED"
    ):
        raise CryptoVerificationError(
            code="manifest_gates_not_green",
            detail="Manifest contains a failed or unsupported deterministic verification gate.",
        )
    for artifact_id, expected in manifest.artifact_digests.items():
        blob = artifact_blobs.get(artifact_id)
        if blob is None:
            raise CryptoVerificationError(
                code="missing_manifest_blob", detail=f"Signed artifact {artifact_id!r} is missing."
            )
        if not hmac.compare_digest(expected, hashlib.sha256(blob).hexdigest()):
            raise CryptoVerificationError(
                code="manifest_blob_digest_mismatch",
                detail=f"Signed artifact {artifact_id!r} does not match its manifest digest.",
            )
