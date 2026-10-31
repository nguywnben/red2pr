"""ADR-032 digest-bound release exception and readiness gate."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from py_contracts.crypto import (
    DOMAIN_EVIDENCE_MANIFEST_V1,
    CryptoVerificationError,
    KeyRing,
    verify_model_ed25519,
)
from py_contracts.evidence import EvidenceManifestV1


@dataclass(frozen=True)
class Finding:
    ref: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    artifact_digest: str
    invariant_violation: bool = False


@dataclass(frozen=True)
class ReleaseException:
    finding_ref: str
    severity: Literal["high"]
    artifact_digest: str
    expires_at: datetime
    revoked: bool = False


@dataclass(frozen=True)
class ReleaseGateResult:
    ready: bool
    blocking_reasons: tuple[str, ...]


def evaluate_release_gate(
    findings: list[Finding],
    exceptions: list[ReleaseException],
    *,
    artifact_digest: str,
    now: datetime,
    flags_enabled: bool = False,
) -> ReleaseGateResult:
    """Fail closed for Critical/invariants and require live exact-digest High exceptions."""
    del flags_enabled  # ADR-032 explicitly makes feature flags irrelevant to hard blockers.
    ref_now = now.astimezone(UTC)
    reasons: list[str] = []
    for finding in findings:
        if finding.artifact_digest != artifact_digest:
            reasons.append(f"finding_digest_mismatch:{finding.ref}")
        if finding.severity == "critical":
            reasons.append(f"critical_finding:{finding.ref}")
        if finding.invariant_violation:
            reasons.append(f"invariant_violation:{finding.ref}")
        if finding.severity == "high":
            permitted = any(
                exc.finding_ref == finding.ref
                and exc.severity == "high"
                and not exc.revoked
                and exc.expires_at.astimezone(UTC) > ref_now
                and exc.artifact_digest == artifact_digest
                for exc in exceptions
            )
            if not permitted:
                reasons.append(f"high_finding_unexcepted:{finding.ref}")
    return ReleaseGateResult(not reasons, tuple(dict.fromkeys(reasons)))


def evaluate_signed_manifest_release_gate(
    manifest: EvidenceManifestV1,
    exceptions: list[ReleaseException],
    *,
    keyring: KeyRing,
    expected_signer_trust_domain: str,
    artifact_digest: str,
    now: datetime,
) -> ReleaseGateResult:
    """Evaluate only verifier-signed findings bound to the exact candidate artifact."""
    try:
        verify_model_ed25519(
            manifest,
            keyring=keyring,
            domain=DOMAIN_EVIDENCE_MANIFEST_V1,
            signed_at=manifest.created_at,
            expected_trust_domain=expected_signer_trust_domain,
        )
    except (CryptoVerificationError, ValueError) as exc:
        raise CryptoVerificationError(
            code="release_manifest_signature_invalid",
            detail="Release readiness requires a valid verifier-signed evidence manifest.",
        ) from exc
    # `diff_digest` is the exact candidate patch bound by approval/publication.
    # Artifact digests also include baseline logs/results and cannot identify the
    # candidate by themselves.
    if artifact_digest != manifest.diff_digest:
        return ReleaseGateResult(False, ("candidate_artifact_digest_mismatch",))
    findings = [
        Finding(
            ref=item.finding_ref,
            severity=item.severity,
            artifact_digest=item.artifact_digest,
            invariant_violation=item.invariant_violation,
        )
        for item in manifest.security_findings
    ]
    if manifest.security_outcome != "pass" and not findings:
        findings.append(
            Finding(
                ref="security_outcome_failed_without_typed_findings",
                severity="critical",
                artifact_digest=artifact_digest,
                invariant_violation=True,
            )
        )
    return evaluate_release_gate(
        findings,
        exceptions,
        artifact_digest=artifact_digest,
        now=now,
    )
