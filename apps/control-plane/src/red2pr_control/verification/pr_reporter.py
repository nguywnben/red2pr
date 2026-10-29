"""Manifest-only, redacted draft PR summary renderer (SEC-017)."""

from __future__ import annotations

import re

from py_contracts.crypto import KeyRing
from py_contracts.evidence import EvidenceManifestV1
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.verification.verifier import verify_evidence_manifest

_DASHBOARD_PATH_RE = re.compile(r"^/w/[a-z0-9-]+/repairs/[a-z0-9-]+/verification$")


def render_pr_summary(
    manifest: EvidenceManifestV1,
    *,
    keyring: KeyRing,
    artifact_blobs: dict[str, bytes],
    expected_signer_trust_domain: str,
    authenticated_dashboard_path: str,
    redactor: Redactor = DEFAULT_REDACTOR,
) -> str:
    """Render fixed text from a verified manifest; caller-supplied model prose is not accepted."""
    verify_evidence_manifest(
        manifest,
        keyring=keyring,
        artifact_blobs=artifact_blobs,
        expected_signer_trust_domain=expected_signer_trust_domain,
    )
    if not _DASHBOARD_PATH_RE.fullmatch(authenticated_dashboard_path):
        raise ValueError("Evidence link must be a same-origin authenticated dashboard path.")
    lines = [
        "## Red2PR verification evidence",
        "",
        "This draft was prepared from signed deterministic verification evidence.",
        "",
        f"- Repair: `{manifest.repair_id}`",
        f"- Source revision: `{manifest.source_sha}`",
        f"- Patch digest: `{manifest.diff_digest}`",
        f"- Baseline: reproduced failure (`{manifest.baseline_result_digest}`)",
        f"- Patched run: signed Sandbox B result (`{manifest.patched_result_digest}`)",
        f"- Regression tests: {manifest.regression.passed_count} passed, "
        f"{manifest.regression.failed_count} failed, {manifest.regression.skipped_count} skipped",
        f"- Diff integrity: `{manifest.integrity_outcome}`",
        f"- Security scan: `{manifest.security_outcome}`",
        f"- Policy gate: `{manifest.policy_outcome}`",
        f"- Sandbox fidelity: `{manifest.fidelity_grade}`",
        f"- Evidence: [Open authenticated verification details]({authenticated_dashboard_path})",
        "",
        "Remote CI has not been evaluated by this local proof.",
    ]
    return redactor.redact_text("\n".join(lines))
