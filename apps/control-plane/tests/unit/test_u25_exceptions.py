from datetime import UTC, datetime, timedelta

from red2pr_control.operations.exceptions import Finding, ReleaseException, evaluate_release_gate

NOW = datetime(2026, 10, 30, tzinfo=UTC)
DIGEST = "a" * 64


def test_only_active_high_exception_for_same_digest_allows_release() -> None:
    finding = Finding("SEC-1", "high", artifact_digest=DIGEST)
    exc = ReleaseException("SEC-1", "high", DIGEST, NOW + timedelta(days=1))
    assert evaluate_release_gate([finding], [exc], artifact_digest=DIGEST, now=NOW).ready


def test_critical_invariant_expired_and_digest_mismatch_always_block() -> None:
    critical = Finding("SEC-2", "critical", artifact_digest=DIGEST)
    invariant = Finding("INV-1", "high", invariant_violation=True, artifact_digest=DIGEST)
    expired = ReleaseException("SEC-1", "high", DIGEST, NOW - timedelta(seconds=1))
    mismatch = ReleaseException("SEC-1", "high", "b" * 64, NOW + timedelta(days=1))
    high = Finding("SEC-1", "high", artifact_digest=DIGEST)
    result = evaluate_release_gate(
        [critical, invariant, high],
        [expired, mismatch],
        artifact_digest=DIGEST,
        now=NOW,
        flags_enabled=True,
    )
    assert not result.ready
    assert set(result.blocking_reasons) == {
        "critical_finding:SEC-2",
        "invariant_violation:INV-1",
        "high_finding_unexcepted:SEC-1",
        "high_finding_unexcepted:INV-1",
    }


def test_exception_with_different_digest_cannot_authorize_build() -> None:
    finding = Finding("SEC-1", "high", artifact_digest=DIGEST)
    exc = ReleaseException("SEC-1", "high", "b" * 64, NOW + timedelta(days=1))
    assert not evaluate_release_gate([finding], [exc], artifact_digest=DIGEST, now=NOW).ready
