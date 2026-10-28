"""Deterministic failure signature extraction & bounded flaky-test classifier (`U13`, `TRI-03`).

Enforces `TRI-03` (`T-TRI-03-P`, `T-TRI-03-N`) and `SEC-017` / `SEC-040`:
- Normalizes untrusted CI logs (stripping ANSI/OSC/bidi control sequences, timestamps,
  durations, hex pointers, UUIDs, temp paths, and line-number drift) before computing a
  tenant- & repository-scoped SHA-256 `fingerprint_hash`.
- Scrubs secrets with `Redactor` BEFORE persisting `signature_label` or `failure_excerpt`.
- Distinguishes `flaky`, `persistent_failure`, `single_pass_unproven`,
  `insufficient_history`, and `unknown` using bounded (`<= 25` recent entries + durable
  counters) attempt-pinned observations:
  * **One green rerun after a single failure (`1` fail + `1` pass) NEVER marks a failure
    `fixed` or `flaky`** — it is explicitly classified `single_pass_unproven` (`T-TRI-03-N`).
  * `flaky` requires repeated failure evidence (`failure_count >= 2`) paired with at least
    one verified green pass on a commit `head_sha` that also failed (`pass_on_same_sha_count >= 1`).
  * Missing, expired (`410`), or unparseable logs remain `unknown`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.integrations import (
    CiConclusion,
    FailureFingerprintObservation,
    FailureFingerprintSummary,
    FlakyClassification,
    JobLogStatus,
)
from py_contracts.primitives import new_uuid7
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import CiJobModel, CiRunModel, FailureFingerprintModel

MAX_RECENT_OBSERVATIONS = 25
FAILURE_CONCLUSIONS: frozenset[str] = frozenset({"failure", "timed_out", "action_required"})

# ANSI CSI / OSC & Unicode bidi control stripping (`SEC-040`)
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_CONTROL_BIDI_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]")

# Volatile token normalizers for stable failure hashing
_ISO_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_HEX_PTR_RE = re.compile(r"\b0x[0-9a-fA-F]{6,16}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_DURATION_RE = re.compile(r"\b\d+(?:\.\d+)?\s*(?:ms|s|sec|seconds)\b", re.IGNORECASE)
_TEMP_PATH_RE = re.compile(
    r"(?:/tmp/[A-Za-z0-9._-]+|[A-Za-z]:\\Users\\[^\\\s]+\\AppData\\Local\\Temp\\[A-Za-z0-9._-]+)"
)
_LINE_NUM_RE = re.compile(r"(:\d+)(?::\d+)?\b")
_WHITESPACE_RE = re.compile(r"\s+")

# Structured test runner signature matchers
_PYTEST_FAILED_RE = re.compile(r"^FAILED\s+([^\s]+?::[^\s]+)(?:\s+-\s+(.+))?$")
_JEST_VITEST_FAIL_FILE_RE = re.compile(r"^FAIL\s+([^\s]+\.(?:test|spec)\.[A-Za-z0-9]+)\b")
_JEST_BULLET_RE = re.compile(r"^[\u25cf\u00d7\u2715]\s+(.+)$")
_GO_FAIL_RE = re.compile(r"^---\s+FAIL:\s+([A-Za-z0-9_./-]+)")
_RUST_FAIL_RE = re.compile(r"^----\s+([A-Za-z0-9_:]+)\s+stdout\s+----$")
_ERROR_KIND_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception|Failure|Fault|Panic)|AssertionError|panic)\b"
)
_EXIT_CODE_RE = re.compile(
    r"(?:exit(?:ed with)? code|returned non-zero exit status)\s+(\d+)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ExtractedFailureSignature:
    """Normalized failure fingerprint & redacted excerpt extracted from a CI job log."""

    fingerprint_hash: str
    signature_label: str
    test_identifier: str | None
    error_kind: str | None
    failure_excerpt: str


def strip_terminal_escapes(text: str) -> str:
    """Strip ANSI CSI/OSC sequences and bidi/control characters (`SEC-040`)."""
    without_osc = _ANSI_OSC_RE.sub("", text)
    without_csi = _ANSI_CSI_RE.sub("", without_osc)
    return _CONTROL_BIDI_RE.sub("", without_csi)


def _normalize_for_hash(line: str) -> str:
    norm = _ISO_TS_RE.sub("<ts>", line)
    norm = _UUID_RE.sub("<uuid>", norm)
    norm = _HEX_PTR_RE.sub("<ptr>", norm)
    norm = _TEMP_PATH_RE.sub("<tmp>", norm)
    norm = _DURATION_RE.sub("<dur>", norm)
    norm = _LINE_NUM_RE.sub(":<line>", norm)
    return _WHITESPACE_RE.sub(" ", norm).strip().lower()


def _normalize_job_stem(job_name: str) -> str:
    """Strip matrix parenthetical suffixes so matrix siblings share canonical job stem."""
    clean = strip_terminal_escapes(job_name).strip()
    paren_idx = clean.find("(")
    if paren_idx > 0:
        clean = clean[:paren_idx].strip()
    return _WHITESPACE_RE.sub(" ", clean).lower()[:120] or "job"


def extract_failure_signature(
    log_text: str,
    *,
    job_name: str,
    redactor: Redactor = DEFAULT_REDACTOR,
) -> ExtractedFailureSignature | None:
    """Extract a deterministic, secret-redacted failure signature from a CI job log.

    Returns `None` when the log is empty or contains no usable content so callers
    keep `flaky_classification = 'unknown'` (`TRI-03`).
    """
    cleaned = strip_terminal_escapes(log_text)
    raw_lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]
    if not raw_lines:
        return None

    test_identifier: str | None = None
    error_kind: str | None = None
    anchor_lines: list[str] = []
    jest_file: str | None = None

    for line in raw_lines:
        # Strip leading GitHub Actions timestamp prefix if present
        stripped_line = _ISO_TS_RE.sub("", line, count=1).strip() if line[:4].isdigit() else line
        if not stripped_line:
            continue

        m_pytest = _PYTEST_FAILED_RE.match(stripped_line)
        if m_pytest is not None and test_identifier is None:
            test_identifier = m_pytest.group(1)[:512]
            tail = m_pytest.group(2)
            if tail:
                m_err = _ERROR_KIND_RE.search(tail)
                if m_err is not None and error_kind is None:
                    error_kind = m_err.group(1)[:120]
            anchor_lines.append(stripped_line)
            continue

        m_jest_file = _JEST_VITEST_FAIL_FILE_RE.match(stripped_line)
        if m_jest_file is not None:
            jest_file = m_jest_file.group(1)[:256]
            anchor_lines.append(stripped_line)
            continue

        m_jest_bullet = _JEST_BULLET_RE.match(stripped_line)
        if m_jest_bullet is not None and test_identifier is None:
            bullet_name = m_jest_bullet.group(1).strip()
            test_identifier = (
                f"{jest_file}::{bullet_name}"[:512] if jest_file else bullet_name[:512]
            )
            anchor_lines.append(stripped_line)
            continue

        m_go = _GO_FAIL_RE.match(stripped_line)
        if m_go is not None and test_identifier is None:
            test_identifier = m_go.group(1)[:512]
            anchor_lines.append(stripped_line)
            continue

        m_rust = _RUST_FAIL_RE.match(stripped_line)
        if m_rust is not None and test_identifier is None:
            test_identifier = m_rust.group(1)[:512]
            anchor_lines.append(stripped_line)
            continue

        if error_kind is None:
            m_err = _ERROR_KIND_RE.search(stripped_line)
            if m_err is not None:
                error_kind = m_err.group(1)[:120]
                anchor_lines.append(stripped_line)
                continue

        m_exit = _EXIT_CODE_RE.search(stripped_line)
        if m_exit is not None:
            if error_kind is None:
                error_kind = f"ExitCode{m_exit.group(1)}"[:120]
            anchor_lines.append(stripped_line)

    if test_identifier is None and jest_file is not None:
        test_identifier = jest_file

    # If no structured test/error marker matched, only synthesize a signature when an explicit
    # failure/error line exists; otherwise return None so unparseable noise stays 'unknown'.
    if not anchor_lines:
        fallback_candidates = [
            ln
            for ln in raw_lines[-40:]
            if any(
                kw in ln.lower()
                for kw in ("error", "fail", "fatal", "assert", "exception", "panic", "timed out")
            )
        ]
        if not fallback_candidates:
            return None
        anchor_lines = fallback_candidates[:3]

    redacted_anchors = [redactor.redact_text(ln) for ln in anchor_lines[:6]]
    redacted_test_id = (
        redactor.redact_text(test_identifier)[:1024] if test_identifier is not None else None
    )
    redacted_error_kind = redactor.redact_text(error_kind)[:120] if error_kind is not None else None

    canonical_anchor = _normalize_for_hash(redacted_anchors[0])
    canonical_material = "|".join(
        [
            "v1",
            _normalize_job_stem(job_name),
            (redacted_test_id or "").lower(),
            (redacted_error_kind or "generic").lower(),
            canonical_anchor[:240],
        ]
    )
    fp_hash = hashlib.sha256(canonical_material.encode("utf-8")).hexdigest()

    if redacted_test_id and redacted_error_kind:
        label = f"{redacted_error_kind} in {redacted_test_id}"
    elif redacted_test_id:
        label = f"Test failure in {redacted_test_id}"
    elif redacted_error_kind:
        label = f"{redacted_error_kind}: {redacted_anchors[0]}"
    else:
        label = redacted_anchors[0]

    excerpt = "\n".join(redacted_anchors)[:980]
    return ExtractedFailureSignature(
        fingerprint_hash=fp_hash,
        signature_label=label[:980],
        test_identifier=redacted_test_id,
        error_kind=redacted_error_kind,
        failure_excerpt=excerpt,
    )


def classify_fingerprint_counts(
    *,
    failure_count: int,
    pass_on_same_sha_count: int,
    distinct_sha_count: int,
) -> tuple[FlakyClassification, str]:
    """Deterministically classify flaky vs unproven vs persistent failure (`TRI-03`)."""
    if failure_count <= 0:
        return (
            "unknown",
            "No verified failure observations recorded against this signature.",
        )
    if failure_count == 1 and pass_on_same_sha_count >= 1:
        return (
            "single_pass_unproven",
            (
                "One green rerun after a single failure on the same commit SHA cannot "
                "establish that the failure is fixed or proven flaky (TRI-03)."
            ),
        )
    if failure_count >= 2 and pass_on_same_sha_count >= 1:
        return (
            "flaky",
            (
                f"Alternating outcomes verified across {failure_count} failed attempts and "
                f"{pass_on_same_sha_count} green rerun(s) on matching commit SHA(s)."
            ),
        )
    if failure_count >= 3 and pass_on_same_sha_count == 0:
        return (
            "persistent_failure",
            (
                f"Consistently failed {failure_count} times across "
                f"{max(1, distinct_sha_count)} commit SHA(s) with zero green reruns."
            ),
        )
    return (
        "insufficient_history",
        (
            f"Observed {failure_count} failure(s) with zero alternating green reruns on a "
            "failing SHA; additional observations required before classifying as flaky."
        ),
    )


def _apply_observation_to_fingerprint(
    fp_row: FailureFingerprintModel,
    *,
    run_id: str,
    attempt_key: str,
    head_sha: str,
    conclusion: str,
    observed_at: datetime,
) -> FlakyClassification:
    """Idempotently append an attempt observation and recompute durable `TRI-03` counters."""
    obs_list: list[dict[str, Any]] = [
        dict(entry) for entry in (fp_row.recent_observations_json or []) if isinstance(entry, dict)
    ]
    # Idempotency guard per `(run_id, attempt_key)` (`No blind retry`)
    already_recorded = any(
        entry.get("run_id") == run_id and entry.get("attempt_key") == attempt_key
        for entry in obs_list
    )
    if not already_recorded:
        obs_list.append(
            {
                "run_id": run_id,
                "attempt_key": attempt_key,
                "head_sha": head_sha,
                "conclusion": conclusion,
                "observed_at": observed_at.astimezone(UTC).isoformat(),
            }
        )

    # Recompute exact counts over known observations + monotonic historical floor
    failed_entries = [e for e in obs_list if str(e.get("conclusion")) in FAILURE_CONCLUSIONS]
    failed_shas = {str(e.get("head_sha")) for e in failed_entries if e.get("head_sha")}
    pass_same_sha_entries = [
        e
        for e in obs_list
        if str(e.get("conclusion")) == "success" and str(e.get("head_sha")) in failed_shas
    ]
    distinct_shas = {str(e.get("head_sha")) for e in obs_list if e.get("head_sha")}

    if not already_recorded:
        if conclusion in FAILURE_CONCLUSIONS:
            fp_row.failure_count = max(fp_row.failure_count + 1, len(failed_entries))
        elif conclusion == "success":
            fp_row.pass_on_same_sha_count = max(
                fp_row.pass_on_same_sha_count + 1,
                len(pass_same_sha_entries),
            )
    else:
        fp_row.failure_count = max(fp_row.failure_count, len(failed_entries))
        fp_row.pass_on_same_sha_count = max(
            fp_row.pass_on_same_sha_count,
            len(pass_same_sha_entries),
        )

    fp_row.distinct_sha_count = max(fp_row.distinct_sha_count, len(distinct_shas), 1)
    fp_row.recent_observations_json = obs_list[-MAX_RECENT_OBSERVATIONS:]
    if observed_at > fp_row.last_seen_at:
        fp_row.last_seen_at = observed_at

    verdict, reason = classify_fingerprint_counts(
        failure_count=fp_row.failure_count,
        pass_on_same_sha_count=fp_row.pass_on_same_sha_count,
        distinct_sha_count=fp_row.distinct_sha_count,
    )
    fp_row.classification = verdict
    fp_row.confidence_reason = reason
    fp_row.version += 1
    fp_row.updated_at = observed_at
    return verdict


async def record_and_classify_job_observation(
    db: AsyncSession,
    *,
    workspace_id: str,
    repository_id: str,
    run_id: str,
    attempt_key: str,
    head_sha: str,
    job_name: str,
    conclusion: str | None,
    log_text: str | None,
    log_status: JobLogStatus,
    redactor: Redactor = DEFAULT_REDACTOR,
    now: datetime | None = None,
) -> tuple[FailureFingerprintModel | None, FlakyClassification, str | None]:
    """Classify a failed or passing-rerun CI job and update `failure_fingerprints` (`TRI-03`).

    Returns `(fingerprint_row, flaky_classification, failure_excerpt)`.
    """
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    norm_conclusion = (conclusion or "unknown").strip().lower()

    # Case 1: Failed / timed_out / action_required job
    if norm_conclusion in FAILURE_CONCLUSIONS:
        if log_text is None or log_status in ("expired", "unavailable", "pending"):
            return None, "unknown", None

        extracted = extract_failure_signature(log_text, job_name=job_name, redactor=redactor)
        if extracted is None:
            return None, "unknown", None

        fp_row = await db.scalar(
            select(FailureFingerprintModel).where(
                FailureFingerprintModel.workspace_id == workspace_id,
                FailureFingerprintModel.repository_id == repository_id,
                FailureFingerprintModel.fingerprint_hash == extracted.fingerprint_hash,
            )
        )
        if fp_row is None:
            fp_row = FailureFingerprintModel(
                id=new_uuid7(now=ref_now),
                workspace_id=workspace_id,
                repository_id=repository_id,
                fingerprint_hash=extracted.fingerprint_hash,
                signature_label=extracted.signature_label,
                test_identifier=extracted.test_identifier,
                error_kind=extracted.error_kind,
                classification="insufficient_history",
                confidence_reason="Initial observation.",
                failure_count=0,
                pass_on_same_sha_count=0,
                distinct_sha_count=0,
                recent_observations_json=[],
                first_seen_at=ref_now,
                last_seen_at=ref_now,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(fp_row)
            await db.flush()

        verdict = _apply_observation_to_fingerprint(
            fp_row,
            run_id=run_id,
            attempt_key=attempt_key,
            head_sha=head_sha,
            conclusion=norm_conclusion,
            observed_at=ref_now,
        )
        await db.flush()
        return fp_row, verdict, extracted.failure_excerpt

    # Case 2: Green rerun (`success`) on a commit SHA where an earlier attempt of this job failed
    if norm_conclusion == "success":
        prior_fp_ids = list(
            (
                await db.scalars(
                    select(CiJobModel.failure_fingerprint_id)
                    .join(
                        CiRunModel,
                        (CiRunModel.workspace_id == CiJobModel.workspace_id)
                        & (CiRunModel.id == CiJobModel.run_id),
                    )
                    .where(
                        CiJobModel.workspace_id == workspace_id,
                        CiJobModel.repository_id == repository_id,
                        CiJobModel.name == job_name[:120],
                        CiRunModel.head_sha == head_sha,
                        CiJobModel.failure_fingerprint_id.is_not(None),
                    )
                    .order_by(CiJobModel.created_at.desc())
                    .limit(5)
                )
            ).all()
        )
        unique_fp_ids = [fid for fid in dict.fromkeys(prior_fp_ids) if fid is not None]
        if not unique_fp_ids:
            return None, "unknown", None

        primary_fp: FailureFingerprintModel | None = None
        primary_verdict: FlakyClassification = "unknown"
        for fp_id in unique_fp_ids:
            fp_row = await db.scalar(
                select(FailureFingerprintModel).where(
                    FailureFingerprintModel.workspace_id == workspace_id,
                    FailureFingerprintModel.id == fp_id,
                )
            )
            if fp_row is None:
                continue
            verdict = _apply_observation_to_fingerprint(
                fp_row,
                run_id=run_id,
                attempt_key=attempt_key,
                head_sha=head_sha,
                conclusion="success",
                observed_at=ref_now,
            )
            # Propagate updated classification onto prior CiJob rows referencing this fingerprint
            prior_jobs = list(
                (
                    await db.scalars(
                        select(CiJobModel).where(
                            CiJobModel.workspace_id == workspace_id,
                            CiJobModel.failure_fingerprint_id == fp_row.id,
                        )
                    )
                ).all()
            )
            for p_job in prior_jobs:
                p_job.flaky_classification = verdict
                p_job.updated_at = ref_now

            if primary_fp is None:
                primary_fp = fp_row
                primary_verdict = verdict

        await db.flush()
        return primary_fp, primary_verdict, None

    return None, "unknown", None


def summarize_run_flaky_classification(
    job_classifications: list[FlakyClassification],
) -> FlakyClassification:
    """Compute conservative run-level flaky summary from job-level classifications."""
    if not job_classifications:
        return "unknown"
    # Persistent failures take priority so real breakages are never masked by a flaky sibling job
    if "persistent_failure" in job_classifications:
        return "persistent_failure"
    if "flaky" in job_classifications:
        return "flaky"
    if "single_pass_unproven" in job_classifications:
        return "single_pass_unproven"
    if "insufficient_history" in job_classifications:
        return "insufficient_history"
    return "unknown"


def fingerprint_model_to_dto(row: FailureFingerprintModel) -> FailureFingerprintSummary:
    """Project `FailureFingerprintModel` to `FailureFingerprintSummary` DTO (`A-08`)."""
    observations: list[FailureFingerprintObservation] = []
    for item in row.recent_observations_json or []:
        raw_obs_at = item.get("observed_at")
        if isinstance(raw_obs_at, str):
            norm_ts = raw_obs_at[:-1] + "+00:00" if raw_obs_at.endswith("Z") else raw_obs_at
            obs_dt = datetime.fromisoformat(norm_ts).astimezone(UTC)
        else:
            obs_dt = row.last_seen_at
        observations.append(
            FailureFingerprintObservation(
                run_id=str(item["run_id"]),
                attempt_key=str(item["attempt_key"]),
                head_sha=str(item["head_sha"]),
                conclusion=cast(CiConclusion, str(item.get("conclusion", "unknown"))),
                observed_at=obs_dt,
            )
        )

    return FailureFingerprintSummary(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        fingerprint_hash=row.fingerprint_hash,
        signature_label=row.signature_label,
        test_identifier=row.test_identifier,
        error_kind=row.error_kind,
        classification=cast(FlakyClassification, row.classification),
        confidence_reason=row.confidence_reason,
        failure_count=row.failure_count,
        pass_on_same_sha_count=row.pass_on_same_sha_count,
        distinct_sha_count=row.distinct_sha_count,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        recent_observations=observations,
    )
