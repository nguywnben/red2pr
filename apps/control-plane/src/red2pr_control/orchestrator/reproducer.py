"""Certified Runner Profiles, A/B Sandbox Reproducer & Non-Waivable ADR-031 Gate (`U15`).

Implements `SAN-02`, `SAN-03`, `W-04`, `ADR-018`, `ADR-031`, `SEC-006`, `SEC-007`,
`SEC-014`, `SEC-024`, `SEC-025`, `SEC-026`, `SEC-030`, `SEC-032`, and `SEC-036`:
- Loads immutable, SHA-256 digest-pinned `RunnerProfileManifest` definitions from
  `apps/worker-supervisor/profiles/*/manifest.json` via `py_contracts.worker` (with
  **zero** imports from `red2pr_worker` or `Z2` secret/publisher/inference modules) and
  synchronizes them into the `profile_revisions` PostgreSQL ledger.
- Selects certified Linux runner profiles (`python-pytest-linux`, `node-jest-linux`,
  `node-vitest-linux`) or admin-opted VM-isolated `custom-linux-declared`, and explicitly
  abstains with `FX_UNSUPPORTED` (`0` sandbox leases dispatched) on macOS, Windows, GPU,
  Docker-in-Docker, privileged, or undeclared secret-backed service CI jobs (`ADR-018`).
- Orchestrates fresh **Sandbox A** (`baseline_a`) reproduction on exact `base_sha` and
  seals `repro_confirmed` ONLY when tests actually ran (`executed_tests_count > 0`),
  exited non-zero without bootstrap/install crashes, and reproduced the expected failure
  fingerprint. Passing baselines, timeouts, zero-test runs (`--passWithNoTests` / exit `5`),
  and unrelated install failures seal `repro_unconfirmed` and route strictly to
  `diagnosis_and_human_handoff` (`ADR-031`).
- Enforces the non-waivable `ADR-031` gate before any candidate patch or **Sandbox B**
  (`patched_b`) run, and verifies clean `patched_b` A/B digest parity + non-regressing
  executed test count + non-increasing skipped/xfailed count (`docs/10_SANDBOX_REPRODUCTION.md`).
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from xml.parsers import expat

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import (
    EventEnvelope,
    RepairPhaseEventPayload,
    ReproVerificationEventPayload,
)
from py_contracts.evidence import FidelityGrade
from py_contracts.primitives import new_uuid7
from py_contracts.worker import (
    ReproductionHandoffOutcome,
    ReproductionPhase,
    ReproductionRunRecord,
    ReproductionStatus,
    ResultArtifactRef,
    ResultTermination,
    ResultV1,
    RunnerProfileCommandSpec,
    RunnerProfileManifest,
    SandboxResourceLimits,
    load_reviewed_profile_manifests,
)
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    NotFoundError,
    UnprocessableEntityError,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    ArtifactModel,
    CiJobModel,
    CiRunModel,
    FailureFingerprintModel,
    ProfileRevisionModel,
    ReproductionRunModel,
    SandboxLeaseModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.orchestrator.worker_broker import WorkerBrokerService
from red2pr_control.triage_evidence.artifact_store import read_artifact_for_authorized_caller
from red2pr_control.triage_evidence.flaky import (
    ExtractedFailureSignature,
    extract_failure_signature,
    strip_terminal_escapes,
)

MAX_JUNIT_XML_BYTES = 2 * 1024 * 1024
UNSUPPORTED_PROFILE_PLACEHOLDER = "fx-unsupported"

_NON_LINUX_RUNNER_RE = re.compile(
    r"(?:^|[^a-z0-9])(macos|darwin|osx|windows|win32|win64|ios|xcode|freebsd)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)
_GPU_RUNNER_RE = re.compile(
    r"(?:^|[^a-z0-9])(gpu|cuda|rocm|nvidia|tpu|metal)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)
_DIND_PRIVILEGED_RE = re.compile(
    r"(?:^|[^a-z0-9])(dind|docker-in-docker|docker:dind|privileged|kubernetes|k8s|"
    r"kind-cluster|minikube)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)
_SECRET_SERVICE_RE = re.compile(
    r"(?:^|[^a-z0-9])(undeclared_secret_service|external-secret-db|vault-live|"
    r"aws-live|gcp-live|live-prod-service)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)
_UNSUPPORTED_ECOSYSTEM_RE = re.compile(
    r"(?:^|[^a-z0-9])(cargo|rust|golang|go-test|gradle|maven|mvn|dotnet|msbuild|"
    r"rspec|bazel|elixir|mix-test|php|phpunit)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)

_VITEST_SIGNAL_RE = re.compile(r"(?:^|[^a-z0-9])vitest(?:[^a-z0-9]|$)", re.IGNORECASE)
_JEST_SIGNAL_RE = re.compile(r"(?:^|[^a-z0-9])jest(?:[^a-z0-9]|$)", re.IGNORECASE)
_NODE_SIGNAL_RE = re.compile(
    r"(?:^|[^a-z0-9])(node|nodejs|npm|pnpm|yarn|ts-test|js-test)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)
_PYTEST_SIGNAL_RE = re.compile(
    r"(?:^|[^a-z0-9])(pytest|python|py3\d*|uv|tox)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)

_LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "uv.lock",
        "poetry.lock",
        "pdm.lock",
        "pipfile.lock",
        "requirements.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    }
)

_PYTEST_BANNER_RE = re.compile(r"={3,}\s*(.+?)\s+in\s+\d+(?:\.\d+)?s\s*={3,}")
_PYTEST_COUNT_TOKEN_RE = re.compile(
    r"\b(\d+)\s+(passed|failed|error|errors|skipped|xfailed|xpassed)\b",
    re.IGNORECASE,
)
_PYTEST_ZERO_RE = re.compile(
    r"(?:\bno tests ran\b|\bcollected 0 items\b)",
    re.IGNORECASE,
)
_JEST_TESTS_LINE_RE = re.compile(r"^\s*Tests:\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_JEST_COUNT_TOKEN_RE = re.compile(
    r"\b(\d+)\s+(failed|passed|skipped|pending|todo|total)\b",
    re.IGNORECASE,
)
_JEST_ZERO_RE = re.compile(r"\bNo tests found\b", re.IGNORECASE)
_VITEST_TESTS_LINE_RE = re.compile(
    r"^\s*Tests\s+((?:\d+\s+(?:failed|passed|skipped|todo)(?:\s*\|\s*)?)+)\s*\((\d+)\)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_VITEST_COUNT_TOKEN_RE = re.compile(
    r"\b(\d+)\s+(failed|passed|skipped|todo)\b",
    re.IGNORECASE,
)
_VITEST_ZERO_RE = re.compile(r"\bNo test files found\b", re.IGNORECASE)

_BOOTSTRAP_INFRA_ERROR_RE = re.compile(
    r"(?:PIP_INSTALL_ERROR|ResolutionImpossible|"
    r"Could not find a version that satisfies the requirement|"
    r"No matching distribution found for|"
    r"npm ERR!|ERR_PNPM_[A-Z0-9_]+|YN0001|"
    r"Cannot find module ['\"]jest['\"]|Cannot find package ['\"]vitest['\"]|"
    r"No module named ['\"]?pytest['\"]?|"
    r"Temporary failure in name resolution|ENOTFOUND\s+registry\.npmjs\.org|"
    r"ECONNREFUSED\s+127\.0\.0\.1)",
    re.IGNORECASE,
)

_XML_DOCTYPE_ENTITY_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def _default_profiles_dir() -> Path:
    candidate = Path(__file__).resolve().parents[4] / "worker-supervisor" / "profiles"
    if candidate.is_dir():
        return candidate
    raise FileNotFoundError(f"Reviewed runner profile directory not found at {candidate}.")


@dataclass(frozen=True, slots=True)
class ProfileSelectionDecision:
    """Deterministic `SAN-03` / `ADR-018` runner profile & fidelity selection result."""

    supported: bool
    profile_id: str | None
    profile_revision: int | None
    profile_digest: str | None
    image_digest: str | None
    repro_command_ids: tuple[str, ...]
    regression_command_ids: tuple[str, ...]
    requires_vm_isolation: bool
    fidelity_grade: FidelityGrade
    fidelity_differences: tuple[str, ...]
    reason_code: str


@dataclass(frozen=True, slots=True)
class ParsedTestExecution:
    """Normalized test runner execution counts & bootstrap crash indicators (`SAN-02`)."""

    executed_tests_count: int
    passed_tests_count: int
    failed_tests_count: int
    skipped_tests_count: int
    zero_tests_banner: bool
    bootstrap_or_infra_error: bool


def _model_to_record(row: ReproductionRunModel) -> ReproductionRunRecord:
    return ReproductionRunRecord(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        repair_id=row.repair_id,
        ci_run_id=row.ci_run_id,
        ci_job_id=row.ci_job_id,
        phase=cast(ReproductionPhase, row.phase),
        baseline_reproduction_id=row.baseline_reproduction_id,
        sandbox_job_id=row.sandbox_job_id,
        sandbox_lease_id=row.sandbox_lease_id,
        profile_id=row.profile_id,
        profile_revision=row.profile_revision,
        profile_digest=row.profile_digest,
        image_digest=row.image_digest,
        base_sha=row.base_sha,
        source_archive_digest=row.source_archive_digest,
        dependency_lock_digest=row.dependency_lock_digest,
        cache_key=row.cache_key,
        patch_digest=row.patch_digest,
        command_ids=list(row.command_ids_json or []),
        command_digest=row.command_digest,
        environment_digest=row.environment_digest,
        expected_fingerprint_hash=row.expected_fingerprint_hash,
        observed_fingerprint_hash=row.observed_fingerprint_hash,
        fingerprint_matched=row.fingerprint_matched,
        executed_tests_count=row.executed_tests_count,
        passed_tests_count=row.passed_tests_count,
        failed_tests_count=row.failed_tests_count,
        skipped_tests_count=row.skipped_tests_count,
        exit_code=row.exit_code,
        termination=cast(ResultTermination | None, row.termination),
        status=cast(ReproductionStatus, row.status),
        fidelity_grade=cast(FidelityGrade, row.fidelity_grade),
        fidelity_differences=list(row.fidelity_differences_json or []),
        handoff_outcome=cast(ReproductionHandoffOutcome, row.handoff_outcome),
        allow_patching=row.allow_patching,
        allow_publication=row.allow_publication,
        failure_reason_code=row.failure_reason_code,
        failure_detail=row.failure_detail,
        result_digest=row.result_digest,
        artifact_refs=[
            ResultArtifactRef.model_validate(item) for item in (row.artifact_refs_json or [])
        ],
        immutable_sealed=row.immutable_sealed,
        started_at=row.started_at,
        finished_at=row.finished_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.version,
    )


class RunnerProfileRegistry:
    """Immutable reviewed runner profile manifest catalog & DB synchronizer (`SAN-03`)."""

    def __init__(self, *, profiles_dir: Path | None = None) -> None:
        resolved_dir = (profiles_dir or _default_profiles_dir()).resolve()
        loaded = load_reviewed_profile_manifests(resolved_dir)
        if not loaded:
            raise ValueError(f"No reviewed runner profiles found in {resolved_dir}.")
        self._profiles_dir = resolved_dir
        self._by_id: dict[str, RunnerProfileManifest] = dict(loaded)

    @property
    def profiles_dir(self) -> Path:
        return self._profiles_dir

    def list_manifests(self) -> list[RunnerProfileManifest]:
        return [self._by_id[k] for k in sorted(self._by_id)]

    def get_manifest(
        self,
        profile_id: str,
        *,
        revision: int | None = None,
    ) -> RunnerProfileManifest:
        manifest = self._by_id.get(profile_id.strip())
        if manifest is None:
            raise NotFoundError(
                code="profile_not_found",
                detail=f"Runner profile {profile_id!r} is not in the reviewed catalog.",
            )
        if revision is not None and manifest.revision != revision:
            raise NotFoundError(
                code="profile_revision_not_found",
                detail=(
                    f"Runner profile {profile_id!r} revision {revision} is not in the "
                    f"reviewed catalog (current={manifest.revision})."
                ),
            )
        return manifest

    def resolve_profile_and_commands(
        self,
        profile_id: str,
        command_ids: Sequence[str],
        *,
        profile_revision: int | None = None,
    ) -> tuple[RunnerProfileManifest, tuple[RunnerProfileCommandSpec, ...]]:
        """Validate `profile_id` and `command_ids` strictly against reviewed manifests."""
        clean_id = profile_id.strip()
        manifest = self._by_id.get(clean_id)
        if manifest is None:
            raise UnprocessableEntityError(
                code="unreviewed_profile_or_command",
                detail=f"Runner profile {clean_id!r} is not an approved reviewed profile.",
            )
        if profile_revision is not None and manifest.revision != profile_revision:
            raise UnprocessableEntityError(
                code="unreviewed_profile_or_command",
                detail=(
                    f"Runner profile {clean_id!r} revision {profile_revision} does not match "
                    f"reviewed revision {manifest.revision}."
                ),
            )
        if not command_ids:
            raise UnprocessableEntityError(
                code="unreviewed_profile_or_command",
                detail="At least one reviewed command_id is required.",
            )
        cmd_map = {cmd.command_id: cmd for cmd in manifest.commands}
        resolved_cmds: list[RunnerProfileCommandSpec] = []
        for raw_cid in command_ids:
            cid = raw_cid.strip()
            spec = cmd_map.get(cid)
            if spec is None:
                raise UnprocessableEntityError(
                    code="unreviewed_profile_or_command",
                    detail=(
                        f"Command ID {cid!r} is not defined in reviewed profile {clean_id!r} "
                        "(raw command interpolation is forbidden, SEC-006)."
                    ),
                )
            resolved_cmds.append(spec)
        return manifest, tuple(resolved_cmds)

    async def sync_profiles_to_db(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        now: datetime | None = None,
    ) -> dict[str, str]:
        """Idempotently register reviewed manifests in `profile_revisions` (`SAN-03`).

        Returns `{profile_id: profile_revision_row_id}` and fails closed with
        `409 profile_revision_digest_conflict` if an existing `(profile_id, revision)`
        row has a differing `manifest_digest` or `image_digest`.
        """
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        synced_by_profile: dict[str, str] = {}
        async with instance_rls_session(session_factory, mode="instance_only") as db:
            for manifest in self.list_manifests():
                digest = manifest.manifest_digest()
                existing = await db.scalar(
                    select(ProfileRevisionModel).where(
                        ProfileRevisionModel.profile_id == manifest.profile_id,
                        ProfileRevisionModel.revision == manifest.revision,
                    )
                )
                if existing is not None:
                    if not hmac.compare_digest(
                        existing.manifest_digest, digest
                    ) or not hmac.compare_digest(existing.image_digest, manifest.image_digest):
                        raise ConflictError(
                            code="profile_revision_digest_conflict",
                            detail=(
                                f"Immutable profile revision "
                                f"{manifest.profile_id}@r{manifest.revision} "
                                "already exists in DB with a different SHA-256 digest."
                            ),
                        )
                    synced_by_profile[manifest.profile_id] = existing.id
                    continue

                row = ProfileRevisionModel(
                    id=new_uuid7(now=ref_now),
                    profile_id=manifest.profile_id,
                    revision=manifest.revision,
                    manifest_digest=digest,
                    display_name=manifest.display_name,
                    ecosystem=manifest.ecosystem,
                    platform=manifest.platform,
                    base_image=manifest.base_image,
                    image_digest=manifest.image_digest,
                    requires_isolated_vm_tier=manifest.requires_isolated_vm_tier,
                    requires_admin_opt_in=manifest.requires_admin_opt_in,
                    manifest_json=manifest.model_dump(mode="json"),
                    version=1,
                    created_at=ref_now,
                    updated_at=ref_now,
                )
                db.add(row)
                synced_by_profile[manifest.profile_id] = row.id
            await db.flush()
        return synced_by_profile


def grade_reproduction_fidelity(
    *,
    supported: bool,
    profile_id: str | None,
    has_pinned_lockfile: bool,
    targeted_only: bool = False,
    runtime_version_mismatch: bool = False,
    has_opaque_ci_actions: bool = False,
    has_service_approximation: bool = False,
    extra_differences: Sequence[str] = (),
) -> tuple[FidelityGrade, tuple[str, ...]]:
    """Assign canonical `F1_TARGETED..FX_UNSUPPORTED` fidelity grade (`SAN-02`, `doc10`)."""
    diffs: list[str] = list(extra_differences)
    if not supported or profile_id is None:
        if not diffs:
            diffs.append("unsupported_runner_environment")
        return "FX_UNSUPPORTED", tuple(dict.fromkeys(diffs))

    if not has_pinned_lockfile:
        diffs.append("dependency_lockfile_unpinned")
    if targeted_only:
        diffs.append("targeted_test_subset_only")
    if runtime_version_mismatch:
        diffs.append("runtime_minor_version_approximated")
    if has_opaque_ci_actions:
        diffs.append("opaque_ci_vendor_actions_not_replayed")
    if has_service_approximation:
        diffs.append("ci_service_or_matrix_approximated")
    if profile_id == "custom-linux-declared":
        diffs.append("custom_declared_profile_vm_isolated")

    dedup_diffs = tuple(dict.fromkeys(diffs))
    if not has_pinned_lockfile or targeted_only:
        return "F1_TARGETED", dedup_diffs
    if (
        has_opaque_ci_actions
        or has_service_approximation
        or runtime_version_mismatch
        or profile_id == "custom-linux-declared"
    ):
        return "F2_APPROX", dedup_diffs
    return "F3_VALIDATED", dedup_diffs


def select_profile_for_ci_job(
    *,
    ci_job_name: str,
    ci_job_stage: str | None = None,
    matrix_dimensions: Mapping[str, str] | None = None,
    repo_files: Sequence[str] = (),
    declared_capabilities: Sequence[str] = (),
    policy_runtime_profile_id: str | None = None,
    custom_profile_admin_opt_in: bool = False,
    has_pinned_lockfile: bool | None = None,
    targeted_only: bool = False,
    runtime_version_mismatch: bool = False,
    has_opaque_ci_actions: bool = False,
    has_service_approximation: bool = False,
    registry: RunnerProfileRegistry | None = None,
) -> ProfileSelectionDecision:
    """Deterministically map a failing CI job onto a reviewed runner profile or `FX_UNSUPPORTED`."""
    reg = registry or RunnerProfileRegistry()
    matrix_vals = " ".join(f"{k}={v}" for k, v in sorted((matrix_dimensions or {}).items()))
    caps_vals = " ".join(declared_capabilities)
    combined_signal = " | ".join(
        part for part in (ci_job_name, ci_job_stage or "", matrix_vals, caps_vals) if part
    )
    normalized_files = {Path(f).name.lower() for f in repo_files if f}
    inferred_lockfile = (
        has_pinned_lockfile
        if has_pinned_lockfile is not None
        else bool(normalized_files & _LOCKFILE_NAMES)
    )

    def _abstain(reason_code: str, difference_note: str) -> ProfileSelectionDecision:
        return ProfileSelectionDecision(
            supported=False,
            profile_id=None,
            profile_revision=None,
            profile_digest=None,
            image_digest=None,
            repro_command_ids=(),
            regression_command_ids=(),
            requires_vm_isolation=False,
            fidelity_grade="FX_UNSUPPORTED",
            fidelity_differences=(difference_note,),
            reason_code=reason_code,
        )

    m_os = _NON_LINUX_RUNNER_RE.search(combined_signal)
    if m_os is not None:
        return _abstain(
            "unsupported_non_linux_runner",
            f"non_linux_runner_detected:{m_os.group(1).lower()}",
        )

    m_gpu = _GPU_RUNNER_RE.search(combined_signal)
    if m_gpu is not None:
        return _abstain(
            "unsupported_gpu_accelerator",
            f"gpu_accelerator_required:{m_gpu.group(1).lower()}",
        )

    m_dind = _DIND_PRIVILEGED_RE.search(combined_signal)
    if m_dind is not None:
        return _abstain(
            "unsupported_privileged_or_dind",
            f"privileged_or_dind_required:{m_dind.group(1).lower()}",
        )

    m_sec = _SECRET_SERVICE_RE.search(combined_signal)
    if m_sec is not None:
        return _abstain(
            "unsupported_secret_backed_service",
            f"undeclared_secret_service_required:{m_sec.group(1).lower()}",
        )

    clean_policy_profile = (policy_runtime_profile_id or "").strip()
    if clean_policy_profile in ("", "default-isolated"):
        clean_policy_profile = ""

    selected_id: str | None = None
    repro_cmds: tuple[str, ...] = ()
    reg_cmds: tuple[str, ...] = ()

    if clean_policy_profile == "custom-linux-declared":
        if not custom_profile_admin_opt_in:
            return _abstain(
                "custom_profile_opt_in_required",
                "custom_linux_declared_requires_admin_opt_in_and_vm_tier",
            )
        selected_id = "custom-linux-declared"
        repro_cmds = ("declared-repro",)
        reg_cmds = ("declared-regression",)
    elif clean_policy_profile in (
        "python-pytest-linux",
        "node-jest-linux",
        "node-vitest-linux",
    ):
        selected_id = clean_policy_profile
        if selected_id == "python-pytest-linux":
            repro_cmds = ("pytest-targeted" if targeted_only else "pytest-repro",)
            reg_cmds = ("pytest-regression",)
        elif selected_id == "node-jest-linux":
            repro_cmds = ("jest-targeted" if targeted_only else "jest-repro",)
            reg_cmds = ("jest-regression",)
        else:
            repro_cmds = ("vitest-targeted" if targeted_only else "vitest-repro",)
            reg_cmds = ("vitest-regression",)
    elif clean_policy_profile:
        return _abstain(
            "unreviewed_policy_profile",
            f"unreviewed_runtime_profile:{clean_policy_profile}",
        )
    else:
        has_vitest_file = any(name.startswith("vitest.config.") for name in normalized_files)
        has_jest_file = any(name.startswith("jest.config.") for name in normalized_files)
        has_pkg_json = "package.json" in normalized_files
        has_python_file = bool(
            normalized_files
            & {
                "pyproject.toml",
                "pytest.ini",
                "tox.ini",
                "setup.cfg",
                "requirements.txt",
                "uv.lock",
                "poetry.lock",
            }
        )

        if _VITEST_SIGNAL_RE.search(combined_signal) or (
            has_vitest_file and not _PYTEST_SIGNAL_RE.search(combined_signal)
        ):
            selected_id = "node-vitest-linux"
            repro_cmds = ("vitest-targeted" if targeted_only else "vitest-repro",)
            reg_cmds = ("vitest-regression",)
        elif _JEST_SIGNAL_RE.search(combined_signal) or (
            (has_jest_file or (has_pkg_json and _NODE_SIGNAL_RE.search(combined_signal)))
            and not _PYTEST_SIGNAL_RE.search(combined_signal)
        ):
            selected_id = "node-jest-linux"
            repro_cmds = ("jest-targeted" if targeted_only else "jest-repro",)
            reg_cmds = ("jest-regression",)
        elif _PYTEST_SIGNAL_RE.search(combined_signal) or (
            has_python_file and not _UNSUPPORTED_ECOSYSTEM_RE.search(combined_signal)
        ):
            selected_id = "python-pytest-linux"
            repro_cmds = ("pytest-targeted" if targeted_only else "pytest-repro",)
            reg_cmds = ("pytest-regression",)
        else:
            return _abstain(
                "no_matching_certified_profile",
                "outside_v1_certified_support_matrix",
            )

    manifest, _ = reg.resolve_profile_and_commands(selected_id, repro_cmds)
    grade, diffs = grade_reproduction_fidelity(
        supported=True,
        profile_id=manifest.profile_id,
        has_pinned_lockfile=inferred_lockfile,
        targeted_only=targeted_only,
        runtime_version_mismatch=runtime_version_mismatch,
        has_opaque_ci_actions=has_opaque_ci_actions,
        has_service_approximation=has_service_approximation,
    )
    is_certified = manifest.ecosystem in ("python", "node")
    return ProfileSelectionDecision(
        supported=True,
        profile_id=manifest.profile_id,
        profile_revision=manifest.revision,
        profile_digest=manifest.manifest_digest(),
        image_digest=manifest.image_digest,
        repro_command_ids=repro_cmds,
        regression_command_ids=reg_cmds,
        requires_vm_isolation=manifest.requires_isolated_vm_tier,
        fidelity_grade=grade,
        fidelity_differences=diffs,
        reason_code="certified_profile_selected"
        if is_certified
        else "custom_declared_profile_selected",
    )


def _parse_junit_xml_counts(junit_xml_text: str) -> tuple[int, int, int] | None:
    """Safely parse `(passed, failed, skipped)` from JUnit XML (`SEC-026` XXE-safe)."""
    trimmed = junit_xml_text.strip()
    if not trimmed:
        return None
    encoded = trimmed.encode("utf-8", errors="replace")
    if len(encoded) > MAX_JUNIT_XML_BYTES:
        raise BadRequestError(
            code="junit_xml_too_large",
            detail="JUnit XML exceeds 2 MiB parser safety ceiling (SEC-026).",
        )
    if _XML_DOCTYPE_ENTITY_RE.search(trimmed):
        raise BadRequestError(
            code="unsafe_junit_xml_dtd",
            detail="JUnit XML DOCTYPE/ENTITY declarations are forbidden (SEC-026).",
        )

    suites_found: list[dict[str, str]] = []
    seen_testsuites_root = False
    suite_depth = 0

    def _forbid_dtd(*_args: Any) -> None:
        raise BadRequestError(
            code="unsafe_junit_xml_dtd",
            detail="JUnit XML DOCTYPE/ENTITY declarations are forbidden (SEC-026).",
        )

    def _start_elem(name: str, attrs: dict[str, str]) -> None:
        nonlocal seen_testsuites_root, suite_depth
        if name == "testsuites":
            seen_testsuites_root = True
        elif name == "testsuite":
            if suite_depth == 0:
                suites_found.append(dict(attrs))
            suite_depth += 1

    def _end_elem(name: str) -> None:
        nonlocal suite_depth
        if name == "testsuite" and suite_depth > 0:
            suite_depth -= 1

    parser = expat.ParserCreate("utf-8")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = _forbid_dtd
    parser.EntityDeclHandler = _forbid_dtd
    parser.StartElementHandler = _start_elem
    parser.EndElementHandler = _end_elem
    try:
        parser.Parse(encoded, True)
    except expat.ExpatError:
        return None

    if not suites_found and seen_testsuites_root:
        return (0, 0, 0)
    if not suites_found:
        return None

    total_tests = 0
    total_failed = 0
    total_skipped = 0
    for suite_attrs in suites_found:
        try:
            tests = max(0, int(suite_attrs.get("tests", "0")))
            failures = max(0, int(suite_attrs.get("failures", "0")))
            errors = max(0, int(suite_attrs.get("errors", "0")))
            skipped = max(0, int(suite_attrs.get("skipped", "0")))
        except ValueError:
            continue
        total_tests += tests
        total_failed += failures + errors
        total_skipped += skipped

    passed = max(0, total_tests - total_failed - total_skipped)
    return (passed, total_failed, total_skipped)


def parse_test_execution_output(
    *,
    stdout_text: str,
    stderr_text: str = "",
    junit_xml_text: str | None = None,
) -> ParsedTestExecution:
    """Extract executed/passed/failed/skipped test counts & install-crash signals (`SAN-02`)."""
    clean_out = strip_terminal_escapes(stdout_text)
    clean_err = strip_terminal_escapes(stderr_text)
    combined = f"{clean_out}\n{clean_err}".strip()

    zero_banner = bool(
        _PYTEST_ZERO_RE.search(combined)
        or _JEST_ZERO_RE.search(combined)
        or _VITEST_ZERO_RE.search(combined)
    )
    bootstrap_err = bool(_BOOTSTRAP_INFRA_ERROR_RE.search(combined))

    if junit_xml_text is not None:
        junit_counts = _parse_junit_xml_counts(junit_xml_text)
        if junit_counts is not None:
            passed, failed, skipped = junit_counts
            executed = passed + failed
            return ParsedTestExecution(
                executed_tests_count=executed,
                passed_tests_count=passed,
                failed_tests_count=failed,
                skipped_tests_count=skipped,
                zero_tests_banner=zero_banner or (executed == 0),
                bootstrap_or_infra_error=bootstrap_err and executed == 0,
            )

    pytest_banners = _PYTEST_BANNER_RE.findall(combined)
    for banner in reversed(pytest_banners):
        tokens = _PYTEST_COUNT_TOKEN_RE.findall(banner)
        if tokens or "no tests ran" in banner.lower():
            passed = 0
            failed = 0
            skipped = 0
            for count_str, label in tokens:
                cnt = int(count_str)
                low = label.lower()
                if low in ("passed", "xpassed"):
                    passed += cnt
                elif low in ("failed", "error", "errors"):
                    failed += cnt
                elif low in ("skipped", "xfailed"):
                    skipped += cnt
            executed = passed + failed
            return ParsedTestExecution(
                executed_tests_count=executed,
                passed_tests_count=passed,
                failed_tests_count=failed,
                skipped_tests_count=skipped,
                zero_tests_banner=zero_banner or (executed == 0),
                bootstrap_or_infra_error=bootstrap_err and executed == 0,
            )

    jest_matches = list(_JEST_TESTS_LINE_RE.finditer(combined))
    if jest_matches:
        tail = jest_matches[-1].group(1)
        tokens = _JEST_COUNT_TOKEN_RE.findall(tail)
        if tokens:
            passed = 0
            failed = 0
            skipped = 0
            for count_str, label in tokens:
                cnt = int(count_str)
                low = label.lower()
                if low == "passed":
                    passed += cnt
                elif low == "failed":
                    failed += cnt
                elif low in ("skipped", "pending", "todo"):
                    skipped += cnt
            executed = passed + failed
            return ParsedTestExecution(
                executed_tests_count=executed,
                passed_tests_count=passed,
                failed_tests_count=failed,
                skipped_tests_count=skipped,
                zero_tests_banner=zero_banner or (executed == 0),
                bootstrap_or_infra_error=bootstrap_err and executed == 0,
            )

    vitest_matches = list(_VITEST_TESTS_LINE_RE.finditer(combined))
    if vitest_matches:
        body = vitest_matches[-1].group(1)
        tokens = _VITEST_COUNT_TOKEN_RE.findall(body)
        if tokens:
            passed = 0
            failed = 0
            skipped = 0
            for count_str, label in tokens:
                cnt = int(count_str)
                low = label.lower()
                if low == "passed":
                    passed += cnt
                elif low == "failed":
                    failed += cnt
                elif low in ("skipped", "todo"):
                    skipped += cnt
            executed = passed + failed
            return ParsedTestExecution(
                executed_tests_count=executed,
                passed_tests_count=passed,
                failed_tests_count=failed,
                skipped_tests_count=skipped,
                zero_tests_banner=zero_banner or (executed == 0),
                bootstrap_or_infra_error=bootstrap_err and executed == 0,
            )

    return ParsedTestExecution(
        executed_tests_count=0,
        passed_tests_count=0,
        failed_tests_count=0,
        skipped_tests_count=0,
        zero_tests_banner=True,
        bootstrap_or_infra_error=bootstrap_err,
    )


def _matches_expected_failure(
    *,
    expected_fingerprint_hash: str | None,
    expected_test_identifier: str | None,
    expected_error_kind: str | None,
    observed: ExtractedFailureSignature | None,
) -> bool:
    if observed is None:
        return False
    if expected_fingerprint_hash is not None and hmac.compare_digest(
        observed.fingerprint_hash,
        expected_fingerprint_hash,
    ):
        return True
    if expected_test_identifier:
        if observed.test_identifier != expected_test_identifier:
            return False
        return not (
            expected_error_kind
            and observed.error_kind
            and observed.error_kind != expected_error_kind
        )
    if expected_fingerprint_hash is not None:
        return False
    if expected_error_kind:
        return observed.error_kind == expected_error_kind
    return bool(observed.test_identifier or observed.error_kind)


class ReproductionOrchestrator:
    """`Z1` A/B Sandbox Reproduction Orchestrator & non-waivable `ADR-031` gate (`U15`)."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        worker_broker: WorkerBrokerService,
        profile_registry: RunnerProfileRegistry | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._broker = worker_broker
        self._registry = profile_registry or RunnerProfileRegistry()
        self._redactor = redactor or DEFAULT_REDACTOR

    @property
    def profile_registry(self) -> RunnerProfileRegistry:
        return self._registry

    async def get_reproduction_run(
        self,
        *,
        workspace_id: str,
        reproduction_id: str,
    ) -> ReproductionRunRecord:
        async with workspace_rls_session(
            self._session_factory,
            workspace_id=workspace_id,
        ) as db:
            row = await db.scalar(
                select(ReproductionRunModel).where(
                    ReproductionRunModel.workspace_id == workspace_id,
                    ReproductionRunModel.id == reproduction_id,
                )
            )
            if row is None:
                raise NotFoundError(
                    code="reproduction_run_not_found",
                    detail="Reproduction run record not found.",
                )
            return _model_to_record(row)

    async def list_reproduction_runs_for_repair(
        self,
        *,
        workspace_id: str,
        repair_id: str,
    ) -> list[ReproductionRunRecord]:
        async with workspace_rls_session(
            self._session_factory,
            workspace_id=workspace_id,
        ) as db:
            rows = (
                await db.scalars(
                    select(ReproductionRunModel)
                    .where(
                        ReproductionRunModel.workspace_id == workspace_id,
                        ReproductionRunModel.repair_id == repair_id,
                    )
                    .order_by(ReproductionRunModel.created_at.asc(), ReproductionRunModel.id.asc())
                )
            ).all()
            return [_model_to_record(r) for r in rows]

    async def record_unsupported_reproduction(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        ci_run_id: str,
        ci_job_id: str,
        base_sha: str,
        selection: ProfileSelectionDecision,
        correlation_id: str,
        source_archive_digest: str | None = None,
        now: datetime | None = None,
    ) -> ReproductionRunRecord:
        """Record an explicit `FX_UNSUPPORTED` abstention (`0` sandbox jobs, `ADR-018`)."""
        if selection.supported or selection.fidelity_grade != "FX_UNSUPPORTED":
            raise BadRequestError(
                code="selection_not_unsupported",
                detail="record_unsupported_reproduction requires an FX_UNSUPPORTED selection.",
            )
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        repro_id = new_uuid7(now=ref_now)
        detail_txt = "; ".join(selection.fidelity_differences)[:1000] or None

        async with workspace_rls_session(
            self._session_factory,
            workspace_id=workspace_id,
        ) as db:
            row = ReproductionRunModel(
                id=repro_id,
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                ci_run_id=ci_run_id,
                ci_job_id=ci_job_id,
                phase="baseline_a",
                baseline_reproduction_id=None,
                sandbox_job_id=None,
                sandbox_lease_id=None,
                profile_revision_id=None,
                profile_id=UNSUPPORTED_PROFILE_PLACEHOLDER,
                profile_revision=1,
                profile_digest=None,
                image_digest=None,
                base_sha=base_sha,
                source_archive_digest=source_archive_digest,
                dependency_lock_digest=None,
                cache_key=None,
                patch_digest=None,
                command_ids_json=[],
                command_digest=None,
                environment_digest=None,
                expected_fingerprint_hash=None,
                observed_fingerprint_hash=None,
                fingerprint_matched=False,
                executed_tests_count=0,
                passed_tests_count=0,
                failed_tests_count=0,
                skipped_tests_count=0,
                exit_code=None,
                termination=None,
                status="unsupported",
                fidelity_grade="FX_UNSUPPORTED",
                fidelity_differences_json=list(selection.fidelity_differences),
                handoff_outcome="unsupported_abstain",
                allow_patching=False,
                allow_publication=False,
                failure_reason_code=selection.reason_code,
                failure_detail=detail_txt,
                result_digest=None,
                artifact_refs_json=[],
                immutable_sealed=True,
                started_at=ref_now,
                finished_at=ref_now,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(row)
            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=ref_now),
                    type="repair.reproduction.completed",
                    occurred_at=ref_now,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    session_id=repair_id,
                    aggregate_id=repair_id,
                    aggregate_version=1,
                    correlation_id=correlation_id,
                    payload=ReproVerificationEventPayload(
                        repair_id=repair_id,
                        outcome="unsupported",
                    ),
                ),
                now=ref_now,
            )
            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=ref_now),
                    type="repair.blocked",
                    occurred_at=ref_now,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    session_id=repair_id,
                    aggregate_id=repair_id,
                    aggregate_version=1,
                    correlation_id=correlation_id,
                    payload=RepairPhaseEventPayload(
                        repair_id=repair_id,
                        state="unsupported_abstain",
                        reason_code=selection.reason_code,
                    ),
                ),
                now=ref_now,
            )
            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                actor_type="system",
                actor_id="reproduction_orchestrator",
                action="repair.reproduction.abstain",
                target=repro_id,
                decision="deny",
                reason_code=selection.reason_code,
                correlation_id=correlation_id,
                metadata={
                    "repair_id": repair_id,
                    "fidelity_grade": "FX_UNSUPPORTED",
                    "fidelity_differences": list(selection.fidelity_differences),
                },
                occurred_at=ref_now,
            )
            await db.flush()
            return _model_to_record(row)

    async def start_baseline_sandbox_a(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        ci_run_id: str,
        ci_job_id: str,
        base_sha: str,
        source_archive_bytes: bytes,
        selection: ProfileSelectionDecision,
        correlation_id: str,
        dependency_lock_digest: str | None = None,
        expected_fingerprint_hash: str | None = None,
        resource_limits: SandboxResourceLimits | None = None,
        now: datetime | None = None,
    ) -> ReproductionRunRecord:
        """Dispatch **Sandbox A** (`baseline_a`) on exact `base_sha` (`SAN-02`, `W-04`)."""
        if not selection.supported or selection.profile_id is None:
            raise ConflictError(
                code="unsupported_profile_cannot_execute",
                detail=(
                    "Unsupported runner selection (FX_UNSUPPORTED) must abstain via "
                    "record_unsupported_reproduction instead of dispatching a sandbox lease."
                ),
            )

        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        synced_ids = await self._registry.sync_profiles_to_db(self._session_factory, now=ref_now)
        manifest, _ = self._registry.resolve_profile_and_commands(
            selection.profile_id,
            selection.repro_command_ids,
            profile_revision=selection.profile_revision,
        )
        manifest_digest = manifest.manifest_digest()
        profile_rev_id = synced_ids.get(manifest.profile_id)
        source_digest = self._broker.register_source_archive(source_archive_bytes)
        cache_key = (
            f"{workspace_id}:{manifest.profile_id}:{dependency_lock_digest}"
            if dependency_lock_digest is not None
            else None
        )

        resolved_expected_fp = expected_fingerprint_hash
        async with workspace_rls_session(
            self._session_factory,
            workspace_id=workspace_id,
        ) as db:
            run_row = await db.scalar(
                select(CiRunModel).where(
                    CiRunModel.workspace_id == workspace_id,
                    CiRunModel.id == ci_run_id,
                )
            )
            if run_row is None:
                raise NotFoundError(
                    code="ci_run_not_found",
                    detail="Referenced CI run was not found in workspace.",
                )
            if run_row.head_sha.lower() != base_sha.lower():
                raise ConflictError(
                    code="base_sha_mismatch_ci_run",
                    detail=(
                        f"Sandbox A base_sha ({base_sha}) does not match CI run head_sha "
                        f"({run_row.head_sha}) (SEC-017)."
                    ),
                )
            job_row = await db.scalar(
                select(CiJobModel).where(
                    CiJobModel.workspace_id == workspace_id,
                    CiJobModel.id == ci_job_id,
                )
            )
            if job_row is None:
                raise NotFoundError(
                    code="ci_job_not_found",
                    detail="Referenced CI job was not found in workspace.",
                )
            if resolved_expected_fp is None:
                resolved_expected_fp = job_row.failure_fingerprint_hash

        sandbox_job_id = await self._broker.enqueue_sandbox_job(
            workspace_id=workspace_id,
            repository_id=repository_id,
            repair_id=repair_id,
            profile_id=manifest.profile_id,
            profile_revision=manifest.revision,
            image_digest=manifest.image_digest,
            base_sha=base_sha,
            source_archive_digest=source_digest,
            dependency_lock_digest=dependency_lock_digest,
            patch_digest=None,
            patch_diff_text=None,
            command_ids=selection.repro_command_ids,
            resource_limits=resource_limits,
            allowed_output_slots=("stdout", "stderr", "junit_xml"),
            requires_vm_isolation=selection.requires_vm_isolation,
            correlation_id=correlation_id,
            dedup_key=f"repro:a:{repair_id}:{ci_job_id}:{base_sha[:12]}",
            now=ref_now,
        )

        repro_id = new_uuid7(now=ref_now)
        async with workspace_rls_session(
            self._session_factory,
            workspace_id=workspace_id,
        ) as db:
            row = ReproductionRunModel(
                id=repro_id,
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                ci_run_id=ci_run_id,
                ci_job_id=ci_job_id,
                phase="baseline_a",
                baseline_reproduction_id=None,
                sandbox_job_id=sandbox_job_id,
                sandbox_lease_id=None,
                profile_revision_id=profile_rev_id,
                profile_id=manifest.profile_id,
                profile_revision=manifest.revision,
                profile_digest=manifest_digest,
                image_digest=manifest.image_digest,
                base_sha=base_sha,
                source_archive_digest=source_digest,
                dependency_lock_digest=dependency_lock_digest,
                cache_key=cache_key,
                patch_digest=None,
                command_ids_json=list(selection.repro_command_ids),
                command_digest=None,
                environment_digest=None,
                expected_fingerprint_hash=resolved_expected_fp,
                observed_fingerprint_hash=None,
                fingerprint_matched=False,
                executed_tests_count=0,
                passed_tests_count=0,
                failed_tests_count=0,
                skipped_tests_count=0,
                exit_code=None,
                termination=None,
                status="running",
                fidelity_grade=selection.fidelity_grade,
                fidelity_differences_json=list(selection.fidelity_differences),
                handoff_outcome="pending",
                allow_patching=False,
                allow_publication=False,
                failure_reason_code=None,
                failure_detail=None,
                result_digest=None,
                artifact_refs_json=[],
                immutable_sealed=False,
                started_at=ref_now,
                finished_at=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(row)
            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                actor_type="system",
                actor_id="reproduction_orchestrator",
                action="repair.reproduction.baseline_started",
                target=repro_id,
                decision="allow",
                reason_code="sandbox_a_dispatched",
                correlation_id=correlation_id,
                metadata={
                    "repair_id": repair_id,
                    "sandbox_job_id": sandbox_job_id,
                    "profile_id": manifest.profile_id,
                    "base_sha": base_sha,
                    "fidelity_grade": selection.fidelity_grade,
                },
                occurred_at=ref_now,
            )
            await db.flush()
            return _model_to_record(row)

    async def _load_sandbox_outputs_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        sandbox_job_id: str,
        now: datetime,
    ) -> tuple[SandboxLeaseModel, ResultV1, str, str, str | None]:
        lease_row = await db.scalar(
            select(SandboxLeaseModel)
            .where(
                SandboxLeaseModel.workspace_id == workspace_id,
                SandboxLeaseModel.job_id == sandbox_job_id,
            )
            .order_by(SandboxLeaseModel.lease_epoch.desc())
            .limit(1)
        )
        if lease_row is None or lease_row.result_json is None:
            raise ConflictError(
                code="sandbox_result_not_ready",
                detail=f"Sandbox job {sandbox_job_id} has not submitted a verified ResultV1 yet.",
            )
        result = ResultV1.model_validate(lease_row.result_json)

        slot_to_artifact_id: dict[str, str] = {}
        for item in lease_row.uploaded_artifacts_json or []:
            slot = str(item.get("slot_name") or "")
            art_id = str(item.get("id") or "")
            if slot and art_id:
                slot_to_artifact_id[slot] = art_id

        async def _read_slot_text(slot_name: str) -> str | None:
            art_id = slot_to_artifact_id.get(slot_name)
            if not art_id:
                return None
            art_row = await db.scalar(
                select(ArtifactModel).where(
                    ArtifactModel.workspace_id == workspace_id,
                    ArtifactModel.id == art_id,
                )
            )
            if art_row is None:
                return None
            raw = await read_artifact_for_authorized_caller(
                db,
                store=self._broker.artifact_store,
                artifact_row=art_row,
                now=now,
            )
            return raw.decode("utf-8", errors="replace")

        stdout_txt = await _read_slot_text("stdout")
        stderr_txt = await _read_slot_text("stderr")
        junit_txt = await _read_slot_text("junit_xml")
        return lease_row, result, stdout_txt or "", stderr_txt or "", junit_txt

    async def finalize_baseline_sandbox_a(
        self,
        *,
        workspace_id: str,
        reproduction_id: str,
        correlation_id: str,
        now: datetime | None = None,
    ) -> ReproductionRunRecord:
        """Evaluate **Sandbox A** result and seal `repro_confirmed` or `repro_unconfirmed`."""
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        async with workspace_rls_session(
            self._session_factory,
            workspace_id=workspace_id,
        ) as db:
            row = await db.scalar(
                select(ReproductionRunModel)
                .where(
                    ReproductionRunModel.workspace_id == workspace_id,
                    ReproductionRunModel.id == reproduction_id,
                )
                .with_for_update()
            )
            if row is None:
                raise NotFoundError(
                    code="reproduction_run_not_found",
                    detail="Baseline reproduction run not found.",
                )
            if row.phase != "baseline_a":
                raise BadRequestError(
                    code="invalid_reproduction_phase",
                    detail="finalize_baseline_sandbox_a only applies to baseline_a runs.",
                )
            if row.immutable_sealed:
                return _model_to_record(row)
            if row.sandbox_job_id is None or row.source_archive_digest is None:
                raise ConflictError(
                    code="baseline_missing_sandbox_job",
                    detail="Baseline reproduction run has no associated sandbox_job_id.",
                )

            (
                lease_row,
                result,
                stdout_txt,
                stderr_txt,
                junit_txt,
            ) = await self._load_sandbox_outputs_in_tx(
                db,
                workspace_id=workspace_id,
                sandbox_job_id=row.sandbox_job_id,
                now=ref_now,
            )

            if (
                row.image_digest is None
                or not hmac.compare_digest(result.image_digest, row.image_digest)
                or not hmac.compare_digest(result.source_digest, row.source_archive_digest)
                or result.patch_digest is not None
            ):
                raise ConflictError(
                    code="baseline_digest_parity_violation",
                    detail=(
                        "Sandbox A ResultV1 image/source/patch digest violated baseline spec "
                        "(SEC-030)."
                    ),
                )

            job_name = row.profile_id
            expected_test_id: str | None = None
            expected_err_kind: str | None = None
            ci_job = await db.scalar(
                select(CiJobModel).where(
                    CiJobModel.workspace_id == workspace_id,
                    CiJobModel.id == row.ci_job_id,
                )
            )
            if ci_job is not None:
                job_name = ci_job.name
                if ci_job.failure_fingerprint_id is not None:
                    fp_row = await db.scalar(
                        select(FailureFingerprintModel).where(
                            FailureFingerprintModel.workspace_id == workspace_id,
                            FailureFingerprintModel.id == ci_job.failure_fingerprint_id,
                        )
                    )
                    if fp_row is not None:
                        expected_test_id = fp_row.test_identifier
                        expected_err_kind = fp_row.error_kind

            parsed = parse_test_execution_output(
                stdout_text=stdout_txt,
                stderr_text=stderr_txt,
                junit_xml_text=junit_txt,
            )
            combined_log = f"{stdout_txt}\n{stderr_txt}".strip()
            observed_sig = (
                extract_failure_signature(
                    combined_log,
                    job_name=job_name,
                    redactor=self._redactor,
                )
                if result.exit_code != 0 or parsed.failed_tests_count > 0
                else None
            )

            all_iso_ok = lease_row.cleanup_verified and all(
                chk.passed for chk in result.isolation_checks
            )
            fp_matched = _matches_expected_failure(
                expected_fingerprint_hash=row.expected_fingerprint_hash,
                expected_test_identifier=expected_test_id,
                expected_error_kind=expected_err_kind,
                observed=observed_sig,
            )

            new_status: ReproductionStatus
            reason_code: str
            handoff: ReproductionHandoffOutcome
            allow_patching = False

            if not all_iso_ok:
                new_status = "repro_unconfirmed"
                reason_code = "sandbox_isolation_or_cleanup_failed"
                handoff = "diagnosis_and_human_handoff"
            elif result.termination == "timeout":
                new_status = "repro_unconfirmed"
                reason_code = "baseline_timeout"
                handoff = "diagnosis_and_human_handoff"
            elif result.termination != "exited":
                new_status = "repro_unconfirmed"
                reason_code = f"baseline_terminated_{result.termination}"
                handoff = "diagnosis_and_human_handoff"
            elif parsed.bootstrap_or_infra_error and parsed.executed_tests_count == 0:
                new_status = "repro_unconfirmed"
                reason_code = "baseline_bootstrap_or_install_error"
                handoff = "diagnosis_and_human_handoff"
            elif parsed.executed_tests_count <= 0 or parsed.zero_tests_banner:
                new_status = "repro_unconfirmed"
                reason_code = "zero_tests_executed"
                handoff = "diagnosis_and_human_handoff"
            elif result.exit_code == 0 or parsed.failed_tests_count <= 0:
                new_status = "repro_unconfirmed"
                reason_code = "baseline_passed_unexpectedly"
                handoff = "diagnosis_and_human_handoff"
            elif not fp_matched:
                new_status = "repro_unconfirmed"
                reason_code = "unrelated_failure_fingerprint"
                handoff = "diagnosis_and_human_handoff"
            elif row.fidelity_grade == "FX_UNSUPPORTED":
                new_status = "unsupported"
                reason_code = "unsupported_fidelity_grade"
                handoff = "unsupported_abstain"
            else:
                new_status = "repro_confirmed"
                reason_code = "baseline_failure_reproduced"
                handoff = "proceed_to_patch"
                allow_patching = True

            detail_excerpt = (
                observed_sig.failure_excerpt[:1000]
                if observed_sig is not None
                else (self._redactor.redact_text(combined_log)[:1000] if combined_log else None)
            )

            row.sandbox_lease_id = lease_row.id
            row.command_digest = result.command_digest
            row.environment_digest = result.environment_digest
            row.observed_fingerprint_hash = (
                observed_sig.fingerprint_hash if observed_sig is not None else None
            )
            row.fingerprint_matched = fp_matched and new_status == "repro_confirmed"
            row.executed_tests_count = parsed.executed_tests_count
            row.passed_tests_count = parsed.passed_tests_count
            row.failed_tests_count = parsed.failed_tests_count
            row.skipped_tests_count = parsed.skipped_tests_count
            row.exit_code = result.exit_code
            row.termination = result.termination
            row.status = new_status
            row.handoff_outcome = handoff
            row.allow_patching = allow_patching
            row.allow_publication = False
            row.failure_reason_code = None if new_status == "repro_confirmed" else reason_code
            row.failure_detail = detail_excerpt
            row.result_digest = lease_row.result_digest
            row.artifact_refs_json = [ref.model_dump(mode="json") for ref in result.artifact_refs]
            row.immutable_sealed = True
            row.finished_at = ref_now
            row.version += 1
            row.updated_at = ref_now

            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=ref_now),
                    type="repair.reproduction.completed",
                    occurred_at=ref_now,
                    workspace_id=workspace_id,
                    repository_id=row.repository_id,
                    session_id=row.repair_id,
                    aggregate_id=row.repair_id,
                    aggregate_version=row.version,
                    correlation_id=correlation_id,
                    payload=ReproVerificationEventPayload(
                        repair_id=row.repair_id,
                        outcome=new_status,
                    ),
                ),
                now=ref_now,
            )

            if new_status != "repro_confirmed":
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="repair.diagnosed",
                        occurred_at=ref_now,
                        workspace_id=workspace_id,
                        repository_id=row.repository_id,
                        session_id=row.repair_id,
                        aggregate_id=row.repair_id,
                        aggregate_version=row.version,
                        correlation_id=correlation_id,
                        payload=RepairPhaseEventPayload(
                            repair_id=row.repair_id,
                            state=handoff,
                            reason_code=reason_code,
                        ),
                    ),
                    now=ref_now,
                )
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="repair.blocked",
                        occurred_at=ref_now,
                        workspace_id=workspace_id,
                        repository_id=row.repository_id,
                        session_id=row.repair_id,
                        aggregate_id=row.repair_id,
                        aggregate_version=row.version,
                        correlation_id=correlation_id,
                        payload=RepairPhaseEventPayload(
                            repair_id=row.repair_id,
                            state="adr031_stop_on_unconfirmed_baseline",
                            reason_code=reason_code,
                        ),
                    ),
                    now=ref_now,
                )

            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                actor_type="system",
                actor_id="reproduction_orchestrator",
                action="repair.reproduction.baseline_finalized",
                target=row.id,
                decision="allow" if new_status == "repro_confirmed" else "deny",
                reason_code=reason_code,
                correlation_id=correlation_id,
                metadata={
                    "repair_id": row.repair_id,
                    "status": new_status,
                    "handoff_outcome": handoff,
                    "executed_tests_count": parsed.executed_tests_count,
                    "failed_tests_count": parsed.failed_tests_count,
                    "allow_patching": allow_patching,
                },
                occurred_at=ref_now,
            )
            await db.flush()
            return _model_to_record(row)

    async def enforce_adr031_baseline_gate(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        correlation_id: str,
        baseline_reproduction_id: str | None = None,
        attempted_stage: str = "patch_generation",
        now: datetime | None = None,
    ) -> ReproductionRunRecord:
        """Non-waivable `ADR-031` gate before patch generation, Sandbox B, or PR publication.

        Never allows waiving `require_baseline`: any missing, `running`, `repro_unconfirmed`,
        or `unsupported` baseline raises `409 adr031_unconfirmed_baseline` and logs a denial.
        """
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        async with workspace_rls_session(
            self._session_factory,
            workspace_id=workspace_id,
        ) as db:
            stmt = select(ReproductionRunModel).where(
                ReproductionRunModel.workspace_id == workspace_id,
                ReproductionRunModel.repair_id == repair_id,
                ReproductionRunModel.phase == "baseline_a",
            )
            if baseline_reproduction_id is not None:
                stmt = stmt.where(ReproductionRunModel.id == baseline_reproduction_id)
            else:
                stmt = stmt.order_by(
                    ReproductionRunModel.created_at.desc(),
                    ReproductionRunModel.id.desc(),
                ).limit(1)
            row = await db.scalar(stmt)

            is_confirmed = (
                row is not None
                and row.immutable_sealed
                and row.status == "repro_confirmed"
                and row.allow_patching
                and row.fingerprint_matched
                and row.fidelity_grade != "FX_UNSUPPORTED"
                and row.executed_tests_count > 0
                and row.failed_tests_count > 0
            )
            if not is_confirmed:
                denial_reason = (
                    "missing_baseline_reproduction"
                    if row is None
                    else f"baseline_{row.status}_{row.failure_reason_code or 'unsealed'}"[:120]
                )
                await append_audit_entry(
                    db,
                    workspace_id=workspace_id,
                    actor_type="system",
                    actor_id="reproduction_orchestrator",
                    action="repair.adr031.gate",
                    target=row.id if row is not None else repair_id,
                    decision="deny",
                    reason_code="adr031_unconfirmed_baseline",
                    correlation_id=correlation_id,
                    metadata={
                        "repair_id": repair_id,
                        "attempted_stage": attempted_stage,
                        "baseline_status": row.status if row is not None else None,
                        "baseline_reason_code": denial_reason,
                    },
                    occurred_at=ref_now,
                )
                if row is not None:
                    await enqueue_outbox_event(
                        db,
                        EventEnvelope(
                            event_id=new_uuid7(now=ref_now),
                            type="repair.blocked",
                            occurred_at=ref_now,
                            workspace_id=workspace_id,
                            repository_id=row.repository_id,
                            session_id=repair_id,
                            aggregate_id=repair_id,
                            aggregate_version=1,
                            correlation_id=correlation_id,
                            payload=RepairPhaseEventPayload(
                                repair_id=repair_id,
                                state=f"blocked_{attempted_stage}"[:120],
                                reason_code="adr031_unconfirmed_baseline",
                            ),
                        ),
                        now=ref_now,
                    )
                await db.flush()
                raise ConflictError(
                    code="adr031_unconfirmed_baseline",
                    detail=(
                        f"ADR-031 violation: cannot proceed to {attempted_stage!r} without a "
                        f"sealed repro_confirmed Sandbox A baseline ({denial_reason})."
                    ),
                )
            assert row is not None
            return _model_to_record(row)

    async def start_patched_sandbox_b(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        baseline_reproduction_id: str,
        patch_diff_text: str,
        correlation_id: str,
        additional_command_ids: Sequence[str] = (),
        resource_limits: SandboxResourceLimits | None = None,
        now: datetime | None = None,
    ) -> ReproductionRunRecord:
        """Dispatch **Sandbox B** (`patched_b`) in a brand-new worktree matching Sandbox A."""
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        baseline = await self.enforce_adr031_baseline_gate(
            workspace_id=workspace_id,
            repair_id=repair_id,
            baseline_reproduction_id=baseline_reproduction_id,
            attempted_stage="patched_sandbox_b",
            correlation_id=correlation_id,
            now=ref_now,
        )
        if baseline.image_digest is None or baseline.source_archive_digest is None:
            raise ConflictError(
                code="adr031_unconfirmed_baseline",
                detail="Confirmed baseline is missing image_digest or source_archive_digest.",
            )

        if not patch_diff_text.strip() or "\x00" in patch_diff_text:
            raise BadRequestError(
                code="invalid_patch_diff",
                detail="Candidate unified diff must be non-empty UTF-8 text without NUL bytes.",
            )
        patch_digest = hashlib.sha256(patch_diff_text.encode("utf-8")).hexdigest()

        combined_commands = list(
            dict.fromkeys([*baseline.command_ids, *list(additional_command_ids)])
        )
        manifest, _ = self._registry.resolve_profile_and_commands(
            baseline.profile_id,
            combined_commands,
            profile_revision=baseline.profile_revision,
        )
        synced_ids = await self._registry.sync_profiles_to_db(self._session_factory, now=ref_now)
        profile_rev_id = synced_ids.get(manifest.profile_id)

        sandbox_b_job_id = await self._broker.enqueue_sandbox_job(
            workspace_id=workspace_id,
            repository_id=baseline.repository_id,
            repair_id=repair_id,
            profile_id=baseline.profile_id,
            profile_revision=baseline.profile_revision,
            image_digest=baseline.image_digest,
            base_sha=baseline.base_sha,
            source_archive_digest=baseline.source_archive_digest,
            dependency_lock_digest=baseline.dependency_lock_digest,
            patch_digest=patch_digest,
            patch_diff_text=patch_diff_text,
            command_ids=combined_commands,
            resource_limits=resource_limits,
            allowed_output_slots=("stdout", "stderr", "junit_xml"),
            requires_vm_isolation=manifest.requires_isolated_vm_tier,
            correlation_id=correlation_id,
            dedup_key=f"repro:b:{repair_id}:{baseline.id}:{patch_digest[:16]}",
            now=ref_now,
        )
        if sandbox_b_job_id == baseline.sandbox_job_id:
            raise ConflictError(
                code="sandbox_b_reused_baseline_job",
                detail="Sandbox B must execute in a brand-new sandbox job/lease (SAN-02).",
            )

        repro_b_id = new_uuid7(now=ref_now)
        async with workspace_rls_session(
            self._session_factory,
            workspace_id=workspace_id,
        ) as db:
            row = ReproductionRunModel(
                id=repro_b_id,
                workspace_id=workspace_id,
                repository_id=baseline.repository_id,
                repair_id=repair_id,
                ci_run_id=baseline.ci_run_id,
                ci_job_id=baseline.ci_job_id,
                phase="patched_b",
                baseline_reproduction_id=baseline.id,
                sandbox_job_id=sandbox_b_job_id,
                sandbox_lease_id=None,
                profile_revision_id=profile_rev_id,
                profile_id=baseline.profile_id,
                profile_revision=baseline.profile_revision,
                profile_digest=baseline.profile_digest,
                image_digest=baseline.image_digest,
                base_sha=baseline.base_sha,
                source_archive_digest=baseline.source_archive_digest,
                dependency_lock_digest=baseline.dependency_lock_digest,
                cache_key=baseline.cache_key,
                patch_digest=patch_digest,
                command_ids_json=combined_commands,
                command_digest=None,
                environment_digest=None,
                expected_fingerprint_hash=baseline.expected_fingerprint_hash,
                observed_fingerprint_hash=None,
                fingerprint_matched=False,
                executed_tests_count=0,
                passed_tests_count=0,
                failed_tests_count=0,
                skipped_tests_count=0,
                exit_code=None,
                termination=None,
                status="running",
                fidelity_grade=baseline.fidelity_grade,
                fidelity_differences_json=list(baseline.fidelity_differences),
                handoff_outcome="pending",
                allow_patching=False,
                allow_publication=False,
                failure_reason_code=None,
                failure_detail=None,
                result_digest=None,
                artifact_refs_json=[],
                immutable_sealed=False,
                started_at=ref_now,
                finished_at=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(row)
            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                actor_type="system",
                actor_id="reproduction_orchestrator",
                action="repair.reproduction.patched_started",
                target=repro_b_id,
                decision="allow",
                reason_code="sandbox_b_dispatched",
                correlation_id=correlation_id,
                metadata={
                    "repair_id": repair_id,
                    "baseline_reproduction_id": baseline.id,
                    "sandbox_job_id": sandbox_b_job_id,
                    "patch_digest": patch_digest,
                },
                occurred_at=ref_now,
            )
            await db.flush()
            return _model_to_record(row)

    async def finalize_patched_sandbox_b(
        self,
        *,
        workspace_id: str,
        reproduction_id: str,
        correlation_id: str,
        now: datetime | None = None,
    ) -> ReproductionRunRecord:
        """Verify **Sandbox B** red->green transition, digest parity & test-count safety."""
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        async with workspace_rls_session(
            self._session_factory,
            workspace_id=workspace_id,
        ) as db:
            row = await db.scalar(
                select(ReproductionRunModel)
                .where(
                    ReproductionRunModel.workspace_id == workspace_id,
                    ReproductionRunModel.id == reproduction_id,
                )
                .with_for_update()
            )
            if row is None:
                raise NotFoundError(
                    code="reproduction_run_not_found",
                    detail="Patched reproduction run not found.",
                )
            if row.phase != "patched_b" or row.baseline_reproduction_id is None:
                raise BadRequestError(
                    code="invalid_reproduction_phase",
                    detail="finalize_patched_sandbox_b only applies to patched_b runs.",
                )
            if row.immutable_sealed:
                return _model_to_record(row)
            if (
                row.sandbox_job_id is None
                or row.patch_digest is None
                or row.source_archive_digest is None
            ):
                raise ConflictError(
                    code="patched_run_missing_job_or_patch",
                    detail="Patched reproduction run is missing sandbox_job_id or patch_digest.",
                )

            baseline_row = await db.scalar(
                select(ReproductionRunModel).where(
                    ReproductionRunModel.workspace_id == workspace_id,
                    ReproductionRunModel.id == row.baseline_reproduction_id,
                )
            )
            if baseline_row is None or baseline_row.status != "repro_confirmed":
                raise ConflictError(
                    code="adr031_unconfirmed_baseline",
                    detail="Parent baseline reproduction is missing or not repro_confirmed.",
                )

            (
                lease_row,
                result,
                stdout_txt,
                stderr_txt,
                junit_txt,
            ) = await self._load_sandbox_outputs_in_tx(
                db,
                workspace_id=workspace_id,
                sandbox_job_id=row.sandbox_job_id,
                now=ref_now,
            )

            same_command_list = list(row.command_ids_json) == list(baseline_row.command_ids_json)
            parity_ok = (
                row.image_digest is not None
                and hmac.compare_digest(result.image_digest, row.image_digest)
                and hmac.compare_digest(result.source_digest, row.source_archive_digest)
                and result.patch_digest is not None
                and hmac.compare_digest(result.patch_digest, row.patch_digest)
                and hmac.compare_digest(
                    result.environment_digest,
                    baseline_row.environment_digest or "",
                )
                and (
                    not same_command_list
                    or hmac.compare_digest(
                        result.command_digest,
                        baseline_row.command_digest or "",
                    )
                )
            )
            if not parity_ok:
                raise ConflictError(
                    code="patched_digest_parity_violation",
                    detail=(
                        "Sandbox B ResultV1 image/source/patch/environment/command digest "
                        "violated Sandbox A parity (SEC-030)."
                    ),
                )

            parsed = parse_test_execution_output(
                stdout_text=stdout_txt,
                stderr_text=stderr_txt,
                junit_xml_text=junit_txt,
            )
            combined_log = f"{stdout_txt}\n{stderr_txt}".strip()
            observed_sig = (
                extract_failure_signature(
                    combined_log,
                    job_name=row.profile_id,
                    redactor=self._redactor,
                )
                if result.exit_code != 0 or parsed.failed_tests_count > 0
                else None
            )

            baseline_executed = baseline_row.passed_tests_count + baseline_row.failed_tests_count
            clean_exec = lease_row.cleanup_verified and result.passed_cleanly()

            new_status: ReproductionStatus
            reason_code: str
            handoff: ReproductionHandoffOutcome
            allow_pub = False

            if not clean_exec:
                new_status = "patched_failed"
                reason_code = (
                    "patched_timeout"
                    if result.termination == "timeout"
                    else "patched_execution_failed"
                )
                handoff = "patch_still_failing"
            elif parsed.bootstrap_or_infra_error:
                new_status = "patched_failed"
                reason_code = "patched_bootstrap_or_install_error"
                handoff = "patch_still_failing"
            elif parsed.executed_tests_count <= 0 or parsed.zero_tests_banner:
                new_status = "patched_failed"
                reason_code = "zero_tests_executed_in_sandbox_b"
                handoff = "patch_still_failing"
            elif parsed.failed_tests_count > 0:
                new_status = "patched_failed"
                reason_code = "patched_tests_still_failing"
                handoff = "patch_still_failing"
            elif (
                parsed.executed_tests_count < baseline_executed
                or parsed.skipped_tests_count > baseline_row.skipped_tests_count
            ):
                new_status = "patched_failed"
                reason_code = "test_count_or_skip_regression"
                handoff = "patch_still_failing"
            else:
                new_status = "patched_passed"
                reason_code = "verified_red_to_green"
                handoff = "verified_red_to_green"
                allow_pub = row.fidelity_grade != "FX_UNSUPPORTED"

            row.sandbox_lease_id = lease_row.id
            row.command_digest = result.command_digest
            row.environment_digest = result.environment_digest
            row.observed_fingerprint_hash = (
                observed_sig.fingerprint_hash if observed_sig is not None else None
            )
            row.fingerprint_matched = False
            row.executed_tests_count = parsed.executed_tests_count
            row.passed_tests_count = parsed.passed_tests_count
            row.failed_tests_count = parsed.failed_tests_count
            row.skipped_tests_count = parsed.skipped_tests_count
            row.exit_code = result.exit_code
            row.termination = result.termination
            row.status = new_status
            row.handoff_outcome = handoff
            row.allow_patching = False
            row.allow_publication = allow_pub
            row.failure_reason_code = None if new_status == "patched_passed" else reason_code
            row.failure_detail = (
                observed_sig.failure_excerpt[:1000] if observed_sig is not None else None
            )
            row.result_digest = lease_row.result_digest
            row.artifact_refs_json = [ref.model_dump(mode="json") for ref in result.artifact_refs]
            row.immutable_sealed = True
            row.finished_at = ref_now
            row.version += 1
            row.updated_at = ref_now

            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=ref_now),
                    type="repair.verification.completed",
                    occurred_at=ref_now,
                    workspace_id=workspace_id,
                    repository_id=row.repository_id,
                    session_id=row.repair_id,
                    aggregate_id=row.repair_id,
                    aggregate_version=row.version,
                    correlation_id=correlation_id,
                    payload=ReproVerificationEventPayload(
                        repair_id=row.repair_id,
                        outcome=new_status,
                    ),
                ),
                now=ref_now,
            )
            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                actor_type="system",
                actor_id="reproduction_orchestrator",
                action="repair.reproduction.patched_finalized",
                target=row.id,
                decision="allow" if new_status == "patched_passed" else "deny",
                reason_code=reason_code,
                correlation_id=correlation_id,
                metadata={
                    "repair_id": row.repair_id,
                    "baseline_reproduction_id": row.baseline_reproduction_id,
                    "status": new_status,
                    "executed_tests_count": parsed.executed_tests_count,
                    "skipped_tests_count": parsed.skipped_tests_count,
                    "allow_publication": allow_pub,
                },
                occurred_at=ref_now,
            )
            await db.flush()
            return _model_to_record(row)


__all__ = [
    "MAX_JUNIT_XML_BYTES",
    "UNSUPPORTED_PROFILE_PLACEHOLDER",
    "ParsedTestExecution",
    "ProfileSelectionDecision",
    "ReproductionOrchestrator",
    "RunnerProfileRegistry",
    "grade_reproduction_fidelity",
    "parse_test_execution_output",
    "select_profile_for_ci_job",
]
