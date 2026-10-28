"""Deterministic repository policy precedence engine & zero-mutation dry-run simulator (`U12`).

Implements `REP-02`, `REP-03`, `A-07`, `S-09`, `W-02`, `W-04`, `W-05`, `W-06`,
`ADR-015`, `ADR-031`, `ADR-033`, `SEC-007`, `SEC-009`, and `SEC-031`:
- Strict 4-layer precedence: `hard_invariant > instance > workspace > repository`.
- Non-overridable safety invariants: `require_baseline = True` (`ADR-031`), `auto_merge = False`
  (`ADR-010`), `deny` always overrides `allow`, `paused` overrides all execution modes, and
  `monitor` mode never permits sandbox execution or publication (`ADR-033`).
- `SEC-009` protected CI/workflow/lockfile/auth/deploy/migration globs and gated test/config
  edit toggles (`AGENTS.md` Principle 3) always escalate to mandatory human approval even when
  `mode == 'auto_repair'`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any, cast

from py_contracts.integrations import (
    AffectedInFlightItem,
    BranchPolicyEvaluation,
    CiConclusion,
    EffectiveRepositoryPolicy,
    HistoricalRunSimulation,
    PathPolicyEvaluation,
    PolicyDenialItem,
    PolicyEvaluationVerdict,
    PolicyReadinessGates,
    PolicyRuleChange,
    PolicyScopeLayer,
    RepositoryMode,
    RepositoryPolicy,
    RepositoryPolicyPreviewResponse,
    RunEligibilityDisposition,
)
from py_contracts.primitives import Money
from red2pr_control.core.config import Red2PrConfig, load_config
from red2pr_control.repositories.glob_guard import (
    HARD_DENIED_PATH_GLOBS,
    PROTECTED_SENSITIVE_PATH_GLOBS,
    PathCanonicalizationError,
    canonicalize_branch_ref,
    canonicalize_glob_pattern,
    canonicalize_repo_path,
    classify_builtin_repo_path,
    first_matching_glob,
)


@dataclass(frozen=True, slots=True)
class WorkspacePolicyLayer:
    """Optional workspace-scoped policy overrides stored on the workspace settings envelope."""

    paused: bool = False
    branch_allowlist: tuple[str, ...] = ()
    branch_denylist: tuple[str, ...] = ()
    file_allowlist: tuple[str, ...] = ()
    file_denylist: tuple[str, ...] = ()
    sensitive_rules: tuple[str, ...] = ()
    max_attempts: int | None = None
    max_diff_lines: int | None = None
    max_calls_per_session: int | None = None
    max_tokens_per_session: int | None = None
    max_wall_seconds: int | None = None
    max_cost_per_session: Money | None = None

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any] | None,
        *,
        workspace_paused: bool = False,
    ) -> WorkspacePolicyLayer:
        if not isinstance(raw, Mapping):
            return cls(paused=workspace_paused)

        def _clean_globs(key: str) -> tuple[str, ...]:
            items = raw.get(key)
            if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
                return ()
            cleaned: list[str] = []
            for item in items:
                if isinstance(item, str):
                    try:
                        cleaned.append(canonicalize_glob_pattern(item))
                    except PathCanonicalizationError:
                        continue
            return tuple(dict.fromkeys(cleaned))

        def _opt_int(key: str, lo: int, hi: int) -> int | None:
            val = raw.get(key)
            if isinstance(val, int) and not isinstance(val, bool) and lo <= val <= hi:
                return val
            return None

        cost_obj: Money | None = None
        raw_cost = raw.get("max_cost_per_session")
        if isinstance(raw_cost, Mapping):
            try:
                cost_obj = Money.model_validate(dict(raw_cost))
            except Exception:
                cost_obj = None

        return cls(
            paused=workspace_paused or bool(raw.get("paused", False)),
            branch_allowlist=_clean_globs("branch_allowlist"),
            branch_denylist=_clean_globs("branch_denylist"),
            file_allowlist=_clean_globs("file_allowlist"),
            file_denylist=_clean_globs("file_denylist"),
            sensitive_rules=_clean_globs("sensitive_rules"),
            max_attempts=_opt_int("max_attempts", 1, 5),
            max_diff_lines=_opt_int("max_diff_lines", 1, 2000),
            max_calls_per_session=_opt_int("max_calls_per_session", 1, 100),
            max_tokens_per_session=_opt_int("max_tokens_per_session", 1, 1_000_000),
            max_wall_seconds=_opt_int("max_wall_seconds", 60, 7200),
            max_cost_per_session=cost_obj,
        )


@dataclass(frozen=True, slots=True)
class PolicyHierarchyContext:
    """Combined instance + workspace + readiness context for evaluating repository policy."""

    instance_config: Red2PrConfig = field(default_factory=load_config)
    instance_paused: bool = False
    workspace_layer: WorkspacePolicyLayer = field(default_factory=WorkspacePolicyLayer)
    worker_isolation_ready: bool = False
    inference_consent_ready: bool = False
    workflow_hazard_blocked: bool = False
    grant_review_required: bool = False


@dataclass(frozen=True, slots=True)
class HistoricalTriggerInput:
    """Read-only projection of a `CiRunTriggerModel` row for dry-run simulation."""

    trigger_id: str
    provider_run_id: str
    attempt_key: str
    ref: str
    head_sha: str
    conclusion: CiConclusion
    untrusted_fork: bool
    triggered_at: datetime


def _dedupe_globs(patterns: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(canonicalize_glob_pattern(p) for p in patterns))


def build_default_repository_policy(
    *,
    instance_config: Red2PrConfig | None = None,
    runtime_profile_id: str = "default-isolated",
) -> RepositoryPolicy:
    """Construct the initial `revision=1` default `RepositoryPolicy` (`ADR-015`, `ADR-031`)."""
    cfg = instance_config if instance_config is not None else load_config()
    defaults = cfg.repository_defaults
    return RepositoryPolicy(
        branch_allowlist=_dedupe_globs(defaults.branch_allowlist),
        branch_denylist=[],
        file_allowlist=[],
        file_denylist=_dedupe_globs(defaults.file_denylist),
        sensitive_rules=_dedupe_globs(defaults.sensitive_file_rules),
        allow_test_edits=False,
        allow_config_edits=False,
        max_attempts=defaults.max_attempts,
        max_diff_lines=defaults.max_diff_lines,
        max_calls_per_session=None,
        max_tokens_per_session=None,
        max_wall_seconds=None,
        max_cost_per_session=None,
        require_baseline=True,
        inference_consent_id=None,
        runtime_profile_id=runtime_profile_id,
    )


def evaluate_readiness_gates(
    ctx: PolicyHierarchyContext,
    *,
    target_mode: RepositoryMode,
) -> PolicyReadinessGates:
    """Compute operational & security readiness gates for `approval` / `auto_repair` modes."""
    reasons: list[str] = []
    if ctx.instance_paused:
        reasons.append("Instance operations are currently paused.")
    if ctx.workspace_layer.paused:
        reasons.append("Workspace automation is currently paused.")
    if ctx.grant_review_required:
        reasons.append(
            "Provider connection was re-authorized after revocation (W-02); explicit "
            "workspace admin review is required before leaving monitor mode."
        )
    if ctx.workflow_hazard_blocked:
        reasons.append(
            "Dangerous CI workflow trigger hazard detected (SEC-031); autonomous "
            "auto_repair mode is blocked until workflows are remediated and rescanned."
        )
    if not ctx.worker_isolation_ready and target_mode in {"approval", "auto_repair"}:
        reasons.append("Isolated Z3 sandbox worker self-test has not passed (Setup Phase 7).")
    if not ctx.inference_consent_ready and target_mode in {"approval", "auto_repair"}:
        reasons.append(
            "Active outbound model inference consent is missing for this repository scope."
        )
    return PolicyReadinessGates(
        worker_isolation_ready=ctx.worker_isolation_ready,
        inference_consent_ready=ctx.inference_consent_ready,
        workflow_hazard_blocked=ctx.workflow_hazard_blocked,
        grant_review_required=ctx.grant_review_required,
        instance_paused=ctx.instance_paused,
        workspace_paused=ctx.workspace_layer.paused,
        blocking_reasons=reasons,
    )


def resolve_effective_policy(
    *,
    repo_mode: RepositoryMode,
    repo_paused: bool,
    repo_policy: RepositoryPolicy,
    ctx: PolicyHierarchyContext,
) -> EffectiveRepositoryPolicy:
    """Resolve effective repository policy under `hard_invariant > instance > workspace > repo`."""
    inst_defaults = ctx.instance_config.repository_defaults
    inst_ai = ctx.instance_config.ai
    ws = ctx.workspace_layer

    sources: dict[str, PolicyScopeLayer] = {
        "require_baseline": "hard_invariant",
        "auto_merge": "hard_invariant",
        "hard_denied_paths": "hard_invariant",
        "protected_paths": "hard_invariant",
    }

    if ctx.instance_paused:
        effective_paused = True
        sources["effective_paused"] = "instance"
    elif ws.paused:
        effective_paused = True
        sources["effective_paused"] = "workspace"
    else:
        effective_paused = repo_paused
        sources["effective_paused"] = "repository"

    # Effective runtime mode respects W-02 & SEC-031 safety ceilings
    if ctx.grant_review_required and repo_mode != "monitor":
        effective_mode: RepositoryMode = "monitor"
        sources["effective_mode"] = "hard_invariant"
    elif ctx.workflow_hazard_blocked and repo_mode == "auto_repair":
        effective_mode = "approval"
        sources["effective_mode"] = "hard_invariant"
    else:
        effective_mode = repo_mode
        sources["effective_mode"] = "repository"

    allow_sandbox = (
        not effective_paused
        and effective_mode in {"approval", "auto_repair"}
        and ctx.worker_isolation_ready
        and ctx.inference_consent_ready
        and not ctx.grant_review_required
    )
    allow_auto_pub = (
        allow_sandbox and effective_mode == "auto_repair" and not ctx.workflow_hazard_blocked
    )

    # Deny lists & sensitive rules merge additively from instance -> workspace -> repository
    merged_file_denylist = _dedupe_globs(
        [*inst_defaults.file_denylist, *ws.file_denylist, *repo_policy.file_denylist]
    )
    sources["file_denylist"] = (
        "instance"
        if inst_defaults.file_denylist and not repo_policy.file_denylist and not ws.file_denylist
        else ("workspace" if ws.file_denylist and not repo_policy.file_denylist else "repository")
    )

    merged_branch_denylist = _dedupe_globs([*ws.branch_denylist, *repo_policy.branch_denylist])
    sources["branch_denylist"] = (
        "workspace" if ws.branch_denylist and not repo_policy.branch_denylist else "repository"
    )

    merged_sensitive = _dedupe_globs(
        [
            *inst_defaults.sensitive_file_rules,
            *ws.sensitive_rules,
            *repo_policy.sensitive_rules,
        ]
    )
    sources["sensitive_rules"] = (
        "repository"
        if repo_policy.sensitive_rules
        else ("workspace" if ws.sensitive_rules else "instance")
    )

    if repo_policy.branch_allowlist:
        eff_branch_allow = _dedupe_globs(repo_policy.branch_allowlist)
        sources["branch_allowlist"] = "repository"
    elif ws.branch_allowlist:
        eff_branch_allow = list(ws.branch_allowlist)
        sources["branch_allowlist"] = "workspace"
    else:
        eff_branch_allow = _dedupe_globs(inst_defaults.branch_allowlist)
        sources["branch_allowlist"] = "instance"

    if repo_policy.file_allowlist:
        eff_file_allow = _dedupe_globs(repo_policy.file_allowlist)
        sources["file_allowlist"] = "repository"
    elif ws.file_allowlist:
        eff_file_allow = list(ws.file_allowlist)
        sources["file_allowlist"] = "workspace"
    else:
        eff_file_allow = []
        sources["file_allowlist"] = "instance"

    # Numeric caps: child scopes can tighten (lower) parent ceilings, never exceed them
    def _cap_int(
        field_name: str,
        inst_val: int,
        ws_val: int | None,
        repo_val: int | None,
    ) -> int:
        chosen = inst_val
        chosen_src: PolicyScopeLayer = "instance"
        if ws_val is not None and ws_val <= chosen:
            chosen = ws_val
            chosen_src = "workspace"
        if repo_val is not None and repo_val <= chosen:
            chosen = repo_val
            chosen_src = "repository"
        sources[field_name] = chosen_src
        return chosen

    eff_max_attempts = _cap_int(
        "max_attempts",
        inst_defaults.max_attempts,
        ws.max_attempts,
        repo_policy.max_attempts,
    )
    eff_max_diff_lines = _cap_int(
        "max_diff_lines",
        inst_defaults.max_diff_lines,
        ws.max_diff_lines,
        repo_policy.max_diff_lines,
    )
    eff_max_calls = _cap_int(
        "max_calls_per_session",
        inst_ai.max_calls_per_session,
        ws.max_calls_per_session,
        repo_policy.max_calls_per_session,
    )
    eff_max_tokens = _cap_int(
        "max_tokens_per_session",
        inst_ai.max_tokens_per_session,
        ws.max_tokens_per_session,
        repo_policy.max_tokens_per_session,
    )
    eff_max_wall = _cap_int(
        "max_wall_seconds",
        inst_ai.max_wall_seconds,
        ws.max_wall_seconds,
        repo_policy.max_wall_seconds,
    )

    eff_cost_amount = inst_ai.max_cost_per_session.amount
    eff_cost_currency = inst_ai.max_cost_per_session.currency
    cost_src: PolicyScopeLayer = "instance"
    if (
        ws.max_cost_per_session is not None
        and ws.max_cost_per_session.currency == eff_cost_currency
        and ws.max_cost_per_session.amount <= eff_cost_amount
    ):
        eff_cost_amount = ws.max_cost_per_session.amount
        cost_src = "workspace"
    if (
        repo_policy.max_cost_per_session is not None
        and repo_policy.max_cost_per_session.currency == eff_cost_currency
        and repo_policy.max_cost_per_session.amount <= eff_cost_amount
    ):
        eff_cost_amount = repo_policy.max_cost_per_session.amount
        cost_src = "repository"
    sources["max_cost_per_session"] = cost_src
    sources["allow_test_edits"] = "repository"
    sources["allow_config_edits"] = "repository"
    sources["runtime_profile_id"] = "repository"

    return EffectiveRepositoryPolicy(
        mode=repo_mode,
        effective_mode=effective_mode,
        paused=repo_paused,
        effective_paused=effective_paused,
        allow_sandbox_execution=allow_sandbox,
        allow_auto_publication=allow_auto_pub,
        require_baseline=True,
        auto_merge=False,
        branch_allowlist=eff_branch_allow,
        branch_denylist=merged_branch_denylist,
        file_allowlist=eff_file_allow,
        file_denylist=merged_file_denylist,
        hard_denied_paths=list(HARD_DENIED_PATH_GLOBS),
        sensitive_rules=merged_sensitive,
        protected_paths=list(PROTECTED_SENSITIVE_PATH_GLOBS),
        allow_test_edits=repo_policy.allow_test_edits,
        allow_config_edits=repo_policy.allow_config_edits,
        max_attempts=eff_max_attempts,
        max_diff_lines=eff_max_diff_lines,
        max_calls_per_session=eff_max_calls,
        max_tokens_per_session=eff_max_tokens,
        max_wall_seconds=eff_max_wall,
        max_cost_per_session=Money(amount=eff_cost_amount, currency=eff_cost_currency),
        inference_consent_id=repo_policy.inference_consent_id,
        runtime_profile_id=repo_policy.runtime_profile_id,
        field_sources=sources,
    )


def validate_policy_against_hierarchy(
    *,
    target_mode: RepositoryMode,
    target_policy: RepositoryPolicy,
    ctx: PolicyHierarchyContext,
    acknowledge_grant_review: bool = False,
) -> list[PolicyDenialItem]:
    """Validate candidate mode + policy against instance/workspace ceilings & readiness gates."""
    denials: list[PolicyDenialItem] = []
    inst_defaults = ctx.instance_config.repository_defaults
    inst_ai = ctx.instance_config.ai
    ws = ctx.workspace_layer

    # 1. W-02 post-revocation reconnect review gate
    if ctx.grant_review_required and not acknowledge_grant_review and target_mode != "monitor":
        denials.append(
            PolicyDenialItem(
                code="grant_review_required",
                source_layer="hard_invariant",
                detail=(
                    "Connection re-authorization review (W-02) is pending; repository must "
                    "remain in monitor mode until reviewed by a workspace admin."
                ),
                blocking_save=True,
            )
        )

    # 2. SEC-031 workflow hazard blocks auto_repair
    if target_mode == "auto_repair" and ctx.workflow_hazard_blocked:
        denials.append(
            PolicyDenialItem(
                code="workflow_hazard_blocks_auto_repair",
                source_layer="hard_invariant",
                detail=(
                    "Repository has flagged workflow hazards (SEC-031); auto_repair cannot be "
                    "enabled until hazardous workflow triggers are removed and rescanned."
                ),
                blocking_save=True,
            )
        )

    # 3. Worker isolation self-test required before enabling auto_repair (`U12` readiness gate)
    if target_mode == "auto_repair" and not ctx.worker_isolation_ready:
        denials.append(
            PolicyDenialItem(
                code="worker_isolation_not_ready",
                source_layer="instance",
                detail=(
                    "Isolated Z3 sandbox worker readiness probe has not passed; auto_repair "
                    "cannot be enabled until worker isolation is verified."
                ),
                blocking_save=True,
            )
        )

    # 4. Outbound model inference consent required before enabling auto_repair
    if target_mode == "auto_repair" and not ctx.inference_consent_ready:
        denials.append(
            PolicyDenialItem(
                code="inference_consent_required",
                source_layer="instance",
                detail=(
                    "Active outbound model inference consent is required before enabling "
                    "auto_repair on this repository."
                ),
                blocking_save=True,
            )
        )

    # 5. Child numeric & AI spend ceilings must not exceed parent instance/workspace caps
    parent_attempts = (
        min(inst_defaults.max_attempts, ws.max_attempts)
        if ws.max_attempts is not None
        else inst_defaults.max_attempts
    )
    if target_policy.max_attempts > parent_attempts:
        denials.append(
            PolicyDenialItem(
                code="max_attempts_exceeds_ceiling",
                source_layer="workspace" if ws.max_attempts is not None else "instance",
                detail=(
                    f"max_attempts ({target_policy.max_attempts}) exceeds parent ceiling "
                    f"({parent_attempts})."
                ),
                blocking_save=True,
            )
        )

    parent_diff = (
        min(inst_defaults.max_diff_lines, ws.max_diff_lines)
        if ws.max_diff_lines is not None
        else inst_defaults.max_diff_lines
    )
    if target_policy.max_diff_lines > parent_diff:
        denials.append(
            PolicyDenialItem(
                code="max_diff_lines_exceeds_ceiling",
                source_layer="workspace" if ws.max_diff_lines is not None else "instance",
                detail=(
                    f"max_diff_lines ({target_policy.max_diff_lines}) exceeds parent ceiling "
                    f"({parent_diff})."
                ),
                blocking_save=True,
            )
        )

    if target_policy.max_calls_per_session is not None:
        parent_calls = (
            min(inst_ai.max_calls_per_session, ws.max_calls_per_session)
            if ws.max_calls_per_session is not None
            else inst_ai.max_calls_per_session
        )
        if target_policy.max_calls_per_session > parent_calls:
            denials.append(
                PolicyDenialItem(
                    code="max_calls_exceeds_ceiling",
                    source_layer="workspace"
                    if ws.max_calls_per_session is not None
                    else "instance",
                    detail=(
                        f"max_calls_per_session ({target_policy.max_calls_per_session}) exceeds "
                        f"parent ceiling ({parent_calls})."
                    ),
                    blocking_save=True,
                )
            )

    if target_policy.max_tokens_per_session is not None:
        parent_tokens = (
            min(inst_ai.max_tokens_per_session, ws.max_tokens_per_session)
            if ws.max_tokens_per_session is not None
            else inst_ai.max_tokens_per_session
        )
        if target_policy.max_tokens_per_session > parent_tokens:
            denials.append(
                PolicyDenialItem(
                    code="max_tokens_exceeds_ceiling",
                    source_layer=(
                        "workspace" if ws.max_tokens_per_session is not None else "instance"
                    ),
                    detail=(
                        f"max_tokens_per_session ({target_policy.max_tokens_per_session}) exceeds "
                        f"parent ceiling ({parent_tokens})."
                    ),
                    blocking_save=True,
                )
            )

    if target_policy.max_wall_seconds is not None:
        parent_wall = (
            min(inst_ai.max_wall_seconds, ws.max_wall_seconds)
            if ws.max_wall_seconds is not None
            else inst_ai.max_wall_seconds
        )
        if target_policy.max_wall_seconds > parent_wall:
            denials.append(
                PolicyDenialItem(
                    code="max_wall_seconds_exceeds_ceiling",
                    source_layer="workspace" if ws.max_wall_seconds is not None else "instance",
                    detail=(
                        f"max_wall_seconds ({target_policy.max_wall_seconds}) exceeds parent "
                        f"ceiling ({parent_wall})."
                    ),
                    blocking_save=True,
                )
            )

    if target_policy.max_cost_per_session is not None:
        parent_cost_currency = inst_ai.max_cost_per_session.currency
        parent_cost_amount = inst_ai.max_cost_per_session.amount
        cost_layer: PolicyScopeLayer = "instance"
        if (
            ws.max_cost_per_session is not None
            and ws.max_cost_per_session.currency == parent_cost_currency
            and ws.max_cost_per_session.amount < parent_cost_amount
        ):
            parent_cost_amount = ws.max_cost_per_session.amount
            cost_layer = "workspace"
        if target_policy.max_cost_per_session.currency != parent_cost_currency:
            denials.append(
                PolicyDenialItem(
                    code="budget_currency_mismatch",
                    source_layer="instance",
                    detail=(
                        f"Budget currency '{target_policy.max_cost_per_session.currency}' must "
                        f"match instance currency '{parent_cost_currency}'."
                    ),
                    blocking_save=True,
                )
            )
        elif target_policy.max_cost_per_session.amount > parent_cost_amount:
            denials.append(
                PolicyDenialItem(
                    code="max_cost_exceeds_ceiling",
                    source_layer=cost_layer,
                    detail=(
                        f"max_cost_per_session ({target_policy.max_cost_per_session.amount}) "
                        f"exceeds parent ceiling ({parent_cost_amount} {parent_cost_currency})."
                    ),
                    blocking_save=True,
                )
            )
        elif target_mode in {
            "approval",
            "auto_repair",
        } and target_policy.max_cost_per_session.amount <= Decimal("0"):
            denials.append(
                PolicyDenialItem(
                    code="zero_budget_blocks_repair",
                    source_layer="repository",
                    detail="Per-session cost cap must be greater than 0.00 for repair modes.",
                    blocking_save=True,
                )
            )

    # Non-blocking runtime warnings surfaced in preview denials
    if target_mode == "approval":
        if not ctx.worker_isolation_ready:
            denials.append(
                PolicyDenialItem(
                    code="worker_isolation_pending",
                    source_layer="instance",
                    detail=(
                        "Approval mode saved, but sandbox execution will stay queued/paused "
                        "until isolated Z3 worker readiness passes."
                    ),
                    blocking_save=False,
                )
            )
        if not ctx.inference_consent_ready:
            denials.append(
                PolicyDenialItem(
                    code="inference_consent_pending",
                    source_layer="instance",
                    detail=(
                        "Approval mode saved, but outbound model calls remain blocked until "
                        "inference consent is granted."
                    ),
                    blocking_save=False,
                )
            )

    return denials


def evaluate_branch_policy(
    raw_ref: str,
    *,
    repo_policy: RepositoryPolicy,
    effective_policy: EffectiveRepositoryPolicy,
    ctx: PolicyHierarchyContext,
) -> BranchPolicyEvaluation:
    """Evaluate a Git branch ref under `hard_invariant > instance > workspace > repository`."""
    try:
        canonical_branch = canonicalize_branch_ref(raw_ref)
    except PathCanonicalizationError as exc:
        return BranchPolicyEvaluation(
            branch=raw_ref[:256] or "<empty>",
            canonical_branch=None,
            verdict="deny",
            matched_rule=None,
            source_layer="hard_invariant",
            reason=exc.detail,
        )

    if canonical_branch.casefold().startswith("red2pr/"):
        return BranchPolicyEvaluation(
            branch=raw_ref,
            canonical_branch=canonical_branch,
            verdict="deny",
            matched_rule="red2pr/**",
            source_layer="hard_invariant",
            reason="Bot-authored red2pr/* repair branches are permanently excluded from loops.",
        )

    # 1. Denylists always override allowlists (workspace -> repository)
    ws_deny = first_matching_glob(
        ctx.workspace_layer.branch_denylist, canonical_branch, case_insensitive=True
    )
    if ws_deny is not None:
        return BranchPolicyEvaluation(
            branch=raw_ref,
            canonical_branch=canonical_branch,
            verdict="deny",
            matched_rule=ws_deny,
            source_layer="workspace",
            reason=f"Branch '{canonical_branch}' matches workspace branch_denylist '{ws_deny}'.",
        )

    repo_deny = first_matching_glob(
        repo_policy.branch_denylist, canonical_branch, case_insensitive=True
    )
    if repo_deny is not None:
        return BranchPolicyEvaluation(
            branch=raw_ref,
            canonical_branch=canonical_branch,
            verdict="deny",
            matched_rule=repo_deny,
            source_layer="repository",
            reason=f"Branch '{canonical_branch}' matches repository branch_denylist '{repo_deny}'.",
        )

    # 2. Every non-empty allowlist across instance -> workspace -> repository must match
    inst_allow = ctx.instance_config.repository_defaults.branch_allowlist
    if inst_allow:
        m_inst = first_matching_glob(inst_allow, canonical_branch, case_insensitive=False)
        if m_inst is None:
            return BranchPolicyEvaluation(
                branch=raw_ref,
                canonical_branch=canonical_branch,
                verdict="deny",
                matched_rule=None,
                source_layer="instance",
                reason="Branch is outside the instance branch_allowlist.",
            )

    ws_allow = ctx.workspace_layer.branch_allowlist
    if ws_allow:
        m_ws = first_matching_glob(ws_allow, canonical_branch, case_insensitive=False)
        if m_ws is None:
            return BranchPolicyEvaluation(
                branch=raw_ref,
                canonical_branch=canonical_branch,
                verdict="deny",
                matched_rule=None,
                source_layer="workspace",
                reason="Branch is outside the workspace branch_allowlist.",
            )

    matched_allow: str | None = "*"
    matched_layer: PolicyScopeLayer = "repository"
    if repo_policy.branch_allowlist:
        m_repo = first_matching_glob(
            repo_policy.branch_allowlist, canonical_branch, case_insensitive=False
        )
        if m_repo is None:
            return BranchPolicyEvaluation(
                branch=raw_ref,
                canonical_branch=canonical_branch,
                verdict="deny",
                matched_rule=None,
                source_layer="repository",
                reason="Branch is outside the repository branch_allowlist.",
            )
        matched_allow = m_repo
        matched_layer = "repository"
    elif ws_allow:
        matched_allow = first_matching_glob(ws_allow, canonical_branch, case_insensitive=False)
        matched_layer = "workspace"
    elif inst_allow:
        matched_allow = first_matching_glob(inst_allow, canonical_branch, case_insensitive=False)
        matched_layer = "instance"

    if effective_policy.effective_mode == "auto_repair" and effective_policy.allow_auto_publication:
        return BranchPolicyEvaluation(
            branch=raw_ref,
            canonical_branch=canonical_branch,
            verdict="allow",
            matched_rule=matched_allow,
            source_layer=matched_layer,
            reason=f"Branch '{canonical_branch}' is eligible for autonomous draft PR repair.",
        )

    return BranchPolicyEvaluation(
        branch=raw_ref,
        canonical_branch=canonical_branch,
        verdict="requires_approval",
        matched_rule=matched_allow,
        source_layer=matched_layer,
        reason=(
            f"Branch '{canonical_branch}' passes branch filters; publication requires human "
            f"review under effective mode '{effective_policy.effective_mode}'."
        ),
    )


def evaluate_path_policy(
    raw_path: str,
    *,
    repo_policy: RepositoryPolicy,
    effective_policy: EffectiveRepositoryPolicy,
    ctx: PolicyHierarchyContext,
) -> PathPolicyEvaluation:
    """Canonicalize & classify a candidate patch path (`SEC-007`, `SEC-009`, `REP-03`)."""
    try:
        canonical = canonicalize_repo_path(raw_path)
    except PathCanonicalizationError as exc:
        return PathPolicyEvaluation(
            raw_path=raw_path[:512] or "<empty>",
            canonical_path=None,
            verdict="deny",
            category="invalid_path",
            matched_rule=exc.code,
            source_layer="hard_invariant",
            reason=exc.detail,
        )

    builtin = classify_builtin_repo_path(canonical)

    # 1. Hard-denied VCS/secret files can never be modified (`SEC-007`)
    if builtin.hard_denied_rule is not None:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="deny",
            category="hard_denied",
            matched_rule=builtin.hard_denied_rule,
            source_layer="hard_invariant",
            reason=(
                f"Path '{canonical}' matches non-waivable secret/VCS hard-deny pattern "
                f"'{builtin.hard_denied_rule}' (SEC-007)."
            ),
        )

    # 2. Explicit file_denylist (instance -> workspace -> repository) always wins over allowlist
    inst_deny = first_matching_glob(
        ctx.instance_config.repository_defaults.file_denylist,
        canonical,
        case_insensitive=True,
    )
    if inst_deny is not None:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="deny",
            category="denied_glob",
            matched_rule=inst_deny,
            source_layer="instance",
            reason=f"Path '{canonical}' is blocked by instance file_denylist '{inst_deny}'.",
        )

    ws_deny = first_matching_glob(
        ctx.workspace_layer.file_denylist,
        canonical,
        case_insensitive=True,
    )
    if ws_deny is not None:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="deny",
            category="denied_glob",
            matched_rule=ws_deny,
            source_layer="workspace",
            reason=f"Path '{canonical}' is blocked by workspace file_denylist '{ws_deny}'.",
        )

    repo_deny = first_matching_glob(
        repo_policy.file_denylist,
        canonical,
        case_insensitive=True,
    )
    if repo_deny is not None:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="deny",
            category="denied_glob",
            matched_rule=repo_deny,
            source_layer="repository",
            reason=f"Path '{canonical}' is blocked by repository file_denylist '{repo_deny}'.",
        )

    # 3. Non-empty file_allowlists (workspace -> repository) restrict patch scope
    if ctx.workspace_layer.file_allowlist:
        ws_allow_match = first_matching_glob(
            ctx.workspace_layer.file_allowlist, canonical, case_insensitive=False
        )
        if ws_allow_match is None:
            return PathPolicyEvaluation(
                raw_path=raw_path,
                canonical_path=canonical,
                verdict="deny",
                category="outside_allowlist",
                matched_rule=None,
                source_layer="workspace",
                reason=f"Path '{canonical}' is outside workspace file_allowlist.",
            )

    matched_allow: str | None = None
    if repo_policy.file_allowlist:
        matched_allow = first_matching_glob(
            repo_policy.file_allowlist, canonical, case_insensitive=False
        )
        if matched_allow is None:
            return PathPolicyEvaluation(
                raw_path=raw_path,
                canonical_path=canonical,
                verdict="deny",
                category="outside_allowlist",
                matched_rule=None,
                source_layer="repository",
                reason=f"Path '{canonical}' is outside repository file_allowlist.",
            )

    # 4. Test & config edit gates (`AGENTS.md` Principle 3 & `REP-03`)
    if builtin.test_file_rule is not None and not repo_policy.allow_test_edits:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="deny",
            category="test_file",
            matched_rule=builtin.test_file_rule,
            source_layer="repository",
            reason=(
                f"Test file '{canonical}' cannot be modified while allow_test_edits=false "
                "(prevents autonomous test weakening)."
            ),
        )

    if builtin.config_file_rule is not None and not repo_policy.allow_config_edits:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="deny",
            category="config_file",
            matched_rule=builtin.config_file_rule,
            source_layer="repository",
            reason=(
                f"Build/tooling config '{canonical}' cannot be modified while "
                "allow_config_edits=false."
            ),
        )

    # 5. SEC-009 protected CI/workflow/lockfile/auth/deploy/migration rules force human approval
    if builtin.protected_sensitive_rule is not None:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="requires_approval",
            category="protected_sensitive",
            matched_rule=builtin.protected_sensitive_rule,
            source_layer="hard_invariant",
            reason=(
                f"Protected path '{canonical}' matches SEC-009 guardrail "
                f"'{builtin.protected_sensitive_rule}' and always requires human approval."
            ),
        )

    for layer_name, rules in (
        ("instance", ctx.instance_config.repository_defaults.sensitive_file_rules),
        ("workspace", ctx.workspace_layer.sensitive_rules),
        ("repository", repo_policy.sensitive_rules),
    ):
        sens_match = first_matching_glob(rules, canonical, case_insensitive=True)
        if sens_match is not None:
            return PathPolicyEvaluation(
                raw_path=raw_path,
                canonical_path=canonical,
                verdict="requires_approval",
                category="protected_sensitive",
                matched_rule=sens_match,
                source_layer=cast(PolicyScopeLayer, layer_name),
                reason=(
                    f"Path '{canonical}' matches {layer_name} sensitive rule '{sens_match}' "
                    "and requires human approval before publication."
                ),
            )

    if builtin.test_file_rule is not None:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="requires_approval",
            category="test_file",
            matched_rule=builtin.test_file_rule,
            source_layer="repository",
            reason=(
                f"Test file '{canonical}' is permitted by allow_test_edits=true, but mandatory "
                "human review is required before publication."
            ),
        )

    if builtin.config_file_rule is not None:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="requires_approval",
            category="config_file",
            matched_rule=builtin.config_file_rule,
            source_layer="repository",
            reason=(
                f"Configuration file '{canonical}' is permitted by allow_config_edits=true, "
                "but mandatory human review is required before publication."
            ),
        )

    if effective_policy.effective_mode == "auto_repair" and effective_policy.allow_auto_publication:
        return PathPolicyEvaluation(
            raw_path=raw_path,
            canonical_path=canonical,
            verdict="allow",
            category="standard",
            matched_rule=matched_allow,
            source_layer="repository",
            reason=f"Path '{canonical}' is permitted for autonomous draft PR publication.",
        )

    return PathPolicyEvaluation(
        raw_path=raw_path,
        canonical_path=canonical,
        verdict="requires_approval",
        category="standard",
        matched_rule=matched_allow,
        source_layer="repository",
        reason=(
            f"Path '{canonical}' passes path rules; human approval is required under "
            f"effective mode '{effective_policy.effective_mode}'."
        ),
    )


def evaluate_patch_paths(
    raw_paths: Sequence[str],
    *,
    diff_lines: int | None,
    repo_policy: RepositoryPolicy,
    effective_policy: EffectiveRepositoryPolicy,
    ctx: PolicyHierarchyContext,
) -> tuple[
    PolicyEvaluationVerdict, list[PathPolicyEvaluation], PolicyEvaluationVerdict | None, str | None
]:
    """Evaluate a complete candidate patch file set and diff-line ceiling."""
    evaluations = [
        evaluate_path_policy(
            p,
            repo_policy=repo_policy,
            effective_policy=effective_policy,
            ctx=ctx,
        )
        for p in raw_paths
    ]

    diff_verdict: PolicyEvaluationVerdict | None = None
    diff_reason: str | None = None
    if diff_lines is not None:
        if diff_lines > effective_policy.max_diff_lines:
            diff_verdict = "deny"
            diff_reason = (
                f"Candidate diff ({diff_lines} lines) exceeds effective max_diff_lines "
                f"ceiling ({effective_policy.max_diff_lines})."
            )
        elif (
            effective_policy.effective_mode == "auto_repair"
            and effective_policy.allow_auto_publication
        ):
            diff_verdict = "allow"
            diff_reason = (
                f"Candidate diff ({diff_lines} lines) is within max_diff_lines "
                f"({effective_policy.max_diff_lines})."
            )
        else:
            diff_verdict = "requires_approval"
            diff_reason = (
                f"Candidate diff ({diff_lines} lines) is within max_diff_lines "
                f"({effective_policy.max_diff_lines}); publication requires approval."
            )

    if any(ev.verdict == "deny" for ev in evaluations) or diff_verdict == "deny":
        overall: PolicyEvaluationVerdict = "deny"
    elif (
        any(ev.verdict == "requires_approval" for ev in evaluations)
        or diff_verdict == "requires_approval"
        or not effective_policy.allow_auto_publication
    ):
        overall = "requires_approval"
    else:
        overall = "allow"

    return overall, evaluations, diff_verdict, diff_reason


def evaluate_run_eligibility(
    *,
    ref: str,
    untrusted_fork: bool,
    repo_policy: RepositoryPolicy,
    effective_policy: EffectiveRepositoryPolicy,
    ctx: PolicyHierarchyContext,
) -> tuple[RunEligibilityDisposition, bool, bool, str]:
    """Determine CI failure trigger eligibility (`ADR-033` monitor vs repair execution)."""
    if effective_policy.effective_paused:
        pause_src = effective_policy.field_sources.get("effective_paused", "repository")
        return (
            "blocked_paused",
            False,
            False,
            f"Execution blocked because {pause_src} pause override is active.",
        )

    if untrusted_fork:
        return (
            "blocked_untrusted_fork",
            False,
            False,
            "Untrusted fork pull request runs never execute autonomous sandbox repair (SEC-031).",
        )

    branch_eval = evaluate_branch_policy(
        ref,
        repo_policy=repo_policy,
        effective_policy=effective_policy,
        ctx=ctx,
    )
    if branch_eval.verdict == "deny":
        return (
            "blocked_branch_policy",
            False,
            False,
            branch_eval.reason,
        )

    if effective_policy.mode == "monitor":
        return (
            "diagnose_only_monitor",
            False,
            False,
            (
                "Monitor mode ingests logs and records diagnosis only; zero sandbox "
                "execution (ADR-033)."
            ),
        )

    if ctx.grant_review_required:
        return (
            "blocked_grant_review",
            False,
            False,
            "Post-revocation connection reconnect awaits admin review (W-02).",
        )

    if not ctx.worker_isolation_ready:
        return (
            "blocked_worker_unready",
            False,
            False,
            "Sandbox execution blocked until isolated Z3 worker readiness probe passes.",
        )

    if not ctx.inference_consent_ready:
        return (
            "blocked_missing_consent",
            False,
            False,
            "Sandbox repair blocked until outbound model inference consent is active.",
        )

    if effective_policy.mode == "auto_repair" and ctx.workflow_hazard_blocked:
        return (
            "blocked_workflow_hazard",
            False,
            False,
            "SEC-031 workflow hazard blocks auto_repair execution.",
        )

    if effective_policy.effective_mode == "auto_repair":
        return (
            "eligible_auto_repair",
            True,
            True,
            "Eligible for isolated sandbox verification and autonomous draft PR publication.",
        )

    return (
        "eligible_approval_gated",
        True,
        False,
        "Eligible for isolated sandbox verification; human approval required before PR creation.",
    )


def compute_policy_rule_changes(
    *,
    current_mode: RepositoryMode,
    current_paused: bool,
    current_policy: RepositoryPolicy,
    target_mode: RepositoryMode,
    target_paused: bool,
    target_policy: RepositoryPolicy,
) -> tuple[list[PolicyRuleChange], bool]:
    """Compute structured policy rule diffs and whether fresh 5m MFA step-up is mandatory."""
    changes: list[PolicyRuleChange] = []
    requires_step_up = False

    if current_mode != target_mode:
        escalates_to_auto = target_mode == "auto_repair"
        if escalates_to_auto:
            requires_step_up = True
        changes.append(
            PolicyRuleChange(
                field="mode",
                before=current_mode,
                after=target_mode,
                impact=(
                    "Enables autonomous draft PR publication after verified proof gates."
                    if target_mode == "auto_repair"
                    else (
                        "Enables isolated sandbox patch verification gated on human approval."
                        if target_mode == "approval"
                        else "Restricts repository to read-only CI ingestion and diagnosis."
                    )
                ),
                requires_step_up=escalates_to_auto,
            )
        )

    if current_paused != target_paused:
        unpausing_auto = current_paused and (not target_paused) and target_mode == "auto_repair"
        if unpausing_auto:
            requires_step_up = True
        changes.append(
            PolicyRuleChange(
                field="paused",
                before=current_paused,
                after=target_paused,
                impact=(
                    "Suspends new repair executions and drains queued repair jobs."
                    if target_paused
                    else "Resumes repository automation according to configured mode."
                ),
                requires_step_up=unpausing_auto,
            )
        )

    cur_dump = current_policy.model_dump(mode="json")
    tgt_dump = target_policy.model_dump(mode="json")

    for key in (
        "branch_allowlist",
        "branch_denylist",
        "file_allowlist",
        "file_denylist",
        "sensitive_rules",
        "allow_test_edits",
        "allow_config_edits",
        "max_attempts",
        "max_diff_lines",
        "max_calls_per_session",
        "max_tokens_per_session",
        "max_wall_seconds",
        "max_cost_per_session",
        "inference_consent_id",
        "runtime_profile_id",
    ):
        before_val = cur_dump.get(key)
        after_val = tgt_dump.get(key)
        if before_val == after_val:
            continue

        step_up_field = False
        if key in {"file_denylist", "branch_denylist", "sensitive_rules"}:
            removed = set(before_val or []) - set(after_val or [])
            if removed:
                step_up_field = True
        elif key in {"allow_test_edits", "allow_config_edits"} and bool(after_val):
            step_up_field = True
        elif key in {"file_allowlist", "branch_allowlist"} and target_mode == "auto_repair":
            # Removing allowlist restrictions or adding broader globs while in auto_repair
            if (before_val and not after_val) or (set(after_val or []) - set(before_val or [])):
                step_up_field = True

        if step_up_field:
            requires_step_up = True

        changes.append(
            PolicyRuleChange(
                field=key,
                before=before_val,
                after=after_val,
                impact=f"Updates repository policy constraint '{key}'.",
                requires_step_up=step_up_field,
            )
        )

    return changes, requires_step_up


def simulate_policy_preview(
    *,
    repository_id: str,
    current_revision: int,
    current_mode: RepositoryMode,
    current_paused: bool,
    current_policy: RepositoryPolicy,
    target_mode: RepositoryMode,
    target_paused: bool,
    target_policy: RepositoryPolicy,
    ctx: PolicyHierarchyContext,
    sample_branches: Sequence[str],
    sample_paths: Sequence[str],
    sample_diff_lines: int | None,
    historical_triggers: Sequence[HistoricalTriggerInput],
    affected_in_flight: Sequence[AffectedInFlightItem],
) -> RepositoryPolicyPreviewResponse:
    """Execute a pure, zero-mutation dry-run simulation of candidate repository policy."""
    readiness = evaluate_readiness_gates(ctx, target_mode=target_mode)
    denials = validate_policy_against_hierarchy(
        target_mode=target_mode,
        target_policy=target_policy,
        ctx=ctx,
    )
    effective = resolve_effective_policy(
        repo_mode=target_mode,
        repo_paused=target_paused,
        repo_policy=target_policy,
        ctx=ctx,
    )
    changed_rules, requires_step_up = compute_policy_rule_changes(
        current_mode=current_mode,
        current_paused=current_paused,
        current_policy=current_policy,
        target_mode=target_mode,
        target_paused=target_paused,
        target_policy=target_policy,
    )

    branch_evals = [
        evaluate_branch_policy(
            b,
            repo_policy=target_policy,
            effective_policy=effective,
            ctx=ctx,
        )
        for b in sample_branches
    ]
    _, path_evals, diff_verdict, diff_reason = evaluate_patch_paths(
        sample_paths,
        diff_lines=sample_diff_lines,
        repo_policy=target_policy,
        effective_policy=effective,
        ctx=ctx,
    )

    simulations: list[HistoricalRunSimulation] = []
    for trig in historical_triggers:
        disp, allow_sbx, allow_pub, reason = evaluate_run_eligibility(
            ref=trig.ref,
            untrusted_fork=trig.untrusted_fork,
            repo_policy=target_policy,
            effective_policy=effective,
            ctx=ctx,
        )
        simulations.append(
            HistoricalRunSimulation(
                trigger_id=trig.trigger_id,
                provider_run_id=trig.provider_run_id,
                attempt_key=trig.attempt_key,
                ref=trig.ref,
                head_sha=trig.head_sha,
                conclusion=trig.conclusion,
                untrusted_fork=trig.untrusted_fork,
                triggered_at=trig.triggered_at,
                disposition=disp,
                allow_sandbox_execution=allow_sbx,
                allow_auto_publication=allow_pub,
                reason=reason,
            )
        )

    can_apply = not any(d.blocking_save for d in denials)
    return RepositoryPolicyPreviewResponse(
        repository_id=repository_id,
        current_revision=current_revision,
        next_revision=current_revision + 1,
        requires_step_up=requires_step_up,
        can_apply=can_apply,
        effective_policy=effective,
        readiness_gates=readiness,
        changed_rules=changed_rules,
        denials=denials,
        branch_evaluations=branch_evals,
        path_evaluations=path_evals,
        historical_run_simulations=simulations,
        affected_in_flight=list(affected_in_flight),
        diff_lines_verdict=diff_verdict,
        diff_lines_reason=diff_reason,
    )
