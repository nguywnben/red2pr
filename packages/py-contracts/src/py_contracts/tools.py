"""Canonical typed agent tool protocol (S-20, SEC-028).

Restricts diagnosis and patch agents to the exact 8 read/propose tools in
docs/36_CANONICAL_CONTRACTS.md (S-20). Retired names ('run_targeted_tests',
'get_run_result') and privileged/shell/network operations are structurally rejected.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, StrictBool, StrictInt, StrictStr, model_validator

from py_contracts.integrations import GitSha
from py_contracts.primitives import (
    ActionReceipt,
    BoundedName,
    BoundedSearchQuery,
    BoundedText,
    InternalId,
    Problem,
    Sha256Digest,
    StrictContractModel,
)


def _validate_safe_repo_relpath(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Repository path must be a string")
    normalized = value.replace("\\", "/")
    if not normalized or len(normalized) > 1024 or "\x00" in normalized:
        raise ValueError("Repository path must be 1..1024 characters without null bytes")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise ValueError("Repository path must be relative to the worktree root")
    segments = [seg for seg in normalized.split("/") if seg]
    if not segments or ".." in segments or "." in segments:
        raise ValueError("Repository path must not contain '.' or '..' traversal segments")
    if segments[0] == ".git":
        raise ValueError("Direct access to .git metadata is prohibited")
    return "/".join(segments)


def _validate_safe_repo_prefix(value: Any) -> str:
    if value == "":
        return ""
    return _validate_safe_repo_relpath(value)


SafeRepoPath = Annotated[StrictStr, BeforeValidator(_validate_safe_repo_relpath)]
SafeRepoPrefix = Annotated[StrictStr, BeforeValidator(_validate_safe_repo_prefix)]

AgentToolName = Literal[
    "read_file",
    "search_repo",
    "read_log_excerpt",
    "read_commit_diff",
    "request_reproduction",
    "apply_patch",
    "run_targeted_test",
    "get_execution_result",
]

AGENT_TOOL_NAMES: tuple[AgentToolName, ...] = (
    "read_file",
    "search_repo",
    "read_log_excerpt",
    "read_commit_diff",
    "request_reproduction",
    "apply_patch",
    "run_targeted_test",
    "get_execution_result",
)

DIAGNOSIS_ALLOWED_TOOLS: tuple[AgentToolName, ...] = (
    "read_file",
    "search_repo",
    "read_log_excerpt",
    "read_commit_diff",
    "request_reproduction",
    "get_execution_result",
)

PATCH_ALLOWED_TOOLS: tuple[AgentToolName, ...] = AGENT_TOOL_NAMES

FORBIDDEN_AGENT_CAPABILITIES: tuple[str, ...] = (
    "publish",
    "merge",
    "approve",
    "rotate_secret",
    "edit_policy",
    "send_network_request",
    "run_host_shell",
)

RETIRED_AGENT_TOOL_ALIASES: frozenset[str] = frozenset(
    {
        "run_targeted_tests",
        "get_run_result",
    }
)

TOOL_DESCRIPTIONS: dict[AgentToolName, str] = {
    "read_file": (
        "Read a bounded UTF-8 slice of a policy-allowlisted repository file at the pinned SHA."
    ),
    "search_repo": (
        "Search policy-allowlisted repository files for a bounded literal substring query."
    ),
    "read_log_excerpt": (
        "Read a redacted, bounded byte slice from a session-scoped CI or sandbox log artifact."
    ),
    "read_commit_diff": ("Inspect a bounded commit diff summary between two repository commits."),
    "request_reproduction": (
        "Propose a reviewed runner profile and command IDs for unpatched Sandbox A reproduction."
    ),
    "apply_patch": (
        "Validate and stage a unified diff artifact against the pinned base SHA and path policy."
    ),
    "run_targeted_test": (
        "Request targeted test execution in Sandbox B against an accepted candidate patch digest."
    ),
    "get_execution_result": (
        "Read the signed deterministic execution result reference for a session sandbox operation."
    ),
}


# Typed Tool Argument Schemas (S-20)
class ReadFileArgs(StrictContractModel):
    path: SafeRepoPath
    offset: Annotated[StrictInt, Field(ge=0)] = 0
    length: Annotated[StrictInt, Field(ge=1, le=65536)] = 16384


class SearchRepoArgs(StrictContractModel):
    query: Annotated[BoundedSearchQuery, Field(min_length=1)]
    path_prefix: SafeRepoPrefix = ""
    max_results: Annotated[StrictInt, Field(ge=1, le=100)] = 25


class ReadLogExcerptArgs(StrictContractModel):
    artifact_id: InternalId
    offset: Annotated[StrictInt, Field(ge=0)] = 0
    length: Annotated[StrictInt, Field(ge=1, le=65536)] = 16384


class ReadCommitDiffArgs(StrictContractModel):
    base_sha: GitSha
    head_sha: GitSha
    max_bytes: Annotated[StrictInt, Field(ge=1, le=262144)] = 65536


class RequestReproductionArgs(StrictContractModel):
    profile_id: BoundedName
    command_ids: Annotated[list[BoundedName], Field(min_length=1, max_length=16)]


class ApplyPatchArgs(StrictContractModel):
    base_sha: GitSha
    patch_artifact_id: InternalId
    expected_worktree_digest: Sha256Digest


class RunTargetedTestArgs(StrictContractModel):
    profile_id: BoundedName
    test_selection_id: BoundedName
    patch_digest: Sha256Digest


class GetExecutionResultArgs(StrictContractModel):
    operation_id: InternalId


ToolArguments = (
    ReadFileArgs
    | SearchRepoArgs
    | ReadLogExcerptArgs
    | ReadCommitDiffArgs
    | RequestReproductionArgs
    | ApplyPatchArgs
    | RunTargetedTestArgs
    | GetExecutionResultArgs
)

_TOOL_NAME_TO_ARGS_MODEL: dict[str, type[StrictContractModel]] = {
    "read_file": ReadFileArgs,
    "search_repo": SearchRepoArgs,
    "read_log_excerpt": ReadLogExcerptArgs,
    "read_commit_diff": ReadCommitDiffArgs,
    "request_reproduction": RequestReproductionArgs,
    "apply_patch": ApplyPatchArgs,
    "run_targeted_test": RunTargetedTestArgs,
    "get_execution_result": GetExecutionResultArgs,
}


# Typed Tool Result Schemas (S-20)
class ReadFileResult(StrictContractModel):
    text: StrictStr = Field(max_length=65536)
    digest: Sha256Digest
    truncated: StrictBool


class SearchMatch(StrictContractModel):
    path: SafeRepoPath
    line: Annotated[StrictInt, Field(ge=1)]
    excerpt: BoundedText


class SearchRepoResult(StrictContractModel):
    matches: list[SearchMatch]
    truncated: StrictBool


class ReadLogExcerptResult(StrictContractModel):
    text: StrictStr = Field(max_length=65536)
    redaction_version: BoundedName
    next_offset: Annotated[StrictInt, Field(ge=0)]


class ReadCommitDiffResult(StrictContractModel):
    artifact_id: InternalId
    summary: BoundedText
    truncated: StrictBool


PatchIntegrityOutcome = Literal["accepted", "rejected_policy", "rejected_integrity"]


class ApplyPatchResult(StrictContractModel):
    patch_digest: Sha256Digest
    changed_paths: list[SafeRepoPath]
    integrity_outcome: PatchIntegrityOutcome


class TrustedExecutionResultRef(StrictContractModel):
    operation_id: InternalId
    job_id: InternalId
    exit_code: StrictInt | None = None
    termination: BoundedName
    result_digest: Sha256Digest


ToolResult = (
    ReadFileResult
    | SearchRepoResult
    | ReadLogExcerptResult
    | ReadCommitDiffResult
    | ApplyPatchResult
    | ActionReceipt
    | TrustedExecutionResultRef
)


class ToolCallRequest(StrictContractModel):
    """S-20 typed agent tool invocation envelope."""

    tool_call_id: InternalId
    repair_id: InternalId
    step_id: BoundedName
    tool_name: AgentToolName
    arguments: ToolArguments
    context_digest: Sha256Digest

    @model_validator(mode="before")
    @classmethod
    def _coerce_arguments_by_tool_name(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        tool_name = data.get("tool_name")
        raw_args = data.get("arguments")
        if isinstance(tool_name, str) and tool_name in _TOOL_NAME_TO_ARGS_MODEL:
            target_cls = _TOOL_NAME_TO_ARGS_MODEL[tool_name]
            if isinstance(raw_args, dict):
                copied = dict(data)
                copied["arguments"] = target_cls.model_validate(raw_args)
                return copied
        return data


ToolCallStatus = Literal["ok", "denied", "failed", "pending"]


class ToolCallResponse(StrictContractModel):
    """S-20 typed agent tool response envelope."""

    tool_call_id: InternalId
    status: ToolCallStatus
    result: ToolResult | None = None
    operation_id: InternalId | None = None
    problem: Problem | None = None


def get_tool_args_model(tool_name: str) -> type[StrictContractModel] | None:
    """Return the strict Pydantic argument model for an allowlisted S-20 tool name."""
    return _TOOL_NAME_TO_ARGS_MODEL.get(tool_name)


def _inline_json_schema_defs(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str):
            prefix = "#/$defs/"
            if node["$ref"].startswith(prefix):
                ref_name = node["$ref"][len(prefix) :]
                if ref_name in defs:
                    resolved = dict(defs[ref_name])
                    for key, value in node.items():
                        if key != "$ref":
                            resolved[key] = value
                    return _inline_json_schema_defs(resolved, defs)
        inlined = {
            key: _inline_json_schema_defs(value, defs)
            for key, value in node.items()
            if key != "$defs"
        }
        if inlined.get("type") == "object" and "additionalProperties" not in inlined:
            inlined["additionalProperties"] = False
        return inlined
    if isinstance(node, list):
        return [_inline_json_schema_defs(item, defs) for item in node]
    return node


def build_s20_tool_parameter_schema(tool_name: AgentToolName) -> dict[str, Any]:
    """Export a flat, strict (`additionalProperties: false`) JSON Schema for Meta Muse."""
    args_cls = _TOOL_NAME_TO_ARGS_MODEL[tool_name]
    raw_schema = args_cls.model_json_schema()
    defs = raw_schema.get("$defs", {})
    flat_schema = _inline_json_schema_defs(raw_schema, defs if isinstance(defs, dict) else {})
    if not isinstance(flat_schema, dict):
        raise TypeError("Expected JSON Schema object dictionary")
    flat_schema["additionalProperties"] = False
    return flat_schema
