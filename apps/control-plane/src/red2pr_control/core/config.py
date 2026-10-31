"""Canonical configuration schema, precedence, and safety invariants (docs/25_CONFIG_SCHEMA.md)."""

from __future__ import annotations

import copy
import os
import re
import urllib.parse
from collections.abc import Mapping
from decimal import Decimal
from typing import Annotated, Any, Literal

import yaml
from pydantic import Field, StrictBool, StrictInt, StrictStr, ValidationError

from py_contracts.primitives import Money, ProblemFieldError, StrictContractModel
from red2pr_control.core.errors import Red2PrError

DeploymentMode = Literal["local", "server", "distributed"]
StorageBackend = Literal["local", "s3-compatible"]
TelemetryMode = Literal["local-only", "otlp"]
InferenceDataPolicy = Literal["consent_required", "public_only", "disabled"]
SandboxBackend = Literal["docker", "podman", "gvisor", "microvm"]
GitLabAuthMode = Literal["signed_webhook", "secret_token"]
TelegramDeliveryMode = Literal["polling", "webhook"]
NotificationSeverity = Literal["info", "warning", "high", "critical"]
RepoRepairMode = Literal["monitor", "approval", "auto_repair"]

_SECRET_REF_RE = re.compile(r"^(?:sec_[A-Za-z0-9_-]{3,120}|ref:[A-Za-z0-9_.:/-]{3,120})$")
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})

_RETIRED_ROOT_KEYS: dict[str, str] = {
    "provisional_pr_allowed": "Provisional PR publication is prohibited under ADR-031.",
    "allow_provisional_pr": "Provisional PR publication is prohibited under ADR-031.",
    "sandbox": "Namespace 'sandbox' was retired; migrate settings under 'runtime.*'.",
}
_RETIRED_REPO_KEYS: dict[str, str] = {
    "provisional_pr_allowed": "Provisional PR publication is prohibited under ADR-031.",
    "allow_provisional_pr": "Provisional PR publication is prohibited under ADR-031.",
}
_RETIRED_AI_KEYS: dict[str, str] = {
    "max_tokens": "Retired ambiguous key 'ai.max_tokens'; use 'ai.max_tokens_per_session'.",
    "max_calls": "Retired ambiguous key 'ai.max_calls'; use 'ai.max_calls_per_session'.",
    "max_cost": "Retired ambiguous key 'ai.max_cost'; use 'ai.max_cost_per_session'.",
}
_FORBIDDEN_PLAINTEXT_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "bot_token",
        "client_secret",
        "master_key",
        "password",
        "private_key",
        "secret",
        "smtp_password",
        "token",
        "webhook_secret",
    }
)
_FORBIDDEN_HOST_SANDBOX_VALUES: frozenset[str] = frozenset(
    {"host", "shell", "local_shell", "none", "disabled"}
)


class ConfigValidationError(Red2PrError):
    """Deterministic configuration validation or safety-invariant failure."""

    def __init__(
        self,
        *,
        code: str,
        detail: str,
        field: str | None = None,
    ) -> None:
        errors = [ProblemFieldError(field=field, code=code)] if field else None
        super().__init__(
            code=code,
            title="Invalid configuration",
            detail=detail,
            status=422,
            errors=errors,
        )


class InstanceBackupConfig(StrictContractModel):
    retention_days: Annotated[StrictInt, Field(ge=1, le=3650)] = 30


class InstanceConfig(StrictContractModel):
    deployment_mode: DeploymentMode = "local"
    public_base_url: StrictStr = "http://127.0.0.1:4280"
    storage_backend: StorageBackend = "local"
    telemetry: TelemetryMode = "local-only"
    backup: InstanceBackupConfig = Field(default_factory=InstanceBackupConfig)


class SecurityBootstrapConfig(StrictContractModel):
    expires_minutes: Annotated[StrictInt, Field(ge=5, le=60)] = 30


class SecurityConfig(StrictContractModel):
    bootstrap: SecurityBootstrapConfig = Field(default_factory=SecurityBootstrapConfig)
    raw_log_retention_days: Annotated[StrictInt, Field(ge=1, le=365)] = 7
    artifact_retention_days: Annotated[StrictInt, Field(ge=1, le=3650)] = 30
    tombstone_retention_days: Annotated[StrictInt, Field(ge=90, le=3650)] = 90
    audit_retention_days: Annotated[StrictInt, Field(ge=365, le=3650)] = 365
    inference_data_policy: InferenceDataPolicy = "consent_required"


class RuntimeConfig(StrictContractModel):
    sandbox_backend: SandboxBackend = "docker"
    require_isolation_preflight: StrictBool = True
    network_execution: Literal["deny"] = "deny"
    egress_policy: Literal["deny_by_default"] = "deny_by_default"
    worker_concurrency: Annotated[StrictInt, Field(ge=1, le=64)] = 2
    cpu_cores: Annotated[StrictInt, Field(ge=1, le=64)] = 4
    memory_mib: Annotated[StrictInt, Field(ge=512, le=262_144)] = 8192
    disk_mib: Annotated[StrictInt, Field(ge=1024, le=1_048_576)] = 40_960
    time_limit_seconds: Annotated[StrictInt, Field(ge=60, le=7200)] = 1800


class GitHubProviderConfig(StrictContractModel):
    app_id: StrictStr | None = None
    installation_id: StrictStr | None = None
    webhook_secret_ref: StrictStr | None = None


class GitLabProviderConfig(StrictContractModel):
    base_url: StrictStr = "https://gitlab.com"
    secret_ref: StrictStr | None = None
    auth_mode: GitLabAuthMode = "signed_webhook"


class ProvidersConfig(StrictContractModel):
    github: GitHubProviderConfig = Field(default_factory=GitHubProviderConfig)
    gitlab: GitLabProviderConfig = Field(default_factory=GitLabProviderConfig)


class AiBudgetCaps(StrictContractModel):
    """Canonical NFR-06 per-session AI spend and execution caps."""

    max_calls_per_session: Annotated[StrictInt, Field(ge=1, le=100)] = 30
    max_tokens_per_session: Annotated[StrictInt, Field(ge=1, le=1_000_000)] = 120_000
    max_wall_seconds: Annotated[StrictInt, Field(ge=60, le=7200)] = 1800
    max_cost_per_session: Money = Field(
        default_factory=lambda: Money(amount=Decimal("5.00"), currency="USD")
    )


class AiConfig(AiBudgetCaps):
    provider: Literal["meta"] = "meta"
    primary_model: StrictStr = "muse-spark-1.3"
    escalation_model: StrictStr | None = None


class NotificationsConfig(StrictContractModel):
    telegram_enabled: StrictBool = False
    telegram_bot_token_ref: StrictStr | None = None
    telegram_delivery_mode: TelegramDeliveryMode = "polling"
    min_severity: NotificationSeverity = "info"
    language: Literal["en"] = "en"


class RepositoryDefaultsConfig(StrictContractModel):
    mode: RepoRepairMode = "monitor"
    branch_allowlist: list[StrictStr] = Field(default_factory=list)
    file_denylist: list[StrictStr] = Field(default_factory=list)
    sensitive_file_rules: list[StrictStr] = Field(
        default_factory=lambda: [
            ".github/workflows/**",
            ".gitlab-ci.yml",
            "**/Dockerfile*",
        ]
    )
    max_attempts: Annotated[StrictInt, Field(ge=1, le=5)] = 2
    max_diff_lines: Annotated[StrictInt, Field(ge=1, le=2000)] = 500
    require_baseline: StrictBool = True
    auto_merge: StrictBool = False


class Red2PrConfig(StrictContractModel):
    """Authoritative instance configuration validated against docs/25_CONFIG_SCHEMA.md."""

    schema_version: Literal[1] = 1
    instance: InstanceConfig = Field(default_factory=InstanceConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    providers: ProvidersConfig = Field(default_factory=ProvidersConfig)
    ai: AiConfig = Field(default_factory=AiConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    repository_defaults: RepositoryDefaultsConfig = Field(default_factory=RepositoryDefaultsConfig)

    def to_redacted_export_dict(self) -> dict[str, Any]:
        """Export schema-versioned settings with secret references replaced by safe status."""
        dumped: dict[str, Any] = self.model_dump(mode="json")
        gh = dumped["providers"]["github"]
        gl = dumped["providers"]["gitlab"]
        notif = dumped["notifications"]

        gh["webhook_secret_ref"] = _redact_secret_ref_status(
            self.providers.github.webhook_secret_ref
        )
        gl["secret_ref"] = _redact_secret_ref_status(self.providers.gitlab.secret_ref)
        notif["telegram_bot_token_ref"] = _redact_secret_ref_status(
            self.notifications.telegram_bot_token_ref
        )
        return dumped


def _redact_secret_ref_status(ref: str | None) -> dict[str, bool]:
    return {"configured": ref is not None, "versioned_ref": ref is not None}


def _parse_env_bool(raw: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigValidationError(
        code="CONFIG_INVALID_VALUE",
        detail=f"Invalid boolean environment value: {raw!r}",
    )


def _apply_bootstrap_env_overrides(data: dict[str, Any], env: Mapping[str, str]) -> None:
    if "RED2PR_DEPLOYMENT_MODE" in env:
        data.setdefault("instance", {})["deployment_mode"] = env["RED2PR_DEPLOYMENT_MODE"].strip()
    if "RED2PR_PUBLIC_BASE_URL" in env:
        data.setdefault("instance", {})["public_base_url"] = env["RED2PR_PUBLIC_BASE_URL"].strip()
    if "RED2PR_REQUIRE_BASELINE" in env:
        data.setdefault("repository_defaults", {})["require_baseline"] = _parse_env_bool(
            env["RED2PR_REQUIRE_BASELINE"]
        )
    if "RED2PR_AUTO_MERGE" in env:
        data.setdefault("repository_defaults", {})["auto_merge"] = _parse_env_bool(
            env["RED2PR_AUTO_MERGE"]
        )
    if "RED2PR_NETWORK_EXECUTION" in env:
        data.setdefault("runtime", {})["network_execution"] = env[
            "RED2PR_NETWORK_EXECUTION"
        ].strip()


def _check_retired_and_secret_keys(raw: Mapping[str, Any]) -> None:
    for root_key, message in _RETIRED_ROOT_KEYS.items():
        if root_key in raw:
            raise ConfigValidationError(
                code="CONFIG_RETIRED_KEY",
                detail=message,
                field=root_key,
            )

    repo_defaults = raw.get("repository_defaults")
    if isinstance(repo_defaults, Mapping):
        for r_key, message in _RETIRED_REPO_KEYS.items():
            if r_key in repo_defaults:
                raise ConfigValidationError(
                    code="CONFIG_RETIRED_KEY",
                    detail=message,
                    field=f"repository_defaults.{r_key}",
                )

    ai_section = raw.get("ai")
    if isinstance(ai_section, Mapping):
        for ai_key, message in _RETIRED_AI_KEYS.items():
            if ai_key in ai_section:
                raise ConfigValidationError(
                    code="CONFIG_RETIRED_KEY",
                    detail=message,
                    field=f"ai.{ai_key}",
                )

    _scan_forbidden_secret_fields(raw, prefix="")


def _scan_forbidden_secret_fields(node: Any, *, prefix: str) -> None:
    if not isinstance(node, Mapping):
        return
    for k, v in node.items():
        key_str = str(k)
        path = f"{prefix}.{key_str}" if prefix else key_str
        if key_str.lower() in _FORBIDDEN_PLAINTEXT_SECRET_KEYS:
            raise ConfigValidationError(
                code="CONFIG_PLAINTEXT_SECRET_FORBIDDEN",
                detail=f"Plaintext secret key {path!r} is forbidden; use an opaque *_secret_ref.",
                field=path,
            )
        if (
            key_str.endswith(("_secret_ref", "_token_ref"))
            and v is not None
            and (not isinstance(v, str) or not _SECRET_REF_RE.fullmatch(v))
        ):
            raise ConfigValidationError(
                code="CONFIG_PLAINTEXT_SECRET_FORBIDDEN",
                detail=(
                    f"Field {path!r} must be an opaque secret broker reference "
                    "matching 'sec_*' or 'ref:*', never a raw credential."
                ),
                field=path,
            )
        if isinstance(v, Mapping):
            _scan_forbidden_secret_fields(v, prefix=path)


def _check_hard_invariants(raw: Mapping[str, Any]) -> None:
    repo_defaults = raw.get("repository_defaults")
    if isinstance(repo_defaults, Mapping):
        if "require_baseline" in repo_defaults and repo_defaults["require_baseline"] is not True:
            raise ConfigValidationError(
                code="CONFIG_INVARIANT",
                detail="repository_defaults.require_baseline must always be true (ADR-031).",
                field="repository_defaults.require_baseline",
            )
        if "auto_merge" in repo_defaults and repo_defaults["auto_merge"] is not False:
            raise ConfigValidationError(
                code="CONFIG_INVARIANT",
                detail="repository_defaults.auto_merge must always be false (ADR-010).",
                field="repository_defaults.auto_merge",
            )

    runtime_cfg = raw.get("runtime")
    if isinstance(runtime_cfg, Mapping):
        if (
            "require_isolation_preflight" in runtime_cfg
            and runtime_cfg["require_isolation_preflight"] is not True
        ):
            raise ConfigValidationError(
                code="CONFIG_INVARIANT",
                detail="runtime.require_isolation_preflight cannot be disabled.",
                field="runtime.require_isolation_preflight",
            )
        if "network_execution" in runtime_cfg and runtime_cfg["network_execution"] != "deny":
            raise ConfigValidationError(
                code="CONFIG_INVARIANT",
                detail="runtime.network_execution must be 'deny' during sandbox test phases.",
                field="runtime.network_execution",
            )
        backend = runtime_cfg.get("sandbox_backend")
        if isinstance(backend, str) and backend.lower() in _FORBIDDEN_HOST_SANDBOX_VALUES:
            raise ConfigValidationError(
                code="CONFIG_INVARIANT",
                detail="Fallback to host shell execution is permanently prohibited.",
                field="runtime.sandbox_backend",
            )


def _validate_urls_and_modes(cfg: Red2PrConfig) -> None:
    parsed = urllib.parse.urlparse(cfg.instance.public_base_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        raise ConfigValidationError(
            code="CONFIG_INVALID_VALUE",
            detail="instance.public_base_url must be a valid http(s) URL with hostname.",
            field="instance.public_base_url",
        )

    if cfg.instance.deployment_mode in {"server", "distributed"}:
        if parsed.scheme != "https" or host in _LOOPBACK_HOSTS:
            raise ConfigValidationError(
                code="CONFIG_INVALID_VALUE",
                detail=(
                    "server and distributed modes require a non-loopback https:// public_base_url."
                ),
                field="instance.public_base_url",
            )
    elif parsed.scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise ConfigValidationError(
            code="CONFIG_INVALID_VALUE",
            detail=(
                "Plain HTTP public_base_url is permitted only on loopback addresses in local mode."
            ),
            field="instance.public_base_url",
        )


def load_config(
    raw_config: Mapping[str, Any] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> Red2PrConfig:
    """Validate layered configuration and enforce non-overridable safety invariants."""
    merged: dict[str, Any] = copy.deepcopy(dict(raw_config)) if raw_config is not None else {}
    effective_env = env if env is not None else os.environ

    _check_retired_and_secret_keys(merged)
    _apply_bootstrap_env_overrides(merged, effective_env)
    _check_retired_and_secret_keys(merged)
    _check_hard_invariants(merged)

    try:
        validated = Red2PrConfig.model_validate(merged)
    except ValidationError as exc:
        first_err = exc.errors()[0]
        loc = ".".join(str(part) for part in first_err.get("loc", ()))
        if any(err.get("type") == "extra_forbidden" for err in exc.errors()):
            raise ConfigValidationError(
                code="CONFIG_UNKNOWN_KEY",
                detail=f"Unknown configuration key at {loc or '<root>'}.",
                field=loc or None,
            ) from exc
        raise ConfigValidationError(
            code="CONFIG_INVALID_VALUE",
            detail=f"Invalid configuration value at {loc or '<root>'}: {first_err.get('msg')}",
            field=loc or None,
        ) from exc

    _validate_urls_and_modes(validated)
    return validated


def parse_config_yaml(
    yaml_text: str,
    *,
    env: Mapping[str, str] | None = None,
) -> Red2PrConfig:
    """Safely parse YAML configuration text (yaml.safe_load) and validate invariants."""
    loaded = yaml.safe_load(yaml_text)
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, Mapping):
        raise ConfigValidationError(
            code="CONFIG_INVALID_VALUE",
            detail="Root YAML configuration document must be a mapping.",
        )
    return load_config(loaded, env=env)


def validate_child_budget_within_parent(
    *,
    parent: AiBudgetCaps,
    child: AiBudgetCaps,
) -> None:
    """Ensure workspace/repository AI caps never exceed instance/parent ceilings."""
    if child.max_calls_per_session > parent.max_calls_per_session:
        raise ConfigValidationError(
            code="CONFIG_BUDGET_EXCEEDS_PARENT",
            detail="Child max_calls_per_session exceeds parent ceiling.",
            field="ai.max_calls_per_session",
        )
    if child.max_tokens_per_session > parent.max_tokens_per_session:
        raise ConfigValidationError(
            code="CONFIG_BUDGET_EXCEEDS_PARENT",
            detail="Child max_tokens_per_session exceeds parent ceiling.",
            field="ai.max_tokens_per_session",
        )
    if child.max_wall_seconds > parent.max_wall_seconds:
        raise ConfigValidationError(
            code="CONFIG_BUDGET_EXCEEDS_PARENT",
            detail="Child max_wall_seconds exceeds parent ceiling.",
            field="ai.max_wall_seconds",
        )
    if child.max_cost_per_session.currency != parent.max_cost_per_session.currency:
        raise ConfigValidationError(
            code="CONFIG_INVALID_VALUE",
            detail="Child budget currency must match parent budget currency.",
            field="ai.max_cost_per_session.currency",
        )
    if child.max_cost_per_session.amount > parent.max_cost_per_session.amount:
        raise ConfigValidationError(
            code="CONFIG_BUDGET_EXCEEDS_PARENT",
            detail="Child max_cost_per_session exceeds parent ceiling.",
            field="ai.max_cost_per_session.amount",
        )
