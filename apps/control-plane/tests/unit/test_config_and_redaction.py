"""Unit, property, security-canary, and integrity tests for U01.

Covers:
- AGENTS.md immutable SHA-256 contract verification
- Canonical wire primitives S-01..S-05 (UUIDv7, opaque provider IDs, UTC timestamps,
  SHA-256 digests, strict Decimal Money, ResourceBase, Problem+JSON, Page<T>, ActionReceipt)
- Canonical configuration schema (docs/25_CONFIG_SCHEMA.md), layered env overrides,
  retired-key rejection (CONFIG_RETIRED_KEY), and hard safety invariants (CONFIG_INVARIANT)
- Deterministic secret redaction engine v1 (token patterns + raw/URL/Base64 registered canaries)
- Structured JSON logging and OpenTelemetry span attribute/event ingress redaction (NFR-13, SEC-017)
"""

from __future__ import annotations

import base64
import io
import json
import logging
import pathlib
import urllib.parse
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import ValidationError

from py_contracts.primitives import (
    MAX_JSON_BODY_BYTES,
    ActionReceipt,
    InstanceResourceBase,
    Money,
    Page,
    PageParams,
    Problem,
    ProblemFieldError,
    WorkspaceResourceBase,
    new_uuid7,
    parse_uuid7_timestamp_ms,
    validate_idempotency_key_window,
)
from red2pr_control.core.config import (
    AiBudgetCaps,
    ConfigValidationError,
    Red2PrConfig,
    load_config,
    parse_config_yaml,
    validate_child_budget_within_parent,
)
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    build_problem,
    problem_from_exception,
)
from red2pr_control.core.integrity import (
    EXPECTED_AGENTS_MD_LF_SHA256,
    IntegrityCheckError,
    verify_agents_md_integrity,
)
from red2pr_control.core.logging import (
    RedactingSpanProcessor,
    StructuredJsonFormatter,
    bind_telemetry_context,
    get_structured_logger,
)
from red2pr_control.core.redaction import REDACTION_VERSION, Redactor

REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]


# ---------------------------------------------------------------------------
# 1. AGENTS.md Integrity Guard
# ---------------------------------------------------------------------------


def test_agents_md_integrity_matches_pinned_baseline() -> None:
    digest = verify_agents_md_integrity(REPO_ROOT / "AGENTS.md")
    assert digest == EXPECTED_AGENTS_MD_LF_SHA256


def test_agents_md_integrity_rejects_tampered_or_missing_file(tmp_path: pathlib.Path) -> None:
    missing = tmp_path / "AGENTS.md"
    with pytest.raises(IntegrityCheckError, match="missing"):
        verify_agents_md_integrity(missing)

    original = (REPO_ROOT / "AGENTS.md").read_bytes()
    tampered = tmp_path / "AGENTS_TAMPERED.md"
    tampered.write_bytes(original + b"\n# unauthorized edit\n")
    with pytest.raises(IntegrityCheckError, match="SHA-256 mismatch"):
        verify_agents_md_integrity(tampered)


def test_import_linter_z1_z2_z3_contracts_configured_and_enforced() -> None:
    import tomllib

    import grimp

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    contracts = {c["id"]: c for c in pyproject["tool"]["importlinter"]["contracts"]}
    assert {
        "contracts-remain-pure",
        "worker-zero-control-imports",
        "control-plane-z1-z2-boundaries",
        "cli-no-secret-or-worker-internals",
    }.issubset(contracts.keys())

    graph = grimp.build_graph("py_contracts", "red2pr_control", "red2pr_worker", "red2pr_cli")
    assert not graph.find_shortest_chain("red2pr_worker", "red2pr_control")
    assert not graph.find_shortest_chain("py_contracts", "red2pr_control")
    assert not graph.find_shortest_chain("red2pr_control.orchestrator", "red2pr_control.secrets")
    assert not graph.find_shortest_chain("red2pr_control.verification", "red2pr_control.publisher")


# ---------------------------------------------------------------------------
# 2. Wire Primitives S-01 .. S-05
# ---------------------------------------------------------------------------


def test_s01_uuid7_monotonic_timestamp_and_idempotency_window() -> None:
    fixed_now = datetime(2026, 10, 27, 6, 0, 0, tzinfo=UTC)
    key = new_uuid7(now=fixed_now)
    assert key[14] == "7"
    extracted_ms = parse_uuid7_timestamp_ms(key)
    assert extracted_ms == int(fixed_now.timestamp() * 1000)

    # Valid within <=7d age and <=5m future skew
    validate_idempotency_key_window(key, now=fixed_now + timedelta(days=6, hours=23))
    validate_idempotency_key_window(key, now=fixed_now - timedelta(minutes=4))

    # Expired (>7d old) -> key_expired
    with pytest.raises(ValueError, match="key_expired"):
        validate_idempotency_key_window(key, now=fixed_now + timedelta(days=7, seconds=1))

    # Excessive future skew (>5m ahead) -> invalid_idempotency_key
    with pytest.raises(ValueError, match="invalid_idempotency_key"):
        validate_idempotency_key_window(key, now=fixed_now - timedelta(minutes=6))

    # Non-v7 UUID (UUIDv4) -> invalid_idempotency_key
    uuid_v4 = "550e8400-e29b-41d4-a716-446655440000"
    with pytest.raises(ValueError, match="invalid_idempotency_key"):
        validate_idempotency_key_window(uuid_v4, now=fixed_now)


def test_s01_money_strict_decimal_rejects_float_and_bad_currency() -> None:
    m = Money(amount=Decimal("5.00"), currency="USD")
    dumped = m.model_dump(mode="json")
    assert dumped == {"amount": "5.00", "currency": "USD"}
    assert MAX_JSON_BODY_BYTES == 1_048_576

    # Float must be rejected to prevent IEEE-754 binary rounding drift
    with pytest.raises(ValidationError):
        Money.model_validate({"amount": 5.0, "currency": "USD"})

    # Negative amount, NaN, lowercase currency, and extra fields rejected
    with pytest.raises(ValidationError):
        Money.model_validate({"amount": "-0.01", "currency": "USD"})
    with pytest.raises(ValidationError):
        Money.model_validate({"amount": "NaN", "currency": "USD"})
    with pytest.raises(ValidationError):
        Money.model_validate({"amount": "1.00", "currency": "usd"})
    with pytest.raises(ValidationError):
        Money.model_validate({"amount": "1.00", "currency": "USD", "extra_key": 1})


@given(
    cents=st.integers(min_value=0, max_value=100_000_000),
    scale=st.integers(min_value=0, max_value=4),
)
@settings(max_examples=60, deadline=None)
def test_s01_money_property_roundtrip_preserves_exact_decimal(cents: int, scale: int) -> None:
    quant = Decimal(10) ** (-scale)
    value = (Decimal(cents) * quant).quantize(quant)
    m = Money(amount=value, currency="USD")
    restored = Money.model_validate_json(m.model_dump_json())
    assert restored.amount == value
    assert restored.currency == "USD"


def test_s01_s02_resource_bases_enforce_utc_opaque_ids_and_forbid_extra() -> None:
    rid = new_uuid7()
    ws_id = new_uuid7()
    ts = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone(timedelta(hours=7)))

    res = WorkspaceResourceBase(
        id=rid,
        workspace_id=ws_id,
        version=1,
        created_at=ts,
        updated_at=ts,
    )
    dumped = res.model_dump(mode="json")
    assert dumped["created_at"].endswith("Z")

    # Naive datetime rejected
    with pytest.raises(ValidationError):
        InstanceResourceBase(
            id=rid,
            version=1,
            created_at=datetime(2026, 10, 27, 12, 0, 0),
            updated_at=ts,
        )

    # Mass-assignment / unknown extra field rejected (422 contract)
    with pytest.raises(ValidationError):
        WorkspaceResourceBase.model_validate(
            {
                "id": rid,
                "workspace_id": ws_id,
                "version": 1,
                "created_at": "2026-10-27T05:00:00Z",
                "updated_at": "2026-10-27T05:00:00Z",
                "role": "admin",
            }
        )


def test_s03_s04_s05_problem_page_and_action_receipt_contracts() -> None:
    redactor = Redactor()
    redactor.register_canary("SUPER_SECRET_CANARY_9911")

    prob = build_problem(
        status=422,
        code="CONFIG_INVARIANT",
        title="Configuration invariant violated",
        detail=(
            "Rejected token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 "
            "and SUPER_SECRET_CANARY_9911"
        ),
        correlation_id="corr-001",
        errors=[
            ProblemFieldError(
                field="repository_defaults.require_baseline",
                code="must_be_true",
            )
        ],
        redactor=redactor,
    )
    assert PROBLEM_JSON_MEDIA_TYPE == "application/problem+json"
    assert "SUPER_SECRET_CANARY_9911" not in prob.detail
    assert "ghp_" not in prob.detail

    # Exception conversion strips internal tracebacks
    exc_prob = problem_from_exception(
        RuntimeError("internal db path /var/lib/postgresql password=topsecretvalue123"),
        correlation_id="corr-002",
        redactor=redactor,
    )
    assert exc_prob.status == 500
    assert "topsecretvalue123" not in exc_prob.detail
    assert "/var/lib/postgresql" not in exc_prob.detail

    # S-04 Page & PageParams bounds
    params = PageParams()
    assert params.limit == 25
    with pytest.raises(ValidationError):
        PageParams(limit=0)
    with pytest.raises(ValidationError):
        PageParams(limit=101)

    page = Page[Problem](
        items=[prob],
        next_cursor=None,
        snapshot_at=datetime(2026, 10, 27, 6, 0, 0, tzinfo=UTC),
    )
    assert len(page.items) == 1

    # S-05 ActionReceipt
    op_id = new_uuid7()
    target_id = new_uuid7()
    receipt = ActionReceipt(
        operation_id=op_id,
        resource_id=target_id,
        state="accepted",
        correlation_id="corr-001",
        status_url=f"/api/v1/operations/{op_id}",
    )
    assert receipt.state == "accepted"
    with pytest.raises(ValidationError):
        ActionReceipt(
            operation_id=op_id,
            resource_id=target_id,
            state="invented_state",  # type: ignore[arg-type]
            correlation_id="corr-001",
            status_url="/api/v1/operations/1",
        )


# ---------------------------------------------------------------------------
# 3. Canonical Configuration Parser & Hard Invariants (docs/25_CONFIG_SCHEMA.md)
# ---------------------------------------------------------------------------


def test_config_loads_doc25_canonical_yaml_and_enforces_defaults() -> None:
    doc25_yaml = """
schema_version: 1
instance:
  deployment_mode: local
  public_base_url: http://127.0.0.1:4280
  telemetry: local-only
ai:
  provider: meta
  primary_model: muse-spark-1.3
  escalation_model: null
  max_calls_per_session: 30
repository_defaults:
  mode: monitor
  require_baseline: true
  auto_merge: false
runtime:
  require_isolation_preflight: true
  network_execution: deny
notifications:
  telegram_enabled: false
"""
    cfg = parse_config_yaml(doc25_yaml)
    assert cfg.instance.deployment_mode == "local"
    assert cfg.ai.primary_model == "muse-spark-1.3"
    assert cfg.ai.max_tokens_per_session == 120_000
    assert cfg.ai.max_wall_seconds == 1800
    assert cfg.ai.max_cost_per_session == Money(amount=Decimal("5.00"), currency="USD")
    assert cfg.repository_defaults.mode == "monitor"
    assert cfg.repository_defaults.require_baseline is True
    assert cfg.repository_defaults.auto_merge is False
    assert cfg.runtime.network_execution == "deny"


@pytest.mark.parametrize(
    "payload",
    [
        {"provisional_pr_allowed": False},
        {"provisional_pr_allowed": True},
        {"allow_provisional_pr": False},
        {"repository_defaults": {"provisional_pr_allowed": False}},
        {"repository_defaults": {"allow_provisional_pr": True}},
        {"sandbox": {"network_execution": "deny"}},
        {"ai": {"max_tokens": 50000}},
        {"ai": {"max_calls": 10}},
    ],
)
def test_config_rejects_retired_keys_even_when_false(payload: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError) as exc_info:
        load_config(payload)
    assert exc_info.value.code == "CONFIG_RETIRED_KEY"


@pytest.mark.parametrize(
    ("payload", "env_overrides"),
    [
        ({"repository_defaults": {"require_baseline": False}}, {}),
        ({"repository_defaults": {"auto_merge": True}}, {}),
        ({"runtime": {"require_isolation_preflight": False}}, {}),
        ({"runtime": {"network_execution": "allow"}}, {}),
        ({"runtime": {"sandbox_backend": "host"}}, {}),
        ({}, {"RED2PR_REQUIRE_BASELINE": "false"}),
        ({}, {"RED2PR_AUTO_MERGE": "true"}),
        ({}, {"RED2PR_NETWORK_EXECUTION": "allow"}),
    ],
)
def test_config_rejects_hard_invariant_violations_in_file_or_env(
    payload: dict[str, Any],
    env_overrides: dict[str, str],
) -> None:
    with pytest.raises(ConfigValidationError) as exc_info:
        load_config(payload, env=env_overrides)
    assert exc_info.value.code == "CONFIG_INVARIANT"


def test_config_enforces_url_tls_rules_secret_refs_and_unknown_keys() -> None:
    # Server mode requires non-loopback HTTPS URL
    with pytest.raises(ConfigValidationError) as exc_info:
        load_config(
            {
                "instance": {
                    "deployment_mode": "server",
                    "public_base_url": "http://red2pr.example.com",
                }
            }
        )
    assert exc_info.value.code == "CONFIG_INVALID_VALUE"

    # Local mode forbids remote non-loopback HTTP URL
    with pytest.raises(ConfigValidationError):
        load_config(
            {
                "instance": {
                    "deployment_mode": "local",
                    "public_base_url": "http://192.168.1.50:4280",
                }
            }
        )

    # Plaintext token instead of opaque secret_ref (sec_* or ref:*) is rejected
    with pytest.raises(ConfigValidationError) as secret_exc:
        load_config(
            {
                "providers": {
                    "github": {
                        "app_id": "12345",
                        "webhook_secret_ref": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
                    }
                }
            }
        )
    assert secret_exc.value.code == "CONFIG_PLAINTEXT_SECRET_FORBIDDEN"

    # Valid opaque secret ref is accepted, and redacted export hides ref internals safely
    valid_cfg: Red2PrConfig = load_config(
        {
            "providers": {
                "github": {
                    "app_id": "12345",
                    "webhook_secret_ref": "sec_gh_webhook_v1",
                }
            }
        }
    )
    exported = valid_cfg.to_redacted_export_dict()
    assert exported["providers"]["github"]["webhook_secret_ref"] == {
        "configured": True,
        "versioned_ref": True,
    }
    assert "sec_gh_webhook_v1" not in json.dumps(exported)

    # Unknown top-level or nested keys rejected
    with pytest.raises(ConfigValidationError) as unknown_exc:
        load_config({"unexpected_namespace": {"foo": "bar"}})
    assert unknown_exc.value.code == "CONFIG_UNKNOWN_KEY"


@given(
    parent_calls=st.integers(min_value=1, max_value=100),
    child_calls=st.integers(min_value=1, max_value=100),
    parent_tokens=st.integers(min_value=1000, max_value=1_000_000),
    child_tokens=st.integers(min_value=1000, max_value=1_000_000),
)
@settings(max_examples=60, deadline=None)
def test_config_budget_hierarchy_property(
    parent_calls: int,
    child_calls: int,
    parent_tokens: int,
    child_tokens: int,
) -> None:
    parent = AiBudgetCaps(
        max_calls_per_session=parent_calls,
        max_tokens_per_session=parent_tokens,
        max_wall_seconds=1800,
        max_cost_per_session=Money(amount=Decimal("5.00"), currency="USD"),
    )
    child = AiBudgetCaps(
        max_calls_per_session=child_calls,
        max_tokens_per_session=child_tokens,
        max_wall_seconds=1800,
        max_cost_per_session=Money(amount=Decimal("5.00"), currency="USD"),
    )
    if child_calls <= parent_calls and child_tokens <= parent_tokens:
        validate_child_budget_within_parent(parent=parent, child=child)
    else:
        with pytest.raises(ConfigValidationError) as exc_info:
            validate_child_budget_within_parent(parent=parent, child=child)
        assert exc_info.value.code == "CONFIG_BUDGET_EXCEEDS_PARENT"


# ---------------------------------------------------------------------------
# 4. Deterministic Redaction Engine v1 & OTel / JSON Logging (SEC-017, NFR-13)
# ---------------------------------------------------------------------------


def test_redaction_engine_scrubs_provider_tokens_pem_and_sensitive_keys() -> None:
    redactor = Redactor()
    assert REDACTION_VERSION == "v1"

    pem_block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0123456789abcdef0123456789abcdef\n"
        "-----END RSA PRIVATE KEY-----"
    )
    gh_token = "ghp_" + "A" * 36
    gl_token = "glpat-" + "b" * 24
    slack_token = "-".join(("xoxb", "123456789012", "123456789012", "AbCdEfGhIjKlMnOpQrStUvWx"))
    tg_token = ":".join(("123456789", "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1"))
    bearer = "Authorization: Bearer super_secret_meta_api_key_99887766"
    cred_url = "https://git_user:my_super_secret_pw@gitlab.internal.local/group/repo.git"

    raw = f"{pem_block}\n{gh_token} {gl_token} {slack_token} {tg_token}\n{bearer}\n{cred_url}"
    scrubbed = redactor.redact_text(raw)

    assert "MIIEowIBAAKCAQEA" not in scrubbed
    assert gh_token not in scrubbed
    assert gl_token not in scrubbed
    assert slack_token not in scrubbed
    assert tg_token not in scrubbed
    assert "super_secret_meta_api_key_99887766" not in scrubbed
    assert "my_super_secret_pw" not in scrubbed

    original_payload: dict[str, Any] = {
        "safe_field": "pytest failed in test_auth.py",
        "nested": {
            "x-gitlab-token": "raw-gitlab-webhook-secret",
            "api_key": "meta-secret-value",
        },
    }
    redacted_payload = redactor.redact_value(original_payload)
    # Input dictionary is never mutated
    assert original_payload["nested"]["api_key"] == "meta-secret-value"
    assert redacted_payload["safe_field"] == "pytest failed in test_auth.py"
    assert "raw-gitlab-webhook-secret" not in json.dumps(redacted_payload)
    assert "meta-secret-value" not in json.dumps(redacted_payload)


@given(
    prefix=st.text(max_size=60),
    canary=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
        min_size=10,
        max_size=36,
    ),
    suffix=st.text(max_size=60),
)
@settings(max_examples=75, deadline=None)
def test_redaction_canary_property_blocks_raw_base64_and_url_encoded_leaks(
    prefix: str,
    canary: str,
    suffix: str,
) -> None:
    redactor = Redactor()
    redactor.register_canary(canary)

    b64_canary = base64.b64encode(canary.encode("utf-8")).decode("ascii")
    url_canary = urllib.parse.quote(canary + "!@#", safe="")
    redactor.register_canary(canary + "!@#")

    sample = {
        "line": f"{prefix}{canary}{suffix}",
        "encoded_b64": f"payload={b64_canary}",
        "encoded_url": f"https://example.test/cb?sec={url_canary}",
    }
    scrubbed = redactor.redact_value(sample)
    serialized = json.dumps(scrubbed)

    assert canary not in serialized
    assert b64_canary not in serialized
    assert url_canary not in serialized


def test_structured_json_logs_and_otel_spans_never_leak_secret_canaries() -> None:
    canary = "CANARY_META_MUSE_SECRET_2026_XYZ987"
    gh_canary = "ghs_" + "Z" * 36

    redactor = Redactor()
    redactor.register_canary(canary)

    # 1. Capture structured JSON logs
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(StructuredJsonFormatter(redactor=redactor))
    logger = get_structured_logger("red2pr_control.tests.u01", handler=handler)

    # 2. Capture OpenTelemetry spans through RedactingSpanProcessor -> InMemorySpanExporter
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(
        RedactingSpanProcessor(
            delegate=SimpleSpanProcessor(exporter),
            redactor=redactor,
        )
    )
    tracer = provider.get_tracer("red2pr_control.tests")

    ws_id = new_uuid7()
    with (
        bind_telemetry_context(
            correlation_id="corr-u01-canary",
            entry_point="webhook",
            workspace_id=ws_id,
            session_id="sess-01",
        ),
        tracer.start_as_current_span("webhook.ingest") as span,
    ):
        span.set_attribute("http.header.authorization", f"Bearer {canary}")
        span.set_attribute("provider.raw_excerpt", f"token={gh_canary}")
        span.record_exception(RuntimeError(f"upstream failed with key={canary}"))
        logger.info(
            f"ingested payload containing {canary} and {gh_canary}",
            extra={
                "event": "webhook.received",
                "attributes": {
                    "secret_header": canary,
                    "safe_repo": "octo/demo",
                },
            },
        )

    # Assert JSON log structure, correlation fields, and zero canary leak
    raw_log = stream.getvalue().strip()
    assert canary not in raw_log
    assert gh_canary not in raw_log

    parsed_log = json.loads(raw_log)
    assert parsed_log["correlation_id"] == "corr-u01-canary"
    assert parsed_log["entry_point"] == "webhook"
    assert parsed_log["workspace_id"] == ws_id
    assert parsed_log["session_id"] == "sess-01"
    assert parsed_log["event"] == "webhook.received"
    assert parsed_log["redaction_version"] == "v1"
    assert parsed_log["attributes"]["safe_repo"] == "octo/demo"

    # Assert OTel exported span attributes and exception events contain zero canary leak
    finished_spans = exporter.get_finished_spans()
    assert len(finished_spans) == 1
    exported_span = finished_spans[0]
    span_attrs_dump = json.dumps(dict(exported_span.attributes or {}))
    assert canary not in span_attrs_dump
    assert gh_canary not in span_attrs_dump

    events_dump = json.dumps([dict(ev.attributes or {}) for ev in exported_span.events])
    assert canary not in events_dump
    assert gh_canary not in events_dump
