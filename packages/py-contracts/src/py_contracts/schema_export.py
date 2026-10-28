"""Deterministic JSON Schema exporter for S-19..S-22 canonical wire contracts."""

from __future__ import annotations

import json
import pathlib
from typing import Any

from py_contracts.events import EventEnvelope
from py_contracts.evidence import EvidenceManifestV1
from py_contracts.primitives import StrictContractModel
from py_contracts.tools import ToolCallRequest, ToolCallResponse
from py_contracts.worker import (
    ResultV1,
    SandboxJobV1,
    WorkerArtifactUploadRequest,
    WorkerArtifactUploadResponse,
    WorkerCancelAckRequest,
    WorkerCancelAckResponse,
    WorkerEnrollHandshakeRequest,
    WorkerEnrollHandshakeResponse,
    WorkerJobHeartbeatRequest,
    WorkerJobHeartbeatResponse,
    WorkerJobResultReceipt,
    WorkerPollRequest,
    WorkerPollResponse,
)


class AgentToolProtocolSchemaBundle(StrictContractModel):
    """Combined JSON Schema root for S-20 ToolCallRequest and ToolCallResponse."""

    request: ToolCallRequest
    response: ToolCallResponse


class SandboxWorkerSchemaBundle(StrictContractModel):
    """Combined JSON Schema root for S-21 SandboxJobV1, ResultV1, and mTLS worker wire DTOs."""

    job: SandboxJobV1
    result: ResultV1
    enroll_request: WorkerEnrollHandshakeRequest | None = None
    enroll_response: WorkerEnrollHandshakeResponse | None = None
    poll_request: WorkerPollRequest | None = None
    poll_response: WorkerPollResponse | None = None
    heartbeat_request: WorkerJobHeartbeatRequest | None = None
    heartbeat_response: WorkerJobHeartbeatResponse | None = None
    upload_request: WorkerArtifactUploadRequest | None = None
    upload_response: WorkerArtifactUploadResponse | None = None
    result_receipt: WorkerJobResultReceipt | None = None
    cancel_ack_request: WorkerCancelAckRequest | None = None
    cancel_ack_response: WorkerCancelAckResponse | None = None


def _format_schema_json(schema: dict[str, Any], *, schema_id: str) -> str:
    enriched: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://red2pr.local/schemas/{schema_id}",
        **schema,
    }
    return json.dumps(enriched, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_canonical_json_schemas() -> dict[str, str]:
    """Render deterministic JSON Schema documents for S-19, S-20, S-21, and S-22."""
    return {
        "s19-event-envelope.v1.schema.json": _format_schema_json(
            EventEnvelope.model_json_schema(),
            schema_id="s19-event-envelope.v1.schema.json",
        ),
        "s20-agent-tool-protocol.v1.schema.json": _format_schema_json(
            AgentToolProtocolSchemaBundle.model_json_schema(),
            schema_id="s20-agent-tool-protocol.v1.schema.json",
        ),
        "s21-sandbox-worker.v1.schema.json": _format_schema_json(
            SandboxWorkerSchemaBundle.model_json_schema(),
            schema_id="s21-sandbox-worker.v1.schema.json",
        ),
        "s22-evidence-manifest.v1.schema.json": _format_schema_json(
            EvidenceManifestV1.model_json_schema(),
            schema_id="s22-evidence-manifest.v1.schema.json",
        ),
    }


def write_canonical_json_schemas(output_dir: pathlib.Path) -> list[pathlib.Path]:
    """Write deterministic S-19..S-22 JSON Schema files to contracts/schemas/."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[pathlib.Path] = []
    for filename, content in render_canonical_json_schemas().items():
        path = output_dir / filename
        path.write_text(content, encoding="utf-8", newline="\n")
        written.append(path)
    return written
