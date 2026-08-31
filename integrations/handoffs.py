"""Materialize backend-neutral handoffs through the frozen Artifact contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hunter_brain.handoffs import HandoffDescriptor
from pentestgpt_agent.protocol import Artifact, RunLayout


def materialize_handoff(
    layout: RunLayout,
    *,
    artifact_id: str,
    descriptor: HandoffDescriptor,
    payload: dict[str, Any],
    producer: str,
) -> Artifact:
    """Write an immutable JSON carrier and return its protocol Artifact."""
    if not artifact_id.strip() or not producer.strip():
        raise ValueError("handoff artifact_id and producer must be nonempty")
    path = layout.artifacts / "handoffs" / f"{artifact_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": descriptor.schema_version,
        "semantic_type": descriptor.semantic_type,
        "payload": payload,
    }
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return Artifact.from_path(
        artifact_id,
        descriptor.semantic_type,
        path,
        producer=producer,
        **descriptor.to_metadata(),
    )


def handoff_payload(path: Path, descriptor: HandoffDescriptor) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("handoff document must be an object")
    if value.get("schema_version") != descriptor.schema_version:
        raise ValueError("handoff document schema does not match artifact metadata")
    if value.get("semantic_type") != descriptor.semantic_type:
        raise ValueError("handoff document type does not match artifact metadata")
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("handoff payload must be an object")
    return payload
