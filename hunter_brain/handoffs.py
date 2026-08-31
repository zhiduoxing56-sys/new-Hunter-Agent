"""Backend-neutral, authorization-preserving cross-domain handoff metadata."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Self


HANDOFF_METADATA_KEY = "hunter_handoff"
HANDOFF_SCHEMA_VERSION = "1.0"


class HandoffCarrier(StrEnum):
    FILE = "file"
    VALUE = "value"


@dataclass(frozen=True)
class HandoffDescriptor:
    """Semantic input carried by a normal protocol ``Artifact``.

    This is deliberately capability-agnostic. Routing remains a catalogue
    lookup from ``semantic_type`` to compatible capabilities.
    """

    semantic_type: str
    carrier: HandoffCarrier
    values: tuple[str, ...]
    source_task_id: str
    source_evidence_refs: tuple[str, ...]
    allowed_targets: tuple[str, ...] = ()
    schema_version: str = HANDOFF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != HANDOFF_SCHEMA_VERSION:
            raise ValueError(f"unsupported handoff schema_version: {self.schema_version!r}")
        for label, value in (
            ("semantic_type", self.semantic_type),
            ("source_task_id", self.source_task_id),
        ):
            if not value.strip():
                raise ValueError(f"handoff {label} must be nonempty")
        for label, values in (
            ("values", self.values),
            ("source_evidence_refs", self.source_evidence_refs),
            ("allowed_targets", self.allowed_targets),
        ):
            if len(values) != len(set(values)) or any(not item.strip() for item in values):
                raise ValueError(f"handoff {label} must contain unique nonempty strings")
        if not self.source_evidence_refs:
            raise ValueError("handoff requires source evidence")
        if self.carrier is HandoffCarrier.VALUE:
            if len(self.values) != 1:
                raise ValueError("value handoff must carry exactly one value")
            if self.values[0] not in self.allowed_targets:
                raise ValueError("value handoff must be explicitly authorized")
        elif self.values:
            raise ValueError("file handoff values must be empty")

    def to_metadata(self) -> dict[str, Any]:
        return {
            HANDOFF_METADATA_KEY: {
                "schema_version": self.schema_version,
                "semantic_type": self.semantic_type,
                "carrier": self.carrier.value,
                "values": list(self.values),
                "source_task_id": self.source_task_id,
                "source_evidence_refs": list(self.source_evidence_refs),
                "authorization": {"allowed_targets": list(self.allowed_targets)},
            }
        }

    @classmethod
    def from_metadata(cls, metadata: dict[str, Any]) -> Self | None:
        raw = metadata.get(HANDOFF_METADATA_KEY)
        if raw is None:
            return None
        if not isinstance(raw, dict):
            raise ValueError("hunter_handoff metadata must be an object")
        authorization = raw.get("authorization", {})
        if not isinstance(authorization, dict):
            raise ValueError("handoff authorization must be an object")
        return cls(
            semantic_type=_string(raw.get("semantic_type"), "semantic_type"),
            carrier=HandoffCarrier(_string(raw.get("carrier"), "carrier")),
            values=_string_tuple(raw.get("values", []), "values"),
            source_task_id=_string(raw.get("source_task_id"), "source_task_id"),
            source_evidence_refs=_string_tuple(
                raw.get("source_evidence_refs", []), "source_evidence_refs"
            ),
            allowed_targets=_string_tuple(
                authorization.get("allowed_targets", []), "allowed_targets"
            ),
            schema_version=_string(raw.get("schema_version"), "schema_version"),
        )

    def authorized_value(self, parent_allowed_targets: set[str]) -> str:
        if self.carrier is not HandoffCarrier.VALUE:
            raise ValueError("file handoff does not carry a direct value")
        value = self.values[0]
        if value not in parent_allowed_targets:
            raise ValueError("handoff value is outside the parent authorization scope")
        return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"handoff {label} must be a nonempty string")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"handoff {label} must be an array of strings")
    return tuple(value)
