"""Evidence-grounded global world state.

The rich brain state is persisted beside, rather than inside, the frozen
protocol ``world_state.json``. ``to_protocol_document`` provides a compatible
projection for existing protocol consumers without changing their contract.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Self

from pentestgpt_agent.protocol import Artifact, Evidence, TaskSpec, WorldStateDocument

from .handoffs import HandoffDescriptor


BRAIN_STATE_SCHEMA_VERSION = "1.0"
BRAIN_STATE_FILENAME = "hunter_brain_state.json"


def _nonempty(value: str, label: str) -> None:
    if not value.strip():
        raise ValueError(f"{label} must be nonempty")


def _unique_nonempty(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)) or any(not value.strip() for value in values):
        raise ValueError(f"{label} must contain unique nonempty values")


@dataclass(frozen=True)
class VerifiedFact:
    fact_id: str
    statement: str
    evidence_refs: tuple[str, ...]
    source_agent: str | None = None

    def __post_init__(self) -> None:
        _nonempty(self.fact_id, "fact_id")
        _nonempty(self.statement, "fact statement")
        _unique_nonempty(self.evidence_refs, "fact evidence_refs")
        if not self.evidence_refs:
            raise ValueError("verified fact requires evidence")


@dataclass(frozen=True)
class UnresolvedQuestion:
    question_id: str
    question: str
    priority: int = 50
    required_output_types: tuple[str, ...] = ()
    source: str = "user_goal"

    def __post_init__(self) -> None:
        _nonempty(self.question_id, "question_id")
        _nonempty(self.question, "question")
        _nonempty(self.source, "question source")
        if not 0 <= self.priority <= 100:
            raise ValueError("question priority must be between 0 and 100")
        _unique_nonempty(self.required_output_types, "required_output_types")


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    statement: str
    rationale: str
    evidence_refs: tuple[str, ...] = ()
    confidence: float | None = None

    def __post_init__(self) -> None:
        _nonempty(self.hypothesis_id, "hypothesis_id")
        _nonempty(self.statement, "hypothesis statement")
        _nonempty(self.rationale, "hypothesis rationale")
        _unique_nonempty(self.evidence_refs, "hypothesis evidence_refs")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("hypothesis confidence must be between 0 and 1")


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    evidence_type: str
    source: str
    description: str
    artifact_ref: str | None = None
    path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _nonempty(self.evidence_id, "evidence_id")
        _nonempty(self.evidence_type, "evidence_type")
        _nonempty(self.source, "evidence source")
        _nonempty(self.description, "evidence description")

    @classmethod
    def from_protocol(cls, evidence: Evidence) -> Self:
        evidence.validate()
        return cls(
            evidence_id=evidence.evidence_id,
            evidence_type=evidence.type,
            source=evidence.source,
            description=evidence.description,
            artifact_ref=evidence.artifact_ref,
            path=evidence.path,
            metadata=evidence.metadata,
        )


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    artifact_type: str
    path: str
    sha256: str
    size: int
    producer_agent: str
    source_task_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for label, value in (
            ("artifact_id", self.artifact_id),
            ("artifact_type", self.artifact_type),
            ("path", self.path),
            ("producer_agent", self.producer_agent),
            ("source_task_id", self.source_task_id),
        ):
            _nonempty(value, label)
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise ValueError("artifact sha256 must be 64 lowercase hexadecimal characters")
        if self.size < 0:
            raise ValueError("artifact size must be nonnegative")

    @classmethod
    def from_protocol(cls, artifact: Artifact, *, source_task_id: str) -> Self:
        artifact.validate()
        if artifact.producer is None:
            raise ValueError("world-state artifact requires a producer")
        return cls(
            artifact_id=artifact.artifact_id,
            artifact_type=artifact.type,
            path=artifact.path,
            sha256=artifact.sha256,
            size=artifact.size,
            producer_agent=artifact.producer,
            source_task_id=source_task_id,
            metadata=artifact.metadata,
        )


@dataclass(frozen=True)
class DispatchRecord:
    dispatch_id: str
    capability_id: str
    objective: str
    input_refs: tuple[str, ...]
    status: str
    new_evidence: bool
    new_facts: bool
    answered_question_ids: tuple[str, ...]
    budget_used: float
    failure_reason: str | None = None
    new_artifacts: bool = False
    question_id: str | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("dispatch_id", self.dispatch_id),
            ("capability_id", self.capability_id),
            ("objective", self.objective),
            ("status", self.status),
        ):
            _nonempty(value, label)
        _unique_nonempty(self.input_refs, "dispatch input_refs")
        _unique_nonempty(self.answered_question_ids, "answered_question_ids")
        if self.budget_used < 0:
            raise ValueError("dispatch budget_used must be nonnegative")
        if self.question_id is not None:
            _nonempty(self.question_id, "dispatch question_id")


@dataclass
class HunterWorldState:
    task_id: str
    user_goal: str
    success_conditions: tuple[str, ...] = ()
    facts: dict[str, VerifiedFact] = field(default_factory=dict)
    unresolved_questions: dict[str, UnresolvedQuestion] = field(default_factory=dict)
    hypotheses: dict[str, Hypothesis] = field(default_factory=dict)
    evidence: dict[str, EvidenceRecord] = field(default_factory=dict)
    artifacts: dict[str, ArtifactRecord] = field(default_factory=dict)
    dispatch_history: list[DispatchRecord] = field(default_factory=list)
    child_task_ids: set[str] = field(default_factory=set)
    schema_version: str = BRAIN_STATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _nonempty(self.task_id, "task_id")
        _nonempty(self.user_goal, "user_goal")
        _unique_nonempty(self.success_conditions, "success_conditions")
        self.validate()

    @classmethod
    def from_task(cls, task: TaskSpec) -> Self:
        task.validate()
        return cls(task.task_id, task.goal, task.success_conditions)

    def validate(self) -> None:
        if self.schema_version != BRAIN_STATE_SCHEMA_VERSION:
            raise ValueError(f"unsupported brain state schema_version: {self.schema_version!r}")
        for key, fact in self.facts.items():
            if key != fact.fact_id:
                raise ValueError("fact map key does not match fact_id")
            if not set(fact.evidence_refs).issubset(self.evidence):
                raise ValueError(f"fact {fact.fact_id!r} references unknown evidence")
        for key, question in self.unresolved_questions.items():
            if key != question.question_id:
                raise ValueError("question map key does not match question_id")
        for key, hypothesis in self.hypotheses.items():
            if key != hypothesis.hypothesis_id:
                raise ValueError("hypothesis map key does not match hypothesis_id")
            if not set(hypothesis.evidence_refs).issubset(self.evidence):
                raise ValueError(
                    f"hypothesis {hypothesis.hypothesis_id!r} references unknown evidence"
                )
        for key, evidence in self.evidence.items():
            if key != evidence.evidence_id:
                raise ValueError("evidence map key does not match evidence_id")
            if evidence.artifact_ref is not None and evidence.artifact_ref not in self.artifacts:
                raise ValueError(
                    f"evidence {evidence.evidence_id!r} references unknown artifact"
                )
        for key, artifact in self.artifacts.items():
            if key != artifact.artifact_id:
                raise ValueError("artifact map key does not match artifact_id")
            handoff = HandoffDescriptor.from_metadata(artifact.metadata)
            if handoff is not None:
                if handoff.semantic_type != artifact.artifact_type:
                    raise ValueError("handoff semantic type does not match artifact type")
                if handoff.source_task_id != artifact.source_task_id:
                    raise ValueError("handoff source task does not match artifact lineage")
                if not set(handoff.source_evidence_refs).issubset(self.evidence):
                    raise ValueError("handoff references unknown source evidence")
        if any(not child_id.strip() for child_id in self.child_task_ids):
            raise ValueError("child_task_ids must contain nonempty values")

    @staticmethod
    def _add_unique(collection: dict[str, Any], key: str, value: Any, label: str) -> None:
        existing = collection.get(key)
        if existing is not None and existing != value:
            raise ValueError(f"conflicting {label}: {key!r}")
        collection[key] = value

    def register_child_task(self, child_task_id: str) -> None:
        _nonempty(child_task_id, "child_task_id")
        if child_task_id == self.task_id:
            raise ValueError("child task must differ from the global task")
        self.child_task_ids.add(child_task_id)

    def add_artifact(self, artifact: ArtifactRecord) -> None:
        if artifact.source_task_id not in {self.task_id, *self.child_task_ids}:
            raise ValueError("artifact source_task_id is outside the world-state task lineage")
        self._add_unique(self.artifacts, artifact.artifact_id, artifact, "artifact")

    def add_evidence(self, evidence: EvidenceRecord) -> None:
        if evidence.artifact_ref is not None and evidence.artifact_ref not in self.artifacts:
            raise ValueError("evidence references an unknown artifact")
        self._add_unique(self.evidence, evidence.evidence_id, evidence, "evidence")

    def add_fact(self, fact: VerifiedFact) -> None:
        if not set(fact.evidence_refs).issubset(self.evidence):
            raise ValueError("verified fact references unknown evidence")
        self._add_unique(self.facts, fact.fact_id, fact, "fact")

    def add_question(self, question: UnresolvedQuestion) -> None:
        self._add_unique(
            self.unresolved_questions, question.question_id, question, "question"
        )

    def resolve_question(self, question_id: str, *, fact_refs: tuple[str, ...]) -> None:
        if question_id not in self.unresolved_questions:
            raise KeyError(f"unknown unresolved question: {question_id!r}")
        if not fact_refs or not set(fact_refs).issubset(self.facts):
            raise ValueError("resolved question requires known verified facts")
        del self.unresolved_questions[question_id]

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        if hypothesis.statement in {fact.statement for fact in self.facts.values()}:
            raise ValueError("a verified fact must not also be stored as a hypothesis")
        if not set(hypothesis.evidence_refs).issubset(self.evidence):
            raise ValueError("hypothesis references unknown evidence")
        self._add_unique(
            self.hypotheses, hypothesis.hypothesis_id, hypothesis, "hypothesis"
        )

    def record_dispatch(self, record: DispatchRecord) -> None:
        if any(item.dispatch_id == record.dispatch_id for item in self.dispatch_history):
            raise ValueError(f"duplicate dispatch_id: {record.dispatch_id!r}")
        self.dispatch_history.append(record)

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "user_goal": self.user_goal,
            "success_conditions": list(self.success_conditions),
            "facts": [asdict(item) for item in self.facts.values()],
            "unresolved_questions": [
                asdict(item) for item in self.unresolved_questions.values()
            ],
            "hypotheses": [asdict(item) for item in self.hypotheses.values()],
            "evidence": [asdict(item) for item in self.evidence.values()],
            "artifacts": [asdict(item) for item in self.artifacts.values()],
            "dispatch_history": [asdict(item) for item in self.dispatch_history],
            "child_task_ids": sorted(self.child_task_ids),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Self:
        def records(name: str, record_type: type[Any], key: str) -> dict[str, Any]:
            raw = value.get(name, [])
            if not isinstance(raw, list):
                raise ValueError(f"{name} must be an array")
            result: dict[str, Any] = {}
            for entry in raw:
                if not isinstance(entry, dict):
                    raise ValueError(f"{name} entries must be objects")
                converted = dict(entry)
                for tuple_field in (
                    "evidence_refs",
                    "required_output_types",
                    "input_refs",
                    "answered_question_ids",
                ):
                    if tuple_field in converted:
                        converted[tuple_field] = tuple(converted[tuple_field])
                item = record_type(**converted)
                identifier = getattr(item, key)
                if identifier in result:
                    raise ValueError(f"duplicate {key}: {identifier!r}")
                result[identifier] = item
            return result

        history_raw = value.get("dispatch_history", [])
        if not isinstance(history_raw, list):
            raise ValueError("dispatch_history must be an array")
        history = []
        for entry in history_raw:
            if not isinstance(entry, dict):
                raise ValueError("dispatch_history entries must be objects")
            converted = dict(entry)
            converted["input_refs"] = tuple(converted.get("input_refs", []))
            converted["answered_question_ids"] = tuple(
                converted.get("answered_question_ids", [])
            )
            history.append(DispatchRecord(**converted))
        children_raw = value.get("child_task_ids", [])
        if not isinstance(children_raw, list) or any(
            not isinstance(item, str) for item in children_raw
        ):
            raise ValueError("child_task_ids must be an array of strings")
        state = cls(
            task_id=str(value["task_id"]),
            user_goal=str(value["user_goal"]),
            success_conditions=tuple(value.get("success_conditions", [])),
            facts=records("facts", VerifiedFact, "fact_id"),
            unresolved_questions=records(
                "unresolved_questions", UnresolvedQuestion, "question_id"
            ),
            hypotheses=records("hypotheses", Hypothesis, "hypothesis_id"),
            evidence=records("evidence", EvidenceRecord, "evidence_id"),
            artifacts=records("artifacts", ArtifactRecord, "artifact_id"),
            dispatch_history=history,
            child_task_ids=set(children_raw),
            schema_version=str(value.get("schema_version", "")),
        )
        state.validate()
        return state

    def to_protocol_document(self) -> WorldStateDocument:
        """Project rich state into the existing frozen protocol document."""

        self.validate()
        return WorldStateDocument(
            task_id=self.task_id,
            facts=[asdict(item) for item in self.facts.values()],
            questions=[asdict(item) for item in self.unresolved_questions.values()],
            hypotheses=[asdict(item) for item in self.hypotheses.values()],
            evidence=[asdict(item) for item in self.evidence.values()],
            history=[asdict(item) for item in self.dispatch_history],
        )

    def save(self, run_directory: Path) -> Path:
        """Atomically save brain-owned state inside one existing task directory."""

        resolved_run = run_directory.resolve()
        if resolved_run.name != self.task_id or not resolved_run.is_dir():
            raise ValueError("run_directory must be the existing directory for this task")
        target = resolved_run / BRAIN_STATE_FILENAME
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{BRAIN_STATE_FILENAME}.", dir=resolved_run
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(self.to_dict(), stream, ensure_ascii=False, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, target)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
        return target

    @classmethod
    def load(cls, run_directory: Path) -> Self:
        path = run_directory.resolve() / BRAIN_STATE_FILENAME
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("brain state must be a JSON object")
        state = cls.from_dict(value)
        if path.parent.name != state.task_id:
            raise ValueError("brain state task_id does not match run directory")
        return state
