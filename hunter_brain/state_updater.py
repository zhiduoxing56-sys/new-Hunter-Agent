"""Deterministic and transactional AgentResult-to-world-state updates."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib

from pentestgpt_agent.protocol import AgentResult, TaskSpec

from .handoffs import HANDOFF_METADATA_KEY, HandoffDescriptor
from .state import (
    ArtifactRecord,
    EvidenceRecord,
    HunterWorldState,
    Hypothesis,
    UnresolvedQuestion,
    VerifiedFact,
)


@dataclass(frozen=True)
class QuestionResolution:
    """A semantic assertion that known facts answer an unresolved question."""

    question_id: str
    fact_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.question_id.strip() or not self.fact_refs:
            raise ValueError("question resolution requires a question and facts")


@dataclass(frozen=True)
class SemanticStateProposal:
    """Optional structured output from a semantic extraction component.

    The updater validates every reference. A model never writes state directly.
    """

    new_questions: tuple[UnresolvedQuestion, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    resolutions: tuple[QuestionResolution, ...] = ()


@dataclass(frozen=True)
class StateDelta:
    added_fact_ids: tuple[str, ...] = ()
    added_evidence_ids: tuple[str, ...] = ()
    added_artifact_ids: tuple[str, ...] = ()
    resolved_question_ids: tuple[str, ...] = ()
    added_question_ids: tuple[str, ...] = ()
    added_hypothesis_ids: tuple[str, ...] = ()
    ignored_ungrounded_finding_ids: tuple[str, ...] = ()

    @property
    def made_progress(self) -> bool:
        return any(
            (
                self.added_fact_ids,
                self.added_evidence_ids,
                self.added_artifact_ids,
                self.resolved_question_ids,
                self.added_question_ids,
                self.added_hypothesis_ids,
            )
        )


@dataclass(frozen=True)
class StateUpdate:
    state: HunterWorldState
    delta: StateDelta


class WorldStateUpdater:
    """Merge one unified backend result into a validated new state snapshot."""

    def apply(
        self,
        old_state: HunterWorldState,
        result: AgentResult,
        *,
        source_task: TaskSpec | None = None,
        semantic_proposal: SemanticStateProposal | None = None,
    ) -> StateUpdate:
        old_state.validate()
        result.validate()
        is_child = result.task_id != old_state.task_id
        if is_child:
            if source_task is None or source_task.task_id != result.task_id:
                raise ValueError("child AgentResult requires its matching TaskSpec")
            source_task.validate()
            brain_metadata = source_task.metadata.get("hunter_brain", {})
            if not isinstance(brain_metadata, dict) or brain_metadata.get(
                "parent_task_id"
            ) != old_state.task_id:
                raise ValueError("child TaskSpec does not belong to this world state")

        state = deepcopy(old_state)
        if is_child:
            state.register_child_task(result.task_id)
        added_artifacts: list[str] = []
        added_evidence: list[str] = []
        added_facts: list[str] = []
        ignored_findings: list[str] = []

        for artifact in result.artifacts:
            artifact_id = self.result_reference(old_state, result, artifact.artifact_id)
            metadata = artifact.metadata
            handoff = HandoffDescriptor.from_metadata(metadata)
            if handoff is not None:
                if handoff.source_task_id != result.task_id:
                    raise ValueError("handoff source_task_id does not match AgentResult")
                handoff = HandoffDescriptor(
                    semantic_type=handoff.semantic_type,
                    carrier=handoff.carrier,
                    values=handoff.values,
                    source_task_id=handoff.source_task_id,
                    source_evidence_refs=tuple(
                        self.result_reference(old_state, result, reference)
                        for reference in handoff.source_evidence_refs
                    ),
                    allowed_targets=handoff.allowed_targets,
                )
                metadata = {**metadata, HANDOFF_METADATA_KEY: handoff.to_metadata()[HANDOFF_METADATA_KEY]}
            artifact_record = ArtifactRecord(
                artifact_id=artifact_id,
                artifact_type=artifact.type,
                path=artifact.path,
                sha256=artifact.sha256,
                size=artifact.size,
                producer_agent=artifact.producer or result.agent_id,
                source_task_id=result.task_id,
                metadata=metadata,
            )
            existed = artifact_record.artifact_id in state.artifacts
            state.add_artifact(artifact_record)
            if not existed:
                added_artifacts.append(artifact_record.artifact_id)

        for evidence in result.evidence:
            evidence_id = self.result_reference(old_state, result, evidence.evidence_id)
            artifact_ref = (
                self.result_reference(old_state, result, evidence.artifact_ref)
                if evidence.artifact_ref is not None
                else None
            )
            evidence_record = EvidenceRecord(
                evidence_id=evidence_id,
                evidence_type=evidence.type,
                source=evidence.source,
                description=evidence.description,
                artifact_ref=artifact_ref,
                path=evidence.path,
                metadata=evidence.metadata,
            )
            existed = evidence_record.evidence_id in state.evidence
            state.add_evidence(evidence_record)
            if not existed:
                added_evidence.append(evidence_record.evidence_id)

        for finding in result.findings:
            if not finding.evidence_refs:
                ignored_findings.append(finding.finding_id)
                continue
            fact_id = self.result_reference(
                old_state,
                result,
                self._fact_id(result.agent_id, finding.finding_id),
            )
            statement = finding.title.strip()
            if finding.description.strip() != statement:
                statement = f"{statement}: {finding.description.strip()}"
            fact = VerifiedFact(
                fact_id=fact_id,
                statement=statement,
                evidence_refs=tuple(
                    self.result_reference(old_state, result, reference)
                    for reference in finding.evidence_refs
                ),
                source_agent=result.agent_id,
            )
            existed = fact_id in state.facts
            state.add_fact(fact)
            if not existed:
                added_facts.append(fact_id)

        added_questions: list[str] = []
        added_hypotheses: list[str] = []
        resolved_questions: list[str] = []
        if semantic_proposal is not None:
            for question in semantic_proposal.new_questions:
                existed = question.question_id in state.unresolved_questions
                state.add_question(question)
                if not existed:
                    added_questions.append(question.question_id)
            for hypothesis in semantic_proposal.hypotheses:
                existed = hypothesis.hypothesis_id in state.hypotheses
                state.add_hypothesis(hypothesis)
                if not existed:
                    added_hypotheses.append(hypothesis.hypothesis_id)
            for resolution in semantic_proposal.resolutions:
                state.resolve_question(
                    resolution.question_id,
                    fact_refs=resolution.fact_refs,
                )
                resolved_questions.append(resolution.question_id)

        state.validate()
        return StateUpdate(
            state=state,
            delta=StateDelta(
                added_fact_ids=tuple(added_facts),
                added_evidence_ids=tuple(added_evidence),
                added_artifact_ids=tuple(added_artifacts),
                resolved_question_ids=tuple(resolved_questions),
                added_question_ids=tuple(added_questions),
                added_hypothesis_ids=tuple(added_hypotheses),
                ignored_ungrounded_finding_ids=tuple(ignored_findings),
            ),
        )

    @staticmethod
    def _fact_id(agent_id: str, finding_id: str) -> str:
        return f"fact-{agent_id}-{finding_id}"

    @staticmethod
    def result_reference(
        state: HunterWorldState,
        result: AgentResult,
        source_id: str,
    ) -> str:
        """Return a stable global identifier while preserving root-result IDs."""

        if result.task_id == state.task_id:
            return source_id
        digest = hashlib.sha256(result.task_id.encode()).hexdigest()[:12]
        return f"child-{digest}-{source_id}"[:128]
