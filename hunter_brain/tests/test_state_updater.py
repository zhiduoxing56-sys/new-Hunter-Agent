from __future__ import annotations

from pathlib import Path

import pytest

from hunter_brain.state import (
    HunterWorldState,
    Hypothesis,
    UnresolvedQuestion,
)
from hunter_brain.state_updater import (
    QuestionResolution,
    SemanticStateProposal,
    WorldStateUpdater,
)
from pentestgpt_agent.protocol import (
    AgentResult,
    Artifact,
    Evidence,
    ExecutionStatus,
    Finding,
    TaskSpec,
)


def _state(task_id: str = "update-task") -> HunterWorldState:
    return HunterWorldState.from_task(
        TaskSpec(
            task_id=task_id,
            domain="dfir",
            target="managed-input",
            goal="Investigate suspicious execution.",
        )
    )


def _result(tmp_path: Path, task_id: str = "update-task") -> AgentResult:
    artifact_path = tmp_path / "evil.exe"
    artifact_path.write_bytes(b"MZ-updater")
    artifact = Artifact.from_path(
        "artifact-evil", "pe", artifact_path, producer="dfir-adapter"
    )
    evidence = Evidence(
        "evidence-1",
        "event_correlation",
        "dfir-adapter",
        "A scheduled task executed evil.exe.",
        artifact_ref=artifact.artifact_id,
    )
    finding = Finding(
        "finding-1",
        "persistence",
        "Suspicious scheduled task",
        "The task launched evil.exe.",
        evidence_refs=(evidence.evidence_id,),
    )
    unsupported = Finding(
        "finding-unsupported",
        "assessment",
        "Possible remote access",
        "This claim has no evidence reference.",
    )
    return AgentResult(
        task_id=task_id,
        agent_id="dfir-adapter",
        domain="dfir",
        status=ExecutionStatus.SUCCESS,
        started_at="2026-08-29T00:00:00+00:00",
        finished_at="2026-08-29T00:00:01+00:00",
        summary="DFIR subtask completed.",
        findings=(finding, unsupported),
        evidence=(evidence,),
        artifacts=(artifact,),
    )


def test_deterministic_update_adds_artifacts_evidence_then_grounded_facts(
    tmp_path: Path,
) -> None:
    old_state = _state()

    update = WorldStateUpdater().apply(old_state, _result(tmp_path))

    assert old_state.artifacts == {}
    assert update.delta.added_artifact_ids == ("artifact-evil",)
    assert update.delta.added_evidence_ids == ("evidence-1",)
    assert update.delta.added_fact_ids == ("fact-dfir-adapter-finding-1",)
    assert update.delta.ignored_ungrounded_finding_ids == ("finding-unsupported",)
    assert update.delta.made_progress is True
    fact = update.state.facts["fact-dfir-adapter-finding-1"]
    assert fact.evidence_refs == ("evidence-1",)
    assert "Possible remote access" not in {item.statement for item in update.state.facts.values()}


def test_reapplying_the_same_result_is_idempotent(tmp_path: Path) -> None:
    updater = WorldStateUpdater()
    result = _result(tmp_path)
    first = updater.apply(_state(), result)

    second = updater.apply(first.state, result)

    assert second.state == first.state
    assert second.delta.added_artifact_ids == ()
    assert second.delta.added_evidence_ids == ()
    assert second.delta.added_fact_ids == ()
    assert second.delta.made_progress is False


def test_task_mismatch_is_rejected_without_mutating_old_state(tmp_path: Path) -> None:
    old_state = _state()
    before = old_state.to_dict()

    with pytest.raises(ValueError, match="matching TaskSpec"):
        WorldStateUpdater().apply(old_state, _result(tmp_path, "another-task"))

    assert old_state.to_dict() == before


def test_conflict_is_transactional_and_leaves_old_state_unchanged(tmp_path: Path) -> None:
    updater = WorldStateUpdater()
    first_result = _result(tmp_path)
    old_state = updater.apply(_state(), first_result).state
    before = old_state.to_dict()
    changed_path = tmp_path / "changed.exe"
    changed_path.write_bytes(b"different")
    conflicting_artifact = Artifact.from_path(
        "artifact-evil", "pe", changed_path, producer="dfir-adapter"
    )
    conflicting = AgentResult(
        task_id="update-task",
        agent_id="dfir-adapter",
        domain="dfir",
        status=ExecutionStatus.SUCCESS,
        started_at="2026-08-29T00:00:02+00:00",
        finished_at="2026-08-29T00:00:03+00:00",
        summary="Conflicting backend output.",
        artifacts=(conflicting_artifact,),
    )

    with pytest.raises(ValueError, match="conflicting artifact"):
        updater.apply(old_state, conflicting)

    assert old_state.to_dict() == before


def test_semantic_proposal_is_validated_and_applied_after_deterministic_facts(
    tmp_path: Path,
) -> None:
    old_state = _state()
    old_state.add_question(
        UnresolvedQuestion("question-execution", "Was evil.exe executed?", priority=90)
    )
    proposal = SemanticStateProposal(
        new_questions=(
            UnresolvedQuestion(
                "question-behavior",
                "What does evil.exe do?",
                priority=80,
                required_output_types=("program_behavior",),
                source="fact-dfir-adapter-finding-1",
            ),
        ),
        hypotheses=(
            Hypothesis(
                "hypothesis-rat",
                "evil.exe may provide remote access.",
                "Behavior remains to be established by reverse engineering.",
                evidence_refs=("evidence-1",),
                confidence=0.3,
            ),
        ),
        resolutions=(
            QuestionResolution(
                "question-execution", ("fact-dfir-adapter-finding-1",)
            ),
        ),
    )

    update = WorldStateUpdater().apply(
        old_state,
        _result(tmp_path),
        semantic_proposal=proposal,
    )

    assert update.delta.added_question_ids == ("question-behavior",)
    assert update.delta.added_hypothesis_ids == ("hypothesis-rat",)
    assert update.delta.resolved_question_ids == ("question-execution",)
    assert "question-execution" not in update.state.unresolved_questions


def test_invalid_semantic_reference_rolls_back_the_whole_update(tmp_path: Path) -> None:
    old_state = _state()
    before = old_state.to_dict()
    proposal = SemanticStateProposal(
        hypotheses=(
            Hypothesis(
                "hypothesis-invalid",
                "Unsupported hypothesis.",
                "Model supplied an invalid evidence identifier.",
                evidence_refs=("missing-evidence",),
            ),
        )
    )

    with pytest.raises(ValueError, match="unknown evidence"):
        WorldStateUpdater().apply(
            old_state,
            _result(tmp_path),
            semantic_proposal=proposal,
        )

    assert old_state.to_dict() == before
