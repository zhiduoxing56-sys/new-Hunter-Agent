from __future__ import annotations

from pathlib import Path

import pytest

from hunter_brain.state import (
    BRAIN_STATE_FILENAME,
    ArtifactRecord,
    DispatchRecord,
    EvidenceRecord,
    HunterWorldState,
    Hypothesis,
    UnresolvedQuestion,
    VerifiedFact,
)
from pentestgpt_agent.protocol import Artifact, Evidence, RunLayout, TaskSpec


def _task(task_id: str = "brain-state") -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        domain="hybrid",
        target="managed-input",
        goal="Determine whether intrusion occurred and explain the suspicious binary.",
        success_conditions=("Intrusion conclusion is supported by evidence.",),
        metadata={"hunter_brain": {"initial_domain": "dfir"}},
    )


def _grounded_state(tmp_path: Path) -> HunterWorldState:
    state = HunterWorldState.from_task(_task())
    artifact_path = tmp_path / "evil.exe"
    artifact_path.write_bytes(b"MZ-sample")
    artifact = Artifact.from_path(
        "artifact-evil", "pe", artifact_path, producer="dfir-adapter"
    )
    state.add_artifact(ArtifactRecord.from_protocol(artifact, source_task_id=state.task_id))
    evidence = Evidence(
        evidence_id="evidence-execution",
        type="event_correlation",
        source="dfir-adapter",
        description="A scheduled task executed evil.exe.",
        artifact_ref="artifact-evil",
    )
    state.add_evidence(EvidenceRecord.from_protocol(evidence))
    state.add_fact(
        VerifiedFact(
            fact_id="fact-execution",
            statement="A scheduled task executed evil.exe.",
            evidence_refs=("evidence-execution",),
            source_agent="dfir-adapter",
        )
    )
    return state


def test_state_starts_from_existing_taskspec_without_changing_it() -> None:
    task = _task()
    original = task.to_dict()

    state = HunterWorldState.from_task(task)

    assert state.task_id == task.task_id
    assert state.user_goal == task.goal
    assert state.success_conditions == task.success_conditions
    assert task.to_dict() == original


def test_verified_fact_must_reference_existing_evidence() -> None:
    state = HunterWorldState.from_task(_task())

    with pytest.raises(ValueError, match="unknown evidence"):
        state.add_fact(VerifiedFact("fact-1", "Unsupported claim.", ("missing",)))
    with pytest.raises(ValueError, match="requires evidence"):
        VerifiedFact("fact-2", "Unsupported claim.", ())


def test_evidence_must_reference_an_existing_artifact(tmp_path: Path) -> None:
    state = HunterWorldState.from_task(_task())
    evidence = EvidenceRecord(
        "evidence-1",
        "file",
        "dfir-adapter",
        "References a missing artifact.",
        artifact_ref="missing",
    )

    with pytest.raises(ValueError, match="unknown artifact"):
        state.add_evidence(evidence)


def test_facts_and_hypotheses_are_strictly_separate(tmp_path: Path) -> None:
    state = _grounded_state(tmp_path)

    with pytest.raises(ValueError, match="must not also"):
        state.add_hypothesis(
            Hypothesis(
                "hypothesis-1",
                "A scheduled task executed evil.exe.",
                "The execution may indicate persistence.",
                evidence_refs=("evidence-execution",),
            )
        )


def test_questions_and_dispatch_history_retain_loop_prevention_data(tmp_path: Path) -> None:
    state = _grounded_state(tmp_path)
    state.add_question(
        UnresolvedQuestion(
            "question-behavior",
            "What does evil.exe do?",
            priority=90,
            required_output_types=("program_behavior",),
            source="fact-execution",
        )
    )
    state.record_dispatch(
        DispatchRecord(
            dispatch_id="dispatch-1",
            capability_id="reverse",
            objective="Explain evil.exe behavior.",
            input_refs=("artifact-evil",),
            status="success",
            new_evidence=True,
            new_facts=False,
            answered_question_ids=("question-behavior",),
            budget_used=1.25,
        )
    )

    record = state.dispatch_history[0]
    assert record.new_evidence is True
    assert record.new_facts is False
    assert record.answered_question_ids == ("question-behavior",)
    assert record.budget_used == 1.25
    assert record.failure_reason is None


def test_question_resolution_requires_verified_facts(tmp_path: Path) -> None:
    state = _grounded_state(tmp_path)
    state.add_question(UnresolvedQuestion("question-1", "Was evil.exe executed?"))

    with pytest.raises(ValueError, match="known verified facts"):
        state.resolve_question("question-1", fact_refs=("missing",))
    state.resolve_question("question-1", fact_refs=("fact-execution",))

    assert "question-1" not in state.unresolved_questions


def test_brain_state_round_trip_uses_a_separate_task_owned_file(tmp_path: Path) -> None:
    task = _task()
    layout = RunLayout.ensure(tmp_path / "runs", task)
    original_protocol_state = layout.world_state_json.read_bytes()
    state = _grounded_state(tmp_path)
    state.add_question(UnresolvedQuestion("question-1", "What does evil.exe do?"))

    saved = state.save(layout.root)
    recovered = HunterWorldState.load(layout.root)

    assert saved == layout.root / BRAIN_STATE_FILENAME
    assert recovered == state
    assert layout.world_state_json.read_bytes() == original_protocol_state


def test_protocol_projection_preserves_the_frozen_document_shape(tmp_path: Path) -> None:
    state = _grounded_state(tmp_path)
    state.add_question(UnresolvedQuestion("question-1", "What does evil.exe do?"))
    state.add_hypothesis(
        Hypothesis(
            "hypothesis-1",
            "evil.exe may be a remote-access tool.",
            "Its provenance is suspicious but behavior is not verified.",
            confidence=0.4,
        )
    )

    document = state.to_protocol_document()
    wire = document.to_dict()

    assert set(wire) == {
        "schema_version",
        "task_id",
        "facts",
        "questions",
        "hypotheses",
        "evidence",
        "history",
    }
    assert wire["task_id"] == state.task_id
    assert wire["facts"][0]["evidence_refs"] == ["evidence-execution"]
    assert wire["hypotheses"][0]["statement"].endswith("remote-access tool.")


def test_artifact_must_belong_to_the_same_task(tmp_path: Path) -> None:
    state = HunterWorldState.from_task(_task())
    record = ArtifactRecord(
        artifact_id="artifact-1",
        artifact_type="pe",
        path=str(tmp_path / "sample.exe"),
        sha256="0" * 64,
        size=0,
        producer_agent="reverse-adapter",
        source_task_id="another-task",
    )

    with pytest.raises(ValueError, match="outside.*lineage"):
        state.add_artifact(record)
