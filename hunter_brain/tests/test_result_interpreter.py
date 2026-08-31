"""Result interpreter: grounded AgentResult -> canonical question resolution.

Covers: a professional AgentResult that passes the adapter contract must be
translated into canonical state, the targeted pending question must be resolved
only when grounded facts exist, and an evidence-empty SUCCESS or a failed
backend must never resolve the question (which would let the global loop
complete without evidence).
"""

from __future__ import annotations

from pathlib import Path

from hunter_brain.decisions import InvokeCapabilityDecision
from hunter_brain.result_interpreter import EvidenceGroundedResultInterpreter
from hunter_brain.state import HunterWorldState, UnresolvedQuestion
from hunter_brain.state_updater import QuestionResolution, WorldStateUpdater
from pentestgpt_agent.protocol import (
    AgentResult,
    Artifact,
    ErrorCategory,
    ErrorDetail,
    Evidence,
    ExecutionStatus,
    Finding,
    TaskSpec,
)

def _task() -> TaskSpec:
    return TaskSpec(
        task_id="interpreter-task",
        domain="dfir",
        target="/evidence/sample",
        goal="Triage the acquired forensic evidence.",
        success_conditions=("The evidence was assessed.",),
        metadata={"file_type": {"normalized_type": "evidence_file"}},
    )


def _decision() -> InvokeCapabilityDecision:
    return InvokeCapabilityDecision(
        "dfir",
        ("input",),
        "question-user-goal",
        "Triage the acquired forensic evidence.",
        ("input",),
        (),
        (),
        ("finding",),
        1.0,
        "Initial triage.",
    )


def _grounded_result(tmp_path: Path, *, status: ExecutionStatus) -> AgentResult:
    path = tmp_path / "out.bin"
    path.write_bytes(b"canonical output")
    artifact = Artifact.from_path("art-1", "text_report", path, producer="mock")
    evidence = Evidence(
        "ev-1", "artifact_reference", "mock", "Grounded evidence.", artifact_ref="art-1"
    )
    finding = Finding(
        "f-1",
        "finding",
        "Canonical finding",
        "A grounded, evidence-backed finding.",
        evidence_refs=("ev-1",),
    )
    return AgentResult(
        task_id=_task().task_id,
        agent_id="mock",
        domain="dfir",
        status=status,
        started_at="2026-08-31T00:00:00+00:00",
        finished_at="2026-08-31T00:00:01+00:00",
        summary="Mock result.",
        findings=(finding,),
        evidence=(evidence,),
        artifacts=(artifact,),
        error=(
            ErrorDetail(ErrorCategory.BACKEND_ERROR, "backend failed", code="MOCK_FAILED")
            if status is ExecutionStatus.FAILED
            else None
        ),
    )


def _empty_result(tmp_path: Path, *, status: ExecutionStatus) -> AgentResult:
    path = tmp_path / "out.bin"
    path.write_bytes(b"no findings")
    artifact = Artifact.from_path("art-2", "text_report", path, producer="mock")
    evidence = Evidence(
        "ev-2", "artifact_reference", "mock", "Evidence without findings.", artifact_ref="art-2"
    )
    return AgentResult(
        task_id=_task().task_id,
        agent_id="mock",
        domain="dfir",
        status=status,
        started_at="2026-08-31T00:00:00+00:00",
        finished_at="2026-08-31T00:00:01+00:00",
        summary="Mock result without findings.",
        evidence=(evidence,),
        artifacts=(artifact,),
    )


def _state() -> HunterWorldState:
    state = HunterWorldState.from_task(_task())
    state.add_question(
        UnresolvedQuestion(
            "question-user-goal", _task().goal, priority=100, source="user_goal"
        )
    )
    return state


def test_success_with_grounded_facts_resolves_targeted_question(tmp_path: Path) -> None:
    result = _grounded_result(tmp_path, status=ExecutionStatus.SUCCESS)
    state = _state()
    preview = WorldStateUpdater().apply(state, result)

    proposal = EvidenceGroundedResultInterpreter().interpret(
        preview=preview, decision=_decision(), result=result
    )

    assert proposal.resolutions == (
        QuestionResolution("question-user-goal", preview.delta.added_fact_ids),
    )
    applied = WorldStateUpdater().apply(state, result, semantic_proposal=proposal)
    assert applied.delta.resolved_question_ids == ("question-user-goal",)
    assert "question-user-goal" not in applied.state.unresolved_questions


def test_success_without_grounded_facts_does_not_resolve(tmp_path: Path) -> None:
    result = _empty_result(tmp_path, status=ExecutionStatus.SUCCESS)
    state = _state()
    preview = WorldStateUpdater().apply(state, result)

    proposal = EvidenceGroundedResultInterpreter().interpret(
        preview=preview, decision=_decision(), result=result
    )

    assert proposal.resolutions == ()
    assert preview.delta.added_fact_ids == ()
    assert "question-user-goal" in preview.state.unresolved_questions


def test_failed_backend_never_resolves_even_with_findings(tmp_path: Path) -> None:
    result = _grounded_result(tmp_path, status=ExecutionStatus.FAILED)
    state = _state()
    preview = WorldStateUpdater().apply(state, result)

    proposal = EvidenceGroundedResultInterpreter().interpret(
        preview=preview, decision=_decision(), result=result
    )

    assert proposal.resolutions == ()


def test_findings_evidence_artifacts_enter_canonical_state(tmp_path: Path) -> None:
    result = _grounded_result(tmp_path, status=ExecutionStatus.SUCCESS)
    state = _state()
    applied = WorldStateUpdater().apply(state, result)

    assert applied.state.facts and any(f.evidence_refs for f in applied.state.facts.values())
    assert applied.state.evidence.get("ev-1") is not None
    assert applied.state.artifacts.get("art-1") is not None
    assert applied.state.artifacts["art-1"].sha256 == result.artifacts[0].sha256


def test_interpreter_never_declares_global_success(tmp_path: Path) -> None:
    result = _grounded_result(tmp_path, status=ExecutionStatus.SUCCESS)
    proposal = EvidenceGroundedResultInterpreter().interpret(
        preview=WorldStateUpdater().apply(_state(), result),
        decision=_decision(),
        result=result,
    )
    assert proposal.new_questions == ()
    assert proposal.hypotheses == ()
