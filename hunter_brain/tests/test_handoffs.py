from __future__ import annotations

from pathlib import Path

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import InvokeCapabilityDecision
from hunter_brain.handoffs import HandoffCarrier, HandoffDescriptor
from hunter_brain.state import HunterWorldState, UnresolvedQuestion
from hunter_brain.state_updater import WorldStateUpdater
from hunter_brain.validator import (
    BudgetSnapshot,
    DeterministicDecisionValidator,
    ValidationCode,
)
from integrations.handoffs import handoff_payload, materialize_handoff
from pentestgpt_agent.protocol import (
    AgentResult,
    AuthorizationScope,
    Evidence,
    ExecutionStatus,
    RunLayout,
    TaskSpec,
)


def _task(tmp_path: Path, *, allowed: str) -> TaskSpec:
    root = (tmp_path / "runs" / "handoff-task").resolve()
    return TaskSpec(
        "handoff-task",
        "hybrid",
        allowed,
        "Route only authorized derived inputs.",
        workspace=str(root),
        scope={"allowed_targets": [allowed]},
        success_conditions=("The authorized target is assessed.",),
        authorization=AuthorizationScope((allowed,), workspace=str(root)),
    )


def _state_with_target_handoff(
    tmp_path: Path,
    *,
    descriptor_target: str,
    parent_target: str,
) -> tuple[TaskSpec, HunterWorldState, str]:
    task = _task(tmp_path, allowed=parent_target)
    layout = RunLayout.ensure(tmp_path / "runs", task)
    descriptor = HandoffDescriptor(
        semantic_type="network_target",
        carrier=HandoffCarrier.VALUE,
        values=(descriptor_target,),
        source_task_id=task.task_id,
        source_evidence_refs=("source-evidence",),
        allowed_targets=(descriptor_target,),
    )
    artifact = materialize_handoff(
        layout,
        artifact_id="derived-target",
        descriptor=descriptor,
        payload={"target": descriptor_target, "basis": "verified observation"},
        producer="professional-backend",
    )
    assert handoff_payload(Path(artifact.path), descriptor)["target"] == descriptor_target
    evidence = Evidence(
        "source-evidence",
        "observation",
        "professional-backend",
        "The target value was observed and preserved.",
        artifact_ref=artifact.artifact_id,
    )
    result = AgentResult(
        task.task_id,
        "professional-backend",
        "dfir",
        ExecutionStatus.SUCCESS,
        "2026-08-30T00:00:00+00:00",
        "2026-08-30T00:00:01+00:00",
        "Produced an authorized target handoff.",
        evidence=(evidence,),
        artifacts=(artifact,),
    )
    state = WorldStateUpdater().apply(HunterWorldState.from_task(task), result).state
    state.add_question(UnresolvedQuestion("assess-target", "Assess the derived target.", 100))
    return task, state, next(iter(state.artifacts))


def _decision(artifact_id: str) -> InvokeCapabilityDecision:
    return InvokeCapabilityDecision(
        "pentest",
        (artifact_id,),
        "assess-target",
        "Assess the authorized derived target.",
        (),
        (),
        ("source-evidence",),
        ("access_proof",),
        1.0,
        "The verified handoff contains a compatible authorized target.",
    )


def test_value_handoff_routes_by_semantic_type_when_authorized(tmp_path: Path) -> None:
    target = "https://authorized.invalid/"
    task, state, artifact_id = _state_with_target_handoff(
        tmp_path,
        descriptor_target=target,
        parent_target=target,
    )

    validation = DeterministicDecisionValidator().validate(
        _decision(artifact_id),
        task=task,
        state=state,
        catalog=default_catalog(),
        budget=BudgetSnapshot(decisions_remaining=2, capability_calls_remaining=1),
    )

    assert validation.accepted is True


def test_value_handoff_cannot_expand_parent_authorization(tmp_path: Path) -> None:
    task, state, artifact_id = _state_with_target_handoff(
        tmp_path,
        descriptor_target="https://outside.invalid/",
        parent_target="https://authorized.invalid/",
    )

    validation = DeterministicDecisionValidator().validate(
        _decision(artifact_id),
        task=task,
        state=state,
        catalog=default_catalog(),
        budget=BudgetSnapshot(decisions_remaining=2, capability_calls_remaining=1),
    )

    assert validation.accepted is False
    assert {issue.code for issue in validation.issues} == {ValidationCode.SCOPE_VIOLATION}
