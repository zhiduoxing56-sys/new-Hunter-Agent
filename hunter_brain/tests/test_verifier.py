from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from hunter_brain.decisions import CompleteDecision, VerifyDecision
from hunter_brain.state import HunterWorldState, UnresolvedQuestion
from hunter_brain.state_updater import QuestionResolution, WorldStateUpdater
from hunter_brain.verifier import (
    GlobalVerificationStatus,
    GlobalVerifier,
    SemanticAssessment,
    SemanticVerificationRequest,
    VerificationCode,
)
from pentestgpt_agent.protocol import AgentResult, AdapterRunner, RunLayout, TaskSpec
from pentestgpt_agent.protocol.mock_adapter import MockAdapter


def _task(task_id: str = "verification-task") -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        domain="pentest",
        target="https://allowed.example/",
        goal="Produce an evidence-backed conclusion.",
        success_conditions=("The conclusion is supported by verified evidence.",),
    )


async def _result_state_layout(
    tmp_path: Path,
) -> tuple[TaskSpec, HunterWorldState, AgentResult, RunLayout]:
    task = _task()
    runs = tmp_path / "runs"
    result = await AdapterRunner(MockAdapter(), runs_root=runs).execute(task)
    state = WorldStateUpdater().apply(HunterWorldState.from_task(task), result).state
    return task, state, result, RunLayout.ensure(runs, task)


@pytest.mark.asyncio
async def test_agent_result_deterministic_filesystem_verification_passes(
    tmp_path: Path,
) -> None:
    task, state, result, layout = await _result_state_layout(tmp_path)

    outcome = await GlobalVerifier().verify_result(
        task=task,
        state=state,
        result=result,
        layout=layout,
    )

    assert outcome.status is GlobalVerificationStatus.PASSED
    assert outcome.issues == ()
    assert {item.check for item in outcome.checks} >= {
        "result_task_matches",
        "result_domain_matches",
        "artifact_exists",
        "artifact_belongs_to_task",
        "sha256_matches",
        "evidence_reference_valid",
    }


@pytest.mark.asyncio
async def test_tampered_artifact_fails_before_semantic_verification(tmp_path: Path) -> None:
    task, state, result, layout = await _result_state_layout(tmp_path)
    Path(result.artifacts[0].path).write_text("tampered", encoding="utf-8")

    outcome = await GlobalVerifier().verify_result(
        task=task,
        state=state,
        result=result,
        layout=layout,
    )

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert VerificationCode.ARTIFACT_HASH_MISMATCH in {
        item.code for item in outcome.issues
    }


@pytest.mark.asyncio
async def test_explicit_deterministic_verification_checks_world_state_artifact(
    tmp_path: Path,
) -> None:
    task, state, _, _ = await _result_state_layout(tmp_path)
    decision = VerifyDecision(
        objective="Verify the persisted backend evidence.",
        evidence_refs=("mock-evidence",),
        verification_checks=(
            "evidence_reference_valid",
            "artifact_exists",
            "sha256_matches",
            "artifact_belongs_to_task",
        ),
        rationale="The artifact must pass deterministic integrity checks.",
    )

    outcome = await GlobalVerifier().verify_request(
        task=task,
        state=state,
        decision=decision,
    )

    assert outcome.status is GlobalVerificationStatus.PASSED
    assert all(item.passed for item in outcome.checks)


def test_unsupported_external_check_is_not_silently_accepted() -> None:
    with pytest.raises(ValueError, match="closed vocabulary"):
        VerifyDecision(
            "Reproduce the exploit.",
            ("mock-evidence",),
            ("exploit_reproduces",),
            "Reproduction requires a dedicated verifier.",
        )


@dataclass
class ResolvingSemanticModel:
    question_id: str
    fact_id: str
    supported: bool | None = True
    calls: list[SemanticVerificationRequest] | None = None

    async def assess(self, request: SemanticVerificationRequest) -> SemanticAssessment:
        if self.calls is not None:
            self.calls.append(request)
        return SemanticAssessment(
            supported=self.supported,
            rationale="The cited fact and evidence answer the question.",
            resolutions=(QuestionResolution(self.question_id, (self.fact_id,)),),
        )


@pytest.mark.asyncio
async def test_semantic_verifier_can_only_return_validated_resolutions(
    tmp_path: Path,
) -> None:
    task, state, _, _ = await _result_state_layout(tmp_path)
    state.add_question(UnresolvedQuestion("question-1", "Did the backend produce evidence?", 90))
    fact_id = next(iter(state.facts))
    calls: list[SemanticVerificationRequest] = []
    verifier = GlobalVerifier(
        semantic_model=ResolvingSemanticModel("question-1", fact_id, calls=calls)
    )
    decision = VerifyDecision(
        "Determine whether the evidence answers the question.",
        ("mock-evidence",),
        ("semantic_support",),
        "Semantic support is required.",
    )

    outcome = await verifier.verify_request(task=task, state=state, decision=decision)

    assert outcome.status is GlobalVerificationStatus.PASSED
    assert outcome.resolutions == (QuestionResolution("question-1", (fact_id,)),)
    assert calls[0].kind == "verification_request"
    assert "raw_output" not in str(calls[0])


@pytest.mark.asyncio
async def test_semantic_model_cannot_invent_question_or_fact_references(
    tmp_path: Path,
) -> None:
    task, state, _, _ = await _result_state_layout(tmp_path)
    verifier = GlobalVerifier(
        semantic_model=ResolvingSemanticModel("missing-question", "missing-fact")
    )
    decision = VerifyDecision(
        "Check semantic support.",
        ("mock-evidence",),
        ("semantic_support",),
        "Semantic support is required.",
    )

    outcome = await verifier.verify_request(task=task, state=state, decision=decision)

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert VerificationCode.SEMANTIC_REFERENCE_INVALID in {
        item.code for item in outcome.issues
    }


@pytest.mark.asyncio
async def test_semantic_check_without_model_is_inconclusive(tmp_path: Path) -> None:
    task, state, _, _ = await _result_state_layout(tmp_path)
    decision = VerifyDecision(
        "Check semantic support.",
        ("mock-evidence",),
        ("semantic_support",),
        "Semantic support is required.",
    )

    outcome = await GlobalVerifier().verify_request(
        task=task, state=state, decision=decision
    )

    assert outcome.status is GlobalVerificationStatus.INCONCLUSIVE
    assert outcome.issues[0].code is VerificationCode.SEMANTIC_MODEL_UNAVAILABLE


@pytest.mark.asyncio
async def test_backend_success_does_not_bypass_global_completion_requirements(
    tmp_path: Path,
) -> None:
    task, state, result, _ = await _result_state_layout(tmp_path)
    state.add_question(UnresolvedQuestion("question-critical", "Is the goal satisfied?", 100))
    assert result.backend_reported_success is True
    decision = CompleteDecision(
        "Backend reported success.",
        {task.success_conditions[0]: ("mock-evidence",)},
        "The backend claimed completion.",
    )

    outcome = await GlobalVerifier().verify_completion(
        task=task,
        state=state,
        decision=decision,
    )

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert VerificationCode.CRITICAL_QUESTION_UNRESOLVED in {
        item.code for item in outcome.issues
    }


@pytest.mark.asyncio
async def test_evidence_grounded_global_completion_passes(tmp_path: Path) -> None:
    task, state, _, _ = await _result_state_layout(tmp_path)
    decision = CompleteDecision(
        "The requested evidence-backed conclusion is available.",
        {task.success_conditions[0]: ("mock-evidence",)},
        "No critical questions remain and evidence exists.",
    )

    outcome = await GlobalVerifier().verify_completion(
        task=task,
        state=state,
        decision=decision,
    )

    assert outcome.status is GlobalVerificationStatus.PASSED
