from __future__ import annotations

import os
from pathlib import Path

import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import CompleteDecision, InvokeCapabilityDecision
from hunter_brain.orchestrator import (
    CapabilityAdapterRegistry,
    HunterOrchestrator,
    OrchestrationStatus,
)
from hunter_brain.state import (
    ArtifactRecord,
    EvidenceRecord,
    HunterWorldState,
    UnresolvedQuestion,
    VerifiedFact,
)
from hunter_brain.state_updater import QuestionResolution, SemanticStateProposal, StateUpdate
from hunter_brain.supervisor import SupervisionOutcome
from hunter_brain.validator import BudgetSnapshot, DeterministicDecisionValidator
from hunter_brain.verifier import GlobalVerifier
from integrations.kong import KongAdapter
from integrations.trudi import TrudiAdapter
from pentestgpt_agent.protocol import (
    AgentResult,
    Artifact,
    AuthorizationScope,
    InputObject,
    TargetObject,
    TaskSpec,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _adapters() -> CapabilityAdapterRegistry:
    return CapabilityAdapterRegistry(
        {
            "reverse": KongAdapter(
                java_home=PROJECT_ROOT.parent / ".tools/jdk21",
                ghidra_dir=(
                    PROJECT_ROOT.parent
                    / ".tools/ghidra-12.0.4/ghidra_12.0.4_PUBLIC"
                ),
                kong_config_dir=PROJECT_ROOT / ".runtime/kong/config",
            ),
            "dfir": TrudiAdapter(mode="lite"),
        }
    )


def _failure_task(tmp_path: Path) -> tuple[TaskSpec, HunterWorldState, str]:
    task_id = "layer-four-real-failure-route"
    root = (tmp_path / "runs" / task_id).resolve()
    path = root / "artifacts/input/not-a-binary.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("harmless evidence that is intentionally not an executable\n", encoding="utf-8")
    source = Artifact.from_path("input-source", "file_artifact", path, producer="layer-one")
    task = TaskSpec(
        task_id,
        "hybrid",
        str(path),
        "Analyze the supplied artifact and preserve useful evidence.",
        timeout=120,
        budget=4.0,
        workspace=str(root),
        scope={"allowed_targets": [str(path)]},
        success_conditions=("At least one compatible real backend produces evidence.",),
        metadata={
            "file_type": {"normalized_type": "file_artifact", "sha256": source.sha256},
            "kong_mode": "info",
            "trudi_mode": "lite",
        },
        input_object=InputObject(
            "input-original",
            "file",
            str(path),
            path=str(path),
            source_name=path.name,
            sha256=source.sha256,
            size_bytes=source.size,
        ),
        target_object=TargetObject("target-original", "file_artifact", str(path)),
        authorization=AuthorizationScope(
            (str(path),),
            allowed_read_paths=(str(root),),
            workspace=str(root),
        ),
    )
    state = HunterWorldState.from_task(task)
    alternate = Artifact.from_path(
        "alternate-evidence",
        "evidence_file",
        path,
        producer="layer-one",
    )
    state.add_artifact(ArtifactRecord.from_protocol(alternate, source_task_id=task.task_id))
    state.add_question(UnresolvedQuestion("question-analyze", task.goal, 100))
    return task, state, alternate.artifact_id


class FailureThenCompatibleSupervisor:
    def __init__(self, task: TaskSpec, alternate_ref: str) -> None:
        self.task = task
        self.alternate_ref = alternate_ref
        self.validator = DeterministicDecisionValidator()
        self.catalog = default_catalog()

    async def decide(
        self, *, task: TaskSpec, state: HunterWorldState, budget: BudgetSnapshot
    ) -> SupervisionOutcome:
        if not state.dispatch_history:
            decision = InvokeCapabilityDecision(
                "reverse", ("input-original",), "question-analyze",
                "Attempt binary metadata analysis.", ("input-original",), (), (),
                ("binary_metadata",), 1.0, "The input type is reverse-compatible.",
            )
        elif not state.evidence:
            decision = InvokeCapabilityDecision(
                "dfir", (self.alternate_ref,), "question-analyze",
                "Preserve and triage the artifact as evidence.", ("input-original",), (), (),
                ("finding",), 1.0, "A different compatible capability remains.",
            )
        else:
            decision = CompleteDecision(
                "The failed path was replaced by a successful evidence path.",
                {task.success_conditions[0]: (list(state.evidence)[-1],)},
                "The alternate backend produced grounded evidence.",
            )
        return SupervisionOutcome(
            decision,
            self.validator.validate(
                decision, task=task, state=state, catalog=self.catalog, budget=budget
            ),
            {},
        )


class ResolveSuccessfulResult:
    def interpret(
        self,
        *,
        preview: StateUpdate,
        decision: InvokeCapabilityDecision,
        result: AgentResult,
    ) -> SemanticStateProposal:
        if not preview.delta.added_fact_ids:
            return SemanticStateProposal()
        return SemanticStateProposal(
            resolutions=(
                QuestionResolution(decision.question_id, (preview.delta.added_fact_ids[0],)),
            )
        )


@pytest.mark.asyncio
async def test_real_failure_switches_to_another_catalog_compatible_backend(
    tmp_path: Path,
) -> None:
    if os.environ.get("HUNTER_LAYER_FOUR_LIVE") != "1":
        pytest.skip("set HUNTER_LAYER_FOUR_LIVE=1 to run real terminal-path tests")
    task, state, alternate = _failure_task(tmp_path)
    result = await HunterOrchestrator(
        supervisor=FailureThenCompatibleSupervisor(task, alternate),
        adapters=_adapters(),
        runs_root=tmp_path / "runs",
        result_interpreter=ResolveSuccessfulResult(),
        verifier=GlobalVerifier(),
    ).run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE
    assert [item.capability_id for item in result.state.dispatch_history] == ["reverse", "dfir"]
    assert result.state.dispatch_history[0].failure_reason
    assert result.state.dispatch_history[1].new_evidence is True


class RepeatingFailedDecisionSupervisor:
    def __init__(self) -> None:
        self.validator = DeterministicDecisionValidator()

    async def decide(
        self, *, task: TaskSpec, state: HunterWorldState, budget: BudgetSnapshot
    ) -> SupervisionOutcome:
        decision = InvokeCapabilityDecision(
            "reverse", ("input-original",), "question-analyze",
            "Attempt binary metadata analysis.", ("input-original",), (), (),
            ("binary_metadata",), 1.0, "Repeat the unchanged failed request.",
        )
        return SupervisionOutcome(
            decision,
            self.validator.validate(
                decision, task=task, state=state, catalog=default_catalog(), budget=budget
            ),
            {},
        )


@pytest.mark.asyncio
async def test_real_failed_call_is_not_executed_twice_without_progress(tmp_path: Path) -> None:
    if os.environ.get("HUNTER_LAYER_FOUR_LIVE") != "1":
        pytest.skip("set HUNTER_LAYER_FOUR_LIVE=1 to run real terminal-path tests")
    task, state, _ = _failure_task(tmp_path)
    result = await HunterOrchestrator(
        supervisor=RepeatingFailedDecisionSupervisor(),
        adapters=_adapters(),
        runs_root=tmp_path / "runs",
    ).run(task, initial_state=state)

    assert result.status is OrchestrationStatus.INVALID_DECISIONS
    assert len(result.state.dispatch_history) == 1
    assert result.state.dispatch_history[0].capability_id == "reverse"
    assert result.state.dispatch_history[0].new_evidence is False


class CompleteImmediatelySupervisor:
    async def decide(
        self, *, task: TaskSpec, state: HunterWorldState, budget: BudgetSnapshot
    ) -> SupervisionOutcome:
        decision = CompleteDecision(
            "Existing verified evidence already satisfies the task.",
            {task.success_conditions[0]: ("existing-evidence",)},
            "No professional call is necessary.",
        )
        return SupervisionOutcome(
            decision,
            DeterministicDecisionValidator().validate(
                decision, task=task, state=state, catalog=default_catalog(), budget=budget
            ),
            {},
        )


@pytest.mark.asyncio
async def test_evidence_complete_task_stops_without_calling_real_registry(
    tmp_path: Path,
) -> None:
    target = "https://already-complete.invalid/"
    task = TaskSpec(
        "layer-four-direct-complete",
        "hybrid",
        target,
        "Use the existing verified conclusion.",
        success_conditions=("The existing conclusion is supported.",),
        authorization=AuthorizationScope((target,)),
    )
    state = HunterWorldState.from_task(task)
    state.add_evidence(
        EvidenceRecord("existing-evidence", "verified_record", "prior-task", "Verified.")
    )
    state.add_fact(
        VerifiedFact("existing-fact", "The conclusion is established.", ("existing-evidence",))
    )
    result = await HunterOrchestrator(
        supervisor=CompleteImmediatelySupervisor(),
        adapters=_adapters(),
        runs_root=tmp_path / "runs",
        verifier=GlobalVerifier(),
    ).run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE
    assert result.budget.capability_calls_used == 0
    assert result.state.dispatch_history == []
