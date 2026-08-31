from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import CompleteDecision, InvokeCapabilityDecision, SupervisorDecision
from hunter_brain.orchestrator import (
    CapabilityAdapterRegistry,
    HunterOrchestrator,
    OrchestrationStatus,
)
from hunter_brain.state import HunterWorldState, UnresolvedQuestion
from hunter_brain.state_updater import QuestionResolution, SemanticStateProposal, StateUpdate
from hunter_brain.supervisor import SupervisionOutcome
from hunter_brain.validator import BudgetSnapshot, DeterministicDecisionValidator
from hunter_brain.verifier import GlobalVerifier
from pentestgpt_agent.protocol import (
    AgentAdapter,
    AgentResult,
    Artifact,
    AuthorizationScope,
    Evidence,
    ExecutionHandle,
    ExecutionStatus,
    Finding,
    HealthcheckResult,
    InputObject,
    PreparedTask,
    RunLayout,
    TargetObject,
    TaskSpec,
)


@dataclass(frozen=True)
class Hop:
    capability_id: str
    input_type: str
    artifact_type: str
    expected_output_type: str


SCENARIOS = (
    pytest.param(
        "forensics-to-reverse",
        (Hop("dfir", "evtx", "suspect_binary", "suspicious_binary"),
         Hop("reverse", "suspect_binary", "binary_metadata", "program_behavior")),
        id="forensics-to-reverse",
    ),
    pytest.param(
        "reverse-to-forensics",
        (Hop("reverse", "pe", "indicator", "domain_name"),
         Hop("dfir", "indicator", "timeline", "timeline")),
        id="reverse-to-forensics",
    ),
    pytest.param(
        "source-to-vulnerability-research",
        (Hop("vulnerability_research", "source_code", "code_location", "vulnerability"),),
        id="source-to-vulnerability-research",
    ),
    pytest.param(
        "network-to-pentest",
        (Hop("pentest", "network_target", "service_information", "service_information"),),
        id="network-to-pentest",
    ),
)


class FakeCapabilityAdapter(AgentAdapter):
    def __init__(self, hop: Hop, calls: list[str]) -> None:
        self.agent_id = f"fake-{hop.capability_id}"
        self.hop = hop
        self.calls = calls

    async def healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        return HealthcheckResult(True, {"fake": True})

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        return PreparedTask(task_spec, run_layout)

    async def run(self, prepared: PreparedTask) -> ExecutionHandle:
        self.calls.append(self.hop.capability_id)
        output = prepared.run_layout.artifacts / "fake-output.bin"
        output.write_bytes(f"fake:{self.hop.capability_id}".encode())
        return ExecutionHandle(
            f"fake-handle-{self.hop.capability_id}",
            "2026-08-30T00:00:00+00:00",
        )

    async def collect(self, prepared: PreparedTask, handle: ExecutionHandle) -> AgentResult:
        artifact = Artifact.from_path(
            "fake-output",
            self.hop.artifact_type,
            prepared.run_layout.artifacts / "fake-output.bin",
            producer=self.agent_id,
        )
        evidence = Evidence(
            "fake-evidence",
            "artifact_analysis",
            self.agent_id,
            "Deterministic fake evidence.",
            artifact_ref=artifact.artifact_id,
        )
        finding = Finding(
            "fake-finding",
            "analysis",
            f"{self.hop.capability_id} completed",
            "The scripted fake adapter produced grounded output.",
            evidence_refs=(evidence.evidence_id,),
        )
        return AgentResult(
            prepared.task_spec.task_id,
            self.agent_id,
            self.hop.capability_id,
            ExecutionStatus.SUCCESS,
            handle.started_at,
            "2026-08-30T00:00:01+00:00",
            "Fake adapter completed.",
            findings=(finding,),
            evidence=(evidence,),
            artifacts=(artifact,),
            metrics={"tool_calls": 0, "fake": True},
        )

    async def stop(self, prepared: PreparedTask | None, *, reason: str) -> None:
        return None


class ScriptedLoopSupervisor:
    def __init__(self, task: TaskSpec, hops: tuple[Hop, ...]) -> None:
        self.task = task
        self.hops = hops
        self.index = 0
        self.validator = DeterministicDecisionValidator()

    async def decide(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> SupervisionOutcome:
        decision: SupervisorDecision
        if self.index < len(self.hops):
            hop = self.hops[self.index]
            if self.index == 0:
                input_ref = task.input_object.input_id
                basis_inputs = (input_ref,)
                basis_facts: tuple[str, ...] = ()
                basis_evidence: tuple[str, ...] = ()
            else:
                input_ref = next(
                    artifact.artifact_id
                    for artifact in state.artifacts.values()
                    if artifact.artifact_type == hop.input_type
                )
                basis_inputs = ()
                basis_facts = (list(state.facts)[-1],)
                basis_evidence = (list(state.evidence)[-1],)
            decision = InvokeCapabilityDecision(
                capability_id=hop.capability_id,
                input_refs=(input_ref,),
                question_id=f"question-{self.index}",
                objective=f"Execute fake {hop.capability_id} hop.",
                basis_input_refs=basis_inputs,
                basis_fact_refs=basis_facts,
                basis_evidence_refs=basis_evidence,
                expected_output_types=(hop.expected_output_type,),
                allocated_budget=1.0,
                rationale="The scripted Layer 2 route requires this hop.",
            )
        else:
            decision = CompleteDecision(
                summary="The scripted fake-agent loop completed.",
                satisfied_conditions={task.success_conditions[0]: (list(state.evidence)[-1],)},
                rationale="Every scripted hop completed with fake evidence.",
            )
        self.index += 1
        validation = self.validator.validate(
            decision,
            task=task,
            state=state,
            catalog=default_catalog(),
            budget=budget,
        )
        return SupervisionOutcome(decision, validation, {})


class ScriptedLoopInterpreter:
    def __init__(self, hop_count: int) -> None:
        self.hop_count = hop_count

    def interpret(
        self,
        *,
        preview: StateUpdate,
        decision: InvokeCapabilityDecision,
        result: AgentResult,
    ) -> SemanticStateProposal:
        current = int(decision.question_id.rsplit("-", 1)[1])
        fact_id = preview.delta.added_fact_ids[0]
        questions = ()
        if current + 1 < self.hop_count:
            questions = (
                UnresolvedQuestion(
                    f"question-{current + 1}",
                    "Continue the scripted cross-domain investigation.",
                    priority=100,
                    source=preview.delta.added_artifact_ids[0],
                ),
            )
        return SemanticStateProposal(
            new_questions=questions,
            resolutions=(QuestionResolution(decision.question_id, (fact_id,)),),
        )


def _task(tmp_path: Path, scenario: str, input_type: str) -> TaskSpec:
    task_id = f"layer-two-{scenario}"
    root = (tmp_path / "runs" / task_id).resolve()
    if input_type == "network_target":
        target = "https://layer-two.invalid/"
        input_object = InputObject("input-original", input_type, target)
        target_object = TargetObject("target-original", input_type, target)
        authorization = AuthorizationScope(allowed_targets=(target,), workspace=str(root))
        metadata = {}
    else:
        path = root / "artifacts" / "input" / "sample.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"deterministic-layer-two-input")
        artifact = Artifact.from_path("source", input_type, path)
        target = str(path)
        input_object = InputObject(
            "input-original",
            "file",
            target,
            path=target,
            source_name=path.name,
            sha256=artifact.sha256,
            size_bytes=artifact.size,
            metadata={"normalized_type": input_type},
        )
        target_object = TargetObject("target-original", input_type, target)
        authorization = AuthorizationScope(
            allowed_targets=(target,),
            allowed_read_paths=(str(root),),
            workspace=str(root),
        )
        metadata = {"file_type": {"normalized_type": input_type}}
    return TaskSpec(
        task_id,
        "hybrid",
        target,
        "Complete the scripted Layer 2 fake-agent route.",
        budget=5.0,
        workspace=str(root),
        scope={"allowed_targets": [target]},
        success_conditions=("The expected fake-agent route completed.",),
        metadata=metadata,
        input_object=input_object,
        target_object=target_object,
        authorization=authorization,
        tool_call_budget=0,
        model_budget=0.0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("scenario", "hops"), SCENARIOS)
async def test_layer_two_scripted_fake_agent_loops(
    tmp_path: Path,
    scenario: str,
    hops: tuple[Hop, ...],
) -> None:
    task = _task(tmp_path, scenario, hops[0].input_type)
    state = HunterWorldState.from_task(task)
    state.add_question(UnresolvedQuestion("question-0", "Start the fake route.", priority=100))
    calls: list[str] = []
    adapters = {
        hop.capability_id: FakeCapabilityAdapter(hop, calls)
        for hop in hops
    }
    orchestrator = HunterOrchestrator(
        supervisor=ScriptedLoopSupervisor(task, hops),
        adapters=CapabilityAdapterRegistry(adapters),
        runs_root=tmp_path / "runs",
        result_interpreter=ScriptedLoopInterpreter(len(hops)),
        verifier=GlobalVerifier(),
    )

    result = await orchestrator.run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE
    assert calls == [hop.capability_id for hop in hops]
    assert result.state.unresolved_questions == {}
    assert result.budget.capability_calls_used == len(hops)
    assert result.budget.tool_calls_used == 0
    assert result.budget.model_budget_used == 0.0
    assert len(result.state.child_task_ids) == len(hops)
