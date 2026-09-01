from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import (
    CompleteDecision,
    InvokeCapabilityDecision,
    SupervisorDecision,
    VerifyDecision,
)
from hunter_brain.orchestrator import (
    AUDIT_FILENAME,
    SUBTASKS_DIRECTORY,
    CapabilityAdapterRegistry,
    HunterOrchestrator,
    OrchestrationStatus,
)
from hunter_brain.state import EvidenceRecord, HunterWorldState, UnresolvedQuestion, VerifiedFact
from hunter_brain.state_updater import (
    QuestionResolution,
    SemanticStateProposal,
    StateUpdate,
)
from hunter_brain.supervisor import SupervisionOutcome
from hunter_brain.validator import BudgetSnapshot, DeterministicDecisionValidator
from hunter_brain.verifier import (
    GlobalVerifier,
    SemanticAssessment,
    SemanticVerificationRequest,
)
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


@dataclass
class ConcurrencyProbe:
    active: int = 0
    maximum: int = 0


class ProducingAdapter(AgentAdapter):
    def __init__(self, agent_id: str, output_type: str, probe: ConcurrencyProbe) -> None:
        self.agent_id = agent_id
        self.output_type = output_type
        self.probe = probe
        self._started_at = "2026-08-29T00:00:00+00:00"

    async def healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        return HealthcheckResult(True, {"agent_id": self.agent_id})

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        return PreparedTask(task_spec, run_layout)

    async def run(self, prepared: PreparedTask) -> ExecutionHandle:
        self.probe.active += 1
        self.probe.maximum = max(self.probe.maximum, self.probe.active)
        output = prepared.run_layout.artifacts / "output.bin"
        output.write_bytes(f"{self.agent_id}:{prepared.task_spec.target}".encode())
        self.probe.active -= 1
        return ExecutionHandle(f"handle-{self.agent_id}", self._started_at)

    async def collect(
        self, prepared: PreparedTask, handle: ExecutionHandle
    ) -> AgentResult:
        artifact = Artifact.from_path(
            "output",
            self.output_type,
            prepared.run_layout.artifacts / "output.bin",
            producer=self.agent_id,
        )
        evidence = Evidence(
            "evidence",
            "artifact_analysis",
            self.agent_id,
            f"{self.agent_id} produced an evidence-backed result.",
            artifact_ref=artifact.artifact_id,
        )
        finding = Finding(
            "finding",
            "analysis",
            f"{self.agent_id} finding",
            "The professional subtask produced grounded information.",
            evidence_refs=(evidence.evidence_id,),
        )
        return AgentResult(
            prepared.task_spec.task_id,
            self.agent_id,
            prepared.task_spec.domain,
            ExecutionStatus.SUCCESS,
            self._started_at,
            "2026-08-29T00:00:01+00:00",
            f"{self.agent_id} completed.",
            findings=(finding,),
            evidence=(evidence,),
            artifacts=(artifact,),
            metrics={"tool_calls": 1},
        )

    async def stop(self, prepared: PreparedTask | None, *, reason: str) -> None:
        return None


class TwoHopSupervisor:
    def __init__(self, task: TaskSpec) -> None:
        self.task = task
        self.calls = 0
        self.validator = DeterministicDecisionValidator()
        self.catalog = default_catalog()

    async def decide(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> SupervisionOutcome:
        decision: SupervisorDecision
        if self.calls == 0:
            decision = InvokeCapabilityDecision(
                capability_id="dfir",
                input_refs=("input-original",),
                question_id="question-investigate",
                objective="Investigate the event log and recover suspicious files.",
                basis_input_refs=("input-original",),
                basis_fact_refs=(),
                basis_evidence_refs=(),
                expected_output_types=("suspicious_binary",),
                allocated_budget=1.0,
                rationale="The event log is the initial evidence source.",
            )
        elif self.calls == 1:
            artifact_id = next(
                item.artifact_id
                for item in state.artifacts.values()
                if item.artifact_type == "suspect_binary"
            )
            decision = InvokeCapabilityDecision(
                capability_id="reverse",
                input_refs=(artifact_id,),
                question_id="question-behavior",
                objective="Explain the recovered binary's behavior.",
                basis_input_refs=(),
                basis_fact_refs=(next(iter(state.facts)),),
                basis_evidence_refs=(next(iter(state.evidence)),),
                expected_output_types=("program_behavior",),
                allocated_budget=1.0,
                rationale="DFIR recovered a suspicious binary whose behavior is unknown.",
            )
        else:
            decision = CompleteDecision(
                summary="The event evidence was investigated and the recovered binary analyzed.",
                satisfied_conditions={
                    self.task.success_conditions[0]: (list(state.evidence)[-1],),
                },
                rationale="Both investigation questions are resolved with evidence.",
            )
        self.calls += 1
        validation = self.validator.validate(
            decision,
            task=task,
            state=state,
            catalog=self.catalog,
            budget=budget,
        )
        return SupervisionOutcome(decision, validation, {"cost": 0.1})


class TwoHopInterpreter:
    def interpret(
        self,
        *,
        preview: StateUpdate,
        decision: InvokeCapabilityDecision,
        result: AgentResult,
    ) -> SemanticStateProposal:
        fact_id = preview.delta.added_fact_ids[0]
        if decision.capability_id == "dfir":
            return SemanticStateProposal(
                new_questions=(
                    UnresolvedQuestion(
                        "question-behavior",
                        "What does the recovered binary do?",
                        priority=100,
                        required_output_types=("program_behavior",),
                        source=fact_id,
                    ),
                ),
                resolutions=(QuestionResolution(decision.question_id, (fact_id,)),),
            )
        return SemanticStateProposal(
            resolutions=(QuestionResolution(decision.question_id, (fact_id,)),)
        )


def _managed_file_task(tmp_path: Path) -> TaskSpec:
    task_id = "orchestrator-two-hop"
    root = (tmp_path / "runs" / task_id).resolve()
    input_path = root / "artifacts" / "input" / "events.evtx"
    input_path.parent.mkdir(parents=True, exist_ok=True)
    input_path.write_bytes(b"event-log-evidence")
    artifact = Artifact.from_path("source", "evtx", input_path)
    return TaskSpec(
        task_id=task_id,
        domain="dfir",
        target=str(input_path),
        goal="Investigate the event log and explain any recovered suspicious binary.",
        budget=5.0,
        workspace=str(root),
        scope={"allowed_targets": [str(input_path)]},
        success_conditions=("The suspicious execution and binary behavior are explained.",),
        metadata={"file_type": {"normalized_type": "evtx"}},
        input_object=InputObject(
            "input-original",
            "file",
            str(input_path),
            path=str(input_path),
            source_name=input_path.name,
            sha256=artifact.sha256,
            size_bytes=artifact.size,
        ),
        target_object=TargetObject("target-original", "evtx", str(input_path)),
        authorization=AuthorizationScope(
            allowed_targets=(str(input_path),),
            allowed_read_paths=(str(root),),
            workspace=str(root),
        ),
        tool_call_budget=10,
        model_budget=2.0,
    )


@pytest.mark.asyncio
async def test_two_hop_cross_domain_loop_is_serial_isolated_and_persistent(
    tmp_path: Path,
) -> None:
    task = _managed_file_task(tmp_path)
    state = HunterWorldState.from_task(task)
    state.add_question(
        UnresolvedQuestion(
            "question-investigate",
            "What suspicious activity and files are present?",
            priority=100,
            required_output_types=("suspicious_binary",),
        )
    )
    probe = ConcurrencyProbe()
    supervisor = TwoHopSupervisor(task)
    orchestrator = HunterOrchestrator(
        supervisor=supervisor,
        adapters=CapabilityAdapterRegistry(
            {
                "dfir": ProducingAdapter("dfir-test", "suspect_binary", probe),
                "reverse": ProducingAdapter("reverse-test", "reverse_analysis", probe),
            }
        ),
        runs_root=tmp_path / "runs",
        result_interpreter=TwoHopInterpreter(),
        verifier=GlobalVerifier(),
    )

    result = await orchestrator.run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE
    assert probe.maximum == 1
    assert supervisor.calls == 3
    assert len(result.state.child_task_ids) == 2
    assert len(result.state.artifacts) == 2
    assert len(result.state.evidence) == 2
    assert len(result.state.facts) == 2
    assert result.state.unresolved_questions == {}
    assert len(set(result.state.artifacts)) == 2
    assert all(identifier.startswith("child-") for identifier in result.state.artifacts)
    global_root = tmp_path / "runs" / task.task_id
    child_roots = sorted((global_root / SUBTASKS_DIRECTORY).glob("*-brain-*"))
    assert len(child_roots) == 2
    assert all((path / "result.json").is_file() for path in child_roots)
    assert HunterWorldState.load(global_root) == result.state
    audit_lines = [
        json.loads(line)
        for line in (global_root / AUDIT_FILENAME).read_text(encoding="utf-8").splitlines()
    ]
    assert [item["event_type"] for item in audit_lines] == [
        "decision",
        "agent_result_verification",
        "capability_result",
        "decision",
        "agent_result_verification",
        "capability_result",
        "decision",
        "completion_verification",
        "completed",
    ]
    assert result.budget.capability_calls_used == 2
    assert result.budget.tool_calls_used == 2
    assert result.budget.total_budget_used == 2.0


class VerifyThenCompleteSupervisor:
    def __init__(self, task: TaskSpec) -> None:
        self.task = task
        self.calls = 0
        self.validator = DeterministicDecisionValidator()

    async def decide(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> SupervisionOutcome:
        decision: SupervisorDecision
        if self.calls == 0:
            decision = VerifyDecision(
                "Verify that the fact answers the user question.",
                ("evidence-existing",),
                ("semantic_support",),
                "A semantic answer check is still required.",
            )
        else:
            decision = CompleteDecision(
                "The existing fact passed semantic verification.",
                {task.success_conditions[0]: ("evidence-existing",)},
                "No critical questions remain.",
            )
        self.calls += 1
        return SupervisionOutcome(
            decision,
            self.validator.validate(
                decision,
                task=task,
                state=state,
                catalog=default_catalog(),
                budget=budget,
            ),
            {},
        )


class RequestOnlyResolvingModel:
    async def assess(self, request: SemanticVerificationRequest) -> SemanticAssessment:
        resolutions = (
            (QuestionResolution("question-existing", ("fact-existing",)),)
            if request.kind == "verification_request"
            else ()
        )
        return SemanticAssessment(True, "The existing evidence supports the fact.", resolutions)


@pytest.mark.asyncio
async def test_explicit_verify_action_passes_resolves_question_and_reenters_loop(
    tmp_path: Path,
) -> None:
    target = "https://allowed.example/"
    task = TaskSpec(
        "verify-loop",
        "pentest",
        target,
        "Verify the existing evidence and finish.",
        success_conditions=("The existing conclusion is verified.",),
        input_object=InputObject("input-network", "network_target", target),
        authorization=AuthorizationScope(allowed_targets=(target,)),
    )
    state = HunterWorldState.from_task(task)
    state.add_evidence(
        EvidenceRecord(
            "evidence-existing",
            "observation",
            "test-source",
            "Existing grounded observation.",
        )
    )
    state.add_fact(
        VerifiedFact("fact-existing", "The observation is established.", ("evidence-existing",))
    )
    state.add_question(UnresolvedQuestion("question-existing", "Is the fact sufficient?", 100))
    probe = ConcurrencyProbe()
    supervisor = VerifyThenCompleteSupervisor(task)
    orchestrator = HunterOrchestrator(
        supervisor=supervisor,
        adapters=CapabilityAdapterRegistry(
            {"pentest": ProducingAdapter("unused", "text_report", probe)}
        ),
        runs_root=tmp_path / "runs",
        verifier=GlobalVerifier(semantic_model=RequestOnlyResolvingModel()),
    )

    result = await orchestrator.run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE
    assert result.state.unresolved_questions == {}
    assert supervisor.calls == 2
    audit = (tmp_path / "runs" / task.task_id / AUDIT_FILENAME).read_text(encoding="utf-8")
    assert "verification_result" in audit
    assert "completion_verification" in audit


class InconclusiveVerifyThenCompleteSupervisor:
    """Issue a semantic-support verify (inconclusive without a semantic model),
    then complete on the existing verified fact."""

    def __init__(self, task: TaskSpec) -> None:
        self.task = task
        self.calls = 0
        self.validator = DeterministicDecisionValidator()

    async def decide(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> SupervisionOutcome:
        decision: SupervisorDecision
        if self.calls == 0:
            decision = VerifyDecision(
                "Verify that the fact answers the user question.",
                ("evidence-existing",),
                ("semantic_support",),
                "A semantic answer check is still required.",
            )
        else:
            decision = CompleteDecision(
                "The existing fact satisfies the goal.",
                {task.success_conditions[0]: ("evidence-existing",)},
                "No critical questions remain.",
            )
        self.calls += 1
        return SupervisionOutcome(
            decision,
            self.validator.validate(
                decision,
                task=task,
                state=state,
                catalog=default_catalog(),
                budget=budget,
            ),
            {},
        )


@pytest.mark.asyncio
async def test_inconclusive_semantic_verify_does_not_dead_end_the_run(
    tmp_path: Path,
) -> None:
    target = "https://allowed.example/"
    task = TaskSpec(
        "verify-inconclusive-loop",
        "pentest",
        target,
        "Verify the existing evidence and finish.",
        success_conditions=("The existing conclusion is verified.",),
        input_object=InputObject("input-network", "network_target", target),
        authorization=AuthorizationScope(allowed_targets=(target,)),
    )
    state = HunterWorldState.from_task(task)
    state.add_evidence(
        EvidenceRecord(
            "evidence-existing",
            "observation",
            "test-source",
            "Existing grounded observation.",
        )
    )
    state.add_fact(
        VerifiedFact("fact-existing", "The observation is established.", ("evidence-existing",))
    )
    probe = ConcurrencyProbe()
    supervisor = InconclusiveVerifyThenCompleteSupervisor(task)
    orchestrator = HunterOrchestrator(
        supervisor=supervisor,
        adapters=CapabilityAdapterRegistry(
            {"pentest": ProducingAdapter("unused", "text_report", probe)}
        ),
        runs_root=tmp_path / "runs",
        verifier=GlobalVerifier(),
    )

    result = await orchestrator.run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE
    assert supervisor.calls == 2
    audit = (tmp_path / "runs" / task.task_id / AUDIT_FILENAME).read_text(encoding="utf-8")
    assert "verification_inconclusive" in audit
    assert "completion_verification" in audit
