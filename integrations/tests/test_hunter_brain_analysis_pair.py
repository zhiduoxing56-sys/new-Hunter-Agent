from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import CompleteDecision, InvokeCapabilityDecision, SupervisorDecision
from hunter_brain.orchestrator import HunterOrchestrator, OrchestrationStatus
from hunter_brain.state import HunterWorldState, UnresolvedQuestion
from hunter_brain.state_updater import QuestionResolution, SemanticStateProposal, StateUpdate
from hunter_brain.supervisor import SupervisionOutcome
from hunter_brain.validator import BudgetSnapshot, DeterministicDecisionValidator
from hunter_brain.verifier import GlobalVerifier
from integrations.hunter_brain import build_analysis_brain_adapters
from pentestgpt_agent.protocol import (
    AgentResult,
    AuthorizationScope,
    InputObject,
    TargetObject,
    TaskSpec,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_analysis_pair_registers_only_public_dfir_and_reverse_capabilities() -> None:
    pair = build_analysis_brain_adapters(repo_root=PROJECT_ROOT)
    registry = pair.registry()

    assert registry.get("dfir") is pair.trudi
    assert registry.get("reverse") is pair.kong
    assert registry.get("pentest") is None
    assert registry.get("vulnerability_research") is None


class EvidenceDrivenAnalysisSupervisor:
    """Acceptance policy that chooses the next backend from catalogued artifact types."""

    def __init__(self, task: TaskSpec) -> None:
        self.task = task
        self.catalog = default_catalog()
        self.validator = DeterministicDecisionValidator()
        self.calls = 0
        self.selected_capabilities: list[str] = []

    async def decide(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> SupervisionOutcome:
        decision: SupervisorDecision
        question = max(
            state.unresolved_questions.values(),
            key=lambda item: (item.priority, item.question_id),
            default=None,
        )
        if question is None:
            decision = CompleteDecision(
                "TRUDI evidence triage and Kong binary metadata analysis both produced evidence.",
                {task.success_conditions[0]: (list(state.evidence)[-1],)},
                "No unresolved question remains after two evidence-producing calls.",
            )
        elif not state.dispatch_history:
            decision = InvokeCapabilityDecision(
                "dfir",
                ("input-evidence",),
                question.question_id,
                "Triage and export the acquired evidence file.",
                ("input-evidence",),
                (),
                (),
                ("suspicious_binary",),
                1.0,
                "The acquired evidence has not been triaged.",
            )
        else:
            candidates = [
                (artifact, capability)
                for artifact in state.artifacts.values()
                for capability in self.catalog.candidates_for_input(artifact.artifact_type)
                if capability.capability_id in {"dfir", "reverse"}
                and not any(
                    record.capability_id == capability.capability_id
                    and artifact.artifact_id in record.input_refs
                    for record in state.dispatch_history
                )
            ]
            artifact, capability = candidates[0]
            decision = InvokeCapabilityDecision(
                capability.capability_id,
                (artifact.artifact_id,),
                question.question_id,
                "Analyze the newly recovered artifact to answer the current question.",
                (),
                (next(reversed(state.facts)),),
                (next(reversed(state.evidence)),),
                tuple(question.required_output_types),
                1.0,
                "A new compatible artifact was produced by the previous professional call.",
            )
        self.calls += 1
        if isinstance(decision, InvokeCapabilityDecision):
            self.selected_capabilities.append(decision.capability_id)
        validation = self.validator.validate(
            decision,
            task=task,
            state=state,
            catalog=self.catalog,
            budget=budget,
        )
        return SupervisionOutcome(decision, validation, {})


class AnalysisPairInterpreter:
    def interpret(
        self,
        *,
        preview: StateUpdate,
        decision: InvokeCapabilityDecision,
        result: AgentResult,
    ) -> SemanticStateProposal:
        if not preview.delta.added_fact_ids:
            return SemanticStateProposal()
        fact_id = preview.delta.added_fact_ids[0]
        if decision.capability_id == "dfir":
            recovered = any(
                artifact.artifact_type == "suspect_binary"
                for artifact in preview.state.artifacts.values()
            )
            if not recovered:
                return SemanticStateProposal()
            return SemanticStateProposal(
                new_questions=(
                    UnresolvedQuestion(
                        "question-binary-behavior",
                        "What format and architecture metadata describes the recovered binary?",
                        100,
                        ("binary_metadata",),
                        fact_id,
                    ),
                ),
                resolutions=(QuestionResolution(decision.question_id, (fact_id,)),),
            )
        return SemanticStateProposal(
            resolutions=(QuestionResolution(decision.question_id, (fact_id,)),)
        )


def _live_task(tmp_path: Path) -> TaskSpec:
    source = Path(os.environ.get("HUNTER_ANALYSIS_PAIR_ELF", "/bin/true")).resolve()
    if not source.is_file():
        pytest.skip(f"ELF fixture is unavailable: {source}")
    task_id = "analysis-pair-live"
    root = (tmp_path / "runs" / task_id).resolve()
    managed = root / "artifacts" / "input" / source.name
    managed.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, managed)
    digest = hashlib.sha256(managed.read_bytes()).hexdigest()
    size = managed.stat().st_size
    return TaskSpec(
        task_id,
        "dfir",
        str(managed),
        "Triage the acquired executable as evidence, then identify its binary metadata.",
        timeout=60,
        budget=4.0,
        workspace=str(root),
        scope={"allowed_targets": [str(managed)]},
        success_conditions=("The acquired evidence and binary metadata are both analyzed.",),
        metadata={
            "file_type": {"normalized_type": "evidence_file", "sha256": digest},
            "export_evidence_artifact": True,
            "kong_mode": "info",
            "trudi_mode": "lite",
        },
        input_object=InputObject(
            "input-evidence",
            "file",
            str(managed),
            path=str(managed),
            source_name=managed.name,
            sha256=digest,
            size_bytes=size,
        ),
        target_object=TargetObject("target-evidence", "evidence_file", str(managed)),
        authorization=AuthorizationScope(
            (str(managed),),
            allowed_read_paths=(str(root),),
            workspace=str(root),
        ),
        tool_call_budget=20,
        model_budget=2.0,
    )


@pytest.mark.asyncio
async def test_real_trudi_to_kong_dynamic_two_backend_loop(tmp_path: Path) -> None:
    if os.environ.get("HUNTER_ANALYSIS_PAIR_LIVE") != "1":
        pytest.skip("set HUNTER_ANALYSIS_PAIR_LIVE=1 to run real TRUDI and Kong")
    java_home = Path(
        os.environ.get("HUNTER_KONG_JAVA_HOME", PROJECT_ROOT.parent / ".tools/jdk21")
    )
    ghidra_dir = Path(
        os.environ.get(
            "HUNTER_KONG_GHIDRA_DIR",
            PROJECT_ROOT.parent / ".tools/ghidra/ghidra_12.1.3_PUBLIC",
        )
    )
    task = _live_task(tmp_path)
    state = HunterWorldState.from_task(task)
    state.add_question(
        UnresolvedQuestion(
            "question-triage",
            "What does initial evidence triage establish?",
            100,
            ("suspicious_binary",),
        )
    )
    supervisor = EvidenceDrivenAnalysisSupervisor(task)
    pair = build_analysis_brain_adapters(
        repo_root=PROJECT_ROOT,
        trudi_mode="lite",
        java_home=java_home,
        ghidra_dir=ghidra_dir,
    )
    orchestrator = HunterOrchestrator(
        supervisor=supervisor,
        adapters=pair.registry(),
        runs_root=tmp_path / "runs",
        result_interpreter=AnalysisPairInterpreter(),
        verifier=GlobalVerifier(),
    )

    result = await orchestrator.run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE
    assert supervisor.selected_capabilities == ["dfir", "reverse"]
    assert result.state.unresolved_questions == {}
    assert {record.capability_id for record in result.state.dispatch_history} == {
        "dfir",
        "reverse",
    }
    assert all(record.new_evidence for record in result.state.dispatch_history)
    assert len(result.state.child_task_ids) == 2


class CatalogThreeStageSupervisor:
    """Choose every hop solely from question output types and accepted input types."""

    def __init__(self, task: TaskSpec) -> None:
        self.task = task
        self.catalog = default_catalog()
        self.validator = DeterministicDecisionValidator()
        self.selected_capabilities: list[str] = []

    async def decide(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> SupervisionOutcome:
        question = max(
            state.unresolved_questions.values(),
            key=lambda item: (item.priority, item.question_id),
            default=None,
        )
        if question is None:
            decision: SupervisorDecision = CompleteDecision(
                "Three real type-driven stages produced grounded evidence.",
                {task.success_conditions[0]: (list(state.evidence)[-1],)},
                "All type-driven questions are resolved.",
            )
        else:
            typed_inputs: list[tuple[str, str]] = []
            if not state.dispatch_history and task.input_object is not None:
                normalized = task.metadata["file_type"]["normalized_type"]
                typed_inputs.append((task.input_object.input_id, str(normalized)))
            typed_inputs.extend(
                (artifact.artifact_id, artifact.artifact_type)
                for artifact in state.artifacts.values()
            )
            choices = [
                (reference, capability)
                for reference, input_type in typed_inputs
                for capability in self.catalog.candidates_for_input(input_type)
                if set(question.required_output_types) & capability.produces
                and not any(
                    record.capability_id == capability.capability_id
                    and reference in record.input_refs
                    for record in state.dispatch_history
                )
            ]
            reference, capability = choices[0]
            decision = InvokeCapabilityDecision(
                capability.capability_id,
                (reference,),
                question.question_id,
                question.question,
                (reference,) if reference == "input-evidence" else (),
                (next(reversed(state.facts)),) if state.facts else (),
                (next(reversed(state.evidence)),) if state.evidence else (),
                (next(iter(set(question.required_output_types) & capability.produces)),),
                1.0,
                "The capability catalogue declares compatible input and output types.",
            )
            self.selected_capabilities.append(capability.capability_id)
        validation = self.validator.validate(
            decision,
            task=task,
            state=state,
            catalog=self.catalog,
            budget=budget,
        )
        return SupervisionOutcome(decision, validation, {})


class ThreeStageInterpreter:
    def interpret(
        self,
        *,
        preview: StateUpdate,
        decision: InvokeCapabilityDecision,
        result: AgentResult,
    ) -> SemanticStateProposal:
        fact_id = preview.delta.added_fact_ids[0]
        produced = set(decision.expected_output_types)
        if "suspicious_binary" in produced:
            questions = (
                UnresolvedQuestion(
                    "question-reverse",
                    "Identify the recovered binary metadata.",
                    100,
                    ("binary_metadata",),
                    fact_id,
                ),
            )
        elif "binary_metadata" in produced:
            questions = (
                UnresolvedQuestion(
                    "question-dfir-correlation",
                    "Correlate the reverse result with forensic evidence.",
                    100,
                    ("finding",),
                    fact_id,
                ),
            )
        else:
            questions = ()
        return SemanticStateProposal(
            new_questions=questions,
            resolutions=(QuestionResolution(decision.question_id, (fact_id,)),),
        )


@pytest.mark.asyncio
async def test_real_catalog_driven_three_stage_dfir_reverse_dfir_loop(
    tmp_path: Path,
) -> None:
    if os.environ.get("HUNTER_ANALYSIS_PAIR_LIVE") != "1":
        pytest.skip("set HUNTER_ANALYSIS_PAIR_LIVE=1 to run real TRUDI and Kong")
    task = _live_task(tmp_path)
    state = HunterWorldState.from_task(task)
    state.add_question(
        UnresolvedQuestion(
            "question-triage",
            "Triage and export the acquired evidence.",
            100,
            ("suspicious_binary",),
        )
    )
    supervisor = CatalogThreeStageSupervisor(task)
    pair = build_analysis_brain_adapters(
        repo_root=PROJECT_ROOT,
        trudi_mode="lite",
        java_home=Path(
            os.environ.get("HUNTER_KONG_JAVA_HOME", PROJECT_ROOT.parent / ".tools/jdk21")
        ),
        ghidra_dir=Path(
            os.environ.get(
                "HUNTER_KONG_GHIDRA_DIR",
                PROJECT_ROOT.parent / ".tools/ghidra/ghidra_12.1.3_PUBLIC",
            )
        ),
    )
    result = await HunterOrchestrator(
        supervisor=supervisor,
        adapters=pair.registry(),
        runs_root=tmp_path / "runs",
        result_interpreter=ThreeStageInterpreter(),
        verifier=GlobalVerifier(),
    ).run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE
    assert supervisor.selected_capabilities == ["dfir", "reverse", "dfir"]
    assert result.state.unresolved_questions == {}
    assert len(result.state.child_task_ids) == 3
