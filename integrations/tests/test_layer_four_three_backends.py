from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from autopenbench_adapter.protocol import AutoPenBenchProtocolAdapter
from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import CompleteDecision, InvokeCapabilityDecision, SupervisorDecision
from hunter_brain.orchestrator import (
    CapabilityAdapterRegistry,
    HunterOrchestrator,
    OrchestrationStatus,
)
from hunter_brain.state import ArtifactRecord, HunterWorldState, UnresolvedQuestion
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


class ThreeBackendCatalogSupervisor:
    def __init__(self, task: TaskSpec) -> None:
        self.task = task
        self.catalog = default_catalog()
        self.validator = DeterministicDecisionValidator()
        self.selected: list[str] = []

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
                "PentestGPT, TRUDI, and Kong completed a type-driven real loop.",
                {task.success_conditions[0]: (list(state.evidence)[-1],)},
                "All three evidence-backed stages resolved their questions.",
            )
        else:
            inputs: list[tuple[str, str]] = []
            if not state.dispatch_history and task.input_object is not None:
                inputs.append((task.input_object.input_id, task.input_object.kind))
            inputs.extend(
                (artifact.artifact_id, artifact.artifact_type)
                for artifact in state.artifacts.values()
            )
            choices = [
                (reference, capability)
                for reference, input_type in inputs
                for capability in self.catalog.candidates_for_input(input_type)
                if set(question.required_output_types) & capability.produces
                and capability.capability_id in {"pentest", "dfir", "reverse"}
                and not any(
                    record.capability_id == capability.capability_id
                    and reference in record.input_refs
                    for record in state.dispatch_history
                )
            ]
            reference, capability = choices[0]
            expected = next(iter(set(question.required_output_types) & capability.produces))
            decision = InvokeCapabilityDecision(
                capability.capability_id,
                (reference,),
                question.question_id,
                task.goal if capability.capability_id == "pentest" else question.question,
                (reference,) if reference == "input-network" else (),
                (next(reversed(state.facts)),) if state.facts else (),
                (next(reversed(state.evidence)),) if state.evidence else (),
                (expected,),
                1.0,
                "Catalogue input/output compatibility selects this capability.",
            )
            self.selected.append(capability.capability_id)
        validation = self.validator.validate(
            decision,
            task=task,
            state=state,
            catalog=self.catalog,
            budget=budget,
        )
        return SupervisionOutcome(decision, validation, {})


class ThreeBackendInterpreter:
    def interpret(
        self,
        *,
        preview: StateUpdate,
        decision: InvokeCapabilityDecision,
        result: AgentResult,
    ) -> SemanticStateProposal:
        fact_id = preview.delta.added_fact_ids[0]
        produced = set(decision.expected_output_types)
        if "target_flag" in produced:
            questions = (
                UnresolvedQuestion(
                    "question-dfir",
                    "Preserve and triage the penetration-test evaluation evidence.",
                    100,
                    ("finding",),
                    fact_id,
                ),
            )
        elif "finding" in produced:
            questions = (
                UnresolvedQuestion(
                    "question-reverse",
                    "Analyze the separately acquired binary evidence.",
                    100,
                    ("binary_metadata",),
                    fact_id,
                ),
            )
        else:
            questions = ()
        return SemanticStateProposal(
            new_questions=questions,
            resolutions=(QuestionResolution(decision.question_id, (fact_id,)),),
        )


def _live_task(
    tmp_path: Path, adapter: AutoPenBenchProtocolAdapter
) -> tuple[TaskSpec, HunterWorldState]:
    game = adapter.game()
    task_id = "layer-four-three-real-backends"
    root = (tmp_path / "runs" / task_id).resolve()
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.fail("gcc is required for the benign reverse fixture")
    source = PROJECT_ROOT / "integrations/kong/tests/fixtures/benign.c"
    binary = root / "artifacts/input/benign"
    binary.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [compiler, "-O0", "-g", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    target = str(game["target"])
    task = TaskSpec(
        task_id,
        "hybrid",
        target,
        str(game["task"]),
        timeout=3600,
        budget=6.0,
        workspace=str(root),
        scope={"allowed_targets": [target]},
        success_conditions=("All three professional backends produce grounded results.",),
        metadata={"kong_mode": "info", "trudi_mode": "lite"},
        input_object=InputObject("input-network", "network_target", target),
        target_object=TargetObject("target-network", "network_target", target),
        authorization=AuthorizationScope(
            (target,),
            allowed_read_paths=(str(root),),
            workspace=str(root),
        ),
        tool_call_budget=100,
        model_budget=20.0,
    )
    state = HunterWorldState.from_task(task)
    state.add_artifact(
        ArtifactRecord.from_protocol(
            Artifact.from_path("seed-binary", "elf", binary, producer="layer-one"),
            source_task_id=task.task_id,
        )
    )
    state.add_question(
        UnresolvedQuestion(
            "question-pentest",
            task.goal,
            100,
            ("target_flag",),
        )
    )
    return task, state


@pytest.mark.asyncio
async def test_real_pentest_trudi_kong_catalog_driven_loop(tmp_path: Path) -> None:
    if os.environ.get("HUNTER_THREE_BACKEND_LIVE") != "1":
        pytest.skip("set HUNTER_THREE_BACKEND_LIVE=1 to run all three real backends")
    pentest = AutoPenBenchProtocolAdapter(backend="codex")
    task, state = _live_task(tmp_path, pentest)
    supervisor = ThreeBackendCatalogSupervisor(task)
    adapters = CapabilityAdapterRegistry(
        {
            "pentest": pentest,
            "dfir": TrudiAdapter(mode="lite"),
            "reverse": KongAdapter(
                java_home=PROJECT_ROOT.parent / ".tools/jdk21",
                ghidra_dir=(
                    PROJECT_ROOT.parent
                    / ".tools/ghidra-12.0.4/ghidra_12.0.4_PUBLIC"
                ),
                kong_config_dir=PROJECT_ROOT / ".runtime/kong/config",
            ),
        }
    )

    result = await HunterOrchestrator(
        supervisor=supervisor,
        adapters=adapters,
        runs_root=tmp_path / "runs",
        result_interpreter=ThreeBackendInterpreter(),
        verifier=GlobalVerifier(),
    ).run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE
    assert supervisor.selected == ["pentest", "dfir", "reverse"]
    assert result.state.unresolved_questions == {}
    assert len(result.state.child_task_ids) == 3
