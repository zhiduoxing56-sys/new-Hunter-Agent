"""Live Layer 4 test: global brain dynamically selects real FuzzingBrain.

Drives HunterOrchestrator with the real FuzzingBrainAdapter and in-process
mock adapters for the other three domains. The deterministic supervisor
must (1) choose vulnerability_research because the unresolved question
requires a trigger, (2) read the real AgentResult into world state, and
(3) replan and hand the trigger_sample to reverse for follow-up analysis.

Skipped unless HUNTER_FUZZINGBRAIN_LIVE=1.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import CompleteDecision, InvokeCapabilityDecision, SupervisorDecision
from hunter_brain.orchestrator import HunterOrchestrator, OrchestrationStatus, _directory_digest
from hunter_brain.state import ArtifactRecord, HunterWorldState, UnresolvedQuestion
from hunter_brain.state_updater import QuestionResolution, SemanticStateProposal
from hunter_brain.supervisor import SupervisionOutcome
from hunter_brain.validator import BudgetSnapshot, DeterministicDecisionValidator
from hunter_brain.verifier import GlobalVerifier
from integrations.fuzzingbrain import FuzzingBrainAdapter
from pentestgpt_agent.protocol import (
    Artifact,
    AuthorizationScope,
    ExecutionStatus,
    InputObject,
    TargetObject,
    TaskSpec,
)
from pentestgpt_agent.protocol.mock_adapter import MockAdapter

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _fixture() -> Path:
    if os.environ.get("HUNTER_FUZZINGBRAIN_LIVE") != "1":
        pytest.skip("set HUNTER_FUZZINGBRAIN_LIVE=1 to run the real FuzzingBrain Layer 4 test")
    fixture = PROJECT_ROOT / "third_party/fuzzingbrain/fixtures/hunterdemo"
    if not (fixture / "repo").is_dir() or not (fixture / "fuzz-tooling" / "projects").is_dir():
        pytest.skip(f"FuzzingBrain fixture is unavailable: {fixture}")
    return fixture


class FuzzingBrainCatalogSupervisor:
    """Deterministic catalog supervisor: select by unresolved question + input."""

    def __init__(self) -> None:
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
                "All questions are answered by evidence-backed findings.",
                {
                    condition: (
                        next(iter(state.evidence.values())).evidence_id
                        if state.evidence
                        else "no-evidence",
                    )
                    for condition in task.success_conditions
                },
                "Every success condition is backed by world-state evidence.",
            )
            return SupervisionOutcome(decision, self.validator.validate(decision, task=task, state=state, catalog=self.catalog, budget=budget), {})

        inputs: list[tuple[str, str]] = []
        if task.input_object is not None:
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
            and not any(
                record.capability_id == capability.capability_id
                and reference in record.input_refs
                for record in state.dispatch_history
            )
        ]
        if not choices:
            raise AssertionError(f"no catalog candidate for question {question.question_id}")
        reference, capability = choices[0]
        expected = next(iter(set(question.required_output_types) & capability.produces))
        decision = InvokeCapabilityDecision(
            capability.capability_id,
            (reference,),
            question.question_id,
            question.question,
            ((reference,) if reference == task.input_object.input_id else ()),
            (next(reversed(state.facts)),) if state.facts else (),
            (next(reversed(state.evidence)),) if state.evidence else (),
            (expected,),
            1.0,
            "Catalogue input/output compatibility selects this capability.",
        )
        self.selected.append(capability.capability_id)
        return SupervisionOutcome(decision, self.validator.validate(decision, task=task, state=state, catalog=self.catalog, budget=budget), {})


class FuzzingBrainInterpreter:
    """Resolve the current question; ask reverse to explain the trigger."""

    def interpret(
        self,
        *,
        preview,
        decision: InvokeCapabilityDecision,
        result,
    ) -> SemanticStateProposal:
        fact_id = preview.delta.added_fact_ids[0] if preview.delta.added_fact_ids else "fact-none"
        new_questions: list[UnresolvedQuestion] = []
        if decision.capability_id == "vulnerability_research":
            new_questions.append(
                UnresolvedQuestion(
                    "question-reverse",
                    "Explain the behavior reachable from the reproduced trigger sample.",
                    90,
                    ("program_behavior",),
                    fact_id,
                )
            )
        return SemanticStateProposal(
            new_questions=tuple(new_questions),
            resolutions=(QuestionResolution(decision.question_id, (fact_id,)),),
        )


def _task(tmp_path: Path, fixture: Path) -> tuple[TaskSpec, HunterWorldState]:
    task_id = "layer-four-real-fuzzingbrain"
    root = (tmp_path / "runs" / task_id).resolve()
    target = str(fixture.resolve())
    task = TaskSpec(
        task_id,
        "vulnerability_research",
        target,
        "Reproduce the deterministic ASan heap-buffer-overflow in the authorized hunterdemo source tree.",
        timeout=1200,
        budget=5.0,
        workspace=str(root),
        scope={"allowed_targets": [target]},
        success_conditions=(
            "FuzzingBrain reproduces a trigger; reverse explains its behavior.",
        ),
        metadata={"fuzzingbrain_task_type": "pov-patch", "fuzzingbrain_scan_mode": "full"},
        input_object=InputObject(
            "input-source", "source_tree", target, path=target,
            source_name=fixture.name, metadata={"kind": "source_tree"},
        ),
        target_object=TargetObject("target-source", "source_tree", target),
        authorization=AuthorizationScope(
            allowed_targets=(target,),
            allowed_read_paths=(target,),
            workspace=str(root),
        ),
        tool_call_budget=50,
        model_budget=5.0,
    )
    state = HunterWorldState.from_task(task)
    state.add_artifact(
        ArtifactRecord.from_protocol(
            Artifact(
                "source-tree",
                "source_tree",
                str(fixture.resolve()),
                _directory_digest(fixture),
                sum(
                    item.stat().st_size
                    for item in fixture.rglob("*")
                    if item.is_file() and not item.is_symlink()
                ),
                {"kind": "source_tree"},
                producer="layer-one",
            ),
            source_task_id=task.task_id,
        )
    )
    state.add_question(
        UnresolvedQuestion(
            "question-reproduce",
            "Reproduce and prove the heap-buffer-overflow in the source tree.",
            100,
            ("trigger_sample",),
        )
    )
    return task, state


@pytest.mark.asyncio
async def test_real_fuzzingbrain_catalog_driven_brain_loop(tmp_path: Path) -> None:
    fixture = _fixture()
    task, state = _task(tmp_path, fixture)

    pentest = MockAdapter()
    pentest.agent_id = "pentest"
    trudi = MockAdapter()
    trudi.agent_id = "trudi"
    kong = MockAdapter()
    kong.agent_id = "kong"
    adapters = {
        "dfir": trudi,
        "reverse": kong,
        "pentest": pentest,
        "vulnerability_research": FuzzingBrainAdapter(repo_root=PROJECT_ROOT),
    }

    supervisor = FuzzingBrainCatalogSupervisor()
    orchestrator = HunterOrchestrator(
        supervisor=supervisor,
        adapters=adapters,
        runs_root=tmp_path / "runs",
        result_interpreter=FuzzingBrainInterpreter(),
        verifier=GlobalVerifier(),
    )

    result = await orchestrator.run(task, initial_state=state)

    assert result.status is OrchestrationStatus.COMPLETE, result.message
    assert supervisor.selected == ["vulnerability_research", "reverse"]

    final = result.state
    trigger_refs = [
        artifact.artifact_id
        for artifact in final.artifacts.values()
        if artifact.artifact_type == "trigger_sample"
    ]
    assert trigger_refs, "FuzzingBrain trigger_sample must reach global world state"

    dispatches = {record.capability_id for record in final.dispatch_history}
    assert "vulnerability_research" in dispatches
    assert "reverse" in dispatches
    reverse_dispatch = next(
        record for record in final.dispatch_history if record.capability_id == "reverse"
    )
    assert any(ref in trigger_refs for ref in reverse_dispatch.input_refs), (
        "reverse must consume the FuzzingBrain trigger_sample artifact"
    )
    assert final.unresolved_questions == {}
    assert (tmp_path / "runs" / task.task_id / "hunter_brain_audit.jsonl").is_file()
