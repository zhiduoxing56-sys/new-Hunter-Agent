"""Real-filesystem integration for Hunter brain implementation phases 1-4."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import (
    CompleteDecision,
    InvokeCapabilityDecision,
    decision_from_dict,
)
from hunter_brain.state import HunterWorldState, UnresolvedQuestion
from hunter_brain.state_updater import WorldStateUpdater
from pentestgpt_agent.protocol import (
    AdapterRunner,
    AuthorizationScope,
    InputObject,
    RunLayout,
    TargetObject,
    TaskSpec,
)
from pentestgpt_agent.protocol.mock_adapter import MockAdapter


@pytest.mark.asyncio
async def test_layer_one_to_real_adapter_result_to_persisted_brain_state(
    tmp_path: Path,
) -> None:
    target = "https://example.test/"
    task = TaskSpec(
        task_id="phases-1-4-real-chain",
        domain="pentest",
        target=target,
        goal="Identify and evidence the authorized target's attack surface.",
        scope={"allowed_targets": [target]},
        success_conditions=("An evidence-backed backend result is available.",),
        input_object=InputObject(
            "input-network",
            "network_target",
            target,
            source_name=target,
        ),
        target_object=TargetObject("target-network", "url", target),
        authorization=AuthorizationScope(allowed_targets=(target,)),
    )
    catalog = default_catalog()
    assert tuple(
        item.capability_id for item in catalog.candidates_for_input("network_target")
    ) == ("pentest",)

    state = HunterWorldState.from_task(task)
    state.add_question(
        UnresolvedQuestion(
            "question-attack-surface",
            "What attack surface is exposed by the authorized target?",
            priority=100,
            required_output_types=("service_information",),
        )
    )
    proposed = InvokeCapabilityDecision(
        capability_id="pentest",
        input_refs=("input-network",),
        question_id="question-attack-surface",
        objective="Assess the explicitly authorized target.",
        basis_input_refs=("input-network",),
        basis_fact_refs=(),
        basis_evidence_refs=(),
        expected_output_types=("service_information",),
        allocated_budget=1.0,
        rationale="The normalized authorized network target is ready.",
    )
    assert decision_from_dict(proposed.to_dict()) == proposed

    runs_root = tmp_path / "runs"
    result = await AdapterRunner(MockAdapter(), runs_root=runs_root).execute(task)
    layout = RunLayout.ensure(runs_root, task)
    layout.validate_result_references(result)
    artifact_path = Path(result.artifacts[0].path)
    assert result.artifacts[0].sha256 == hashlib.sha256(artifact_path.read_bytes()).hexdigest()

    update = WorldStateUpdater().apply(state, result)
    assert update.delta.added_artifact_ids == ("mock-output",)
    assert update.delta.added_evidence_ids == ("mock-evidence",)
    assert update.delta.added_fact_ids == ("fact-mock-adapter-mock-finding",)
    shared_world_state_before = layout.world_state_json.read_bytes()
    brain_path = update.state.save(layout.root)

    assert HunterWorldState.load(layout.root) == update.state
    assert brain_path.name == "hunter_brain_state.json"
    assert layout.world_state_json.read_bytes() == shared_world_state_before
    assert layout.read_result() == result

    completion = CompleteDecision(
        summary="The backend result and persisted artifact are evidence-backed.",
        satisfied_conditions={
            task.success_conditions[0]: ("mock-evidence",),
        },
        rationale="The requested integration evidence exists and its hash was verified.",
    )
    assert decision_from_dict(completion.to_dict()) == completion
