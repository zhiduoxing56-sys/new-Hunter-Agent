"""Live Layer 3 test: TaskSpec -> FuzzingBrainAdapter -> real FuzzingBrain.

Runs the full protocol boundary against the isolated local FuzzingBrain
runtime (MongoDB/Redis/Docker + DeepSeek) using the committed deterministic
hunterdemo fixture, then asserts the collected AgentResult carries a real
reproducible trigger with hashed artifacts that reach world state.

Skipped unless HUNTER_FUZZINGBRAIN_LIVE=1 so the default suite stays green
without the local services.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from hunter_brain.state import HunterWorldState
from hunter_brain.state_updater import WorldStateUpdater
from integrations.fuzzingbrain import FuzzingBrainAdapter
from pentestgpt_agent.protocol import (
    AdapterRunner,
    AuthorizationScope,
    ExecutionStatus,
    InputObject,
    RunLayout,
    TargetObject,
    TaskSpec,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _fixture() -> Path:
    if os.environ.get("HUNTER_FUZZINGBRAIN_LIVE") != "1":
        pytest.skip("set HUNTER_FUZZINGBRAIN_LIVE=1 to run the real FuzzingBrain Layer 3 test")
    fixture = PROJECT_ROOT / "third_party/fuzzingbrain/fixtures/hunterdemo"
    if not (fixture / "repo").is_dir() or not (fixture / "fuzz-tooling" / "projects").is_dir():
        pytest.skip(f"FuzzingBrain fixture is unavailable: {fixture}")
    return fixture


def _task(tmp_path: Path, fixture: Path) -> TaskSpec:
    task_id = uuid.uuid4().hex[:24]  # valid 24-hex ObjectId consumed by the backend
    workspace = (tmp_path / "runs" / task_id).resolve()
    target = str(fixture.resolve())
    return TaskSpec(
        task_id=task_id,
        domain="vulnerability_research",
        target=target,
        goal="Reproduce the deterministic ASan heap-buffer-overflow in the authorized hunterdemo fixture.",
        workspace=str(workspace),
        scope={"allowed_targets": [target]},
        success_conditions=("FuzzingBrain produces a reproducible ASan trigger.",),
        metadata={"fuzzingbrain_task_type": "pov-patch", "fuzzingbrain_scan_mode": "full"},
        input_object=InputObject(
            "input-source", "directory", target, path=target,
            source_name=fixture.name, metadata={"kind": "source_tree"},
        ),
        target_object=TargetObject("target-source", "source_tree", target),
        authorization=AuthorizationScope(
            allowed_targets=(target,),
            allowed_read_paths=(target,),
            workspace=str(workspace),
        ),
        timeout=1200,
        model_budget=4.0,
    )


@pytest.mark.asyncio
async def test_real_fuzzingbrain_adapter_reproduces_pov(tmp_path: Path) -> None:
    """Exercise only the real FuzzingBrain backend across the Layer 3 boundary."""
    fixture = _fixture()
    task = _task(tmp_path, fixture)

    adapter = FuzzingBrainAdapter(repo_root=PROJECT_ROOT)
    health = await adapter.healthcheck(task)
    assert health.available is True
    assert health.details["credential_source"] in {
        "process_environment",
        "kong_sqlite_child_process",
    }

    runs_root = tmp_path / "runs"
    result = await AdapterRunner(adapter, runs_root=runs_root).execute(task)

    assert result.status is ExecutionStatus.SUCCESS, result.summary
    assert result.agent_id == "fuzzingbrain"
    assert result.artifacts
    assert result.evidence
    assert result.findings

    trigger = next((a for a in result.artifacts if a.type == "trigger_sample"), None)
    assert trigger is not None
    assert trigger.sha256
    trigger_path = Path(trigger.path)
    assert trigger_path.is_file()
    assert trigger_path.stat().st_size >= 5

    layout = RunLayout.ensure(runs_root, task)
    layout.validate_result_references(result)

    initial_state = HunterWorldState.from_task(task)
    update = WorldStateUpdater().apply(initial_state, result)
    assert update.delta.added_artifact_ids
    assert update.delta.added_evidence_ids
    assert update.delta.added_fact_ids
    assert update.state.save(layout.root).is_file()
