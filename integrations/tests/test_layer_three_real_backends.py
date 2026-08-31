from __future__ import annotations

import json
import os
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest

from hunter_brain.state import HunterWorldState
from hunter_brain.state_updater import WorldStateUpdater
from integrations.kong import KongAdapter
from integrations.trudi import TrudiAdapter
from pentestgpt_agent.protocol import (
    AdapterRunner,
    AuthorizationScope,
    ExecutionStatus,
    InputObject,
    RunLayout,
    TargetObject,
    TaskSpec,
)


def _trudi_evidence() -> Path:
    value = os.environ.get("HUNTER_TRUDI_SMOKE_EVIDENCE")
    if not value:
        pytest.skip("set HUNTER_TRUDI_SMOKE_EVIDENCE to run the real TRUDI Layer 3 test")
    path = Path(value).resolve()
    if not path.is_file():
        pytest.fail(f"TRUDI smoke evidence does not exist: {path}")
    return path


@pytest.mark.asyncio
async def test_real_trudi_contract_adapter_result_world_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise exactly one real backend across the complete Layer 3 boundary."""
    source_evidence = _trudi_evidence()
    task_id = "layer-three-real-trudi"
    workspace = (tmp_path / "runs" / task_id).resolve()
    evidence_path = workspace / "artifacts" / "input" / source_evidence.name
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_evidence, evidence_path)
    digest = sha256(evidence_path.read_bytes()).hexdigest()
    runtime_home = workspace / "runtime" / "home"
    runtime_cache = workspace / "runtime" / "cache"
    runtime_home.mkdir(parents=True, exist_ok=True)
    runtime_cache.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(runtime_home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(runtime_cache))
    task = TaskSpec(
        task_id=task_id,
        domain="dfir",
        target=str(evidence_path),
        goal="Perform real deterministic TRUDI MCP triage of the supplied evidence.",
        workspace=str(workspace),
        scope={"allowed_targets": [str(evidence_path)]},
        success_conditions=("TRUDI returns evidence-backed file triage.",),
        metadata={
            "file_type": {"normalized_type": "log", "sha256": digest},
            "trudi_mode": "lite",
        },
        input_object=InputObject(
            "input-evidence",
            "file",
            str(evidence_path),
            path=str(evidence_path),
            source_name=evidence_path.name,
            sha256=digest,
            size_bytes=evidence_path.stat().st_size,
        ),
        target_object=TargetObject("target-evidence", "log", str(evidence_path)),
        authorization=AuthorizationScope(
            allowed_targets=(str(evidence_path),),
            allowed_read_paths=(str(evidence_path.parent),),
            workspace=str(workspace),
        ),
    )

    adapter = TrudiAdapter(mode="lite")
    health = await adapter.healthcheck(task)
    assert health.available is True
    assert int(health.details["tool_count"]) == 4
    assert health.details["scope"] == "lightweight_file_triage"

    runs_root = tmp_path / "runs"
    result = await AdapterRunner(adapter, runs_root=runs_root).execute(task)
    assert result.status is ExecutionStatus.SUCCESS
    assert result.agent_id == "trudi"
    assert result.artifacts and result.evidence and result.findings
    assert result.metrics["reasoning_backend_used"] is False

    layout = RunLayout.ensure(runs_root, task)
    assert TaskSpec.from_dict(json.loads(layout.task_json.read_text(encoding="utf-8"))) == task
    assert layout.read_result() == result
    layout.validate_result_references(result)

    initial_state = HunterWorldState.from_task(task)
    update = WorldStateUpdater().apply(initial_state, result)
    world_path = update.state.save(layout.root)

    assert update.delta.added_artifact_ids
    assert update.delta.added_evidence_ids
    assert update.delta.added_fact_ids
    assert HunterWorldState.load(layout.root) == update.state
    assert world_path.is_file()


@pytest.mark.asyncio
async def test_real_kong_contract_adapter_result_world_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise only the real Kong/Ghidra backend across the Layer 3 boundary."""
    if os.environ.get("HUNTER_KONG_LAYER3_LIVE") != "1":
        pytest.skip("set HUNTER_KONG_LAYER3_LIVE=1 to run the real Kong Layer 3 test")

    project_root = Path(__file__).resolve().parents[2]
    projects_root = project_root.parent
    java_home = projects_root / ".tools" / "jdk21"
    ghidra_dir = projects_root / ".tools" / "ghidra-12.0.4" / "ghidra_12.0.4_PUBLIC"
    config_dir = project_root / ".runtime" / "kong" / "config"
    source = project_root / "integrations" / "kong" / "tests" / "fixtures" / "benign.c"
    required = (
        java_home / "bin" / "java",
        ghidra_dir / "support" / "analyzeHeadless",
        config_dir / "config.db",
        source,
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        pytest.fail(f"Kong Layer 3 prerequisites are missing: {missing}")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.fail("gcc is required to build the benign Kong fixture")

    task_id = "layer-three-real-kong"
    workspace = (tmp_path / "runs" / task_id).resolve()
    binary = workspace / "artifacts" / "input" / "benign"
    binary.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [compiler, "-O0", "-g", "-fno-pie", "-no-pie", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )
    digest = sha256(binary.read_bytes()).hexdigest()
    runtime_home = workspace / "runtime" / "home"
    runtime_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(runtime_home))
    monkeypatch.setenv("KONG_PROVIDER", "custom")
    monkeypatch.setenv("KONG_BASE_URL", "https://api.deepseek.com")
    monkeypatch.setenv("KONG_MODEL", "deepseek-v4-flash")

    task = TaskSpec(
        task_id=task_id,
        domain="reverse",
        target=str(binary),
        goal="Perform real Kong/Ghidra analysis of the supplied benign ELF.",
        workspace=str(workspace),
        scope={"allowed_targets": [str(binary)]},
        success_conditions=("Kong returns evidence-backed binary analysis.",),
        metadata={
            "file_type": {"normalized_type": "elf", "sha256": digest},
            "kong_mode": "analyze",
        },
        input_object=InputObject(
            "input-binary",
            "file",
            str(binary),
            path=str(binary),
            source_name=binary.name,
            sha256=digest,
            size_bytes=binary.stat().st_size,
        ),
        target_object=TargetObject("target-binary", "elf", str(binary)),
        authorization=AuthorizationScope(
            allowed_targets=(str(binary),),
            allowed_read_paths=(str(binary.parent),),
            workspace=str(workspace),
        ),
        timeout=300,
    )

    adapter = KongAdapter(
        java_home=java_home,
        ghidra_dir=ghidra_dir,
        kong_config_dir=config_dir,
    )
    health = await adapter.healthcheck(task)
    assert health.available is True
    assert health.details["mode"] == "analyze"
    assert health.details["provider_ready"] is True

    runs_root = tmp_path / "runs"
    result = await AdapterRunner(adapter, runs_root=runs_root).execute(task)
    assert result.status is ExecutionStatus.SUCCESS
    assert result.agent_id == "kong"
    assert result.artifacts and result.evidence and result.findings
    assert result.metrics["mode"] == "analyze"
    assert int(result.metrics["llm_calls"]) > 0

    layout = RunLayout.ensure(runs_root, task)
    assert TaskSpec.from_dict(json.loads(layout.task_json.read_text(encoding="utf-8"))) == task
    assert layout.read_result() == result
    layout.validate_result_references(result)

    initial_state = HunterWorldState.from_task(task)
    update = WorldStateUpdater().apply(initial_state, result)
    world_path = update.state.save(layout.root)

    assert update.delta.added_artifact_ids
    assert update.delta.added_evidence_ids
    assert update.delta.added_fact_ids
    assert HunterWorldState.load(layout.root) == update.state
    assert world_path.is_file()
