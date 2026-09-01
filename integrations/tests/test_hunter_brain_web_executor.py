"""Default Web autonomous executor exposes and dispatches all four domains.

Phase-one收口: the Web autonomous entry (``build_analysis_brain_executor``)
must register ``pentest`` and ``vulnerability_research`` in addition to the
existing ``dfir``/``reverse`` pair, reusing the four-domain assembly in
``build_hunter_brain_adapters``. All backends here are in-process mocks so the
suite never starts Docker, Ghidra, TRUDI MCP, or FuzzingBrain services.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

import pytest

from autopenbench_adapter.protocol import AutoPenBenchProtocolAdapter
from hunter_brain.supervisor import (
    DeepSeekSupervisorConfig,
    ModelDecisionResult,
)
from integrations.fuzzingbrain import FuzzingBrainAdapter
from integrations.hunter_brain import build_analysis_brain_executor
from integrations.kong import KongAdapter
from integrations.trudi import TrudiAdapter
from pentestgpt_agent.intake import prepare_task
from pentestgpt_agent.intake.models import IntakeLimits
from pentestgpt_agent.protocol import (
    AuthorizationScope,
    ExecutionStatus,
    InputObject,
    PreparedTask,
    RunLayout,
    TargetObject,
    TaskSpec,
)
from pentestgpt_agent.protocol.io import atomic_write_json
from pentestgpt_agent.protocol.mock_adapter import MockAdapter


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class RecordingMockAdapter(MockAdapter):
    """MockAdapter that records every TaskSpec the global loop hands it."""

    def __init__(self, *, agent_id: str) -> None:
        super().__init__()
        self.agent_id = agent_id
        self.task_specs: list[TaskSpec] = []

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        self.task_specs.append(task_spec)
        return await super().prepare(task_spec, run_layout)


class CrashTriggerMockAdapter(RecordingMockAdapter):
    """VR mock that reproduces a real crash ``trigger_sample`` artifact.

    Phase 3C completion truth requires deterministic goal evidence for a
    vulnerability-research completion: a reproduced trigger is that evidence.
    A generic SUCCESS with only an output file is intentionally NOT a global
    completion anymore.
    """

    async def collect(self, prepared: PreparedTask, handle) -> Any:
        results = prepared.run_layout.artifacts / "fuzzingbrain-workspace" / "results" / "povs"
        results.mkdir(parents=True, exist_ok=True)
        trigger = results / "crash-1"
        trigger.write_bytes(b"ASAN: heap-buffer-overflow\n")
        from pentestgpt_agent.protocol import AgentResult, Artifact, Evidence, Finding

        artifact = Artifact.from_path(
            "fuzzingbrain-trigger-0", "trigger_sample", trigger, producer=self.agent_id
        )
        evidence = Evidence(
            "fuzzingbrain-trigger-0-evidence",
            "backend_output",
            self.agent_id,
            "FuzzingBrain reproduced a crash trigger.",
            artifact_ref=artifact.artifact_id,
        )
        finding = Finding(
            "fuzzingbrain-reproduced-vulnerability",
            "vulnerability",
            "Reproduced vulnerability trigger",
            "The crash trigger demonstrates a reproducible vulnerability.",
            evidence_refs=(evidence.evidence_id,),
        )
        return AgentResult(
            task_id=prepared.task_spec.task_id,
            agent_id=self.agent_id,
            domain=prepared.task_spec.domain,
            status=ExecutionStatus.SUCCESS,
            started_at="2026-08-31T00:00:00+00:00",
            finished_at="2026-08-31T00:00:01+00:00",
            summary="FuzzingBrain produced a reproducible vulnerability trigger.",
            findings=(finding,),
            evidence=(evidence,),
            artifacts=(artifact,),
        )


class ScriptedDecisionModel:
    """Return canned decision JSON, never calling an external model."""

    def __init__(self, decisions: list[dict[str, Any]]) -> None:
        self.decisions = decisions
        self.calls = 0

    async def decide(
        self,
        *,
        system_instructions: str,
        context: dict[str, Any],
    ) -> ModelDecisionResult:
        value = self.decisions[min(self.calls, len(self.decisions) - 1)]
        self.calls += 1
        return ModelDecisionResult(value=value, usage={})


class CompletingModel:
    """Invoke one capability, then complete citing real evidence from context.

    Mirrors the expected post-Result-Interpreter behavior: after a grounded
    professional result, the supervisor may complete because the targeted
    question was resolved by canonical evidence.
    """

    def __init__(self, invoke_decision: dict[str, Any]) -> None:
        self.invoke_decision = invoke_decision
        self.calls = 0

    async def decide(
        self,
        *,
        system_instructions: str,
        context: dict[str, Any],
    ) -> ModelDecisionResult:
        if self.calls == 0:
            self.calls += 1
            return ModelDecisionResult(value=self.invoke_decision, usage={})
        evidence = context.get("available_inputs", {}).get("evidence_ids") or []
        assert evidence, "completion requires grounded evidence in context"
        conditions = context.get("success_conditions") or [
            "The supplied input was assessed."
        ]
        value = {
            "schema_version": "1.0",
            "action": "complete",
            "summary": "Grounded professional evidence satisfies the goal.",
            "satisfied_conditions": {
                condition: [evidence[-1]] for condition in conditions
            },
            "rationale": "The professional backend produced grounded evidence and no critical question remains.",
        }
        return ModelDecisionResult(value=value, usage={})


def _invoke_decision(
    capability_id: str,
    input_ref: str,
    question_id: str,
    objective: str,
    output_type: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "action": "invoke_capability",
        "capability_id": capability_id,
        "input_refs": [input_ref],
        "question_id": question_id,
        "objective": objective,
        "basis_input_refs": [input_ref],
        "basis_fact_refs": [],
        "basis_evidence_refs": [],
        "expected_output_types": [output_type],
        "allocated_budget": 1.0,
        "rationale": f"{capability_id} accepts the task input.",
    }
    return {
        "schema_version": "1.0",
        "action": "blocked",
        "reason": "The requested professional capability assessed the input.",
        "blocking_question_ids": [question_id],
        "attempted_capability_ids": [capability_id],
        "retryable": False,
        "rationale": "No further capability is required for this phase.",
    }


def _executor(
    tmp_path: Path,
    *,
    model: ScriptedDecisionModel,
    pentest: RecordingMockAdapter | None = None,
    vulnerability_research: RecordingMockAdapter | None = None,
    dfir: RecordingMockAdapter | None = None,
    reverse: RecordingMockAdapter | None = None,
):
    runs = tmp_path / "runs"
    runs.mkdir(exist_ok=True)
    return build_analysis_brain_executor(
        repo_root=PROJECT_ROOT,
        runs_root=runs,
        config=DeepSeekSupervisorConfig(api_key="test-only-key"),
        model=model,
        pentest_adapter=pentest,
        vulnerability_research_adapter=vulnerability_research,
        dfir_adapter=dfir,
        reverse_adapter=reverse,
    )


def _managed_file(runs_root: Path, task_id: str, name: str, content: bytes) -> tuple[Path, str, int]:
    managed = (runs_root / task_id / "artifacts" / "input" / name).resolve()
    managed.parent.mkdir(parents=True, exist_ok=True)
    managed.write_bytes(content)
    return managed, hashlib.sha256(content).hexdigest(), managed.stat().st_size


def _file_task(
    runs_root: Path,
    *,
    task_id: str,
    domain: str,
    input_type: str,
    name: str,
    content: bytes,
    goal: str,
) -> TaskSpec:
    managed, digest, size = _managed_file(runs_root, task_id, name, content)
    workspace = str(managed.parent.parent.parent)
    return TaskSpec(
        task_id=task_id,
        domain=domain,
        target=str(managed),
        goal=goal,
        timeout=120,
        budget=4.0,
        workspace=workspace,
        scope={"allowed_targets": [str(managed)]},
        success_conditions=(f"{domain} produced grounded evidence.",),
        metadata={"file_type": {"normalized_type": input_type, "sha256": digest}},
        input_object=InputObject(
            "input",
            "file",
            str(managed),
            path=str(managed),
            source_name=name,
            sha256=digest,
            size_bytes=size,
        ),
        target_object=TargetObject("target", input_type, str(managed)),
        authorization=AuthorizationScope(
            (str(managed),),
            allowed_read_paths=(str(managed),),
            workspace=workspace,
        ),
        tool_call_budget=20,
        model_budget=2.0,
    )


def _network_task(runs_root: Path) -> TaskSpec:
    return prepare_task(
        "http://127.0.0.1:8080",
        runs_root=runs_root,
        allowed_roots=(runs_root,),
        task_id="web-pentest-audit",
        goal="Assess the explicitly authorized network target.",
        limits=IntakeLimits(max_input_bytes=1_000_000),
    )


def _benchmark_task(
    runs_root: Path,
    *,
    task_id: str = "web-pentest-benchmark",
    canonical_task: str = "Discover the target and obtain the flag.",
) -> TaskSpec:
    """A pentest task carrying a validated benchmark contract (deterministic)."""
    target = "in-vitro_web_security_vm0"
    workspace = runs_root / task_id
    workspace.mkdir(parents=True, exist_ok=True)
    task = TaskSpec(
        task_id=task_id,
        domain="pentest",
        target=target,
        goal=canonical_task,
        workspace=str(workspace),
        metadata={
            "input_kind": "network_target",
            "semantic_input_type": "network_target",
            "benchmark": {
                "case_id": "in-vitro/web_security/vm0",
                "target": target,
                "task": canonical_task,
                "source": "test-registry",
            },
        },
        input_object=InputObject(
            "bench-input", "network_target", target, source_name=target
        ),
        target_object=TargetObject("bench-target", "network_target", target),
        authorization=AuthorizationScope(allowed_targets=(target,)),
    )
    atomic_write_json(workspace / "task.json", task.to_dict())
    return task


def _uploaded_file_task(
    staging: Path,
    runs_root: Path,
    name: str,
    content: bytes,
    *,
    task_id: str,
    goal: str,
) -> TaskSpec:
    source = staging / name
    source.write_bytes(content)
    return prepare_task(
        source,
        runs_root=runs_root,
        allowed_roots=(staging,),
        task_id=task_id,
        goal=goal,
        limits=IntakeLimits(max_input_bytes=1_000_000),
    )


def test_default_web_executor_registers_four_real_adapters(tmp_path: Path) -> None:
    executor = _executor(tmp_path, model=ScriptedDecisionModel([]))

    registry = executor.orchestrator.adapters
    assert set(registry._adapters) == {
        "dfir",
        "reverse",
        "pentest",
        "vulnerability_research",
    }
    assert isinstance(registry.get("pentest"), AutoPenBenchProtocolAdapter)
    assert isinstance(registry.get("vulnerability_research"), FuzzingBrainAdapter)
    assert isinstance(registry.get("dfir"), TrudiAdapter)
    assert isinstance(registry.get("reverse"), KongAdapter)
    assert registry.get("vulnerability_research")._processes == {}
    assert registry.get("dfir")._processes == {}
    assert registry.get("reverse")._processes == {}
    assert registry.get("pentest").last_pid is None


def test_four_domain_capabilities_are_visible_at_the_default_entry(tmp_path: Path) -> None:
    executor = _executor(tmp_path, model=ScriptedDecisionModel([]))

    catalog = executor.orchestrator.supervisor.catalog
    assert catalog.capability_ids == (
        "dfir",
        "reverse",
        "pentest",
        "vulnerability_research",
    )
    assert len(catalog) == 4
    assert catalog.get("pentest").accepts("network_target")
    assert catalog.get("vulnerability_research").accepts("source_code")


@pytest.mark.asyncio
async def test_web_autonomous_mode_dispatch_pentest(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    pentest = RecordingMockAdapter(agent_id="pentest-mock")
    model = CompletingModel(
        _invoke_decision(
            "pentest",
            "bench-input",
            "question-user-goal",
            "Assess the authorized network target.",
            "access_proof",
        )
    )
    executor = _executor(tmp_path, model=model, pentest=pentest)

    result = await executor.execute(_benchmark_task(runs))

    assert result.raw_output["orchestration_status"] == "complete"
    assert result.status is ExecutionStatus.SUCCESS
    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "pentest"
    assert history[0]["new_evidence"] is True
    assert pentest.task_specs[0].domain == "pentest"


@pytest.mark.asyncio
async def test_web_autonomous_mode_dispatch_vulnerability_research(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    vulnerability = CrashTriggerMockAdapter(agent_id="vulnerability-mock")
    model = CompletingModel(
        _invoke_decision(
            "vulnerability_research",
            "input",
            "question-user-goal",
            "Find reproducible vulnerabilities in the supplied source.",
            "vulnerability",
        )
    )
    executor = _executor(tmp_path, model=model, vulnerability_research=vulnerability)

    task = _file_task(
        runs,
        task_id="web-vuln-audit",
        domain="vulnerability_research",
        input_type="source_code",
        name="sample.c",
        content=b"int main(void) { return 0; }\n",
        goal="Find reproducible vulnerabilities in the supplied source.",
    )
    result = await executor.execute(task)

    assert result.raw_output["orchestration_status"] == "complete"
    assert result.status is ExecutionStatus.SUCCESS
    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "vulnerability_research"
    assert history[0]["new_evidence"] is True
    assert vulnerability.task_specs[0].domain == "vulnerability_research"


@pytest.mark.asyncio
async def test_web_autonomous_mode_dfir_call_still_passes(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    dfir = RecordingMockAdapter(agent_id="trudi-mock")
    model = CompletingModel(
        _invoke_decision(
            "dfir",
            "input",
            "question-user-goal",
            "Triage the acquired forensic evidence.",
            "finding",
        )
    )
    executor = _executor(tmp_path, model=model, dfir=dfir)

    task = _file_task(
        runs,
        task_id="web-dfir-triage",
        domain="dfir",
        input_type="evidence_file",
        name="capture.log",
        content=b"host=demo event=login result=success\n",
        goal="Triage the acquired forensic evidence.",
    )
    result = await executor.execute(task)

    assert result.raw_output["orchestration_status"] == "complete"
    assert result.status is ExecutionStatus.SUCCESS
    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "dfir"
    assert history[0]["new_evidence"] is True
    assert dfir.task_specs[0].domain == "dfir"


@pytest.mark.asyncio
async def test_web_autonomous_mode_reverse_call_still_passes(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    reverse = RecordingMockAdapter(agent_id="kong-mock")
    model = CompletingModel(
        _invoke_decision(
            "reverse",
            "input",
            "question-user-goal",
            "Identify the supplied binary's metadata.",
            "binary_metadata",
        )
    )
    executor = _executor(tmp_path, model=model, reverse=reverse)

    task = _file_task(
        runs,
        task_id="web-reverse-audit",
        domain="reverse",
        input_type="elf",
        name="sample.bin",
        content=b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00" + b"\x00" * 32,
        goal="Identify the supplied binary's metadata.",
    )
    result = await executor.execute(task)

    # Phase 3C: a generic reverse backend cannot complete globally without a
    # benchmark oracle or verified goal evidence. Dispatch + evidence must still
    # work; a false global COMPLETE must not.
    assert result.raw_output["orchestration_status"] != "complete"
    assert result.status is not ExecutionStatus.SUCCESS
    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "reverse"
    assert history[0]["new_evidence"] is True
    assert reverse.task_specs[0].domain == "reverse"


@pytest.mark.asyncio
async def test_four_domain_assembly_keeps_decision_validator_active(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    pentest = RecordingMockAdapter(agent_id="pentest-mock")
    incompatible = _invoke_decision(
        "pentest",
        "input",
        "question-user-goal",
        "Attempt a pentest against a source-only input.",
        "access_proof",
    )
    executor = _executor(
        tmp_path,
        model=ScriptedDecisionModel([incompatible]),
        pentest=pentest,
    )

    task = _file_task(
        runs,
        task_id="web-invalid-pentest",
        domain="vulnerability_research",
        input_type="source_code",
        name="sample.c",
        content=b"int main(void) { return 0; }\n",
        goal="The supervisor proposes pentest on source input.",
    )
    result = await executor.execute(task)

    assert result.raw_output["orchestration_status"] == "invalid_decisions"
    assert result.error is not None
    assert pentest.task_specs == []


@pytest.mark.asyncio
async def test_web_autonomous_dispatch_dfir_for_real_log_text(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    staging = tmp_path / "staging"
    staging.mkdir()
    dfir = RecordingMockAdapter(agent_id="trudi-mock")
    task = _uploaded_file_task(
        staging,
        runs,
        "auth.log",
        b"host=demo event=login result=success\n",
        task_id="web-dfir-log",
        goal="Triage the acquired log evidence.",
    )
    assert task.metadata["semantic_input_type"] == "log"
    model = CompletingModel(
        _invoke_decision(
            "dfir",
            "web-dfir-log",
            "question-user-goal",
            "Triage the acquired log evidence.",
            "finding",
        )
    )
    executor = _executor(tmp_path, model=model, dfir=dfir)

    result = await executor.execute(task)

    assert result.raw_output["orchestration_status"] == "complete"
    assert result.status is ExecutionStatus.SUCCESS
    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "dfir"
    assert history[0]["new_evidence"] is True
    assert dfir.task_specs[0].domain == "dfir"


@pytest.mark.asyncio
async def test_web_autonomous_dispatch_vulnerability_research_for_source_zip(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    staging = tmp_path / "staging"
    staging.mkdir()
    vulnerability = CrashTriggerMockAdapter(agent_id="vulnerability-mock")
    archive = staging / "src.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("project/pyproject.toml", "[project]\n")
        bundle.writestr("project/main.py", "pass\n")
    task = prepare_task(
        archive,
        runs_root=runs,
        allowed_roots=(staging,),
        task_id="web-vuln-zip",
        goal="Audit the supplied project archive.",
        limits=IntakeLimits(max_input_bytes=1_000_000),
    )
    assert task.metadata["semantic_input_type"] == "source_bundle"
    model = CompletingModel(
        _invoke_decision(
            "vulnerability_research",
            "web-vuln-zip",
            "question-user-goal",
            "Audit the supplied project archive.",
            "vulnerability",
        )
    )
    executor = _executor(tmp_path, model=model, vulnerability_research=vulnerability)

    result = await executor.execute(task)

    assert result.raw_output["orchestration_status"] == "complete"
    assert result.status is ExecutionStatus.SUCCESS
    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "vulnerability_research"
    assert vulnerability.task_specs[0].domain == "vulnerability_research"


@pytest.mark.asyncio
async def test_web_autonomous_dispatch_vulnerability_research_for_project_directory(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    staging = tmp_path / "staging"
    staging.mkdir()
    vulnerability = CrashTriggerMockAdapter(agent_id="vulnerability-mock")
    project = staging / "proj"
    (project / "src").mkdir(parents=True)
    (project / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (project / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    task = prepare_task(
        project,
        runs_root=runs,
        allowed_roots=(staging,),
        task_id="web-vuln-dir",
        goal="Audit the supplied project directory.",
        limits=IntakeLimits(max_input_bytes=1_000_000),
    )
    assert task.metadata["semantic_input_type"] == "source_tree"
    model = CompletingModel(
        _invoke_decision(
            "vulnerability_research",
            "web-vuln-dir",
            "question-user-goal",
            "Audit the supplied project directory.",
            "vulnerability",
        )
    )
    executor = _executor(tmp_path, model=model, vulnerability_research=vulnerability)

    result = await executor.execute(task)

    assert result.raw_output["orchestration_status"] == "complete"
    assert result.status is ExecutionStatus.SUCCESS
    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "vulnerability_research"
    assert vulnerability.task_specs[0].domain == "vulnerability_research"


@pytest.mark.asyncio
async def test_web_autonomous_refuses_plain_text_for_every_capability(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    staging = tmp_path / "staging"
    staging.mkdir()
    dfir = RecordingMockAdapter(agent_id="trudi-mock")
    task = _uploaded_file_task(
        staging,
        runs,
        "notes.txt",
        b"just some notes\n",
        task_id="web-plain-text",
        goal="Triage the file.",
    )
    assert task.metadata["semantic_input_type"] is None
    model = ScriptedDecisionModel(
        [
            _invoke_decision(
                "dfir",
                "web-plain-text",
                "question-user-goal",
                "Triage the file.",
                "finding",
            )
        ]
    )
    executor = _executor(tmp_path, model=model, dfir=dfir)

    result = await executor.execute(task)

    assert result.raw_output["orchestration_status"] == "invalid_decisions"
    assert result.error is not None
    assert dfir.task_specs == []


@pytest.mark.asyncio
async def test_subtask_accepts_decision_citing_both_input_and_target_refs(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    dfir = RecordingMockAdapter(agent_id="trudi-mock")
    task = _file_task(
        runs,
        task_id="web-both-refs",
        domain="dfir",
        input_type="evidence_file",
        name="capture.log",
        content=b"host=demo event=login result=success\n",
        goal="Triage the acquired forensic evidence.",
    )
    decision = {
        "schema_version": "1.0",
        "action": "invoke_capability",
        "capability_id": "dfir",
        "input_refs": ["input", "target"],
        "question_id": "question-user-goal",
        "objective": "Triage the acquired forensic evidence.",
        "basis_input_refs": ["input", "target"],
        "basis_fact_refs": [],
        "basis_evidence_refs": [],
        "expected_output_types": ["finding"],
        "allocated_budget": 1.0,
        "rationale": "The model cited both the input object and the target object.",
    }
    executor = _executor(
        tmp_path,
        model=CompletingModel(decision),
        dfir=dfir,
    )

    result = await executor.execute(task)

    assert result.raw_output["orchestration_status"] == "complete"
    assert result.status is ExecutionStatus.SUCCESS
    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "dfir"
    assert dfir.task_specs[0].domain == "dfir"


@pytest.mark.asyncio
async def test_subtask_dedups_network_target_when_both_refs_are_cited(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    pentest = RecordingMockAdapter(agent_id="pentest-mock")
    decision = {
        "schema_version": "1.0",
        "action": "invoke_capability",
        "capability_id": "pentest",
        "input_refs": ["input", "target"],
        "question_id": "question-user-goal",
        "objective": "Assess the authorized network target.",
        "basis_input_refs": ["input", "target"],
        "basis_fact_refs": [],
        "basis_evidence_refs": [],
        "expected_output_types": ["access_proof"],
        "allocated_budget": 1.0,
        "rationale": "The model cited both the input object and the target object.",
    }
    target = "in-vitro_web_security_vm0"
    canonical_task = "Discover the target and obtain the flag."
    workspace = tmp_path / "runs" / "web-both-network-refs"
    workspace.mkdir(parents=True, exist_ok=True)
    task = TaskSpec(
        task_id="web-both-network-refs",
        domain="pentest",
        target=target,
        goal=canonical_task,
        success_conditions=("Target assessed.",),
        metadata={
            "semantic_input_type": "network_target",
            "benchmark": {
                "case_id": "in-vitro/web_security/vm0",
                "target": target,
                "task": canonical_task,
                "source": "test-registry",
            },
        },
        input_object=InputObject("input", "network_target", target),
        target_object=TargetObject("target", "network_target", target),
        authorization=AuthorizationScope(allowed_targets=(target,)),
        workspace=str(workspace),
    )
    atomic_write_json(workspace / "task.json", task.to_dict())
    executor = _executor(
        tmp_path,
        model=CompletingModel(decision),
        pentest=pentest,
    )

    result = await executor.execute(task)

    assert result.raw_output["orchestration_status"] == "complete"
    assert result.status is ExecutionStatus.SUCCESS
    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "pentest"
    assert pentest.task_specs[0].domain == "pentest"
    assert set(pentest.task_specs[0].authorization.allowed_targets) == {target}
