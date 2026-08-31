"""Completion & verification closure correctness tests (Phase 2D).

Proves three deterministic invariants at the default-executor level:

1. The default success condition (or explicit conditions) must never let a
   partial professional result complete a multi-part user goal.
2. A non-critical cross-domain follow-up question must not let the first
   domain's success complete a goal that still requires the second domain.
3. ``AgentResult.SUCCESS`` is never ``Hunter global SUCCESS``: evidence-empty
   or mis-linked results cannot resolve the critical question or pass the
   deterministic completion gates.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from hunter_brain.supervisor import ModelDecisionResult
from integrations.hunter_brain import build_analysis_brain_executor
from pentestgpt_agent.protocol import (
    AuthorizationScope,
    ExecutionStatus,
    InputObject,
    PreparedTask,
    RunLayout,
    TargetObject,
    TaskSpec,
)
from pentestgpt_agent.protocol.mock_adapter import MockAdapter


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class RecordingMockAdapter(MockAdapter):
    def __init__(self, *, agent_id: str) -> None:
        super().__init__()
        self.agent_id = agent_id
        self.task_specs: list[TaskSpec] = []

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        self.task_specs.append(task_spec)
        return await super().prepare(task_spec, run_layout)


class SuspectBinaryMockAdapter(RecordingMockAdapter):
    """DFIR mock that exports a real ELF as a ``suspect_binary`` artifact."""

    async def collect(self, prepared: PreparedTask, handle) -> Any:
        binary = prepared.run_layout.artifacts / "exported-suspect.bin"
        binary.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
        from pentestgpt_agent.protocol import AgentResult, Artifact, Evidence, Finding

        artifact = Artifact.from_path(
            "trudi-exported-evidence", "suspect_binary", binary, producer=self.agent_id
        )
        evidence = Evidence(
            "trudi-evidence", "artifact_reference", self.agent_id, "DFIR evidence.",
            artifact_ref=artifact.artifact_id,
        )
        finding = Finding(
            "trudi-finding", "suspicious_file_discovery", "Exported a suspicious binary",
            "The evidence contained an ELF that was exported for reverse analysis.",
            evidence_refs=(evidence.evidence_id,),
        )
        return AgentResult(
            task_id=prepared.task_spec.task_id,
            agent_id=self.agent_id,
            domain=prepared.task_spec.domain,
            status=ExecutionStatus.SUCCESS,
            started_at="2026-08-31T00:00:00+00:00",
            finished_at="2026-08-31T00:00:01+00:00",
            summary="DFIR exported a suspect binary.",
            findings=(finding,),
            evidence=(evidence,),
            artifacts=(artifact,),
        )


class EvidenceEmptyMockAdapter(RecordingMockAdapter):
    """Returns AgentResult.SUCCESS with evidence but no findings (no facts)."""

    async def collect(self, prepared: PreparedTask, handle) -> Any:
        output = prepared.run_layout.artifacts / "output.txt"
        output.write_text("no findings", encoding="utf-8")
        from pentestgpt_agent.protocol import AgentResult, Artifact, Evidence

        artifact = Artifact.from_path("report", "text_report", output, producer=self.agent_id)
        evidence = Evidence(
            "report-evidence", "artifact_reference", self.agent_id, "Evidence without findings.",
            artifact_ref=artifact.artifact_id,
        )
        return AgentResult(
            task_id=prepared.task_spec.task_id,
            agent_id=self.agent_id,
            domain=prepared.task_spec.domain,
            status=ExecutionStatus.SUCCESS,
            started_at="2026-08-31T00:00:00+00:00",
            finished_at="2026-08-31T00:00:01+00:00",
            summary="Backend success but no grounded finding.",
            evidence=(evidence,),
            artifacts=(artifact,),
        )


class ScriptedContextModel:
    """Issue decisions from a script; complete decisions read context evidence."""

    def __init__(self, script: list[dict[str, Any]]) -> None:
        self.script = script
        self.calls = 0

    async def decide(
        self, *, system_instructions: str, context: dict[str, Any]
    ) -> ModelDecisionResult:
        action = self.script[min(self.calls, len(self.script) - 1)]
        self.calls += 1
        if action["action"] == "complete":
            evidence = context.get("available_inputs", {}).get("evidence_ids") or []
            conditions = action.get("conditions") or context.get("success_conditions") or []
            action = {
                "schema_version": "1.0",
                "action": "complete",
                "summary": "Grounded evidence satisfies the goal.",
                "satisfied_conditions": {
                    condition: [evidence[-1]] for condition in conditions
                },
                "rationale": "Deterministic completion script.",
            }
        return ModelDecisionResult(value=action, usage={})


def _executor(
    tmp_path: Path,
    *,
    model: ScriptedContextModel,
    dfir: RecordingMockAdapter | None = None,
    reverse: RecordingMockAdapter | None = None,
):
    runs = tmp_path / "runs"
    runs.mkdir(exist_ok=True)
    return build_analysis_brain_executor(
        repo_root=PROJECT_ROOT,
        runs_root=runs,
        config=None,
        model=model,
        dfir_adapter=dfir,
        reverse_adapter=reverse,
    )


def _managed(tmp_path: Path, name: str, content: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _invoke(capability_id: str, input_ref: str, question_id: str, output_type: str) -> dict:
    return {
        "schema_version": "1.0",
        "action": "invoke_capability",
        "capability_id": capability_id,
        "input_refs": [input_ref],
        "question_id": question_id,
        "objective": f"Run {capability_id}.",
        "basis_input_refs": [input_ref],
        "basis_fact_refs": [],
        "basis_evidence_refs": [],
        "expected_output_types": [output_type],
        "allocated_budget": 1.0,
        "rationale": f"{capability_id} accepts the task input.",
    }


@pytest.mark.asyncio
async def test_multipart_goal_never_completes_after_first_domain(tmp_path: Path) -> None:
    evidence = _managed(tmp_path, "capture.log", b"host=demo event=login\n")
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    task = TaskSpec(
        task_id="multipart-goal",
        domain="dfir",
        target=str(evidence),
        goal="Find the suspicious file and determine its behavior.",
        success_conditions=(
            "A suspicious file was found.",
            "The file's behavior was identified.",
        ),
        metadata={"file_type": {"normalized_type": "evidence_file", "sha256": digest}},
        input_object=InputObject(
            "input", "file", str(evidence), path=str(evidence),
            source_name="capture.log", sha256=digest,
        ),
        target_object=TargetObject("target", "evidence_file", str(evidence)),
        authorization=AuthorizationScope((str(evidence),)),
        workspace=str(tmp_path / "runs" / "multipart-goal"),
    )
    dfir = RecordingMockAdapter(agent_id="trudi-mock")
    model = ScriptedContextModel(
        [
            _invoke("dfir", "input", "question-user-goal", "finding"),
            {"action": "complete", "conditions": ["A suspicious file was found."]},
            {"action": "complete", "conditions": ["A suspicious file was found."]},
            {"action": "complete", "conditions": ["A suspicious file was found."]},
        ]
    )

    result = await _executor(tmp_path, model=model, dfir=dfir).execute(task)

    history = result.raw_output["world_state"]["dispatch_history"]
    assert history[0]["capability_id"] == "dfir"
    assert history[0]["new_evidence"] is True
    assert result.raw_output["world_state"]["facts"]
    assert result.raw_output["orchestration_status"] != "complete"
    assert result.status is not ExecutionStatus.SUCCESS


@pytest.mark.asyncio
async def test_cross_domain_goal_requires_both_domains_before_complete(
    tmp_path: Path,
) -> None:
    evidence = _managed(tmp_path, "suspicious", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    task = TaskSpec(
        task_id="cross-domain-goal",
        domain="dfir",
        target=str(evidence),
        goal=(
            "Triage the evidence, locate the exported suspicious binary, reverse-engineer "
            "its behavior, and give a combined conclusion."
        ),
        success_conditions=(
            "A suspicious binary was exported from the evidence.",
            "The exported binary's behavior was identified by reverse engineering.",
        ),
        metadata={
            "file_type": {"normalized_type": "evidence_file", "sha256": digest},
            "export_evidence_artifact": True,
        },
        input_object=InputObject(
            "input", "file", str(evidence), path=str(evidence),
            source_name="suspicious", sha256=digest,
        ),
        target_object=TargetObject("target", "evidence_file", str(evidence)),
        authorization=AuthorizationScope((str(evidence),)),
        workspace=str(tmp_path / "runs" / "cross-domain-goal"),
    )
    dfir = SuspectBinaryMockAdapter(agent_id="trudi-mock")
    reverse = RecordingMockAdapter(agent_id="kong-mock")

    class CrossDomainModel:
        def __init__(self) -> None:
            self.calls = 0

        async def decide(self, *, system_instructions, context):
            self.calls += 1
            if self.calls == 1:
                return ModelDecisionResult(
                    _invoke("dfir", "input", "question-user-goal", "finding"), {}
                )
            if self.calls == 2:
                # Attempt premature completion citing only the DFIR condition.
                value = {
                    "schema_version": "1.0",
                    "action": "complete",
                    "summary": "DFIR part only.",
                    "satisfied_conditions": {
                        "A suspicious binary was exported from the evidence.": ["none"]
                    },
                    "rationale": "Only the DFIR part is complete.",
                }
                return ModelDecisionResult(value, {})
            if self.calls == 3:
                artifacts = context.get("available_inputs", {}).get("artifacts", [])
                suspect = next(
                    (a["artifact_id"] for a in artifacts if a["type"] == "suspect_binary"),
                    None,
                )
                evidence = context.get("available_inputs", {}).get("evidence_ids") or []
                assert suspect, "context must expose the suspect_binary artifact"
                assert evidence, "context must expose DFIR evidence to ground the handoff"
                value = {
                    "schema_version": "1.0",
                    "action": "invoke_capability",
                    "capability_id": "reverse",
                    "input_refs": [suspect],
                    "question_id": self._cross_domain_question(context),
                    "objective": "Reverse-engineer the exported suspicious binary.",
                    "basis_input_refs": [],
                    "basis_fact_refs": [],
                    "basis_evidence_refs": [evidence[-1]],
                    "expected_output_types": ["binary_metadata"],
                    "allocated_budget": 1.0,
                    "rationale": "The exported suspect binary requires reverse analysis.",
                }
                return ModelDecisionResult(value, {})
            evidence = context.get("available_inputs", {}).get("evidence_ids") or []
            assert evidence
            value = {
                "schema_version": "1.0",
                "action": "complete",
                "summary": "Both DFIR and Reverse evidence ground the goal.",
                "satisfied_conditions": {
                    "A suspicious binary was exported from the evidence.": [evidence[0]],
                    "The exported binary's behavior was identified by reverse engineering.": [
                        evidence[-1]
                    ],
                },
                "rationale": "Both success conditions are grounded.",
            }
            return ModelDecisionResult(value, {})

        @staticmethod
        def _cross_domain_question(context) -> str:
            questions = context.get("unresolved_questions") or []
            return next(
                (q["question_id"] for q in questions if q["question_id"].startswith("cross-domain-")),
                "question-user-goal",
            )

    result = await _executor(tmp_path, model=CrossDomainModel(), dfir=dfir, reverse=reverse).execute(task)

    world = result.raw_output["world_state"]
    history = world["dispatch_history"]
    assert [h["capability_id"] for h in history] == ["dfir", "reverse"]
    assert "question-user-goal" in history[0]["answered_question_ids"]
    assert result.raw_output["orchestration_status"] == "complete"
    assert result.status is ExecutionStatus.SUCCESS
    # canonical state holds evidence from BOTH professional domains.
    agents = {e["source"] for e in world["evidence"]}
    assert {"trudi-mock", "kong-mock"} <= agents
    # Reverse evidence is required for completion.
    complete_conditions = [
        c for c in result.raw_output["terminal_decision"]["satisfied_conditions"]
    ]
    assert "The exported binary's behavior was identified by reverse engineering." in complete_conditions


@pytest.mark.asyncio
async def test_backend_success_without_grounded_facts_cannot_complete(
    tmp_path: Path,
) -> None:
    evidence = _managed(tmp_path, "evidence.log", b"host=demo event=login\n")
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    task = TaskSpec(
        task_id="empty-evidence-success",
        domain="dfir",
        target=str(evidence),
        goal="Determine the file's behavior.",
        success_conditions=("The file's behavior was identified.",),
        metadata={"file_type": {"normalized_type": "evidence_file", "sha256": digest}},
        input_object=InputObject(
            "input", "file", str(evidence), path=str(evidence),
            source_name="evidence.log", sha256=digest,
        ),
        target_object=TargetObject("target", "evidence_file", str(evidence)),
        authorization=AuthorizationScope((str(evidence),)),
        workspace=str(tmp_path / "runs" / "empty-evidence-success"),
    )
    dfir = EvidenceEmptyMockAdapter(agent_id="trudi-mock")
    model = ScriptedContextModel([_invoke("dfir", "input", "question-user-goal", "finding")])

    result = await _executor(tmp_path, model=model, dfir=dfir).execute(task)

    assert result.raw_output["world_state"]["facts"] == []
    assert result.raw_output["orchestration_status"] != "complete"
    assert result.status is not ExecutionStatus.SUCCESS


@pytest.mark.asyncio
async def test_mislinked_evidence_fails_closed(tmp_path: Path) -> None:
    from pentestgpt_agent.protocol import AgentResult, Artifact, Evidence, Finding

    class MislinkedMock(RecordingMockAdapter):
        async def collect(self, prepared, handle):
            output = prepared.run_layout.artifacts / "out.bin"
            output.write_bytes(b"x")
            artifact = Artifact.from_path(
                "real-artifact", "text_report", output, producer=self.agent_id
            )
            evidence = Evidence(
                "bad-evidence", "artifact_reference", self.agent_id, "Bad link.",
                artifact_ref="does-not-exist",
            )
            finding = Finding(
                "f", "finding", "T", "D", evidence_refs=("bad-evidence",)
            )
            return AgentResult(
                task_id=prepared.task_spec.task_id,
                agent_id=self.agent_id,
                domain=prepared.task_spec.domain,
                status=ExecutionStatus.SUCCESS,
                started_at="2026-08-31T00:00:00+00:00",
                finished_at="2026-08-31T00:00:01+00:00",
                summary="bad link",
                findings=(finding,),
                evidence=(evidence,),
                artifacts=(artifact,),
            )

    evidence = _managed(tmp_path, "evidence.log", b"x\n")
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    task = TaskSpec(
        task_id="mislinked",
        domain="dfir",
        target=str(evidence),
        goal="Assess the evidence.",
        success_conditions=("Assessed.",),
        metadata={"file_type": {"normalized_type": "evidence_file", "sha256": digest}},
        input_object=InputObject(
            "input", "file", str(evidence), path=str(evidence),
            source_name="evidence.log", sha256=digest,
        ),
        target_object=TargetObject("target", "evidence_file", str(evidence)),
        authorization=AuthorizationScope((str(evidence),)),
        workspace=str(tmp_path / "runs" / "mislinked"),
    )
    dfir = MislinkedMock(agent_id="trudi-mock")
    model = ScriptedContextModel([_invoke("dfir", "input", "question-user-goal", "finding")])

    result = await _executor(tmp_path, model=model, dfir=dfir).execute(task)

    assert result.raw_output["orchestration_status"] != "complete"
    assert result.status is not ExecutionStatus.SUCCESS


def _ensure_executor(runs: Path):
    from hunter_brain.supervisor import DeepSeekSupervisorConfig

    return build_analysis_brain_executor(
        repo_root=PROJECT_ROOT,
        runs_root=runs,
        config=DeepSeekSupervisorConfig(api_key="test-only-key"),
    )


def test_ensure_success_conditions_preserves_explicit_multipart_conditions(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    workspace = runs / "explicit-conditions"
    workspace.mkdir(parents=True, exist_ok=True)
    task = TaskSpec(
        task_id="explicit-conditions",
        domain="dfir",
        target="/evidence",
        goal="Find the file and determine its behavior.",
        success_conditions=("Found the file.", "Determined its behavior."),
        workspace=str(workspace),
    )
    executor = _ensure_executor(runs)

    updated = executor._ensure_success_conditions(task)

    assert updated.success_conditions == ("Found the file.", "Determined its behavior.")


def test_ensure_success_conditions_adds_goal_grounded_default_only_when_empty(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    workspace = runs / "empty-conditions"
    workspace.mkdir(parents=True, exist_ok=True)
    task = TaskSpec(
        task_id="empty-conditions",
        domain="dfir",
        target="/evidence",
        goal="Triage the acquired evidence and report indicators.",
        success_conditions=(),
        workspace=str(workspace),
    )
    executor = _ensure_executor(runs)

    updated = executor._ensure_success_conditions(task)

    assert len(updated.success_conditions) == 1
    assert task.goal in updated.success_conditions[0]
    persisted = (workspace / "task.json").read_text(encoding="utf-8")
    assert "Triage the acquired evidence" in persisted


def test_removing_reverse_evidence_prevents_complete(tmp_path: Path) -> None:
    """The cross-domain COMPLETE basis must trace to Reverse evidence.

    If the Reverse evidence is absent from canonical state, the same completion
    decision is rejected: the deterministic gate never fabricates a basis.
    """
    from hunter_brain.validator import BudgetSnapshot, DeterministicDecisionValidator
    from hunter_brain.capabilities import default_catalog
    from hunter_brain.decisions import CompleteDecision
    from hunter_brain.state import HunterWorldState, UnresolvedQuestion

    task = TaskSpec(
        task_id="no-reverse-basis",
        domain="dfir",
        target="/evidence",
        goal="Triage, locate the exported suspicious binary, reverse it, conclude.",
        success_conditions=(
            "A suspicious binary was exported from the evidence.",
            "The exported binary's behavior was identified by reverse engineering.",
        ),
    )
    state = HunterWorldState.from_task(task)
    state.add_question(UnresolvedQuestion("question-user-goal", task.goal, priority=100))

    decision = CompleteDecision(
        "Both domains are complete.",
        {
            "A suspicious binary was exported from the evidence.": ("trudi-evidence",),
            "The exported binary's behavior was identified by reverse engineering.": (
                "kong-analysis-evidence",
            ),
        },
        "Completion cites Reverse evidence that is not in canonical state.",
    )

    validation = DeterministicDecisionValidator().validate(
        decision,
        task=task,
        state=state,
        catalog=default_catalog(),
        budget=BudgetSnapshot(
            decisions_remaining=5, capability_calls_remaining=2, total_budget_remaining=10.0
        ),
    )

    assert validation.accepted is False
    assert any(
        issue.code.value == "unknown_evidence"
        and issue.reference == "kong-analysis-evidence"
        for issue in validation.issues
    )
