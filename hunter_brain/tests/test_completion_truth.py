"""Completion-truth contract tests (Phase 3C).

The global completion verifier must never treat ``AgentResult.SUCCESS`` or
"an artifact file exists" as the goal being verified. These tests pin the
contract:

- deterministic goal evidence (canonical verified facts) verifies a completion;
- benchmark oracles (AutoPenBench judge, VR crash evidence, reverse analysis
  truth, cross-domain provenance, DFIR availability) decide benchmark runs;
- false successes are rejected as ``NOT_VERIFIED``; timeouts and unavailable
  oracles are honestly ``INCONCLUSIVE``/``UNAVAILABLE``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hunter_brain.decisions import CompleteDecision
from hunter_brain.state import (
    ArtifactRecord,
    EvidenceRecord,
    HunterWorldState,
    VerifiedFact,
)
from hunter_brain.verifier import GlobalVerificationStatus, GlobalVerifier
from pentestgpt_agent.protocol import TaskSpec


def _task(
    *,
    task_id: str = "completion-truth-task",
    domain: str = "pentest",
    goal: str = "Produce an evidence-backed conclusion.",
    success_conditions: tuple[str, ...] = ("The conclusion is supported by verified evidence.",),
    metadata: dict | None = None,
) -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        domain=domain,
        target="https://allowed.example/",
        goal=goal,
        success_conditions=success_conditions,
        metadata=metadata or {},
    )


def _artifact(
    state: HunterWorldState,
    artifact_id: str,
    artifact_type: str,
    path: Path,
    *,
    producer: str = "test-backend",
    source_task_id: str | None = None,
) -> str:
    artifact = ArtifactRecord(
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        size=path.stat().st_size,
        producer_agent=producer,
        source_task_id=source_task_id or state.task_id,
    )
    state.add_artifact(artifact)
    return artifact.artifact_id


def _evidence(state: HunterWorldState, evidence_id: str, artifact_ref: str | None = None) -> str:
    state.add_evidence(
        EvidenceRecord(
            evidence_id=evidence_id,
            evidence_type="artifact_reference",
            source="test-backend",
            description="Backend-produced evidence.",
            artifact_ref=artifact_ref,
        )
    )
    return evidence_id


def _complete(state: HunterWorldState, conditions: dict[str, tuple[str, ...]]) -> CompleteDecision:
    return CompleteDecision(
        "Grounded evidence satisfies the goal.",
        conditions,
        "Completion truth contract test.",
    )


async def _verify(
    task: TaskSpec,
    state: HunterWorldState,
    decision: CompleteDecision,
    *,
    verifier: GlobalVerifier | None = None,
):
    return await (verifier or GlobalVerifier()).verify_completion(
        task=task,
        state=state,
        decision=decision,
    )


@pytest.mark.asyncio
async def test_real_success_is_verified_by_canonical_fact(tmp_path: Path) -> None:
    task = _task()
    state = HunterWorldState.from_task(task)
    artifact = tmp_path / "out.txt"
    artifact.write_text("result", encoding="utf-8")
    ref = _artifact(state, "result", "text_report", artifact)
    _evidence(state, "evidence", ref)
    state.add_fact(VerifiedFact("fact", "The conclusion is verified.", ("evidence",)))

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.PASSED
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "verified"
    assert outcome.completion_truth.verifier_id == "deterministic_goal_evidence"


@pytest.mark.asyncio
async def test_model_self_reported_success_without_grounding_is_not_verified(
    tmp_path: Path,
) -> None:
    task = _task()
    state = HunterWorldState.from_task(task)
    artifact = tmp_path / "out.txt"
    artifact.write_text("result", encoding="utf-8")
    ref = _artifact(state, "result", "text_report", artifact)
    _evidence(state, "evidence", ref)

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "not_verified"
    assert outcome.completion_truth.reason == "goal_evidence_insufficient"


@pytest.mark.asyncio
async def test_artifact_file_exists_alone_is_not_verified(tmp_path: Path) -> None:
    task = _task()
    state = HunterWorldState.from_task(task)
    artifact = tmp_path / "output.bin"
    artifact.write_bytes(b"\x00" * 8)
    ref = _artifact(state, "output", "backend_output", artifact)
    _evidence(state, "evidence", ref)

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert outcome.completion_truth.verdict.value == "not_verified"


@pytest.mark.asyncio
async def test_autopenbench_oracle_rejects_judge_failure(tmp_path: Path) -> None:
    task = _task(
        domain="pentest",
        goal="Discover the target and access flag.txt.",
        metadata={
            "benchmark": {
                "source": "autopenbench_games_json",
                "case_id": "in-vitro/web_security/vm1",
            }
        },
    )
    state = HunterWorldState.from_task(task)
    evaluation = tmp_path / "autopenbench-evaluation.json"
    evaluation.write_text(
        json.dumps(
            {
                "result": "failure",
                "judge": {
                    "success": False,
                    "oracle": "upstream_data_games_json_exact_flag",
                    "submitted_answers": [],
                },
            }
        ),
        encoding="utf-8",
    )
    _artifact(state, "backend-result", "backend_output", evaluation)
    _evidence(state, "backend-result-evidence", "backend-result")
    state.add_fact(VerifiedFact("fact", "PentestGPT AutoPenBench evaluation.", ("backend-result-evidence",)))

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("backend-result-evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "not_verified"
    assert outcome.completion_truth.reason == "judge_not_success"


@pytest.mark.asyncio
async def test_autopenbench_oracle_verifies_exact_flag_match(tmp_path: Path) -> None:
    task = _task(
        domain="pentest",
        goal="Discover the target and access flag.txt.",
        metadata={
            "benchmark": {
                "source": "autopenbench_games_json",
                "case_id": "in-vitro/web_security/vm0",
            }
        },
    )
    state = HunterWorldState.from_task(task)
    evaluation = tmp_path / "autopenbench-evaluation.json"
    evaluation.write_text(
        json.dumps(
            {
                "result": "success",
                "judge": {
                    "success": True,
                    "oracle": "upstream_data_games_json_exact_flag",
                    "submitted_answers": ["QnwieQY7t7MoxguK"],
                },
            }
        ),
        encoding="utf-8",
    )
    _artifact(state, "backend-result", "backend_output", evaluation)
    _evidence(state, "backend-result-evidence", "backend-result")

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("backend-result-evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.PASSED
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "verified"
    assert outcome.completion_truth.reason == "judge_success_exact_flag_match"


@pytest.mark.asyncio
async def test_autopenbench_oracle_unavailable_without_evaluation(tmp_path: Path) -> None:
    task = _task(
        domain="pentest",
        metadata={"benchmark": {"source": "autopenbench_games_json"}},
    )
    state = HunterWorldState.from_task(task)
    _evidence(state, "evidence")

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.INCONCLUSIVE
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "unavailable"


def _vr_state(tmp_path: Path, *, domain: str = "vulnerability_research", dispatch_status: str | None = None) -> tuple[TaskSpec, HunterWorldState]:
    task = _task(domain=domain, goal="Audit the supplied C project for a crash.")
    state = HunterWorldState.from_task(task)
    if dispatch_status is not None:
        from hunter_brain.state import DispatchRecord

        state.record_dispatch(
            DispatchRecord(
                dispatch_id="dispatch-0001",
                capability_id="vulnerability_research",
                objective="Fuzz the project.",
                input_refs=("input",),
                status=dispatch_status,
                new_evidence=False,
                new_facts=False,
                answered_question_ids=(),
                budget_used=1.0,
            )
        )
    return task, state


@pytest.mark.asyncio
async def test_vr_positive_trigger_is_verified(tmp_path: Path) -> None:
    task, state = _vr_state(tmp_path)
    trigger = tmp_path / "povs" / "crash-1"
    trigger.parent.mkdir(parents=True)
    trigger.write_bytes(b"ASAN: heap-buffer-overflow\n")
    _artifact(state, "fuzzingbrain-trigger-0", "trigger_sample", trigger)
    _evidence(state, "trigger-evidence", "fuzzingbrain-trigger-0")

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("trigger-evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.PASSED
    assert outcome.completion_truth.verdict.value == "verified"
    assert outcome.completion_truth.reason == "crash_trigger_reproduced"


@pytest.mark.asyncio
async def test_vr_fixed_timeout_is_inconclusive_not_no_vulnerability(tmp_path: Path) -> None:
    task, state = _vr_state(tmp_path, dispatch_status="timeout")
    _evidence(state, "trigger-evidence")

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("trigger-evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.INCONCLUSIVE
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "inconclusive"
    assert outcome.completion_truth.reason == "campaign_timeout_no_crash"


@pytest.mark.asyncio
async def test_vr_finished_without_trigger_is_not_verified(tmp_path: Path) -> None:
    task, state = _vr_state(tmp_path)
    _evidence(state, "evidence")

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "not_verified"
    assert outcome.completion_truth.reason == "no_crash_reproduced"


@pytest.mark.asyncio
async def test_reverse_backend_tool_failure_is_not_verified(tmp_path: Path) -> None:
    task = _task(domain="reverse", goal="Identify any backdoor functions.")
    state = HunterWorldState.from_task(task)
    analysis = tmp_path / "analysis.json"
    analysis.write_text(
        json.dumps(
            {
                "binary": {"name": "liblzma.so.5.6.1"},
                "stats": {"total_functions": 478, "analyzed": 2, "named": 0, "errors": 445},
                "functions": [],
            }
        ),
        encoding="utf-8",
    )
    _artifact(state, "kong-analysis", "reverse_analysis", analysis)
    _evidence(state, "kong-analysis-evidence", "kong-analysis")

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("kong-analysis-evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "not_verified"
    assert outcome.completion_truth.reason == "backend_tool_failure"


@pytest.mark.asyncio
async def test_reverse_named_analysis_without_ground_truth_is_inconclusive(
    tmp_path: Path,
) -> None:
    task = _task(domain="reverse", goal="Identify any backdoor functions.")
    state = HunterWorldState.from_task(task)
    analysis = tmp_path / "analysis.json"
    analysis.write_text(
        json.dumps(
            {
                "binary": {"name": "sample.so"},
                "stats": {"total_functions": 10, "analyzed": 9, "named": 9, "errors": 0},
                "functions": [{"name": "foo", "original_name": "foo", "address": "0x0"}],
            }
        ),
        encoding="utf-8",
    )
    _artifact(state, "kong-analysis", "reverse_analysis", analysis)
    _evidence(state, "kong-analysis-evidence", "kong-analysis")

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("kong-analysis-evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.INCONCLUSIVE
    assert outcome.completion_truth.verdict.value == "inconclusive"
    assert outcome.completion_truth.reason == "analysis_complete_ground_truth_unverified"


@pytest.mark.asyncio
async def test_reverse_expected_functions_eval_oracle_requires_all(tmp_path: Path) -> None:
    task = _task(
        domain="reverse",
        goal="Identify any backdoor functions.",
        metadata={
            "completion_oracle": {
                "type": "reverse_expected_functions",
                "functions": ["init_rsa_public_decrypt", "function_hook_replace"],
            }
        },
    )
    state = HunterWorldState.from_task(task)
    analysis = tmp_path / "analysis.json"
    analysis.write_text(
        json.dumps(
            {
                "binary": {"name": "liblzma.so.5.6.1"},
                "stats": {"total_functions": 478, "analyzed": 478, "named": 1, "errors": 0},
                "functions": [
                    {"name": "init_rsa_public_decrypt", "original_name": "init_rsa_public_decrypt"},
                    {"name": "not_a_backdoor", "original_name": "not_a_backdoor"},
                ],
            }
        ),
        encoding="utf-8",
    )
    _artifact(state, "kong-analysis", "reverse_analysis", analysis)
    _evidence(state, "kong-analysis-evidence", "kong-analysis")

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("kong-analysis-evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.reason == "expected_backdoor_functions_not_identified"


def _cross_domain_state(
    tmp_path: Path,
    *,
    consumed_bytes: bytes,
) -> tuple[TaskSpec, HunterWorldState]:
    task = _task(
        task_id="cross-domain-goal",
        domain="dfir",
        goal="Triage, export the suspicious binary, reverse it, conclude.",
        success_conditions=(
            "A suspicious binary was exported from the evidence.",
            "The exported binary's behavior was identified by reverse engineering.",
        ),
        metadata={"completion_oracle": {"type": "cross_domain_provenance"}},
    )
    state = HunterWorldState.from_task(task)
    state.register_child_task("child-dfir")
    state.register_child_task("child-reverse")
    suspect = tmp_path / "exported-suspect.bin"
    suspect.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    _artifact(state, "trudi-exported-evidence", "suspect_binary", suspect, source_task_id="child-dfir")
    analysis = tmp_path / "analysis.json"
    consumed = tmp_path / "consumed-input.bin"
    consumed.write_bytes(consumed_bytes)
    analysis.write_text(
        json.dumps({"binary": {"path": str(consumed)}, "stats": {"named": 9}}),
        encoding="utf-8",
    )
    _artifact(state, "kong-analysis", "reverse_analysis", analysis, source_task_id="child-reverse")
    _evidence(state, "trudi-evidence", "trudi-exported-evidence")
    _evidence(state, "kong-evidence", "kong-analysis")
    return task, state


@pytest.mark.asyncio
async def test_cross_domain_provenance_match_is_verified(tmp_path: Path) -> None:
    payload = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
    task, state = _cross_domain_state(tmp_path, consumed_bytes=payload)

    outcome = await _verify(
        task,
        state,
        _complete(
            state,
            {
                task.success_conditions[0]: ("trudi-evidence",),
                task.success_conditions[1]: ("kong-evidence",),
            },
        ),
    )

    assert outcome.status is GlobalVerificationStatus.PASSED
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "verified"
    assert outcome.completion_truth.reason == "reverse_consumed_trudi_export_with_sha"


@pytest.mark.asyncio
async def test_cross_domain_provenance_mismatch_is_not_verified(tmp_path: Path) -> None:
    task, state = _cross_domain_state(tmp_path, consumed_bytes=b"different-bytes")

    outcome = await _verify(
        task,
        state,
        _complete(
            state,
            {
                task.success_conditions[0]: ("trudi-evidence",),
                task.success_conditions[1]: ("kong-evidence",),
            },
        ),
    )

    assert outcome.status is GlobalVerificationStatus.FAILED
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "not_verified"
    assert outcome.completion_truth.reason == "cross_domain_provenance_mismatch"


@pytest.mark.asyncio
async def test_dfir_benchmark_unavailable_is_explicit(tmp_path: Path) -> None:
    task = _task(
        domain="dfir",
        metadata={
            "completion_oracle": {
                "type": "dfir_benchmark",
                "status": "missing",
                "reason": "CFReDS images are not vendored.",
            }
        },
    )
    state = HunterWorldState.from_task(task)
    _evidence(state, "evidence")

    outcome = await _verify(
        task,
        state,
        _complete(state, {task.success_conditions[0]: ("evidence",)}),
    )

    assert outcome.status is GlobalVerificationStatus.INCONCLUSIVE
    assert outcome.completion_truth is not None
    assert outcome.completion_truth.verdict.value == "unavailable"
    assert outcome.completion_truth.reason == "benchmark_unavailable"
