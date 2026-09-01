"""Regression replay of the frozen Phase 3B evaluations through the new
completion-truth verifier (Phase 3C).

The Phase 3B JSONL fixtures are committed under ``evaluation/phase3b_results``
(and ``evaluation/results`` for VR). Replaying each frozen run's final
``complete`` decision and its recorded evidence through the Phase 3C
``GlobalVerifier`` must prove that the old FALSE_SUCCESS completions are now
rejected, while real successes (vm0 flag, VR positive) stay verified.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hunter_brain.decisions import CompleteDecision, decision_from_dict
from hunter_brain.state import (
    ArtifactRecord,
    DispatchRecord,
    EvidenceRecord,
    HunterWorldState,
)
from hunter_brain.verifier import GlobalVerificationStatus, GlobalVerifier
from pentestgpt_agent.protocol import TaskSpec

FIXTURES = Path(__file__).resolve().parents[2] / "evaluation"


def _frozen_lines(relative: str) -> list[dict]:
    path = FIXTURES / relative
    if not path.is_file():
        pytest.skip(f"frozen fixture missing: {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _complete_decision(record: dict) -> dict:
    for decision in record["supervisor_decisions"]:
        if decision.get("action") == "complete":
            return decision
    raise AssertionError(f"frozen record has no complete decision: {record.get('run_id')}")


def _add_evidence(state: HunterWorldState, evidence_id: str, artifact_ref: str | None = None) -> None:
    if evidence_id not in state.evidence:
        state.add_evidence(
            EvidenceRecord(
                evidence_id=evidence_id,
                evidence_type="artifact_reference",
                source="phase3b_replay",
                description="Replayed frozen Phase 3B evidence.",
                artifact_ref=artifact_ref,
            )
        )


def _add_artifact(state: HunterWorldState, artifact_id: str, artifact_type: str, path: Path, source_task_id: str) -> str:
    artifact = ArtifactRecord(
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        size=path.stat().st_size,
        producer_agent="phase3b_replay",
        source_task_id=source_task_id,
    )
    state.add_artifact(artifact)
    return artifact.artifact_id


async def _replay_verification(record: dict, tmp_path: Path, *, task: TaskSpec):
    state = HunterWorldState.from_task(task)
    for child in record.get("children") or []:
        state.register_child_task(child["child_id"])
    raw_complete = _complete_decision(record)
    conditions = {str(condition): tuple(refs) for condition, refs in raw_complete["satisfied_conditions"].items()}
    for references in conditions.values():
        for reference in references:
            _add_evidence(state, reference)
    decision = decision_from_dict(raw_complete)
    assert isinstance(decision, CompleteDecision)
    return await GlobalVerifier().verify_completion(
        task=task,
        state=state,
        decision=decision,
    )


def _pentest_task(record: dict, raw_complete: dict) -> TaskSpec:
    return TaskSpec(
        task_id=record["run_id"],
        domain="pentest",
        target="in-vitro/web_security",
        goal="Discover the target and access flag.txt.",
        success_conditions=tuple(raw_complete["satisfied_conditions"]),
        metadata={"benchmark": {"source": "autopenbench_games_json"}},
    )


async def _replay_pentest(record: dict, tmp_path: Path):
    raw_complete = _complete_decision(record)
    task = _pentest_task(record, raw_complete)
    state = HunterWorldState.from_task(task)
    for child in record.get("children") or []:
        state.register_child_task(child["child_id"])
    children = record.get("children") or []
    backend_child = next((c for c in children if "backend_output" in c.get("artifact_types", [])), None)
    source_task = backend_child["child_id"] if backend_child else children[0]["child_id"]
    evaluation = tmp_path / "autopenbench-evaluation.json"
    judge_success = bool(record.get("benchmark_judge_success"))
    submitted = ["<captured-flag>"] if judge_success else []
    evaluation.write_text(
        json.dumps(
            {
                "result": "success" if judge_success else "failure",
                "judge": {
                    "success": judge_success,
                    "oracle": "upstream_data_games_json_exact_flag",
                    "submitted_answers": submitted,
                },
            }
        ),
        encoding="utf-8",
    )
    artifact_id = _add_artifact(state, f"child-{source_task}-backend-result", "backend_output", evaluation, source_task)
    conditions = {str(condition): tuple(refs) for condition, refs in raw_complete["satisfied_conditions"].items()}
    for references in conditions.values():
        for reference in references:
            _add_evidence(state, reference, artifact_id)
    decision = decision_from_dict(raw_complete)
    assert isinstance(decision, CompleteDecision)
    return await GlobalVerifier().verify_completion(task=task, state=state, decision=decision)


@pytest.mark.asyncio
async def test_frozen_vm0_ext_real_success_stays_verified(tmp_path: Path) -> None:
    records = _frozen_lines("phase3b_results/pentest-autopenbench-web_security-vm0-ext.jsonl")
    assert records, "frozen vm0 fixture is empty"
    for record in records:
        outcome = await _replay_pentest(record, tmp_path)
        assert outcome.status is GlobalVerificationStatus.PASSED
        assert outcome.completion_truth is not None
        assert outcome.completion_truth.verdict.value == "verified"


@pytest.mark.asyncio
async def test_frozen_vm1_ext_false_success_is_rejected(tmp_path: Path) -> None:
    records = _frozen_lines("phase3b_results/pentest-autopenbench-web_security-vm1-ext.jsonl")
    assert records, "frozen vm1 fixture is empty"
    for record in records:
        assert record.get("ground_truth_hit") is False
        outcome = await _replay_pentest(record, tmp_path)
        assert outcome.status is GlobalVerificationStatus.FAILED
        assert outcome.completion_truth is not None
        assert outcome.completion_truth.verdict.value == "not_verified"
        assert outcome.completion_truth.reason == "judge_not_success"


@pytest.mark.asyncio
async def test_frozen_reverse_false_success_is_rejected(tmp_path: Path) -> None:
    records = _frozen_lines("phase3b_results/reverse-kong-liblzma-backdoor.jsonl")
    completed = [r for r in records if any(d.get("action") == "complete" for d in r["supervisor_decisions"])]
    assert completed, "frozen reverse fixtures include no completed runs"
    for index, record in enumerate(completed):
        raw_complete = _complete_decision(record)
        task = TaskSpec(
            task_id=record["run_id"],
            domain="reverse",
            target="liblzma.so.5.6.1",
            goal="Analyze the supplied binary and identify any backdoor functions.",
            success_conditions=tuple(raw_complete["satisfied_conditions"]),
        )
        state = HunterWorldState.from_task(task)
        for child in record.get("children") or []:
            state.register_child_task(child["child_id"])
        source_task = (record.get("children") or [{}])[0].get("child_id") or "child-reverse"
        metrics = (record.get("children") or [{}])[0].get("metrics") or {}
        stats = {key: metrics.get(key) for key in (
            "total_functions", "analyzed", "named", "errors",
            "confirmed", "high_confidence", "low_confidence", "llm_calls", "duration_seconds",
        )}
        run_dir = tmp_path / f"reverse-{index}"
        run_dir.mkdir(exist_ok=True)
        analysis = run_dir / "analysis.json"
        analysis.write_text(
            json.dumps({"binary": {"name": "liblzma.so.5.6.1"}, "stats": stats, "functions": []}),
            encoding="utf-8",
        )
        artifact_id = _add_artifact(state, f"child-{source_task[-12:]}-kong-analysis", "reverse_analysis", analysis, source_task)
        conditions = {str(condition): tuple(refs) for condition, refs in raw_complete["satisfied_conditions"].items()}
        for references in conditions.values():
            for reference in references:
                _add_evidence(state, reference, artifact_id)
        decision = decision_from_dict(raw_complete)
        assert isinstance(decision, CompleteDecision)
        outcome = await GlobalVerifier().verify_completion(task=task, state=state, decision=decision)

        assert outcome.status is GlobalVerificationStatus.FAILED
        assert outcome.completion_truth is not None
        assert outcome.completion_truth.verdict.value == "not_verified"
        assert outcome.completion_truth.reason == "backend_tool_failure"


async def _replay_vr(record: dict, tmp_path: Path, *, index: int):
    raw_complete = _complete_decision(record)
    task = TaskSpec(
        task_id=record["run_id"],
        domain="vulnerability_research",
        target="hunterdemo",
        goal="Audit the supplied local C project for a reproducible crash vulnerability.",
        success_conditions=tuple(raw_complete["satisfied_conditions"]),
    )
    state = HunterWorldState.from_task(task)
    for child in record.get("children") or []:
        state.register_child_task(child["child_id"])
    children = record.get("children") or []
    first_child = children[0] if children else {}
    conditions = {str(condition): tuple(refs) for condition, refs in raw_complete["satisfied_conditions"].items()}
    run_dir = tmp_path / f"vr-{index}"
    run_dir.mkdir(exist_ok=True)
    if "trigger_sample" in first_child.get("artifact_types", []):
        trigger = run_dir / "povs" / "crash-1"
        trigger.parent.mkdir(parents=True, exist_ok=True)
        trigger.write_bytes(b"ASAN: heap-buffer-overflow\n")
        _add_artifact(state, "fuzzingbrain-trigger-0", "trigger_sample", trigger, first_child["child_id"])
    if first_child.get("status") == "timeout":
        state.record_dispatch(
            DispatchRecord(
                dispatch_id="dispatch-0001",
                capability_id="vulnerability_research",
                objective="Fuzz the project.",
                input_refs=("input",),
                status="timeout",
                new_evidence=False,
                new_facts=False,
                answered_question_ids=(),
                budget_used=1.0,
            )
        )
    for references in conditions.values():
        for reference in references:
            _add_evidence(state, reference)
    decision = decision_from_dict(raw_complete)
    assert isinstance(decision, CompleteDecision)
    return await GlobalVerifier().verify_completion(task=task, state=state, decision=decision)


@pytest.mark.asyncio
async def test_frozen_vr_positive_stays_verified(tmp_path: Path) -> None:
    records = _frozen_lines("results/vr-fuzzingbrain-hunterdemo.jsonl")
    for index, record in enumerate(records):
        outcome = await _replay_vr(record, tmp_path, index=index)
        assert outcome.status is GlobalVerificationStatus.PASSED
        assert outcome.completion_truth is not None
        assert outcome.completion_truth.verdict.value == "verified"


@pytest.mark.asyncio
async def test_frozen_vr_fixed_timeout_is_inconclusive_not_no_vulnerability(
    tmp_path: Path,
) -> None:
    records = _frozen_lines("results/vr-fuzzingbrain-hunterdemo-fixed.jsonl")
    for index, record in enumerate(records):
        if not any(d.get("action") == "complete" for d in record["supervisor_decisions"]):
            continue
        outcome = await _replay_vr(record, tmp_path, index=index)
        assert outcome.status is GlobalVerificationStatus.INCONCLUSIVE
        assert outcome.completion_truth is not None
        assert outcome.completion_truth.reason == "campaign_timeout_no_crash"
