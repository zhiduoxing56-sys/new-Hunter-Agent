from __future__ import annotations

from pathlib import Path

import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import InvokeCapabilityDecision
from hunter_brain.question_generator import CrossDomainQuestionGenerator
from hunter_brain.state import HunterWorldState
from hunter_brain.state_updater import WorldStateUpdater
from pentestgpt_agent.protocol import AgentResult, Artifact, ExecutionStatus, TaskSpec


@pytest.mark.parametrize(
    ("producer", "artifact_type", "expected_candidate"),
    (
        ("dfir", "suspect_binary", "reverse"),
        ("reverse", "indicator", "dfir"),
        ("pentest", "file_artifact", "reverse"),
        ("reverse", "source_code", "vulnerability_research"),
        ("vulnerability_research", "vulnerability", "pentest"),
    ),
)
def test_cross_domain_candidates_come_from_artifacts_and_catalog(
    tmp_path: Path,
    producer: str,
    artifact_type: str,
    expected_candidate: str,
) -> None:
    task = TaskSpec("cross-domain-task", producer, "input", "Investigate safely")
    state = HunterWorldState.from_task(task)
    path = tmp_path / f"{artifact_type}.bin"
    path.write_bytes(b"evidence")
    result = AgentResult(
        task_id=task.task_id,
        agent_id=producer,
        domain=producer,
        status=ExecutionStatus.SUCCESS,
        started_at="2026-08-30T00:00:00+00:00",
        finished_at="2026-08-30T00:00:01+00:00",
        summary="Produced a cross-domain artifact.",
        artifacts=(
            Artifact.from_path(
                "new-artifact", artifact_type, path, producer=producer
            ),
        ),
    )
    preview = WorldStateUpdater().apply(state, result)
    decision = InvokeCapabilityDecision(
        producer,
        ("input",),
        "original-question",
        "Produce evidence.",
        ("input",),
        (),
        (),
        ("finding",),
        1.0,
        "Initial analysis.",
    )

    proposal = CrossDomainQuestionGenerator().interpret(
        preview=preview,
        decision=decision,
        result=result,
    )

    candidates = default_catalog().candidates_for_input(artifact_type)
    assert expected_candidate in {item.capability_id for item in candidates}
    assert len(proposal.new_questions) == 1
    assert proposal.new_questions[0].source == "new-artifact"
    assert artifact_type in proposal.new_questions[0].question
    applied = WorldStateUpdater().apply(state, result, semantic_proposal=proposal)
    assert applied.delta.added_question_ids == (
        proposal.new_questions[0].question_id,
    )


def test_cross_domain_questions_are_exploratory_not_completion_blockers(
    tmp_path: Path,
) -> None:
    task = TaskSpec("nonblocking-task", "dfir", "input", "Investigate safely")
    state = HunterWorldState.from_task(task)
    path = tmp_path / "trigger.bin"
    path.write_bytes(b"crash input")
    result = AgentResult(
        task_id=task.task_id,
        agent_id="dfir",
        domain="dfir",
        status=ExecutionStatus.SUCCESS,
        started_at="2026-08-31T00:00:00+00:00",
        finished_at="2026-08-31T00:00:01+00:00",
        summary="Recovered a trigger sample.",
        artifacts=(
            Artifact.from_path("trigger", "trigger_sample", path, producer="dfir"),
        ),
    )
    preview = WorldStateUpdater().apply(state, result)
    decision = InvokeCapabilityDecision(
        "dfir",
        ("input",),
        "q",
        "Analyze.",
        ("input",),
        (),
        (),
        ("finding",),
        1.0,
        "Need it.",
    )

    proposal = CrossDomainQuestionGenerator().interpret(
        preview=preview, decision=decision, result=result
    )

    assert len(proposal.new_questions) == 1
    assert proposal.new_questions[0].priority < 80


def test_no_question_is_generated_without_a_compatible_other_domain(
    tmp_path: Path,
) -> None:
    task = TaskSpec("no-route-task", "dfir", "input", "Investigate safely")
    state = HunterWorldState.from_task(task)
    path = tmp_path / "report.txt"
    path.write_text("report", encoding="utf-8")
    result = AgentResult(
        task_id=task.task_id,
        agent_id="dfir",
        domain="dfir",
        status=ExecutionStatus.SUCCESS,
        started_at="2026-08-30T00:00:00+00:00",
        finished_at="2026-08-30T00:00:01+00:00",
        summary="Produced a local report.",
        artifacts=(Artifact.from_path("report", "dfir_raw_result", path, producer="dfir"),),
    )
    preview = WorldStateUpdater().apply(state, result)
    decision = InvokeCapabilityDecision(
        "dfir",
        ("input",),
        "q",
        "Analyze.",
        ("input",),
        (),
        (),
        ("finding",),
        1.0,
        "Need it.",
    )

    proposal = CrossDomainQuestionGenerator().interpret(
        preview=preview, decision=decision, result=result
    )

    assert proposal.new_questions == ()
