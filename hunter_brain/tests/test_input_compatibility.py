"""Semantic Layer-1 input compatibility with capability accepted types.

Verifies that the Layer-1 semantic bridge (``metadata.semantic_input_type``)
feeds the decision validator, that plain ``text``/``directory``/``archive``
inputs are still refused unless the bridge classified them, and that scope and
authorization checks are never bypassed by the bridge.
"""

from __future__ import annotations

import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import InvokeCapabilityDecision
from hunter_brain.state import HunterWorldState, UnresolvedQuestion
from hunter_brain.validator import (
    BudgetSnapshot,
    DeterministicDecisionValidator,
    ValidationCode,
    resolve_input_type,
)
from pentestgpt_agent.protocol import (
    AuthorizationScope,
    InputObject,
    TargetObject,
    TaskSpec,
)


def _file_task(*, semantic_type: str | None, normalized_type: str = "text") -> TaskSpec:
    target = "/evidence/sample"
    return TaskSpec(
        task_id="compat-task",
        domain="dfir",
        target=target,
        goal="Triage the supplied input.",
        success_conditions=("The input is assessed.",),
        metadata={
            "file_type": {"normalized_type": normalized_type},
            "semantic_input_type": semantic_type,
            "semantic_input_rationale": ["test fixture"],
        },
        input_object=InputObject("input", "file", target),
        target_object=TargetObject("target", normalized_type, target),
        authorization=AuthorizationScope(allowed_targets=(target,)),
    )


def _state(task: TaskSpec) -> HunterWorldState:
    state = HunterWorldState.from_task(task)
    state.add_question(
        UnresolvedQuestion("question-goal", task.goal, priority=100, source="user_goal")
    )
    return state


def _invoke(task: TaskSpec, capability_id: str, output_type: str) -> InvokeCapabilityDecision:
    return InvokeCapabilityDecision(
        capability_id,
        ("input",),
        "question-goal",
        f"Run {capability_id}.",
        ("input",),
        (),
        (),
        (output_type,),
        1.0,
        "Test fixture decision.",
    )


def _validate(task: TaskSpec, decision: InvokeCapabilityDecision):
    return DeterministicDecisionValidator().validate(
        decision,
        task=task,
        state=_state(task),
        catalog=default_catalog(),
        budget=BudgetSnapshot(
            decisions_remaining=10,
            capability_calls_remaining=8,
            total_budget_remaining=10.0,
        ),
    )


@pytest.mark.parametrize(
    ("semantic", "capability", "output_type"),
    [
        ("log", "dfir", "finding"),
        ("evidence_file", "dfir", "finding"),
        ("pcap", "dfir", "finding"),
        ("source_code", "vulnerability_research", "vulnerability"),
        ("source_tree", "vulnerability_research", "vulnerability"),
        ("source_bundle", "vulnerability_research", "vulnerability"),
        ("elf", "reverse", "binary_metadata"),
        ("network_target", "pentest", "access_proof"),
    ],
)
def test_bridged_semantic_types_are_accepted_by_their_capability(
    semantic: str, capability: str, output_type: str
) -> None:
    task = _file_task(semantic_type=semantic)
    validation = _validate(task, _invoke(task, capability, output_type))
    assert validation.accepted is True, validation.issues


def test_plain_text_is_still_incompatible_with_every_capability() -> None:
    task = _file_task(semantic_type=None, normalized_type="text")
    catalog = default_catalog()
    for capability_id in catalog.capability_ids:
        capability = catalog.get(capability_id)
        output_type = next(iter(capability.produces))
        validation = _validate(task, _invoke(task, capability_id, output_type))
        assert validation.accepted is False
        assert any(
            issue.code is ValidationCode.INCOMPATIBLE_INPUT
            for issue in validation.issues
        ), capability_id


def test_bare_directory_without_bridge_is_rejected() -> None:
    task = TaskSpec(
        task_id="compat-dir",
        domain="vulnerability_research",
        target="/projects/bare",
        goal="Audit the project.",
        success_conditions=("Assessed.",),
        metadata={"input_kind": "directory", "semantic_input_type": None},
        input_object=InputObject("input", "directory", "/projects/bare"),
        target_object=TargetObject("target", "directory", "/projects/bare"),
        authorization=AuthorizationScope(allowed_targets=("/projects/bare",)),
    )
    validation = _validate(task, _invoke(task, "vulnerability_research", "vulnerability"))
    assert validation.accepted is False
    assert any(
        issue.code is ValidationCode.INCOMPATIBLE_INPUT for issue in validation.issues
    )


def test_unknown_semantic_value_is_not_accepted_anywhere() -> None:
    task = _file_task(semantic_type="not-a-real-type")
    validation = _validate(task, _invoke(task, "dfir", "finding"))
    assert validation.accepted is False
    assert any(
        issue.code is ValidationCode.INCOMPATIBLE_INPUT for issue in validation.issues
    )


def test_semantic_bridge_does_not_bypass_authorization_scope() -> None:
    task = _file_task(semantic_type="network_target")
    task = TaskSpec(
        task_id="compat-scope",
        domain="pentest",
        target="http://attacker.invalid/",
        goal="Assess the target.",
        success_conditions=("Assessed.",),
        metadata={"semantic_input_type": "network_target"},
        input_object=InputObject("input", "network_target", "http://attacker.invalid/"),
        target_object=TargetObject("target", "url", "http://attacker.invalid/"),
        authorization=AuthorizationScope(allowed_targets=("http://authorized.example/",)),
    )
    validation = _validate(task, _invoke(task, "pentest", "access_proof"))
    assert validation.accepted is False
    assert any(
        issue.code is ValidationCode.SCOPE_VIOLATION for issue in validation.issues
    )


def test_resolve_input_type_prefers_semantic_then_normalized_then_kind() -> None:
    assert resolve_input_type(_file_task(semantic_type="log", normalized_type="text")) == "log"
    assert resolve_input_type(_file_task(semantic_type=None, normalized_type="pcap")) == "pcap"
    task = _file_task(semantic_type=None, normalized_type=None)
    task = TaskSpec(
        task_id="compat-kind",
        domain="dfir",
        target="/x",
        goal="g",
        input_object=InputObject("input", "evidence_file", "/x"),
        authorization=AuthorizationScope(allowed_targets=("/x",)),
    )
    assert resolve_input_type(task) == "evidence_file"
