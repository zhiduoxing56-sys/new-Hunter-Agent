from __future__ import annotations

import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.decisions import (
    BlockedDecision,
    CompleteDecision,
    InvokeCapabilityDecision,
    VerifyDecision,
)
from hunter_brain.state import (
    ArtifactRecord,
    DispatchRecord,
    EvidenceRecord,
    HunterWorldState,
    UnresolvedQuestion,
    VerifiedFact,
)
from hunter_brain.validator import (
    BudgetSnapshot,
    DeterministicDecisionValidator,
    ValidationCode,
)
from pentestgpt_agent.protocol import (
    AuthorizationScope,
    InputObject,
    TargetObject,
    TaskSpec,
)


def _task() -> TaskSpec:
    target = "https://allowed.example/"
    return TaskSpec(
        task_id="validator-task",
        domain="pentest",
        target=target,
        goal="Assess the authorized service and explain any recovered binary.",
        success_conditions=("The conclusion is supported by evidence.",),
        input_object=InputObject("input-network", "network_target", target),
        target_object=TargetObject("target-network", "url", target),
        authorization=AuthorizationScope(allowed_targets=(target,)),
    )


def _state() -> HunterWorldState:
    state = HunterWorldState.from_task(_task())
    state.add_question(
        UnresolvedQuestion(
            "question-surface",
            "What services are exposed?",
            priority=90,
            required_output_types=("service_information",),
        )
    )
    return state


def _invoke(**changes: object) -> InvokeCapabilityDecision:
    values: dict[str, object] = {
        "capability_id": "pentest",
        "input_refs": ("input-network",),
        "question_id": "question-surface",
        "objective": "Identify exposed services.",
        "basis_input_refs": ("input-network",),
        "basis_fact_refs": (),
        "basis_evidence_refs": (),
        "expected_output_types": ("service_information",),
        "allocated_budget": 2.0,
        "rationale": "The authorized target is ready for assessment.",
    }
    values.update(changes)
    return InvokeCapabilityDecision(**values)  # type: ignore[arg-type]


def _validate(
    decision: object,
    *,
    task: TaskSpec | None = None,
    state: HunterWorldState | None = None,
    budget: BudgetSnapshot | None = None,
):
    return DeterministicDecisionValidator().validate(
        decision,  # type: ignore[arg-type]
        task=task or _task(),
        state=state or _state(),
        catalog=default_catalog(),
        budget=budget or BudgetSnapshot(decisions_remaining=10, capability_calls_remaining=5),
    )


def _codes(validation: object) -> set[ValidationCode]:
    return {item.code for item in validation.issues}  # type: ignore[attr-defined]


def test_valid_authorized_initial_invoke_is_accepted() -> None:
    validation = _validate(_invoke())

    assert validation.accepted is True
    assert validation.issues == ()


@pytest.mark.parametrize(
    ("capability_id", "input_ref", "code"),
    [
        ("reverse", "input-network", ValidationCode.INCOMPATIBLE_INPUT),
        ("missing", "input-network", ValidationCode.UNKNOWN_CAPABILITY),
        ("pentest", "missing-input", ValidationCode.UNKNOWN_INPUT),
    ],
)
def test_capability_and_input_compatibility_are_enforced(
    capability_id: str, input_ref: str, code: ValidationCode
) -> None:
    validation = _validate(
        _invoke(capability_id=capability_id, input_refs=(input_ref,))
    )

    assert validation.accepted is False
    assert code in _codes(validation)


def test_binary_artifact_can_be_sent_to_reverse_but_event_log_cannot() -> None:
    state = _state()
    state.add_artifact(
        ArtifactRecord(
            "artifact-binary",
            "suspect_binary",
            "/managed/evil.exe",
            "0" * 64,
            10,
            "dfir-adapter",
            state.task_id,
        )
    )
    state.add_artifact(
        ArtifactRecord(
            "artifact-events",
            "evtx",
            "/managed/events.evtx",
            "1" * 64,
            10,
            "dfir-adapter",
            state.task_id,
        )
    )
    reverse = _invoke(
        capability_id="reverse",
        input_refs=("artifact-binary",),
        expected_output_types=("program_behavior",),
    )
    wrong = _invoke(
        capability_id="reverse",
        input_refs=("artifact-events",),
        expected_output_types=("program_behavior",),
    )

    assert _validate(reverse, state=state).accepted is True
    assert ValidationCode.INCOMPATIBLE_INPUT in _codes(_validate(wrong, state=state))


def test_forged_fact_evidence_and_layer_one_references_are_rejected() -> None:
    decision = _invoke(
        basis_input_refs=("forged-input",),
        basis_fact_refs=("forged-fact",),
        basis_evidence_refs=("forged-evidence",),
    )

    codes = _codes(_validate(decision))

    assert ValidationCode.UNKNOWN_INPUT in codes
    assert ValidationCode.UNKNOWN_FACT in codes
    assert ValidationCode.UNKNOWN_EVIDENCE in codes


def test_out_of_scope_network_target_is_rejected() -> None:
    task = _task()
    task_value = task.to_dict()
    task_value["input_object"]["original_value"] = "https://outside.example/"
    out_of_scope = TaskSpec.from_dict(task_value)
    state = HunterWorldState.from_task(out_of_scope)
    state.add_question(UnresolvedQuestion("question-surface", "What services are exposed?", 90))

    validation = _validate(_invoke(), task=out_of_scope, state=state)

    assert ValidationCode.SCOPE_VIOLATION in _codes(validation)


def test_duplicate_call_without_progress_is_rejected() -> None:
    state = _state()
    state.record_dispatch(
        DispatchRecord(
            "dispatch-1",
            "pentest",
            "Identify exposed services.",
            ("input-network",),
            "success",
            False,
            False,
            (),
            1.0,
            question_id="question-surface",
        )
    )

    validation = _validate(_invoke(), state=state)

    assert ValidationCode.DUPLICATE_CALL in _codes(validation)


def test_same_cross_domain_sequence_is_allowed_when_it_makes_progress() -> None:
    state = _state()
    for index, capability in enumerate(("dfir", "reverse", "dfir", "reverse")):
        state.record_dispatch(
            DispatchRecord(
                f"dispatch-{index}",
                capability,
                f"Investigation step {index}",
                ("input-network",),
                "success",
                True,
                False,
                (),
                1.0,
            )
        )

    validation = _validate(_invoke(), state=state)

    assert ValidationCode.NO_PROGRESS_LOOP not in _codes(validation)


def test_consecutive_no_progress_limit_stops_the_path() -> None:
    state = _state()
    for index, capability in enumerate(("dfir", "reverse", "dfir")):
        state.record_dispatch(
            DispatchRecord(
                f"dispatch-{index}",
                capability,
                f"No-progress step {index}",
                (f"input-{index}",),
                "partial",
                False,
                False,
                (),
                1.0,
            )
        )

    validation = _validate(_invoke(), state=state)

    assert ValidationCode.NO_PROGRESS_LOOP in _codes(validation)


def test_completion_requires_conditions_evidence_and_no_critical_questions() -> None:
    state = _state()
    decision = CompleteDecision(
        "Premature completion.",
        {"Different condition": ("missing-evidence",)},
        "The model tried to finish too early.",
    )

    codes = _codes(_validate(decision, state=state))

    assert ValidationCode.SUCCESS_CONDITION_MISSING in codes
    assert ValidationCode.SUCCESS_CONDITION_UNKNOWN in codes
    assert ValidationCode.UNKNOWN_EVIDENCE in codes
    assert ValidationCode.CRITICAL_QUESTION_UNRESOLVED in codes


def test_evidence_grounded_completion_is_accepted_after_question_resolution() -> None:
    state = _state()
    state.add_evidence(
        EvidenceRecord("evidence-1", "report", "verifier", "Verified conclusion.")
    )
    state.add_fact(VerifiedFact("fact-1", "Conclusion verified.", ("evidence-1",)))
    state.resolve_question("question-surface", fact_refs=("fact-1",))
    decision = CompleteDecision(
        "The requested conclusion is supported.",
        {_task().success_conditions[0]: ("evidence-1",)},
        "No critical questions remain.",
    )

    assert _validate(decision, state=state).accepted is True


@pytest.mark.parametrize(
    ("budget", "code"),
    [
        (BudgetSnapshot(decisions_remaining=0), ValidationCode.DECISION_BUDGET_EXHAUSTED),
        (
            BudgetSnapshot(decisions_remaining=1, capability_calls_remaining=0),
            ValidationCode.CAPABILITY_BUDGET_EXHAUSTED,
        ),
        (
            BudgetSnapshot(
                decisions_remaining=1,
                capability_calls_remaining=1,
                total_budget_remaining=1.0,
            ),
            ValidationCode.ALLOCATION_EXCEEDS_BUDGET,
        ),
    ],
)
def test_budget_limits_are_enforced(budget: BudgetSnapshot, code: ValidationCode) -> None:
    assert code in _codes(_validate(_invoke(), budget=budget))


def test_verify_and_blocked_references_are_checked() -> None:
    verify = VerifyDecision(
        "Verify evidence.",
        ("missing-evidence",),
        ("artifact_exists",),
        "Verification is required.",
    )
    blocked = BlockedDecision(
        "No route remains.",
        ("missing-question",),
        ("missing-capability",),
        False,
        "All known routes failed.",
    )

    assert ValidationCode.UNKNOWN_EVIDENCE in _codes(_validate(verify))
    blocked_codes = _codes(_validate(blocked))
    assert ValidationCode.UNKNOWN_QUESTION in blocked_codes
    assert ValidationCode.UNKNOWN_CAPABILITY in blocked_codes
