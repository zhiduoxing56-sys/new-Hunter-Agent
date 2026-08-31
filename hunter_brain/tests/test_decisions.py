from __future__ import annotations

import pytest

from hunter_brain.decisions import (
    BlockedDecision,
    CompleteDecision,
    DecisionAction,
    InvokeCapabilityDecision,
    SupervisorDecision,
    VerifyDecision,
    decision_from_dict,
)


def _invoke() -> InvokeCapabilityDecision:
    return InvokeCapabilityDecision(
        capability_id="reverse",
        input_refs=("artifact-evil",),
        question_id="question-behavior",
        objective="Explain network communication and persistence behavior.",
        basis_input_refs=(),
        basis_fact_refs=("fact-execution",),
        basis_evidence_refs=("evidence-execution",),
        expected_output_types=("program_behavior", "indicator"),
        allocated_budget=3.0,
        rationale="The binary is available and its behavior remains unknown.",
    )


@pytest.mark.parametrize(
    "decision",
    [
        _invoke(),
        VerifyDecision(
            objective="Verify the reported artifact integrity.",
            evidence_refs=("evidence-execution",),
            verification_checks=("artifact_exists", "sha256_matches"),
            rationale="The evidence must be verified before global completion.",
        ),
        CompleteDecision(
            summary="The evidence supports the requested conclusion.",
            satisfied_conditions={
                "Explain the suspicious binary.": ("evidence-behavior",),
            },
            rationale="Every success condition has evidence.",
        ),
        BlockedDecision(
            reason="No compatible artifact is available.",
            blocking_question_ids=("question-behavior",),
            attempted_capability_ids=("dfir",),
            retryable=True,
            rationale="A binary must be recovered before reverse engineering.",
        ),
    ],
)
def test_all_four_decision_types_round_trip(decision: SupervisorDecision) -> None:
    wire = decision.to_dict()

    assert decision_from_dict(wire) == decision
    assert wire["action"] in {item.value for item in DecisionAction}
    assert wire["schema_version"] == "1.0"


def test_invoke_contract_contains_every_required_supervisor_answer() -> None:
    wire = _invoke().to_dict()

    assert wire["capability_id"] == "reverse"
    assert wire["input_refs"] == ["artifact-evil"]
    assert wire["question_id"] == "question-behavior"
    assert wire["objective"]
    assert wire["basis_input_refs"] == []
    assert wire["basis_fact_refs"] == ["fact-execution"]
    assert wire["basis_evidence_refs"] == ["evidence-execution"]
    assert wire["expected_output_types"] == ["program_behavior", "indicator"]
    assert wire["allocated_budget"] == 3.0


def test_first_decision_can_use_a_layer_one_input_as_its_basis() -> None:
    decision = InvokeCapabilityDecision(
        capability_id="pentest",
        input_refs=("input-network",),
        question_id="question-attack-surface",
        objective="Identify the authorized target's attack surface.",
        basis_input_refs=("input-network",),
        basis_fact_refs=(),
        basis_evidence_refs=(),
        expected_output_types=("service_information",),
        allocated_budget=2.0,
        rationale="Layer one supplied an authorized network target.",
    )

    assert decision_from_dict(decision.to_dict()) == decision


def test_free_text_and_unknown_actions_are_not_executable_decisions() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        decision_from_dict("reverse evil.exe")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="four supported actions"):
        decision_from_dict(
            {"schema_version": "1.0", "action": "run_shell", "command": "do something"}
        )


def test_unknown_fields_are_rejected_instead_of_becoming_commands() -> None:
    value = _invoke().to_dict()
    value["command"] = "private_backend_function()"

    with pytest.raises(ValueError, match="unknown=.*command"):
        decision_from_dict(value)


@pytest.mark.parametrize(
    "change",
    [
        {"input_refs": []},
        {"basis_input_refs": [], "basis_fact_refs": [], "basis_evidence_refs": []},
        {"expected_output_types": []},
        {"allocated_budget": 0},
        {"question_id": ""},
    ],
)
def test_incomplete_invoke_decisions_are_rejected(change: dict[str, object]) -> None:
    value = _invoke().to_dict()
    value.update(change)

    with pytest.raises(ValueError):
        decision_from_dict(value)


@pytest.mark.parametrize("raw", ["1.0", "3", "2.5e1"])
def test_quoted_numeric_budget_from_real_model_is_accepted(raw: str) -> None:
    value = _invoke().to_dict()
    value["allocated_budget"] = raw

    decision = decision_from_dict(value)

    assert isinstance(decision, InvokeCapabilityDecision)
    assert decision.allocated_budget == float(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("medium", 1.0), ("MEDIUM_TO_HIGH", 1.5), ("high", 2.0)],
)
def test_cost_tier_budget_from_real_model_is_mapped(raw: str, expected: float) -> None:
    value = _invoke().to_dict()
    value["allocated_budget"] = raw

    decision = decision_from_dict(value)

    assert isinstance(decision, InvokeCapabilityDecision)
    assert decision.allocated_budget == expected


@pytest.mark.parametrize("raw", ["not-a-number", "", "nan", "inf", True])
def test_non_numeric_budget_is_still_rejected(raw: object) -> None:
    value = _invoke().to_dict()
    value["allocated_budget"] = raw

    with pytest.raises(ValueError, match="allocated_budget"):
        decision_from_dict(value)


def test_complete_decision_requires_evidence_for_each_condition() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        CompleteDecision(
            summary="Unsupported completion.",
            satisfied_conditions={"Explain the suspicious binary.": ()},
            rationale="The model tried to finish without evidence.",
        )


def test_wrong_schema_version_is_rejected() -> None:
    value = _invoke().to_dict()
    value["schema_version"] = "2.0"

    with pytest.raises(ValueError, match="schema_version"):
        decision_from_dict(value)
