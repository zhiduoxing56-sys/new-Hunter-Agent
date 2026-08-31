"""Verification contract: the closed verification vocabulary.

The supervisor may only emit verification checks from ``VerificationCheck``.
Every member is executable by the GlobalVerifier, and any free-text or unknown
check name fails closed at decision construction/parsing, never reaching the
verifier.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunter_brain.decisions import (
    VerificationCheck,
    VerifyDecision,
    decision_from_dict,
)
from hunter_brain.state import HunterWorldState
from hunter_brain.state_updater import WorldStateUpdater
from hunter_brain.supervisor import HunterSupervisor
from hunter_brain.verifier import (
    GlobalVerificationStatus,
    GlobalVerifier,
    VerificationCode,
)
from pentestgpt_agent.protocol import AdapterRunner, TaskSpec
from pentestgpt_agent.protocol.mock_adapter import MockAdapter


def _task() -> TaskSpec:
    return TaskSpec(
        task_id="verification-contract-task",
        domain="pentest",
        target="https://allowed.example/",
        goal="Produce an evidence-backed conclusion.",
        success_conditions=("The conclusion is supported by verified evidence.",),
    )


async def _state(tmp_path: Path) -> HunterWorldState:
    runs = tmp_path / "runs"
    result = await AdapterRunner(MockAdapter(), runs_root=runs).execute(_task())
    return WorldStateUpdater().apply(HunterWorldState.from_task(_task()), result).state


@pytest.mark.parametrize("check", list(VerificationCheck))
@pytest.mark.asyncio
async def test_every_verification_check_is_executable(
    tmp_path: Path, check: VerificationCheck
) -> None:
    state = await _state(tmp_path)
    evidence_id = next(iter(state.evidence))
    decision = VerifyDecision(
        "Verify the mock evidence.",
        (evidence_id,),
        (check.value,),
        "Every vocabulary check must execute.",
    )

    outcome = await GlobalVerifier().verify_request(
        task=_task(), state=state, decision=decision
    )

    assert outcome.status in {
        GlobalVerificationStatus.PASSED,
        GlobalVerificationStatus.FAILED,
        GlobalVerificationStatus.INCONCLUSIVE,
    }
    assert not any(
        issue.code is VerificationCode.CHECK_UNSUPPORTED for issue in outcome.issues
    )


@pytest.mark.parametrize(
    "bad_check",
    ["exploit_reproduces", "Check the evidence for ELF format", "artifact sha matches"],
)
def test_free_text_or_unknown_check_is_rejected_at_construction(
    bad_check: str,
) -> None:
    with pytest.raises(ValueError, match="closed vocabulary"):
        VerifyDecision(
            "Verify evidence.",
            ("mock-evidence",),
            (bad_check,),
            "Unknown checks must fail closed.",
        )


def test_empty_check_name_is_rejected_as_nonempty() -> None:
    with pytest.raises(ValueError):
        VerifyDecision(
            "Verify evidence.",
            ("mock-evidence",),
            ("",),
            "Empty checks are never valid.",
        )


@pytest.mark.parametrize("bad_check", ["exploit_reproduces", "artifact sha matches"])
def test_decision_from_dict_rejects_schema_out_of_bounds_check(bad_check: str) -> None:
    value = {
        "schema_version": "1.0",
        "action": "verify",
        "objective": "Verify evidence.",
        "evidence_refs": ["mock-evidence"],
        "verification_checks": [bad_check],
        "rationale": "The supervisor must not invent check names.",
    }
    with pytest.raises(ValueError, match="closed vocabulary"):
        decision_from_dict(value)


def test_supervisor_context_exposes_the_closed_vocabulary() -> None:
    supervisor = HunterSupervisor(
        model=MockDecisionModel(),  # type: ignore[arg-type]
        catalog=_catalog(),
    )
    context = supervisor.build_context(
        task=_task(),
        state=HunterWorldState.from_task(_task()),
        budget=_budget(),
    )
    vocabulary = context["verification_checks_vocabulary"]
    assert set(vocabulary) == {check.value for check in VerificationCheck}
    assert all(vocabulary[name] for name in vocabulary)


def _catalog():
    from hunter_brain.capabilities import default_catalog

    return default_catalog()


def _budget():
    from hunter_brain.validator import BudgetSnapshot

    return BudgetSnapshot(
        decisions_remaining=10,
        capability_calls_remaining=8,
        total_budget_remaining=10.0,
    )


class MockDecisionModel:
    async def decide(self, **kwargs):
        from hunter_brain.supervisor import ModelDecisionResult

        return ModelDecisionResult(
            {
                "schema_version": "1.0",
                "action": "blocked",
                "reason": "unused",
                "blocking_question_ids": ["question-user-goal"],
                "attempted_capability_ids": [],
                "retryable": False,
                "rationale": "unused",
            },
            {},
        )
