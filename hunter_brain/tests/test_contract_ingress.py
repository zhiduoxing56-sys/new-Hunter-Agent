"""Supervisor decision contract-ingress tests (Phase 3D-A).

The model is only a proposal source. The ingress pipeline must:

- normalize only deterministic wrapping (fenced JSON / surrounding text);
- run schema + semantic validation before anything reaches canonical state;
- retry with bounded attempts, feeding exact machine-readable errors back;
- terminate retry early on repeated identical invalid / no-progress proposals;
- never mutate canonical state on any rejected attempt;
- never let an invalid decision become a COMPLETE.

The frozen Phase 3B invalid-decision corpus is replayed to prove the old
rejected decisions are now recovered-or-honestly-terminated without polluting
canonical state.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from hunter_brain.contract_ingress import (
    DecisionIngressPolicy,
    DecisionNormalizationError,
    decision_fingerprint,
    normalize_decision_json,
)
from hunter_brain.capabilities import default_catalog
from hunter_brain.orchestrator import HunterOrchestrator, OrchestrationStatus
from hunter_brain.state import (
    DispatchRecord,
    HunterWorldState,
    UnresolvedQuestion,
)
from hunter_brain.supervisor import (
    DecisionModel,
    HunterSupervisor,
    ModelDecisionResult,
    SupervisorDecisionRejected,
)
from hunter_brain.validator import (
    BudgetSnapshot,
    DeterministicDecisionValidator,
    ValidationCode,
    ValidatorPolicy,
)
from pentestgpt_agent.protocol import (
    AuthorizationScope,
    InputObject,
    TargetObject,
    TaskSpec,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _task() -> TaskSpec:
    target = "https://allowed.example/"
    return TaskSpec(
        task_id="ingress-task",
        domain="pentest",
        target=target,
        goal="Identify exposed services.",
        success_conditions=("Service findings are evidence-backed.",),
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
            priority=100,
            required_output_types=("service_information",),
        )
    )
    return state


def _valid_invoke() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "action": "invoke_capability",
        "capability_id": "pentest",
        "input_refs": ["input-network"],
        "question_id": "question-surface",
        "objective": "Identify exposed services.",
        "basis_input_refs": ["input-network"],
        "basis_fact_refs": [],
        "basis_evidence_refs": [],
        "expected_output_types": ["service_information"],
        "allocated_budget": 1.0,
        "rationale": "High-priority question with a compatible authorized input.",
    }


def _valid_blocked() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "action": "blocked",
        "reason": "No legal capability remains for this question.",
        "blocking_question_ids": ["question-surface"],
        "attempted_capability_ids": ["pentest"],
        "retryable": False,
        "rationale": "The only compatible capability made no progress.",
    }


@dataclass
class ScriptedModel(DecisionModel):
    values: list[dict[str, Any] | None]
    raw_texts: list[str] = field(default_factory=list)
    contexts: list[dict[str, Any]] = field(default_factory=list)
    calls: int = field(default=0)

    def __post_init__(self) -> None:
        if not self.raw_texts:
            self.raw_texts = [
                json.dumps(value) if value is not None else "not-json"
                for value in self.values
            ]

    async def decide(
        self,
        *,
        system_instructions: str,
        context: dict[str, Any],
    ) -> ModelDecisionResult:
        self.contexts.append(context)
        index = min(self.calls, len(self.values) - 1)
        self.calls += 1
        return ModelDecisionResult(
            value=self.values[index],
            usage={"prompt_tokens": 10},
            raw_content=self.raw_texts[index],
        )


def _supervisor(model: ScriptedModel, policy: DecisionIngressPolicy | None = None) -> HunterSupervisor:
    return HunterSupervisor(
        model=model,
        catalog=default_catalog(),
        ingress_policy=policy,
    )


def _budget() -> BudgetSnapshot:
    return BudgetSnapshot(
        decisions_remaining=5,
        capability_calls_remaining=3,
        total_budget_remaining=10.0,
    )


# ---------------------------------------------------------------------------
# normalization
# ---------------------------------------------------------------------------


def test_normalize_plain_json() -> None:
    assert normalize_decision_json(json.dumps(_valid_invoke())) == _valid_invoke()


def test_normalize_fenced_json() -> None:
    raw = "```json\n" + json.dumps(_valid_invoke()) + "\n```"
    assert normalize_decision_json(raw) == _valid_invoke()


def test_normalize_leading_and_trailing_prose() -> None:
    raw = "Here is the decision I chose:\n" + json.dumps(_valid_invoke()) + "\nThat is my answer."
    assert normalize_decision_json(raw) == _valid_invoke()


def test_normalize_ignores_trailing_text_after_object() -> None:
    raw = json.dumps(_valid_invoke()) + "\n(ignore this note)"
    assert normalize_decision_json(raw) == _valid_invoke()


def test_normalize_rejects_non_json() -> None:
    with pytest.raises(DecisionNormalizationError):
        normalize_decision_json("the supervisor says: scan now, no json")


def test_normalize_rejects_json_array() -> None:
    with pytest.raises(DecisionNormalizationError):
        normalize_decision_json("[1, 2, 3]")


def test_decision_fingerprint_is_canonical_across_field_order() -> None:
    first = _valid_invoke()
    second = {key: first[key] for key in reversed(list(first))}
    assert decision_fingerprint(first) == decision_fingerprint(second)


def test_decision_fingerprint_raw_for_unparseable() -> None:
    assert decision_fingerprint(None, raw="garbage") == decision_fingerprint(None, raw="garbage")
    assert decision_fingerprint(None, raw="garbage") != decision_fingerprint(None, raw="other")


# ---------------------------------------------------------------------------
# ingress recovery / rejection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_json_is_retried_and_recovered() -> None:
    model = ScriptedModel([None, _valid_invoke()])
    supervisor = _supervisor(model)

    outcome = await supervisor.decide(task=_task(), state=_state(), budget=_budget())

    assert outcome.validation.accepted is True
    assert outcome.decision.action.value == "invoke_capability"
    assert len(outcome.traces) == 2
    assert outcome.traces[0].accepted is False
    assert outcome.traces[0].parse_error is not None
    assert outcome.traces[1].accepted is True


@pytest.mark.asyncio
async def test_missing_required_field_is_rejected_after_repeat() -> None:
    invalid = {"action": "invoke_capability", "capability_id": "pentest"}
    model = ScriptedModel([invalid, invalid])
    supervisor = _supervisor(model)

    with pytest.raises(SupervisorDecisionRejected) as exc_info:
        await supervisor.decide(task=_task(), state=_state(), budget=_budget())

    assert exc_info.value.code == "repeated_invalid_decision"
    assert all(trace.parse_error for trace in exc_info.value.traces)


@pytest.mark.asyncio
async def test_repeated_identical_invalid_output_terminates_early() -> None:
    model = ScriptedModel([None, None])
    supervisor = _supervisor(model)

    with pytest.raises(SupervisorDecisionRejected, match="repeated"):
        await supervisor.decide(task=_task(), state=_state(), budget=_budget())

    assert model.calls == 2  # early stop, not max_attempts=3


@pytest.mark.asyncio
async def test_semantically_equivalent_no_progress_decision_terminates_early() -> None:
    invalid = dict(_valid_invoke())
    invalid["expected_output_types"] = ["does_not_exist_output"]
    model = ScriptedModel([invalid, invalid])
    supervisor = _supervisor(model)

    with pytest.raises(SupervisorDecisionRejected) as exc_info:
        await supervisor.decide(task=_task(), state=_state(), budget=_budget())

    assert exc_info.value.code == "repeated_no_progress_decision"
    assert model.calls == 2


@pytest.mark.asyncio
async def test_retry_prompt_carries_errors_and_stable_state_revision() -> None:
    invalid = dict(_valid_invoke())
    invalid["expected_output_types"] = ["does_not_exist_output"]
    model = ScriptedModel([invalid, _valid_invoke()])
    supervisor = _supervisor(model)

    await supervisor.decide(task=_task(), state=_state(), budget=_budget())

    assert len(model.contexts) == 2
    retry = model.contexts[1]["decision_retry"]
    assert retry["retry_index"] == 1
    assert retry["state_revision"]
    assert any(
        issue.get("code") == "unknown_expected_output"
        for issue in retry["previous_decision_errors"]
    )
    assert "state_revision" not in model.contexts[0]


@pytest.mark.asyncio
async def test_stale_state_revision_is_constant_across_retries() -> None:
    invalid = dict(_valid_invoke())
    invalid["expected_output_types"] = ["does_not_exist_output"]
    different = dict(invalid)
    different["rationale"] = "a different rationale so the fingerprint differs"
    model = ScriptedModel([invalid, different, _valid_invoke()])
    supervisor = _supervisor(model)

    await supervisor.decide(task=_task(), state=_state(), budget=_budget())

    rev_1 = model.contexts[1]["decision_retry"]["state_revision"]
    rev_2 = model.contexts[2]["decision_retry"]["state_revision"]
    assert rev_1 == rev_2


@pytest.mark.asyncio
async def test_retry_exhaustion_is_honest_and_never_completes() -> None:
    invalid_a = dict(_valid_invoke())
    invalid_a["expected_output_types"] = ["does_not_exist_a"]
    invalid_b = dict(_valid_invoke())
    invalid_b["expected_output_types"] = ["does_not_exist_b"]
    invalid_c = dict(_valid_invoke())
    invalid_c["expected_output_types"] = ["does_not_exist_c"]
    model = ScriptedModel([invalid_a, invalid_b, invalid_c])
    supervisor = _supervisor(model)

    with pytest.raises(SupervisorDecisionRejected) as exc_info:
        await supervisor.decide(task=_task(), state=_state(), budget=_budget())

    assert exc_info.value.code == "invalid_decision_exhausted"
    assert len(exc_info.value.traces) == 3
    assert model.calls == 3


@pytest.mark.asyncio
async def test_illegal_complete_missing_completion_basis_is_rejected() -> None:
    illegal_complete = {
        "schema_version": "1.0",
        "action": "complete",
        "summary": "Goal is done.",
        "satisfied_conditions": {
            "A condition that is not in the TaskSpec": ["evidence-does-not-exist"],
        },
        "rationale": "Completion without a legal basis.",
    }
    model = ScriptedModel([illegal_complete, illegal_complete])
    supervisor = _supervisor(model)

    with pytest.raises(SupervisorDecisionRejected) as exc_info:
        await supervisor.decide(task=_task(), state=_state(), budget=_budget())

    assert exc_info.value.code == "repeated_no_progress_decision"
    codes = {
        issue.get("code")
        for trace in exc_info.value.traces
        for issue in trace.validation_issues
    }
    assert "success_condition_unknown" in codes
    assert "unknown_evidence" in codes


@pytest.mark.asyncio
async def test_rejected_attempts_never_mutate_canonical_state() -> None:
    state = _state()
    before = json.dumps(state.to_dict(), sort_keys=True)
    invalid = dict(_valid_invoke())
    invalid["expected_output_types"] = ["does_not_exist_output"]
    model = ScriptedModel([invalid, invalid])
    supervisor = _supervisor(model)

    with pytest.raises(SupervisorDecisionRejected):
        await supervisor.decide(task=_task(), state=state, budget=_budget())

    after = json.dumps(state.to_dict(), sort_keys=True)
    assert before == after


# ---------------------------------------------------------------------------
# backend failure awareness
# ---------------------------------------------------------------------------


def _failed_state(*, count: int) -> HunterWorldState:
    state = _state()
    for index in range(count):
        state.record_dispatch(
            DispatchRecord(
                dispatch_id=f"dispatch-{index}",
                capability_id="pentest",
                objective="Identify exposed services.",
                input_refs=("input-network",),
                status="timeout",
                new_evidence=False,
                new_facts=False,
                answered_question_ids=(),
                budget_used=1.0,
                question_id="question-surface",
            )
        )
    return state


def test_repeated_backend_timeout_without_new_evidence_is_blocked() -> None:
    state = _failed_state(count=2)
    validator = DeterministicDecisionValidator(
        policy=ValidatorPolicy(max_repeated_backend_failure=2)
    )
    from hunter_brain.decisions import decision_from_dict

    validation = validator.validate(
        decision_from_dict(_valid_invoke()),
        task=_task(),
        state=state,
        catalog=default_catalog(),
        budget=_budget(),
    )

    assert validation.accepted is False
    assert ValidationCode.BACKEND_REPEATED_FAILURE in {
        item.code for item in validation.issues
    }


def test_single_backend_timeout_does_not_yet_block() -> None:
    state = _failed_state(count=1)
    validator = DeterministicDecisionValidator(
        policy=ValidatorPolicy(max_repeated_backend_failure=2)
    )
    from hunter_brain.decisions import decision_from_dict

    validation = validator.validate(
        decision_from_dict(_valid_invoke()),
        task=_task(),
        state=state,
        catalog=default_catalog(),
        budget=_budget(),
    )

    assert ValidationCode.BACKEND_REPEATED_FAILURE not in {
        item.code for item in validation.issues
    }


# ---------------------------------------------------------------------------
# orchestrator trace completeness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orchestrator_writes_decision_attempt_trace(tmp_path: Path) -> None:
    class TracingSupervisor:
        def __init__(self, model: ScriptedModel) -> None:
            self.model = model
            self.supervisor = _supervisor(model)

        async def decide(self, *, task, state, budget):
            return await self.supervisor.decide(task=task, state=state, budget=budget)

    invalid = dict(_valid_invoke())
    invalid["expected_output_types"] = ["does_not_exist_output"]
    model = ScriptedModel([invalid, _valid_blocked()])
    supervisor = HunterSupervisor(
        model=model,
        catalog=default_catalog(),
    )
    from hunter_brain.orchestrator import CapabilityAdapterRegistry

    orchestrator = HunterOrchestrator(
        supervisor=supervisor,
        adapters=CapabilityAdapterRegistry({"pentest": _NoOpAdapter()}),
        runs_root=tmp_path / "runs",
    )
    result = await orchestrator.run(_task(), initial_state=_state())

    assert result.status is OrchestrationStatus.BLOCKED
    audit = (tmp_path / "runs" / _task().task_id / "hunter_brain_audit.jsonl").read_text(
        encoding="utf-8"
    )
    attempts = [line for line in audit.splitlines() if '"decision_attempt"' in line]
    assert len(attempts) == 2
    first = json.loads(attempts[0])
    assert first["payload"]["accepted"] is False
    assert first["payload"]["validation_issues"]
    second = json.loads(attempts[1])
    assert second["payload"]["accepted"] is True
    assert first["payload"]["decision_index"] == second["payload"]["decision_index"]


class _NoOpAdapter:
    async def execute(self, task_spec: TaskSpec):  # pragma: no cover - never reached
        raise AssertionError("blocked decision must not invoke an adapter")


# ---------------------------------------------------------------------------
# frozen Phase 3B invalid-decision corpus replay
# ---------------------------------------------------------------------------


def _frozen_corpus() -> list[dict[str, Any]]:
    value = json.loads((FIXTURES / "phase3b_invalid_decisions.json").read_text(encoding="utf-8"))
    return value["cases"]


@pytest.mark.parametrize(
    "index",
    range(3),
)
@pytest.mark.asyncio
async def test_frozen_phase3b_invalid_decision_recovers_or_terminates_honestly(
    index: int,
) -> None:
    frozen = _frozen_corpus()[index]
    decision_value = frozen["decision"]

    # Replay: the frozen rejected decision, then a legal alternative. Either the
    # ingress recovers to the alternative, or it honestly terminates. Canonical
    # state must never be mutated by any rejected attempt.
    state = _state()
    before = json.dumps(state.to_dict(), sort_keys=True)
    model = ScriptedModel([decision_value, _valid_blocked()])
    supervisor = HunterSupervisor(model=model, catalog=default_catalog())

    try:
        outcome = await supervisor.decide(task=_task(), state=state, budget=_budget())
    except SupervisorDecisionRejected as exc:
        assert exc.code in {"repeated_no_progress_decision", "repeated_invalid_decision"}
        assert all(not trace.accepted for trace in exc.traces)
    else:
        assert outcome.validation.accepted is True
        assert outcome.decision.action.value in {"blocked", "invoke_capability"}
    assert json.dumps(state.to_dict(), sort_keys=True) == before
