from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from hunter_brain.capabilities import default_catalog
from hunter_brain.state import DispatchRecord, HunterWorldState, UnresolvedQuestion
from hunter_brain.supervisor import (
    DecisionModel,
    DeepSeekDecisionModel,
    DeepSeekSupervisorConfig,
    HunterSupervisor,
    ModelDecisionResult,
    SupervisorConfigurationError,
    SupervisorContextLimits,
    SupervisorDecisionRejected,
    SupervisorModelError,
)
from hunter_brain.validator import BudgetSnapshot
from pentestgpt_agent.protocol import (
    AuthorizationScope,
    InputObject,
    TargetObject,
    TaskSpec,
)


def _task() -> TaskSpec:
    target = "https://allowed.example/"
    return TaskSpec(
        task_id="supervisor-task",
        domain="pentest",
        target=target,
        goal="Identify the authorized target's exposed services.",
        success_conditions=("Service findings are evidence-backed.",),
        input_object=InputObject("input-network", "network_target", target),
        target_object=TargetObject("target-network", "url", target),
        authorization=AuthorizationScope(allowed_targets=(target,)),
    )


def _state() -> HunterWorldState:
    state = HunterWorldState.from_task(_task())
    state.add_question(
        UnresolvedQuestion(
            "question-low", "What secondary detail is useful?", priority=20
        )
    )
    state.add_question(
        UnresolvedQuestion(
            "question-surface",
            "What services are exposed?",
            priority=100,
            required_output_types=("service_information",),
        )
    )
    return state


def _invoke_wire(*, input_ref: str = "input-network") -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "action": "invoke_capability",
        "capability_id": "pentest",
        "input_refs": [input_ref],
        "question_id": "question-surface",
        "objective": "Identify exposed services.",
        "basis_input_refs": ["input-network"],
        "basis_fact_refs": [],
        "basis_evidence_refs": [],
        "expected_output_types": ["service_information"],
        "allocated_budget": 1.0,
        "rationale": "The highest-priority question has an authorized compatible input.",
    }


@dataclass
class RecordingModel(DecisionModel):
    value: dict[str, Any]
    contexts: list[dict[str, Any]] = field(default_factory=list)
    instructions: list[str] = field(default_factory=list)

    async def decide(
        self,
        *,
        system_instructions: str,
        context: dict[str, Any],
    ) -> ModelDecisionResult:
        self.instructions.append(system_instructions)
        self.contexts.append(context)
        return ModelDecisionResult(self.value, {"prompt_tokens": 123}, "request-test")


@pytest.mark.asyncio
async def test_supervisor_selects_one_structured_step_then_runs_validator() -> None:
    model = RecordingModel(_invoke_wire())
    supervisor = HunterSupervisor(model=model, catalog=default_catalog())

    outcome = await supervisor.decide(
        task=_task(),
        state=_state(),
        budget=BudgetSnapshot(decisions_remaining=5, capability_calls_remaining=3),
    )

    assert outcome.decision.action.value == "invoke_capability"
    assert outcome.validation.accepted is True
    assert outcome.model_usage == {"prompt_tokens": 123}
    assert outcome.request_id == "request-test"
    assert "exactly one" in model.instructions[0]


def test_context_is_priority_sorted_bounded_and_contains_no_raw_backend_output() -> None:
    state = _state()
    for index in range(5):
        state.record_dispatch(
            DispatchRecord(
                f"dispatch-{index}",
                "pentest",
                f"Objective {index}",
                ("input-network",),
                "partial",
                index == 4,
                False,
                (),
                0.5,
            )
        )
    supervisor = HunterSupervisor(
        model=RecordingModel(_invoke_wire()),
        catalog=default_catalog(),
        context_limits=SupervisorContextLimits(max_history=2),
    )

    context = supervisor.build_context(
        task=_task(),
        state=state,
        budget=BudgetSnapshot(
            decisions_remaining=4,
            capability_calls_remaining=2,
            model_budget_remaining=3.0,
            tool_calls_remaining=10,
            total_budget_remaining=5.0,
        ),
    )
    serialized = json.dumps(context)

    assert context["unresolved_questions"][0]["question_id"] == "question-surface"
    assert [item["dispatch_id"] for item in context["dispatch_history"]] == [
        "dispatch-3",
        "dispatch-4",
    ]
    assert context["remaining_budget"]["tool_calls"] == 10
    assert "invoke_capability" in context["decision_contract"]
    assert "raw_output" not in serialized
    assert "result.json" not in serialized


@pytest.mark.asyncio
async def test_invalid_model_contract_is_rejected_before_validation() -> None:
    supervisor = HunterSupervisor(
        model=RecordingModel({"action": "run_command", "command": "scan"}),
        catalog=default_catalog(),
    )

    with pytest.raises(SupervisorDecisionRejected, match="repeated"):
        await supervisor.decide(
            task=_task(),
            state=_state(),
            budget=BudgetSnapshot(decisions_remaining=2),
        )


@pytest.mark.asyncio
async def test_structured_but_forged_model_reference_is_returned_as_rejected() -> None:
    supervisor = HunterSupervisor(
        model=RecordingModel(_invoke_wire(input_ref="forged-input")),
        catalog=default_catalog(),
    )

    with pytest.raises(SupervisorDecisionRejected) as exc_info:
        await supervisor.decide(
            task=_task(),
            state=_state(),
            budget=BudgetSnapshot(decisions_remaining=2, capability_calls_remaining=2),
        )

    assert exc_info.value.code == "repeated_no_progress_decision"
    rejected_traces = [t for t in exc_info.value.traces if not t.accepted]
    assert rejected_traces
    assert any(
        issue.get("code") == "unknown_input"
        for trace in rejected_traces
        for issue in trace.validation_issues
    )


def test_deepseek_config_supports_existing_hunter_environment_without_leaking_key() -> None:
    config = DeepSeekSupervisorConfig.from_env(
        {
            "HUNTER_MODEL_API_KEY": "secret-value",
            "HUNTER_MODEL_NAME": "deepseek-test",
            "HUNTER_MODEL_BASE_URL": "https://provider.test/v1/",
            "HUNTER_MODEL_TIMEOUT_S": "12",
        }
    )

    assert config.base_url == "https://provider.test/v1"
    assert config.model == "deepseek-test"
    assert "secret-value" not in json.dumps(config.public_description())
    with pytest.raises(SupervisorConfigurationError, match="API key"):
        DeepSeekSupervisorConfig.from_env({})


@pytest.mark.asyncio
async def test_deepseek_client_posts_json_only_and_parses_decision() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers["authorization"]
        captured["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"x-request-id": "deepseek-request"},
            json={
                "choices": [{"message": {"content": json.dumps(_invoke_wire())}}],
                "usage": {"prompt_tokens": 25, "completion_tokens": 10},
            },
        )

    model = DeepSeekDecisionModel(
        DeepSeekSupervisorConfig(
            api_key="secret-value",
            model="deepseek-test",
            base_url="https://provider.test/v1",
        ),
        transport=httpx.MockTransport(handler),
    )

    result = await model.decide(
        system_instructions="Choose one decision.",
        context={"user_goal": "test"},
    )

    assert result.value == _invoke_wire()
    assert result.request_id == "deepseek-request"
    assert captured["authorization"] == "Bearer secret-value"
    assert captured["payload"]["response_format"] == {"type": "json_object"}
    assert captured["payload"]["temperature"] == 0


@pytest.mark.asyncio
async def test_deepseek_client_maps_provider_and_output_failures() -> None:
    auth_model = DeepSeekDecisionModel(
        DeepSeekSupervisorConfig(api_key="secret"),
        transport=httpx.MockTransport(lambda request: httpx.Response(401)),
    )
    invalid_model = DeepSeekDecisionModel(
        DeepSeekSupervisorConfig(api_key="secret"),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"choices": [{"message": {"content": "not-json"}}]},
            )
        ),
    )

    with pytest.raises(SupervisorModelError, match="authentication"):
        await auth_model.decide(system_instructions="test", context={})
    invalid_result = await invalid_model.decide(system_instructions="test", context={})
    assert invalid_result.value is None
    assert invalid_result.raw_content == "not-json"
