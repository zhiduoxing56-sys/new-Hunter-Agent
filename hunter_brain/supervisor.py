"""One-step Hunter global supervisor with a compact, structured model boundary."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Protocol

import httpx
from pentestgpt_agent.protocol import TaskSpec

from .capabilities import CapabilityCatalog
from .decisions import SupervisorDecision, decision_from_dict
from .state import HunterWorldState
from .validator import (
    BudgetSnapshot,
    DecisionValidation,
    DeterministicDecisionValidator,
)


SYSTEM_INSTRUCTIONS = """You are the Hunter global security-task supervisor.
Choose exactly one highest-value next action. Output one JSON object matching the
decision contract and no prose. You may only invoke a registered coarse-grained
professional capability; never choose its internal tools or emit commands.
Prioritize the highest-priority unresolved question. Cite only identifiers that
exist in the supplied compact context. Do not repeat a capability/input/question
combination after it made no progress. Professional backends decide their own
internal execution. Choose complete only when evidence satisfies every success
condition and no critical question remains. Otherwise invoke one capability,
request verification, or report a genuine block."""


class SupervisorConfigurationError(ValueError):
    pass


class SupervisorModelError(RuntimeError):
    pass


class SupervisorOutputError(ValueError):
    pass


@dataclass(frozen=True)
class ModelDecisionResult:
    value: dict[str, Any]
    usage: dict[str, Any]
    request_id: str | None = None


class DecisionModel(Protocol):
    async def decide(
        self,
        *,
        system_instructions: str,
        context: dict[str, Any],
    ) -> ModelDecisionResult: ...


@dataclass(frozen=True)
class DeepSeekSupervisorConfig:
    api_key: str
    model: str = "deepseek-v4-flash"
    base_url: str = "https://api.deepseek.com"
    timeout_seconds: float = 90.0

    def __post_init__(self) -> None:
        if not self.api_key.strip():
            raise SupervisorConfigurationError("DeepSeek API key must be nonempty")
        if not self.model.strip():
            raise SupervisorConfigurationError("DeepSeek model must be nonempty")
        if not self.base_url.startswith(("https://", "http://")):
            raise SupervisorConfigurationError("DeepSeek base URL must use HTTP or HTTPS")
        if not 1 <= self.timeout_seconds <= 300:
            raise SupervisorConfigurationError("DeepSeek timeout must be 1-300 seconds")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> DeepSeekSupervisorConfig:
        values = os.environ if env is None else env
        api_key = values.get("HUNTER_MODEL_API_KEY") or values.get("DEEPSEEK_API_KEY")
        if api_key is None:
            raise SupervisorConfigurationError(
                "DeepSeek API key is required via HUNTER_MODEL_API_KEY or DEEPSEEK_API_KEY"
            )
        timeout_raw = values.get("HUNTER_MODEL_TIMEOUT_S", "90")
        try:
            timeout = float(timeout_raw)
        except ValueError as exc:
            raise SupervisorConfigurationError("HUNTER_MODEL_TIMEOUT_S must be numeric") from exc
        return cls(
            api_key=api_key,
            model=values.get("HUNTER_MODEL_NAME", "deepseek-v4-flash"),
            base_url=values.get("HUNTER_MODEL_BASE_URL", "https://api.deepseek.com").rstrip("/"),
            timeout_seconds=timeout,
        )

    def public_description(self) -> dict[str, Any]:
        return {
            "provider": "deepseek_openai_compatible",
            "model": self.model,
            "base_url": self.base_url,
            "timeout_seconds": self.timeout_seconds,
        }


class DeepSeekDecisionModel:
    """Minimal no-tools DeepSeek client dedicated to structured decisions."""

    def __init__(
        self,
        config: DeepSeekSupervisorConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.transport = transport

    async def decide(
        self,
        *,
        system_instructions: str,
        context: dict[str, Any],
    ) -> ModelDecisionResult:
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_instructions},
                {
                    "role": "user",
                    "content": json.dumps(context, ensure_ascii=False, sort_keys=True),
                },
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
        }
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(
                transport=self.transport,
                timeout=self.config.timeout_seconds,
            ) as client:
                response = await client.post(
                    f"{self.config.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise SupervisorModelError("DeepSeek supervisor request timed out") from exc
        except httpx.RequestError as exc:
            raise SupervisorModelError("DeepSeek supervisor connection failed") from exc
        if response.status_code in {401, 403}:
            raise SupervisorModelError("DeepSeek supervisor authentication failed")
        if response.status_code == 429:
            raise SupervisorModelError("DeepSeek supervisor was rate limited")
        if response.status_code >= 400:
            raise SupervisorModelError(
                f"DeepSeek supervisor failed with HTTP {response.status_code}"
            )
        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            value = json.loads(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise SupervisorOutputError(
                "DeepSeek supervisor response did not contain a JSON decision"
            ) from exc
        if not isinstance(value, dict):
            raise SupervisorOutputError("DeepSeek supervisor decision must be a JSON object")
        usage = body.get("usage", {})
        if not isinstance(usage, dict):
            usage = {}
        return ModelDecisionResult(
            value=value,
            usage=usage,
            request_id=response.headers.get("x-request-id"),
        )


@dataclass(frozen=True)
class SupervisorContextLimits:
    max_facts: int = 30
    max_questions: int = 20
    max_hypotheses: int = 12
    max_artifacts: int = 30
    max_history: int = 20

    def __post_init__(self) -> None:
        if any(value < 1 for value in asdict(self).values()):
            raise ValueError("all supervisor context limits must be positive")


@dataclass(frozen=True)
class SupervisionOutcome:
    decision: SupervisorDecision
    validation: DecisionValidation
    model_usage: dict[str, Any]
    request_id: str | None = None


class HunterSupervisor:
    def __init__(
        self,
        *,
        model: DecisionModel,
        catalog: CapabilityCatalog,
        validator: DeterministicDecisionValidator | None = None,
        context_limits: SupervisorContextLimits | None = None,
    ) -> None:
        self.model = model
        self.catalog = catalog
        self.validator = validator or DeterministicDecisionValidator()
        self.context_limits = context_limits or SupervisorContextLimits()

    async def decide(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> SupervisionOutcome:
        context = self.build_context(task=task, state=state, budget=budget)
        model_result = await self.model.decide(
            system_instructions=SYSTEM_INSTRUCTIONS,
            context=context,
        )
        try:
            decision = decision_from_dict(model_result.value)
        except ValueError as exc:
            raise SupervisorOutputError(f"invalid structured supervisor decision: {exc}") from exc
        validation = self.validator.validate(
            decision,
            task=task,
            state=state,
            catalog=self.catalog,
            budget=budget,
        )
        return SupervisionOutcome(
            decision=decision,
            validation=validation,
            model_usage=model_result.usage,
            request_id=model_result.request_id,
        )

    def build_context(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> dict[str, Any]:
        task.validate()
        state.validate()
        if task.task_id != state.task_id:
            raise ValueError("TaskSpec and world state belong to different tasks")
        limits = self.context_limits
        questions = sorted(
            state.unresolved_questions.values(),
            key=lambda item: (-item.priority, item.question_id),
        )[: limits.max_questions]
        history = state.dispatch_history[-limits.max_history :]
        return {
            "decision_schema_version": "1.0",
            "decision_contract": self._decision_contract(),
            "user_goal": state.user_goal,
            "success_conditions": list(state.success_conditions),
            "world_state_summary": {
                "counts": {
                    "facts": len(state.facts),
                    "unresolved_questions": len(state.unresolved_questions),
                    "hypotheses": len(state.hypotheses),
                    "evidence": len(state.evidence),
                    "artifacts": len(state.artifacts),
                    "dispatches": len(state.dispatch_history),
                },
                "facts": [
                    {
                        "fact_id": item.fact_id,
                        "statement": item.statement,
                        "evidence_refs": list(item.evidence_refs),
                    }
                    for item in list(state.facts.values())[-limits.max_facts :]
                ],
                "hypotheses": [
                    {
                        "hypothesis_id": item.hypothesis_id,
                        "statement": item.statement,
                        "evidence_refs": list(item.evidence_refs),
                        "confidence": item.confidence,
                    }
                    for item in list(state.hypotheses.values())[-limits.max_hypotheses :]
                ],
            },
            "unresolved_questions": [
                {
                    "question_id": item.question_id,
                    "question": item.question,
                    "priority": item.priority,
                    "required_output_types": list(item.required_output_types),
                }
                for item in questions
            ],
            "available_inputs": self._available_inputs(task, state, limits.max_artifacts),
            "capabilities": self.catalog.to_dict(),
            "dispatch_history": [asdict(item) for item in history],
            "remaining_budget": {
                "decisions": budget.decisions_remaining,
                "capability_calls": budget.capability_calls_remaining,
                "model": budget.model_budget_remaining,
                "tool_calls": budget.tool_calls_remaining,
                "total": budget.total_budget_remaining,
            },
        }

    @staticmethod
    def _decision_contract() -> dict[str, list[str]]:
        return {
            "invoke_capability": [
                "schema_version",
                "action",
                "capability_id",
                "input_refs",
                "question_id",
                "objective",
                "basis_input_refs",
                "basis_fact_refs",
                "basis_evidence_refs",
                "expected_output_types",
                "allocated_budget",
                "rationale",
            ],
            "verify": [
                "schema_version",
                "action",
                "objective",
                "evidence_refs",
                "verification_checks",
                "rationale",
            ],
            "complete": [
                "schema_version",
                "action",
                "summary",
                "satisfied_conditions",
                "rationale",
            ],
            "blocked": [
                "schema_version",
                "action",
                "reason",
                "blocking_question_ids",
                "attempted_capability_ids",
                "retryable",
                "rationale",
            ],
        }

    @staticmethod
    def _available_inputs(
        task: TaskSpec,
        state: HunterWorldState,
        max_artifacts: int,
    ) -> dict[str, Any]:
        layer_one: list[dict[str, Any]] = []
        if task.input_object is not None:
            normalized = task.metadata.get("file_type", {})
            normalized_type = (
                normalized.get("normalized_type")
                if isinstance(normalized, dict)
                else None
            )
            layer_one.append(
                {
                    "input_id": task.input_object.input_id,
                    "type": normalized_type or task.input_object.kind,
                }
            )
        if task.target_object is not None:
            layer_one.append(
                {
                    "input_id": task.target_object.target_id,
                    "type": task.target_object.kind,
                }
            )
        return {
            "layer_one": layer_one,
            "artifacts": [
                {
                    "artifact_id": item.artifact_id,
                    "type": item.artifact_type,
                    "sha256": item.sha256,
                    "producer_agent": item.producer_agent,
                    "source_task_id": item.source_task_id,
                }
                for item in list(state.artifacts.values())[-max_artifacts:]
            ],
            "evidence_ids": list(state.evidence)[-max_artifacts:],
        }
