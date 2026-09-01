"""One-step Hunter global supervisor with a compact, structured model boundary."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Protocol

import httpx
from pentestgpt_agent.protocol import TaskSpec

from .capabilities import CapabilityCatalog
from .contract_ingress import (
    DecisionIngressPolicy,
    DecisionNormalizationError,
    decision_fingerprint,
    normalize_decision_json,
)
from .decisions import SupervisorDecision, VerificationCheck, decision_from_dict
from .state import HunterWorldState
from .validator import (
    BudgetSnapshot,
    DecisionValidation,
    DeterministicDecisionValidator,
    resolve_input_type,
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
request verification, or report a genuine block.
Never invent question identifiers: cite only question_ids present in
unresolved_questions. When no critical question (priority >= 80) remains and
grounded evidence satisfies every success condition, choose complete even if
non-critical cross-domain follow-up questions remain unresolved; pursuing them
is optional, not required for completion.
For a verify action, verification_checks must contain only names from the
supplied verification_checks_vocabulary; never invent a check name.
Structured formats: complete.satisfied_conditions must be a JSON object mapping
each success condition to an array of evidence_ids that exist in the context
(e.g. {"condition": ["evidence_id"]}); verify.evidence_refs is an array of
evidence_ids; invoke_capability.allocated_budget is a number or a cost tier.
basis_input_refs must contain only Layer-1 input/target ids; to ground a call on
an artifact or evidence, use input_refs plus basis_fact_refs and
basis_evidence_refs instead."""


class SupervisorConfigurationError(ValueError):
    pass


class SupervisorModelError(RuntimeError):
    pass


class SupervisorOutputError(ValueError):
    pass


class SupervisorDecisionRejected(SupervisorOutputError):
    """Bounded decision-ingress retry exhausted or repeated an identical
    invalid/no-progress proposal. Carries the exact per-attempt trace so the
    caller can audit raw outputs, normalization, errors, and retry indices.
    """

    def __init__(
        self,
        *,
        code: str,
        message: str,
        traces: tuple["DecisionAttemptTrace", ...],
    ) -> None:
        super().__init__(message)
        self.code = code
        self.rejection_message = message
        self.traces = traces


@dataclass(frozen=True)
class DecisionAttemptTrace:
    """One auditable attempt of the decision ingress pipeline."""

    attempt_index: int
    raw_output: str
    normalized: dict[str, Any] | None
    parse_error: str | None
    validation_issues: tuple[dict[str, Any], ...]
    fingerprint: str
    accepted: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_index": self.attempt_index,
            "raw_output": self.raw_output,
            "normalized": self.normalized,
            "parse_error": self.parse_error,
            "validation_issues": [
                dict(issue) for issue in self.validation_issues
            ],
            "fingerprint": self.fingerprint,
            "accepted": self.accepted,
        }


@dataclass(frozen=True)
class ModelDecisionResult:
    value: dict[str, Any] | None
    usage: dict[str, Any]
    request_id: str | None = None
    raw_content: str = ""


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
        except (KeyError, IndexError, TypeError) as exc:
            raise SupervisorOutputError(
                "DeepSeek supervisor response did not contain a text decision"
            ) from exc
        if not isinstance(content, str):
            raise SupervisorOutputError(
                "DeepSeek supervisor decision content is not text"
            )
        try:
            value = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            value = None
        if not isinstance(value, dict):
            value = None
        usage = body.get("usage", {})
        if not isinstance(usage, dict):
            usage = {}
        return ModelDecisionResult(
            value=value,
            usage=usage,
            request_id=response.headers.get("x-request-id"),
            raw_content=content,
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
    traces: tuple[DecisionAttemptTrace, ...] = ()


class HunterSupervisor:
    def __init__(
        self,
        *,
        model: DecisionModel,
        catalog: CapabilityCatalog,
        validator: DeterministicDecisionValidator | None = None,
        context_limits: SupervisorContextLimits | None = None,
        ingress_policy: DecisionIngressPolicy | None = None,
    ) -> None:
        self.model = model
        self.catalog = catalog
        self.validator = validator or DeterministicDecisionValidator()
        self.context_limits = context_limits or SupervisorContextLimits()
        self.ingress_policy = ingress_policy or DecisionIngressPolicy()

    async def decide(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> SupervisionOutcome:
        base_context = self.build_context(task=task, state=state, budget=budget)
        state_revision = _state_revision(state)
        base_usage: dict[str, Any] = {}
        traces: list[DecisionAttemptTrace] = []
        last_fingerprint: str | None = None
        consecutive_repeats = 0
        for attempt in range(self.ingress_policy.max_attempts):
            previous = traces[-1] if traces else None
            context = self._attempt_context(base_context, attempt, previous, state_revision)
            model_result = await self.model.decide(
                system_instructions=SYSTEM_INSTRUCTIONS,
                context=context,
            )
            _merge_usage(base_usage, model_result.usage)
            raw = model_result.raw_content or ""
            normalized: dict[str, Any] | None = model_result.value
            parse_error: str | None = None
            if normalized is None:
                try:
                    normalized = normalize_decision_json(raw)
                except DecisionNormalizationError as exc:
                    parse_error = str(exc)
            fingerprint = decision_fingerprint(normalized, raw=raw)
            if fingerprint == last_fingerprint:
                consecutive_repeats += 1
            else:
                consecutive_repeats = 1
            last_fingerprint = fingerprint
            if normalized is None:
                traces.append(
                    DecisionAttemptTrace(
                        attempt, raw, None, parse_error, (), fingerprint, False
                    )
                )
                if consecutive_repeats >= self.ingress_policy.max_repeated_invalid:
                    raise SupervisorDecisionRejected(
                        code="repeated_invalid_decision",
                        message=(
                            "The supervisor repeated the same invalid output "
                            f"{consecutive_repeats} times: {parse_error}"
                        ),
                        traces=tuple(traces),
                    )
                continue
            try:
                decision = decision_from_dict(normalized)
            except ValueError as exc:
                traces.append(
                    DecisionAttemptTrace(
                        attempt,
                        raw,
                        normalized,
                        f"invalid structured supervisor decision: {exc}",
                        (),
                        fingerprint,
                        False,
                    )
                )
                if consecutive_repeats >= self.ingress_policy.max_repeated_invalid:
                    raise SupervisorDecisionRejected(
                        code="repeated_invalid_decision",
                        message=(
                            "The supervisor repeated an identical invalid "
                            f"decision {consecutive_repeats} times: {exc}"
                        ),
                        traces=tuple(traces),
                    )
                continue
            validation = self.validator.validate(
                decision,
                task=task,
                state=state,
                catalog=self.catalog,
                budget=budget,
            )
            issues = tuple(
                {
                    "code": issue.code.value,
                    "message": issue.message,
                    "reference": issue.reference,
                }
                for issue in validation.issues
            )
            traces.append(
                DecisionAttemptTrace(
                    attempt, raw, normalized, None, issues, fingerprint, validation.accepted
                )
            )
            if validation.accepted:
                return SupervisionOutcome(
                    decision,
                    validation,
                    base_usage,
                    model_result.request_id,
                    tuple(traces),
                )
            if consecutive_repeats >= self.ingress_policy.max_repeated_invalid:
                codes = {issue["code"] for issue in issues}
                raise SupervisorDecisionRejected(
                    code="repeated_no_progress_decision",
                    message=(
                        "The supervisor repeated an identical rejected decision "
                        f"{consecutive_repeats} times (codes={sorted(codes)})."
                    ),
                    traces=tuple(traces),
                )
        last_trace = traces[-1] if traces else None
        raise SupervisorDecisionRejected(
            code="invalid_decision_exhausted",
            message=(
                "Supervisor decision ingress exhausted "
                f"{self.ingress_policy.max_attempts} attempts without an accepted decision."
            ),
            traces=tuple(traces),
        ) if last_trace is not None else SupervisorDecisionRejected(
            code="invalid_decision_exhausted",
            message="Supervisor decision ingress produced no decision attempt.",
            traces=(),
        )

    def _attempt_context(
        self,
        base_context: dict[str, Any],
        attempt: int,
        previous: DecisionAttemptTrace | None,
        state_revision: str,
    ) -> dict[str, Any]:
        if attempt == 0 or previous is None:
            return base_context
        errors: list[dict[str, Any]] = []
        if previous.parse_error is not None:
            errors.append({"stage": "parse", "error": previous.parse_error})
        errors.extend(dict(issue) for issue in previous.validation_issues)
        context = dict(base_context)
        context["decision_retry"] = {
            "retry_index": attempt,
            "state_revision": state_revision,
            "instruction": (
                "Your previous decision was rejected. Output exactly one "
                "corrected decision JSON object. Do not repeat the rejected "
                "decision. Use only identifiers and vocabulary present in this "
                "context. If no valid action is possible, output a genuine "
                "blocked decision."
            ),
            "previous_decision_errors": errors,
        }
        return context

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
            "verification_checks_vocabulary": VerificationCheck.meanings(),
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
            layer_one.append(
                {
                    "input_id": task.input_object.input_id,
                    "type": resolve_input_type(task) or task.input_object.kind,
                }
            )
        if task.target_object is not None:
            layer_one.append(
                {
                    "input_id": task.target_object.target_id,
                    "type": resolve_input_type(task) or task.target_object.kind,
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


def _state_revision(state: HunterWorldState) -> str:
    """Stable fingerprint of the canonical world state for retry prompts.

    A retry never mutates canonical state, so the revision is constant across
    attempts of one decision; the model can rely on it.
    """
    payload = json.dumps(state.to_dict(), ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _merge_usage(accumulator: dict[str, Any], usage: dict[str, Any]) -> None:
    """Aggregate token/cost usage across bounded ingress retry attempts."""
    if not isinstance(usage, dict):
        return
    for key, value in usage.items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            accumulator[key] = accumulator.get(key, 0) + value
        elif key not in accumulator:
            accumulator[key] = value
