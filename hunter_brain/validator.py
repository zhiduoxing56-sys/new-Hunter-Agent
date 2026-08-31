"""Deterministic policy gate for every global-supervisor decision."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pentestgpt_agent.protocol import TaskSpec

from .capabilities import Capability, CapabilityCatalog
from .decisions import (
    BlockedDecision,
    CompleteDecision,
    InvokeCapabilityDecision,
    SupervisorDecision,
    VerifyDecision,
)
from .handoffs import HandoffCarrier, HandoffDescriptor
from .state import HunterWorldState


def resolve_input_type(task: TaskSpec) -> str | None:
    """Resolve the semantic Layer-1 input type used for capability compatibility.

    Layer 1 stores its deterministic semantic classification in
    ``metadata.semantic_input_type`` when it exists (see the intake semantic
    bridge). Fall back to the audited normalized content type, then to the raw
    input kind, so hand-built TaskSpecs keep the previous behavior.
    """
    semantic = task.metadata.get("semantic_input_type")
    if isinstance(semantic, str) and semantic.strip():
        return semantic
    file_type = task.metadata.get("file_type")
    if isinstance(file_type, dict) and isinstance(
        file_type.get("normalized_type"), str
    ):
        return file_type["normalized_type"]
    if task.input_object is not None:
        return task.input_object.kind
    if task.target_object is not None:
        return task.target_object.kind
    return None


class ValidationCode(StrEnum):
    TASK_MISMATCH = "task_mismatch"
    UNKNOWN_CAPABILITY = "unknown_capability"
    UNKNOWN_INPUT = "unknown_input"
    INCOMPATIBLE_INPUT = "incompatible_input"
    UNKNOWN_QUESTION = "unknown_question"
    UNKNOWN_FACT = "unknown_fact"
    UNKNOWN_EVIDENCE = "unknown_evidence"
    UNKNOWN_EXPECTED_OUTPUT = "unknown_expected_output"
    SCOPE_VIOLATION = "scope_violation"
    DUPLICATE_CALL = "duplicate_call"
    NO_PROGRESS_LOOP = "no_progress_loop"
    SUCCESS_CONDITION_MISSING = "success_condition_missing"
    SUCCESS_CONDITION_UNKNOWN = "success_condition_unknown"
    CRITICAL_QUESTION_UNRESOLVED = "critical_question_unresolved"
    DECISION_BUDGET_EXHAUSTED = "decision_budget_exhausted"
    CAPABILITY_BUDGET_EXHAUSTED = "capability_budget_exhausted"
    ALLOCATION_EXCEEDS_BUDGET = "allocation_exceeds_budget"


@dataclass(frozen=True)
class ValidationIssue:
    code: ValidationCode
    message: str
    reference: str | None = None


@dataclass(frozen=True)
class DecisionValidation:
    accepted: bool
    issues: tuple[ValidationIssue, ...] = ()

    def __post_init__(self) -> None:
        if self.accepted == bool(self.issues):
            raise ValueError("accepted validation must have no issues and rejection must have issues")


@dataclass(frozen=True)
class BudgetSnapshot:
    decisions_used: int = 0
    capability_calls_used: int = 0
    model_budget_used: float = 0.0
    tool_calls_used: int = 0
    total_budget_used: float = 0.0
    decisions_remaining: int | None = None
    capability_calls_remaining: int | None = None
    model_budget_remaining: float | None = None
    tool_calls_remaining: int | None = None
    total_budget_remaining: float | None = None

    def __post_init__(self) -> None:
        values = (
            self.decisions_used,
            self.capability_calls_used,
            self.model_budget_used,
            self.tool_calls_used,
            self.total_budget_used,
            self.decisions_remaining,
            self.capability_calls_remaining,
            self.model_budget_remaining,
            self.tool_calls_remaining,
            self.total_budget_remaining,
        )
        if any(value is not None and value < 0 for value in values):
            raise ValueError("budget counters must be nonnegative")


@dataclass(frozen=True)
class ValidatorPolicy:
    max_consecutive_no_progress: int = 3
    critical_question_priority: int = 80

    def __post_init__(self) -> None:
        if self.max_consecutive_no_progress < 1:
            raise ValueError("max_consecutive_no_progress must be positive")
        if not 0 <= self.critical_question_priority <= 100:
            raise ValueError("critical_question_priority must be between 0 and 100")


class DeterministicDecisionValidator:
    def __init__(self, policy: ValidatorPolicy | None = None) -> None:
        self.policy = policy or ValidatorPolicy()

    def validate(
        self,
        decision: SupervisorDecision,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        catalog: CapabilityCatalog,
        budget: BudgetSnapshot,
    ) -> DecisionValidation:
        task.validate()
        state.validate()
        issues: list[ValidationIssue] = []
        if task.task_id != state.task_id:
            issues.append(
                ValidationIssue(
                    ValidationCode.TASK_MISMATCH,
                    "TaskSpec and world state belong to different tasks.",
                )
            )
        if isinstance(decision, InvokeCapabilityDecision):
            self._validate_invoke(decision, task, state, catalog, budget, issues)
        elif isinstance(decision, VerifyDecision):
            self._validate_verify(decision, state, budget, issues)
        elif isinstance(decision, CompleteDecision):
            self._validate_complete(decision, task, state, issues)
        elif isinstance(decision, BlockedDecision):
            self._validate_blocked(decision, state, catalog, issues)
        return DecisionValidation(not issues, tuple(issues))

    def _validate_invoke(
        self,
        decision: InvokeCapabilityDecision,
        task: TaskSpec,
        state: HunterWorldState,
        catalog: CapabilityCatalog,
        budget: BudgetSnapshot,
        issues: list[ValidationIssue],
    ) -> None:
        capability: Capability | None
        try:
            capability = catalog.get(decision.capability_id)
        except KeyError:
            capability = None
            issues.append(
                ValidationIssue(
                    ValidationCode.UNKNOWN_CAPABILITY,
                    "The selected capability is not registered.",
                    decision.capability_id,
                )
            )
        if decision.question_id not in state.unresolved_questions:
            issues.append(
                ValidationIssue(
                    ValidationCode.UNKNOWN_QUESTION,
                    "The selected question is not unresolved in world state.",
                    decision.question_id,
                )
            )
        self._validate_basis(decision, task, state, issues)
        for reference in decision.input_refs:
            try:
                input_type, target_value = self._resolve_input(reference, task, state)
            except ValueError as exc:
                issues.append(
                    ValidationIssue(
                        ValidationCode.SCOPE_VIOLATION,
                        str(exc),
                        reference,
                    )
                )
                continue
            if input_type is None:
                issues.append(
                    ValidationIssue(
                        ValidationCode.UNKNOWN_INPUT,
                        "The selected input does not exist in task or world state.",
                        reference,
                    )
                )
                continue
            if capability is not None and not capability.accepts(input_type):
                issues.append(
                    ValidationIssue(
                        ValidationCode.INCOMPATIBLE_INPUT,
                        f"{capability.capability_id} does not accept {input_type}.",
                        reference,
                    )
                )
            if target_value is not None and target_value not in self._allowed_targets(task):
                issues.append(
                    ValidationIssue(
                        ValidationCode.SCOPE_VIOLATION,
                        "The referenced network target is outside the authorized scope.",
                        reference,
                    )
                )
        if capability is not None:
            for output_type in decision.expected_output_types:
                if output_type not in capability.produces:
                    issues.append(
                        ValidationIssue(
                            ValidationCode.UNKNOWN_EXPECTED_OUTPUT,
                            f"{capability.capability_id} does not declare this output type.",
                            output_type,
                        )
                    )
        if self._is_duplicate_without_progress(decision, state):
            issues.append(
                ValidationIssue(
                    ValidationCode.DUPLICATE_CALL,
                    "The same capability, inputs, and question already made no progress.",
                )
            )
        if self._trailing_no_progress(state) >= self.policy.max_consecutive_no_progress:
            issues.append(
                ValidationIssue(
                    ValidationCode.NO_PROGRESS_LOOP,
                    "The current path reached the consecutive no-progress limit.",
                )
            )
        self._validate_nonterminal_budget(decision.allocated_budget, budget, issues)

    @staticmethod
    def _validate_basis(
        decision: InvokeCapabilityDecision,
        task: TaskSpec,
        state: HunterWorldState,
        issues: list[ValidationIssue],
    ) -> None:
        known_task_inputs = {
            item
            for item in (
                task.input_object.input_id if task.input_object else None,
                task.target_object.target_id if task.target_object else None,
            )
            if item is not None
        }
        for reference in decision.basis_input_refs:
            if reference not in known_task_inputs:
                issues.append(
                    ValidationIssue(
                        ValidationCode.UNKNOWN_INPUT,
                        "The cited Layer 1 input does not exist.",
                        reference,
                    )
                )
        for reference in decision.basis_fact_refs:
            if reference not in state.facts:
                issues.append(
                    ValidationIssue(
                        ValidationCode.UNKNOWN_FACT,
                        "The cited fact does not exist.",
                        reference,
                    )
                )
        for reference in decision.basis_evidence_refs:
            if reference not in state.evidence:
                issues.append(
                    ValidationIssue(
                        ValidationCode.UNKNOWN_EVIDENCE,
                        "The cited evidence does not exist.",
                        reference,
                    )
                )

    def _validate_verify(
        self,
        decision: VerifyDecision,
        state: HunterWorldState,
        budget: BudgetSnapshot,
        issues: list[ValidationIssue],
    ) -> None:
        for reference in decision.evidence_refs:
            if reference not in state.evidence:
                issues.append(
                    ValidationIssue(
                        ValidationCode.UNKNOWN_EVIDENCE,
                        "Verification references unknown evidence.",
                        reference,
                    )
                )
        self._validate_nonterminal_budget(0.0, budget, issues)

    def _validate_complete(
        self,
        decision: CompleteDecision,
        task: TaskSpec,
        state: HunterWorldState,
        issues: list[ValidationIssue],
    ) -> None:
        required = set(task.success_conditions)
        declared = set(decision.satisfied_conditions)
        for condition in sorted(required - declared):
            issues.append(
                ValidationIssue(
                    ValidationCode.SUCCESS_CONDITION_MISSING,
                    "A TaskSpec success condition was not satisfied.",
                    condition,
                )
            )
        if required:
            for condition in sorted(declared - required):
                issues.append(
                    ValidationIssue(
                        ValidationCode.SUCCESS_CONDITION_UNKNOWN,
                        "Completion cites a condition not present in TaskSpec.",
                        condition,
                    )
                )
        for references in decision.satisfied_conditions.values():
            for reference in references:
                if reference not in state.evidence:
                    issues.append(
                        ValidationIssue(
                            ValidationCode.UNKNOWN_EVIDENCE,
                            "Completion references unknown evidence.",
                            reference,
                        )
                    )
        for question in state.unresolved_questions.values():
            if question.priority >= self.policy.critical_question_priority:
                issues.append(
                    ValidationIssue(
                        ValidationCode.CRITICAL_QUESTION_UNRESOLVED,
                        "A critical question remains unresolved.",
                        question.question_id,
                    )
                )

    @staticmethod
    def _validate_blocked(
        decision: BlockedDecision,
        state: HunterWorldState,
        catalog: CapabilityCatalog,
        issues: list[ValidationIssue],
    ) -> None:
        for reference in decision.blocking_question_ids:
            if reference not in state.unresolved_questions:
                issues.append(
                    ValidationIssue(
                        ValidationCode.UNKNOWN_QUESTION,
                        "Blocked decision references an unknown unresolved question.",
                        reference,
                    )
                )
        for capability_id in decision.attempted_capability_ids:
            try:
                catalog.get(capability_id)
            except KeyError:
                issues.append(
                    ValidationIssue(
                        ValidationCode.UNKNOWN_CAPABILITY,
                        "Blocked decision references an unknown capability.",
                        capability_id,
                    )
                )

    @staticmethod
    def _validate_nonterminal_budget(
        allocation: float,
        budget: BudgetSnapshot,
        issues: list[ValidationIssue],
    ) -> None:
        if budget.decisions_remaining == 0:
            issues.append(
                ValidationIssue(
                    ValidationCode.DECISION_BUDGET_EXHAUSTED,
                    "No global decision budget remains.",
                )
            )
        if allocation > 0 and budget.capability_calls_remaining == 0:
            issues.append(
                ValidationIssue(
                    ValidationCode.CAPABILITY_BUDGET_EXHAUSTED,
                    "No professional capability-call budget remains.",
                )
            )
        if budget.total_budget_remaining is not None and allocation > budget.total_budget_remaining:
            issues.append(
                ValidationIssue(
                    ValidationCode.ALLOCATION_EXCEEDS_BUDGET,
                    "The proposed allocation exceeds remaining total budget.",
                )
            )

    @staticmethod
    def _resolve_input(
        reference: str,
        task: TaskSpec,
        state: HunterWorldState,
    ) -> tuple[str | None, str | None]:
        if task.input_object is not None and reference == task.input_object.input_id:
            return resolve_input_type(task), (
                task.input_object.original_value
                if task.input_object.kind == "network_target"
                else None
            )
        if task.target_object is not None and reference == task.target_object.target_id:
            return resolve_input_type(task), task.target_object.value
        if reference in state.artifacts:
            artifact = state.artifacts[reference]
            handoff = HandoffDescriptor.from_metadata(artifact.metadata)
            if handoff is not None and handoff.carrier is HandoffCarrier.VALUE:
                return handoff.semantic_type, handoff.authorized_value(
                    DeterministicDecisionValidator._allowed_targets(task)
                )
            return artifact.artifact_type, None
        if reference in state.evidence:
            return state.evidence[reference].evidence_type, None
        return None, None

    @staticmethod
    def _allowed_targets(task: TaskSpec) -> set[str]:
        if task.authorization is not None:
            return set(task.authorization.allowed_targets)
        scoped = task.scope.get("allowed_targets", [])
        if isinstance(scoped, list) and all(isinstance(item, str) for item in scoped):
            return set(scoped) or {task.target}
        return {task.target}

    @staticmethod
    def _is_duplicate_without_progress(
        decision: InvokeCapabilityDecision, state: HunterWorldState
    ) -> bool:
        for record in reversed(state.dispatch_history):
            same_question = (
                record.question_id == decision.question_id
                if record.question_id is not None
                else record.objective == decision.objective
            )
            if (
                record.capability_id == decision.capability_id
                and record.input_refs == decision.input_refs
                and same_question
            ):
                return not (
                    record.new_evidence
                    or record.new_facts
                    or record.new_artifacts
                    or record.answered_question_ids
                )
        return False

    @staticmethod
    def _trailing_no_progress(state: HunterWorldState) -> int:
        count = 0
        for record in reversed(state.dispatch_history):
            if (
                record.new_evidence
                or record.new_facts
                or record.new_artifacts
                or record.answered_question_ids
            ):
                break
            count += 1
        return count
