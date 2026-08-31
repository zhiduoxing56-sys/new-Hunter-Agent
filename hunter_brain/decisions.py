"""Closed, structured output contract for one global-supervisor decision."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeAlias

from .capabilities import CapabilityCost


DECISION_SCHEMA_VERSION = "1.0"


class DecisionAction(StrEnum):
    INVOKE_CAPABILITY = "invoke_capability"
    VERIFY = "verify"
    COMPLETE = "complete"
    BLOCKED = "blocked"


class VerificationCheck(StrEnum):
    """The single, explicit, finite verification vocabulary.

    The global verifier only ever executes checks from this set. A supervisor
    may not invent a natural-language check name; unknown names fail closed.
    """

    EVIDENCE_REFERENCE_VALID = "evidence_reference_valid"
    ARTIFACT_EXISTS = "artifact_exists"
    SHA256_MATCHES = "sha256_matches"
    ARTIFACT_BELONGS_TO_TASK = "artifact_belongs_to_task"
    SEMANTIC_SUPPORT = "semantic_support"

    @classmethod
    def meanings(cls) -> dict[str, str]:
        return {
            cls.EVIDENCE_REFERENCE_VALID.value: "evidence points to an artifact the task owns",
            cls.ARTIFACT_EXISTS.value: "the evidence artifact exists on disk",
            cls.SHA256_MATCHES.value: "the evidence artifact SHA-256 matches world state",
            cls.ARTIFACT_BELONGS_TO_TASK.value: "the evidence artifact belongs to this task lineage",
            cls.SEMANTIC_SUPPORT.value: "a configured semantic model supports the conclusion",
        }


def _text(value: str, label: str) -> None:
    if not value.strip():
        raise ValueError(f"{label} must be nonempty")


def _refs(values: tuple[str, ...], label: str, *, required: bool = False) -> None:
    if required and not values:
        raise ValueError(f"{label} must not be empty")
    if len(values) != len(set(values)) or any(not item.strip() for item in values):
        raise ValueError(f"{label} must contain unique nonempty values")


def _base(action: DecisionAction, rationale: str, schema_version: str) -> None:
    if schema_version != DECISION_SCHEMA_VERSION:
        raise ValueError(f"unsupported decision schema_version: {schema_version!r}")
    _text(rationale, f"{action.value} rationale")


@dataclass(frozen=True)
class InvokeCapabilityDecision:
    capability_id: str
    input_refs: tuple[str, ...]
    question_id: str
    objective: str
    basis_input_refs: tuple[str, ...]
    basis_fact_refs: tuple[str, ...]
    basis_evidence_refs: tuple[str, ...]
    expected_output_types: tuple[str, ...]
    allocated_budget: float
    rationale: str
    action: DecisionAction = DecisionAction.INVOKE_CAPABILITY
    schema_version: str = DECISION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _base(self.action, self.rationale, self.schema_version)
        if self.action is not DecisionAction.INVOKE_CAPABILITY:
            raise ValueError("invoke decision has the wrong action")
        _text(self.capability_id, "capability_id")
        _text(self.question_id, "question_id")
        _text(self.objective, "objective")
        _refs(self.input_refs, "input_refs", required=True)
        _refs(self.basis_input_refs, "basis_input_refs")
        _refs(self.basis_fact_refs, "basis_fact_refs")
        _refs(self.basis_evidence_refs, "basis_evidence_refs")
        if not self.basis_input_refs and not self.basis_fact_refs and not self.basis_evidence_refs:
            raise ValueError("invoke decision requires an input, fact, or evidence basis")
        _refs(self.expected_output_types, "expected_output_types", required=True)
        if self.allocated_budget <= 0:
            raise ValueError("allocated_budget must be positive")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action": self.action.value,
            "capability_id": self.capability_id,
            "input_refs": list(self.input_refs),
            "question_id": self.question_id,
            "objective": self.objective,
            "basis_input_refs": list(self.basis_input_refs),
            "basis_fact_refs": list(self.basis_fact_refs),
            "basis_evidence_refs": list(self.basis_evidence_refs),
            "expected_output_types": list(self.expected_output_types),
            "allocated_budget": self.allocated_budget,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class VerifyDecision:
    objective: str
    evidence_refs: tuple[str, ...]
    verification_checks: tuple[str, ...]
    rationale: str
    action: DecisionAction = DecisionAction.VERIFY
    schema_version: str = DECISION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _base(self.action, self.rationale, self.schema_version)
        if self.action is not DecisionAction.VERIFY:
            raise ValueError("verify decision has the wrong action")
        _text(self.objective, "verification objective")
        _refs(self.evidence_refs, "evidence_refs", required=True)
        _refs(self.verification_checks, "verification_checks", required=True)
        unknown = [
            check for check in self.verification_checks if check not in VerificationCheck
        ]
        if unknown:
            raise ValueError(
                "verification_checks must use the closed vocabulary; "
                f"unknown: {', '.join(unknown)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action": self.action.value,
            "objective": self.objective,
            "evidence_refs": list(self.evidence_refs),
            "verification_checks": list(self.verification_checks),
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class CompleteDecision:
    summary: str
    satisfied_conditions: dict[str, tuple[str, ...]]
    rationale: str
    action: DecisionAction = DecisionAction.COMPLETE
    schema_version: str = DECISION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _base(self.action, self.rationale, self.schema_version)
        if self.action is not DecisionAction.COMPLETE:
            raise ValueError("complete decision has the wrong action")
        _text(self.summary, "completion summary")
        if not self.satisfied_conditions:
            raise ValueError("complete decision requires satisfied_conditions")
        for condition, evidence_refs in self.satisfied_conditions.items():
            _text(condition, "success condition")
            _refs(evidence_refs, "success-condition evidence", required=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action": self.action.value,
            "summary": self.summary,
            "satisfied_conditions": {
                condition: list(refs) for condition, refs in self.satisfied_conditions.items()
            },
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class BlockedDecision:
    reason: str
    blocking_question_ids: tuple[str, ...]
    attempted_capability_ids: tuple[str, ...]
    retryable: bool
    rationale: str
    action: DecisionAction = DecisionAction.BLOCKED
    schema_version: str = DECISION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _base(self.action, self.rationale, self.schema_version)
        if self.action is not DecisionAction.BLOCKED:
            raise ValueError("blocked decision has the wrong action")
        _text(self.reason, "blocked reason")
        _refs(self.blocking_question_ids, "blocking_question_ids", required=True)
        _refs(self.attempted_capability_ids, "attempted_capability_ids")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action": self.action.value,
            "reason": self.reason,
            "blocking_question_ids": list(self.blocking_question_ids),
            "attempted_capability_ids": list(self.attempted_capability_ids),
            "retryable": self.retryable,
            "rationale": self.rationale,
        }


SupervisorDecision: TypeAlias = (
    InvokeCapabilityDecision | VerifyDecision | CompleteDecision | BlockedDecision
)


def decision_from_dict(value: dict[str, Any]) -> SupervisorDecision:
    """Strictly parse model JSON; arbitrary free text is not a decision."""

    if not isinstance(value, dict):
        raise ValueError("decision must be a JSON object")
    try:
        action = DecisionAction(_string(value, "action"))
    except (TypeError, ValueError) as exc:
        raise ValueError("decision action must be one of the four supported actions") from exc
    schema_version = _string(value, "schema_version")
    rationale = _string(value, "rationale")
    if action is DecisionAction.INVOKE_CAPABILITY:
        _exact_keys(
            value,
            {
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
            },
        )
        return InvokeCapabilityDecision(
            capability_id=_string(value, "capability_id"),
            input_refs=_string_tuple(value, "input_refs"),
            question_id=_string(value, "question_id"),
            objective=_string(value, "objective"),
            basis_input_refs=_string_tuple(value, "basis_input_refs"),
            basis_fact_refs=_string_tuple(value, "basis_fact_refs"),
            basis_evidence_refs=_string_tuple(value, "basis_evidence_refs"),
            expected_output_types=_string_tuple(value, "expected_output_types"),
            allocated_budget=_number(value, "allocated_budget"),
            rationale=rationale,
            schema_version=schema_version,
        )
    if action is DecisionAction.VERIFY:
        _exact_keys(
            value,
            {
                "schema_version",
                "action",
                "objective",
                "evidence_refs",
                "verification_checks",
                "rationale",
            },
        )
        return VerifyDecision(
            objective=_string(value, "objective"),
            evidence_refs=_string_tuple(value, "evidence_refs"),
            verification_checks=_string_tuple(value, "verification_checks"),
            rationale=rationale,
            schema_version=schema_version,
        )
    if action is DecisionAction.COMPLETE:
        _exact_keys(
            value,
            {"schema_version", "action", "summary", "satisfied_conditions", "rationale"},
        )
        conditions = value.get("satisfied_conditions")
        if not isinstance(conditions, dict) or any(
            not isinstance(key, str) for key in conditions
        ):
            raise ValueError("satisfied_conditions must be an object")
        return CompleteDecision(
            summary=_string(value, "summary"),
            satisfied_conditions={
                condition: _strings(refs, "satisfied-condition evidence")
                for condition, refs in conditions.items()
            },
            rationale=rationale,
            schema_version=schema_version,
        )
    _exact_keys(
        value,
        {
            "schema_version",
            "action",
            "reason",
            "blocking_question_ids",
            "attempted_capability_ids",
            "retryable",
            "rationale",
        },
    )
    retryable = value.get("retryable")
    if not isinstance(retryable, bool):
        raise ValueError("retryable must be a boolean")
    return BlockedDecision(
        reason=_string(value, "reason"),
        blocking_question_ids=_string_tuple(value, "blocking_question_ids"),
        attempted_capability_ids=_string_tuple(value, "attempted_capability_ids"),
        retryable=retryable,
        rationale=rationale,
        schema_version=schema_version,
    )


def _exact_keys(value: dict[str, Any], expected: set[str]) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"decision fields do not match contract; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )


def _string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ValueError(f"{key} must be a string")
    return item


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be an array of strings")
    return tuple(value)


def _string_tuple(value: dict[str, Any], key: str) -> tuple[str, ...]:
    return _strings(value.get(key), key)


# Real model fallbacks for ``allocated_budget``: the capability cost vocabulary
# is occasionally echoed instead of a numeric allocation. The tiers are an
# explicit finite enum (``CapabilityCost``); each maps to a deterministic
# default budget. No free-text budget parsing is ever accepted.
BUDGET_BY_COST = {
    CapabilityCost.MEDIUM: 1.0,
    CapabilityCost.MEDIUM_TO_HIGH: 1.5,
    CapabilityCost.HIGH: 2.0,
}


def _number(value: dict[str, Any], key: str) -> float:
    item = value.get(key)
    if isinstance(item, bool):
        raise ValueError(f"{key} must be a number")
    if isinstance(item, (int, float)):
        return float(item)
    if isinstance(item, str):
        stripped = item.strip().lower()
        try:
            cost = CapabilityCost(stripped)
        except ValueError:
            cost = None
        if cost in BUDGET_BY_COST:
            return BUDGET_BY_COST[cost]
        # Real model JSON occasionally quotes numbers (e.g. "1.0"). Accept a
        # clearly numeric string rather than failing the whole decision.
        try:
            parsed = float(item)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number") from None
        if not math.isfinite(parsed):
            raise ValueError(f"{key} must be a finite number")
        return parsed
    raise ValueError(f"{key} must be a number")
