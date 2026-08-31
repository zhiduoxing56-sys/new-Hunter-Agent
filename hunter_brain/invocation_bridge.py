"""Deterministic capability-specific child-task invocation contracts.

The supervisor owns semantic decisions: which capability, which question, a
semantic objective, and input/basis references. A deterministic bridge owns the
machine-level contract of a child TaskSpec, such as the exact backend-required
goal string for benchmark-backed capabilities (e.g. AutoPenBench).

The model's objective is never used to fabricate a backend-required goal and is
always preserved in child audit metadata. Canonical case/task/target values may
only come from the parent's validated canonical metadata; any missing, empty,
conflicting or inconsistent contract fails closed and the backend is never
launched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from pentestgpt_agent.protocol import TaskSpec

from .decisions import InvokeCapabilityDecision


BENCHMARK_METADATA_KEY = "benchmark"
BACKEND_GOAL_AUDIT_KEY = "backend_goal_source"
SUPERVISOR_OBJECTIVE_AUDIT_KEY = "supervisor_objective"


class InvocationContractError(ValueError):
    """Raised when a capability's machine-level invocation contract is invalid."""


@dataclass(frozen=True)
class InvocationOverride:
    """A deterministic override for one child TaskSpec field set."""

    goal: str
    audit: dict[str, Any] = field(default_factory=dict)


class InvocationBridge(Protocol):
    """Applies a capability-specific machine contract to a child TaskSpec."""

    def apply(
        self,
        *,
        parent: TaskSpec,
        decision: InvokeCapabilityDecision,
        resolved_target: str,
        supervisor_objective: str,
    ) -> InvocationOverride | None:
        """Return an override for the child, or ``None`` for generic behavior.

        May raise ``InvocationContractError`` to fail closed before the backend
        is launched.
        """
        ...


class PentestBenchmarkBridge:
    """Binds the pentest child goal to a validated benchmark contract.

    When the supervisor selects ``pentest``, the child backend goal is taken
    deterministically from ``parent.metadata.benchmark`` (validated at parent
    creation time from the benchmark registry), never from the model's
    paraphrased objective. The supervisor objective is retained in the child's
    ``hunter_brain`` audit metadata.
    """

    def apply(
        self,
        *,
        parent: TaskSpec,
        decision: InvokeCapabilityDecision,
        resolved_target: str,
        supervisor_objective: str,
    ) -> InvocationOverride | None:
        if decision.capability_id != "pentest":
            return None
        benchmark = parent.metadata.get(BENCHMARK_METADATA_KEY)
        if not isinstance(benchmark, dict):
            raise InvocationContractError(
                "pentest capability selected but the parent task has no "
                f"{BENCHMARK_METADATA_KEY} contract metadata"
            )
        target = benchmark.get("target")
        task = benchmark.get("task")
        case_id = benchmark.get("case_id")
        if not isinstance(target, str) or not target.strip():
            raise InvocationContractError("benchmark contract target is missing or empty")
        if not isinstance(task, str) or not task.strip():
            raise InvocationContractError("benchmark contract task is missing or empty")
        if resolved_target != target:
            raise InvocationContractError(
                "resolved child target does not match the benchmark contract target"
            )
        if parent.goal != task:
            raise InvocationContractError(
                "parent goal does not match the benchmark contract task; "
                "the canonical task may only come from the validated contract"
            )
        return InvocationOverride(
            goal=task,
            audit={
                BACKEND_GOAL_AUDIT_KEY: BENCHMARK_METADATA_KEY,
                SUPERVISOR_OBJECTIVE_AUDIT_KEY: supervisor_objective,
                "benchmark_case_id": case_id,
                "benchmark_target": target,
            },
        )
