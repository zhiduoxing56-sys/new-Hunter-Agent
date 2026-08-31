"""Serial global execution loop over the frozen public adapter lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from pentestgpt_agent.protocol import (
    AdapterRunner,
    AgentAdapter,
    AgentResult,
    AuthorizationScope,
    InputObject,
    RunLayout,
    TargetObject,
    TaskSpec,
)

from .decisions import (
    BlockedDecision,
    CompleteDecision,
    InvokeCapabilityDecision,
    SupervisorDecision,
    VerifyDecision,
)
from .handoffs import HandoffCarrier, HandoffDescriptor
from .invocation_bridge import InvocationBridge, InvocationContractError
from .state import DispatchRecord, HunterWorldState, UnresolvedQuestion
from .state_updater import (
    SemanticStateProposal,
    StateUpdate,
    WorldStateUpdater,
)
from .supervisor import (
    SupervisionOutcome,
    SupervisorModelError,
    SupervisorOutputError,
)
from .validator import BudgetSnapshot, resolve_input_type
from .verifier import GlobalVerificationOutcome, GlobalVerificationStatus, GlobalVerifier


AUDIT_FILENAME = "hunter_brain_audit.jsonl"
SUBTASKS_DIRECTORY = "hunter_brain_subtasks"


class OrchestrationStatus(StrEnum):
    COMPLETE = "complete"
    BLOCKED = "blocked"
    VERIFICATION_REQUIRED = "verification_required"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INVALID_DECISIONS = "invalid_decisions"
    MODEL_ERROR = "model_error"
    ADAPTER_UNAVAILABLE = "adapter_unavailable"
    VERIFICATION_FAILED = "verification_failed"
    INVOCATION_CONTRACT_FAILED = "invocation_contract_failed"


@dataclass(frozen=True)
class OrchestrationLimits:
    max_decisions: int = 12
    max_capability_calls: int = 8
    max_rejected_decisions: int = 3

    def __post_init__(self) -> None:
        if min(
            self.max_decisions,
            self.max_capability_calls,
            self.max_rejected_decisions,
        ) < 1:
            raise ValueError("orchestration limits must be positive")


@dataclass
class BudgetLedger:
    limits: OrchestrationLimits
    task: TaskSpec
    decisions_used: int = 0
    capability_calls_used: int = 0
    rejected_decisions: int = 0
    model_budget_used: float = 0.0
    tool_calls_used: int = 0
    total_budget_used: float = 0.0

    def snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            decisions_used=self.decisions_used,
            capability_calls_used=self.capability_calls_used,
            model_budget_used=self.model_budget_used,
            tool_calls_used=self.tool_calls_used,
            total_budget_used=self.total_budget_used,
            decisions_remaining=max(self.limits.max_decisions - self.decisions_used, 0),
            capability_calls_remaining=max(
                self.limits.max_capability_calls - self.capability_calls_used, 0
            ),
            model_budget_remaining=self._remaining(
                self.task.model_budget, self.model_budget_used
            ),
            tool_calls_remaining=self._remaining_int(
                self.task.tool_call_budget, self.tool_calls_used
            ),
            total_budget_remaining=self._remaining(
                self.task.budget, self.total_budget_used
            ),
        )

    def record_decision(self, outcome: SupervisionOutcome) -> None:
        self.decisions_used += 1
        usage = outcome.model_usage
        cost = usage.get("cost", usage.get("total_cost", 0.0))
        if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
            self.model_budget_used += float(cost)

    def record_capability(self, decision: InvokeCapabilityDecision, result: AgentResult) -> None:
        self.capability_calls_used += 1
        self.total_budget_used += decision.allocated_budget
        tool_calls = result.metrics.get("tool_calls", 0)
        if isinstance(tool_calls, int) and not isinstance(tool_calls, bool) and tool_calls >= 0:
            self.tool_calls_used += tool_calls

    @staticmethod
    def _remaining(limit: float | None, used: float) -> float | None:
        return None if limit is None else max(limit - used, 0.0)

    @staticmethod
    def _remaining_int(limit: int | None, used: int) -> int | None:
        return None if limit is None else max(limit - used, 0)


class SupervisorEngine(Protocol):
    async def decide(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        budget: BudgetSnapshot,
    ) -> SupervisionOutcome: ...


class ResultInterpreter(Protocol):
    def interpret(
        self,
        *,
        preview: StateUpdate,
        decision: InvokeCapabilityDecision,
        result: AgentResult,
    ) -> SemanticStateProposal: ...


@dataclass(frozen=True)
class OrchestrationResult:
    status: OrchestrationStatus
    state: HunterWorldState
    budget: BudgetSnapshot
    terminal_decision: SupervisorDecision | None = None
    message: str | None = None


class CapabilityAdapterRegistry:
    def __init__(self, adapters: Mapping[str, AgentAdapter]) -> None:
        if not adapters:
            raise ValueError("adapter registry must not be empty")
        self._adapters = dict(adapters)

    def get(self, capability_id: str) -> AgentAdapter | None:
        return self._adapters.get(capability_id)


class HunterOrchestrator:
    def __init__(
        self,
        *,
        supervisor: SupervisorEngine,
        adapters: CapabilityAdapterRegistry,
        runs_root: Path,
        state_updater: WorldStateUpdater | None = None,
        result_interpreter: ResultInterpreter | None = None,
        question_generator: ResultInterpreter | None = None,
        verifier: GlobalVerifier | None = None,
        limits: OrchestrationLimits | None = None,
        invocation_bridge: InvocationBridge | None = None,
    ) -> None:
        self.supervisor = supervisor
        self.adapters = adapters
        self.runs_root = runs_root
        self.state_updater = state_updater or WorldStateUpdater()
        self.result_interpreter = result_interpreter
        self.question_generator = question_generator
        self.verifier = verifier
        self.limits = limits or OrchestrationLimits()
        self.invocation_bridge = invocation_bridge

    async def run(
        self,
        task: TaskSpec,
        *,
        initial_state: HunterWorldState | None = None,
    ) -> OrchestrationResult:
        task.validate()
        layout = RunLayout.ensure(self.runs_root, task)
        state = initial_state or self._initial_state(task)
        if state.task_id != task.task_id:
            raise ValueError("initial state does not belong to TaskSpec")
        state.save(layout.root)
        audit = _BrainAuditLog(layout.root / AUDIT_FILENAME, task.task_id)
        ledger = BudgetLedger(self.limits, task)

        while ledger.decisions_used < self.limits.max_decisions:
            try:
                outcome = await self.supervisor.decide(
                    task=task,
                    state=state,
                    budget=ledger.snapshot(),
                )
            except (SupervisorModelError, SupervisorOutputError) as exc:
                audit.append("supervisor_error", {"error": f"{type(exc).__name__}: {exc}"})
                return OrchestrationResult(
                    OrchestrationStatus.MODEL_ERROR,
                    state,
                    ledger.snapshot(),
                    message=str(exc),
                )
            ledger.record_decision(outcome)
            audit.append(
                "decision",
                {
                    "decision": outcome.decision.to_dict(),
                    "accepted": outcome.validation.accepted,
                    "issues": [
                        {
                            "code": issue.code.value,
                            "message": issue.message,
                            "reference": issue.reference,
                        }
                        for issue in outcome.validation.issues
                    ],
                    "model_usage": outcome.model_usage,
                    "request_id": outcome.request_id,
                },
            )
            if not outcome.validation.accepted:
                ledger.rejected_decisions += 1
                if ledger.rejected_decisions >= self.limits.max_rejected_decisions:
                    return OrchestrationResult(
                        OrchestrationStatus.INVALID_DECISIONS,
                        state,
                        ledger.snapshot(),
                        outcome.decision,
                        "Supervisor exceeded the rejected-decision limit.",
                    )
                continue
            decision = outcome.decision
            if isinstance(decision, CompleteDecision):
                if self.verifier is not None:
                    verification = await self.verifier.verify_completion(
                        task=task,
                        state=state,
                        decision=decision,
                    )
                    audit.append(
                        "completion_verification",
                        self._verification_payload(verification),
                    )
                    if verification.status is not GlobalVerificationStatus.PASSED:
                        status = (
                            OrchestrationStatus.VERIFICATION_REQUIRED
                            if verification.status is GlobalVerificationStatus.INCONCLUSIVE
                            else OrchestrationStatus.VERIFICATION_FAILED
                        )
                        return OrchestrationResult(
                            status,
                            state,
                            ledger.snapshot(),
                            decision,
                            "Global completion verification did not pass.",
                        )
                state.save(layout.root)
                audit.append("completed", {"decision": decision.to_dict()})
                return OrchestrationResult(
                    OrchestrationStatus.COMPLETE,
                    state,
                    ledger.snapshot(),
                    decision,
                )
            if isinstance(decision, BlockedDecision):
                state.save(layout.root)
                audit.append("blocked", {"decision": decision.to_dict()})
                return OrchestrationResult(
                    OrchestrationStatus.BLOCKED,
                    state,
                    ledger.snapshot(),
                    decision,
                )
            if isinstance(decision, VerifyDecision):
                if self.verifier is not None:
                    verification = await self.verifier.verify_request(
                        task=task,
                        state=state,
                        decision=decision,
                    )
                    audit.append(
                        "verification_result",
                        self._verification_payload(verification),
                    )
                    if verification.status is GlobalVerificationStatus.FAILED:
                        return OrchestrationResult(
                            OrchestrationStatus.VERIFICATION_FAILED,
                            state,
                            ledger.snapshot(),
                            decision,
                            "Requested global verification failed.",
                        )
                    if verification.status is GlobalVerificationStatus.INCONCLUSIVE:
                        return OrchestrationResult(
                            OrchestrationStatus.VERIFICATION_REQUIRED,
                            state,
                            ledger.snapshot(),
                            decision,
                            "Requested global verification was inconclusive.",
                        )
                    for resolution in verification.resolutions:
                        state.resolve_question(
                            resolution.question_id,
                            fact_refs=resolution.fact_refs,
                        )
                    state.save(layout.root)
                    continue
                state.save(layout.root)
                audit.append("verification_requested", {"decision": decision.to_dict()})
                return OrchestrationResult(
                    OrchestrationStatus.VERIFICATION_REQUIRED,
                    state,
                    ledger.snapshot(),
                    decision,
                    "Global verification is implemented in phase 8.",
                )
            adapter = self.adapters.get(decision.capability_id)
            if adapter is None:
                audit.append(
                    "adapter_unavailable", {"capability_id": decision.capability_id}
                )
                return OrchestrationResult(
                    OrchestrationStatus.ADAPTER_UNAVAILABLE,
                    state,
                    ledger.snapshot(),
                    decision,
                    f"No adapter registered for {decision.capability_id}.",
                )
            try:
                child_task = self._build_subtask(
                    task,
                    state,
                    decision,
                    layout,
                    ledger.capability_calls_used + 1,
                )
            except InvocationContractError as exc:
                audit.append(
                    "invocation_contract_failed",
                    {"capability_id": decision.capability_id, "error": str(exc)},
                )
                return OrchestrationResult(
                    OrchestrationStatus.INVOCATION_CONTRACT_FAILED,
                    state,
                    ledger.snapshot(),
                    decision,
                    f"Invocation contract failed for {decision.capability_id}: {exc}",
                )
            subtasks_root = layout.root / SUBTASKS_DIRECTORY
            result = await AdapterRunner(adapter, runs_root=subtasks_root).execute(child_task)
            child_layout = RunLayout.ensure(subtasks_root, child_task)
            child_layout.validate_result_references(result)
            if self.verifier is not None:
                verification = await self.verifier.verify_result(
                    task=child_task,
                    state=state,
                    result=result,
                    layout=child_layout,
                )
                audit.append(
                    "agent_result_verification",
                    self._verification_payload(verification),
                )
                if verification.status is GlobalVerificationStatus.FAILED:
                    return OrchestrationResult(
                        OrchestrationStatus.VERIFICATION_FAILED,
                        state,
                        ledger.snapshot(),
                        decision,
                        "Professional AgentResult failed global verification.",
                    )
            preview = self.state_updater.apply(
                state,
                result,
                source_task=child_task,
            )
            interpreted = (
                self.result_interpreter.interpret(
                    preview=preview,
                    decision=decision,
                    result=result,
                )
                if self.result_interpreter is not None
                else None
            )
            generated = (
                self.question_generator.interpret(
                    preview=preview,
                    decision=decision,
                    result=result,
                )
                if self.question_generator is not None
                else None
            )
            proposal = self._merge_proposals(interpreted, generated)
            update = (
                self.state_updater.apply(
                    state,
                    result,
                    source_task=child_task,
                    semantic_proposal=proposal,
                )
                if proposal is not None
                else preview
            )
            state = update.state
            ledger.record_capability(decision, result)
            state.record_dispatch(
                DispatchRecord(
                    dispatch_id=f"dispatch-{ledger.capability_calls_used:04d}",
                    capability_id=decision.capability_id,
                    objective=decision.objective,
                    input_refs=decision.input_refs,
                    status=result.status.value,
                    new_evidence=bool(update.delta.added_evidence_ids),
                    new_facts=bool(update.delta.added_fact_ids),
                    answered_question_ids=update.delta.resolved_question_ids,
                    budget_used=decision.allocated_budget,
                    failure_reason=result.error.message if result.error else None,
                    new_artifacts=bool(update.delta.added_artifact_ids),
                    question_id=decision.question_id,
                )
            )
            state.save(layout.root)
            audit.append(
                "capability_result",
                {
                    "child_task_id": child_task.task_id,
                    "capability_id": decision.capability_id,
                    "agent_id": result.agent_id,
                    "status": result.status.value,
                    "delta": {
                        "facts": list(update.delta.added_fact_ids),
                        "evidence": list(update.delta.added_evidence_ids),
                        "artifacts": list(update.delta.added_artifact_ids),
                        "resolved_questions": list(update.delta.resolved_question_ids),
                    },
                    "error": result.error.to_dict() if result.error else None,
                },
            )

        return OrchestrationResult(
            OrchestrationStatus.BUDGET_EXHAUSTED,
            state,
            ledger.snapshot(),
            message="Global decision budget exhausted.",
        )

    @staticmethod
    def _merge_proposals(
        first: SemanticStateProposal | None,
        second: SemanticStateProposal | None,
    ) -> SemanticStateProposal | None:
        if first is None:
            return second
        if second is None:
            return first
        return SemanticStateProposal(
            new_questions=first.new_questions + second.new_questions,
            hypotheses=first.hypotheses + second.hypotheses,
            resolutions=first.resolutions + second.resolutions,
        )

    @staticmethod
    def _verification_payload(outcome: GlobalVerificationOutcome) -> dict[str, Any]:
        return {
            "status": outcome.status.value,
            "checks": [
                {
                    "check": item.check,
                    "passed": item.passed,
                    "reference": item.reference,
                    "detail": item.detail,
                }
                for item in outcome.checks
            ],
            "issues": [
                {
                    "code": item.code.value,
                    "message": item.message,
                    "reference": item.reference,
                }
                for item in outcome.issues
            ],
            "resolved_questions": [item.question_id for item in outcome.resolutions],
            "semantic_rationale": outcome.semantic_rationale,
        }

    @staticmethod
    def _initial_state(task: TaskSpec) -> HunterWorldState:
        state = HunterWorldState.from_task(task)
        state.add_question(
            UnresolvedQuestion(
                "question-user-goal",
                task.goal,
                priority=100,
                source="user_goal",
            )
        )
        return state

    def _build_subtask(
        self,
        parent: TaskSpec,
        state: HunterWorldState,
        decision: InvokeCapabilityDecision,
        layout: RunLayout,
        sequence: int,
    ) -> TaskSpec:
        child_id = f"{parent.task_id[:112]}-brain-{sequence:04d}"
        child_root = (layout.root / SUBTASKS_DIRECTORY / child_id).resolve()
        input_directory = child_root / "artifacts" / "input"
        input_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved = [self._resolve_reference(ref, parent, state) for ref in decision.input_refs]
        staged: list[dict[str, Any]] = []
        primary_target: str
        primary_input: InputObject
        primary_target_object: TargetObject
        allowed_targets: tuple[str, ...]
        allowed_read_paths: tuple[str, ...]
        first_type, first_value, first_path = resolved[0]
        if first_path is not None:
            for index, (input_type, value, source_path) in enumerate(resolved):
                if source_path is None:
                    raise ValueError("one professional subtask cannot mix file and network inputs")
                destination = input_directory / f"{index:02d}-{source_path.name}"
                if source_path.is_dir():
                    shutil.copytree(
                        source_path, destination, symlinks=False, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(
                            ".git", ".venv", "__pycache__", "build",
                            "worker_workspace", "results", "logs",
                        ),
                    )
                    digest = _directory_digest(destination)
                else:
                    shutil.copy2(source_path, destination)
                    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
                staged.append(
                    {
                        "source_ref": decision.input_refs[index],
                        "type": input_type,
                        "path": str(destination),
                        "sha256": digest,
                        "size": _path_size(destination),
                    }
                )
            primary = staged[0]
            primary_target = str(primary["path"])
            primary_kind = "directory" if Path(primary_target).is_dir() else "file"
            primary_input = InputObject(
                "brain-primary-input",
                primary_kind,
                first_value,
                path=primary_target,
                source_name=Path(first_value).name,
                sha256=str(primary["sha256"]),
                size_bytes=int(primary["size"]),
                metadata={"normalized_type": first_type},
            )
            primary_target_object = TargetObject(
                "brain-primary-target", first_type, primary_target
            )
            allowed_targets = (primary_target,)
            allowed_read_paths = (str(child_root),)
        else:
            if any(path is not None for _, _, path in resolved[1:]):
                raise ValueError("one professional subtask cannot mix network and file inputs")
            primary_target = first_value
            primary_input = InputObject(
                "brain-primary-input",
                "network_target",
                first_value,
                source_name=first_value,
                metadata={"normalized_type": first_type},
            )
            primary_target_object = TargetObject(
                "brain-primary-target", first_type, first_value
            )
            allowed_targets = tuple(
                dict.fromkeys(value for _, value, _ in resolved)
            )
            allowed_read_paths = ()
            staged = [
                {"source_ref": ref, "type": input_type, "value": value}
                for ref, (input_type, value, _) in zip(decision.input_refs, resolved, strict=True)
            ]
        metadata = dict(parent.metadata)
        metadata["hunter_brain"] = {
            "parent_task_id": parent.task_id,
            "question_id": decision.question_id,
            "input_refs": list(decision.input_refs),
            "basis_input_refs": list(decision.basis_input_refs),
            "basis_fact_refs": list(decision.basis_fact_refs),
            "basis_evidence_refs": list(decision.basis_evidence_refs),
            "expected_output_types": list(decision.expected_output_types),
            "managed_inputs": staged,
        }
        scope = dict(parent.scope)
        scope["allowed_targets"] = list(allowed_targets)
        authorization = AuthorizationScope(
            allowed_targets=allowed_targets,
            allowed_read_paths=allowed_read_paths,
            allowed_environment=(
                parent.authorization.allowed_environment
                if parent.authorization is not None
                else ()
            ),
            forbidden_actions=(
                parent.authorization.forbidden_actions
                if parent.authorization is not None
                else ()
            ),
            workspace=str(child_root),
            metadata={"hunter_brain_parent_task_id": parent.task_id},
        )
        child = TaskSpec(
            task_id=child_id,
            domain=decision.capability_id,
            target=primary_target,
            goal=decision.objective,
            timeout=parent.timeout,
            budget=decision.allocated_budget,
            workspace=str(child_root),
            scope=scope,
            success_conditions=tuple(
                f"Produce {output_type}" for output_type in decision.expected_output_types
            ),
            metadata=metadata,
            input_object=primary_input,
            target_object=primary_target_object,
            authorization=authorization,
            tool_call_budget=parent.tool_call_budget,
            model_budget=parent.model_budget,
            resource_limits=parent.resource_limits,
        )
        return self._apply_invocation_bridge(parent, decision, child, primary_target)

    def _apply_invocation_bridge(
        self,
        parent: TaskSpec,
        decision: InvokeCapabilityDecision,
        child: TaskSpec,
        resolved_target: str,
    ) -> TaskSpec:
        """Apply the deterministic capability invocation contract to a child."""
        if self.invocation_bridge is None:
            return child
        override = self.invocation_bridge.apply(
            parent=parent,
            decision=decision,
            resolved_target=resolved_target,
            supervisor_objective=decision.objective,
        )
        if override is None:
            return child
        child = replace(child, goal=override.goal)
        hunter_brain = dict(child.metadata.get("hunter_brain", {}))
        hunter_brain.update(override.audit)
        metadata = dict(child.metadata)
        metadata["hunter_brain"] = hunter_brain
        return replace(child, metadata=metadata)

    @staticmethod
    def _resolve_reference(
        reference: str,
        task: TaskSpec,
        state: HunterWorldState,
    ) -> tuple[str, str, Path | None]:
        if task.input_object is not None and reference == task.input_object.input_id:
            input_type = resolve_input_type(task) or task.input_object.kind
            path = Path(task.input_object.path) if task.input_object.path else None
            return input_type, task.input_object.original_value, path
        if task.target_object is not None and reference == task.target_object.target_id:
            shared_path = (
                Path(task.input_object.path)
                if task.input_object is not None and task.input_object.path is not None
                else None
            )
            return (
                resolve_input_type(task) or task.target_object.kind,
                task.target_object.value,
                shared_path,
            )
        artifact = state.artifacts.get(reference)
        if artifact is not None:
            path = Path(artifact.path).resolve()
            if path.is_file():
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual != artifact.sha256:
                    raise ValueError(f"artifact input integrity mismatch: {reference}")
                handoff = HandoffDescriptor.from_metadata(artifact.metadata)
                if handoff is not None and handoff.carrier is HandoffCarrier.VALUE:
                    allowed_targets = (
                        set(task.authorization.allowed_targets)
                        if task.authorization is not None
                        else set(str(item) for item in task.scope.get("allowed_targets", []))
                    )
                    return handoff.semantic_type, handoff.authorized_value(allowed_targets), None
                return artifact.artifact_type, artifact.path, path
            if path.is_dir():
                # Source-tree / directory evidence is a first-class input for
                # capabilities such as vulnerability_research and dfir.
                return artifact.artifact_type, artifact.path, path
            raise ValueError(f"artifact input is missing: {reference}")
        evidence = state.evidence.get(reference)
        if evidence is not None:
            if evidence.artifact_ref is not None:
                return HunterOrchestrator._resolve_reference(
                    evidence.artifact_ref, task, state
                )
            if evidence.path is not None:
                path = Path(evidence.path).resolve()
                if path.is_file():
                    return evidence.evidence_type, evidence.path, path
        raise ValueError(f"input reference cannot be materialized: {reference}")


class _BrainAuditLog:
    def __init__(self, path: Path, task_id: str) -> None:
        self.path = path
        self.task_id = task_id
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.touch(exist_ok=True, mode=0o600)

    def append(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {
            "task_id": self.task_id,
            "event_type": event_type,
            "payload": payload,
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def _directory_digest(directory: Path) -> str:
    """Stable content hash over a staged source-tree directory."""
    import hashlib

    hasher = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(directory).as_posix()
        hasher.update(relative.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


def _path_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for item in path.rglob("*"):
        if item.is_file() and not item.is_symlink():
            total += item.stat().st_size
    return total
