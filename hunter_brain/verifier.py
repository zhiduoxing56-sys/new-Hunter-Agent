"""Independent deterministic and optional semantic global verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from pentestgpt_agent.protocol import AgentResult, RunLayout, TaskSpec

from .decisions import CompleteDecision, VerifyDecision
from .state import HunterWorldState
from .state_updater import QuestionResolution


class GlobalVerificationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class VerificationCode(StrEnum):
    RESULT_CONTRACT_INVALID = "result_contract_invalid"
    RESULT_TASK_MISMATCH = "result_task_mismatch"
    RESULT_DOMAIN_MISMATCH = "result_domain_mismatch"
    ARTIFACT_MISSING = "artifact_missing"
    ARTIFACT_OUTSIDE_TASK = "artifact_outside_task"
    ARTIFACT_HASH_MISMATCH = "artifact_hash_mismatch"
    EVIDENCE_UNKNOWN = "evidence_unknown"
    EVIDENCE_REFERENCE_INVALID = "evidence_reference_invalid"
    SUCCESS_CONDITION_MISSING = "success_condition_missing"
    SUCCESS_CONDITION_UNKNOWN = "success_condition_unknown"
    CRITICAL_QUESTION_UNRESOLVED = "critical_question_unresolved"
    SEMANTIC_MODEL_UNAVAILABLE = "semantic_model_unavailable"
    SEMANTIC_NOT_SUPPORTED = "semantic_not_supported"
    SEMANTIC_REFERENCE_INVALID = "semantic_reference_invalid"
    CONFLICTING_FACTS = "conflicting_facts"
    CHECK_UNSUPPORTED = "check_unsupported"


@dataclass(frozen=True)
class VerificationIssue:
    code: VerificationCode
    message: str
    reference: str | None = None


@dataclass(frozen=True)
class DeterministicCheck:
    check: str
    passed: bool
    reference: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class SemanticVerificationRequest:
    kind: str
    objective: str
    user_goal: str
    success_conditions: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    facts: tuple[dict[str, Any], ...]
    unresolved_questions: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class SemanticAssessment:
    supported: bool | None
    rationale: str
    resolutions: tuple[QuestionResolution, ...] = ()
    conflicting_fact_pairs: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.rationale.strip():
            raise ValueError("semantic rationale must be nonempty")


class SemanticVerificationModel(Protocol):
    async def assess(self, request: SemanticVerificationRequest) -> SemanticAssessment: ...


@dataclass(frozen=True)
class GlobalVerificationOutcome:
    status: GlobalVerificationStatus
    checks: tuple[DeterministicCheck, ...] = ()
    issues: tuple[VerificationIssue, ...] = ()
    resolutions: tuple[QuestionResolution, ...] = ()
    semantic_rationale: str | None = None

    @property
    def passed(self) -> bool:
        return self.status is GlobalVerificationStatus.PASSED


class GlobalVerifier:
    def __init__(
        self,
        *,
        semantic_model: SemanticVerificationModel | None = None,
        critical_question_priority: int = 80,
    ) -> None:
        if not 0 <= critical_question_priority <= 100:
            raise ValueError("critical_question_priority must be between 0 and 100")
        self.semantic_model = semantic_model
        self.critical_question_priority = critical_question_priority

    async def verify_result(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        result: AgentResult,
        layout: RunLayout,
    ) -> GlobalVerificationOutcome:
        checks: list[DeterministicCheck] = []
        issues: list[VerificationIssue] = []
        try:
            result.validate()
        except ValueError as exc:
            issues.append(
                VerificationIssue(
                    VerificationCode.RESULT_CONTRACT_INVALID,
                    str(exc),
                )
            )
            return self._outcome(checks, issues)
        self._check(
            result.task_id == task.task_id,
            "result_task_matches",
            VerificationCode.RESULT_TASK_MISMATCH,
            "AgentResult does not belong to its subtask.",
            result.task_id,
            checks,
            issues,
        )
        self._check(
            result.domain == task.domain,
            "result_domain_matches",
            VerificationCode.RESULT_DOMAIN_MISMATCH,
            "AgentResult domain does not match its subtask.",
            result.domain,
            checks,
            issues,
        )
        artifact_ids = {item.artifact_id for item in result.artifacts}
        for artifact in result.artifacts:
            path = Path(artifact.path).resolve()
            exists = path.is_file()
            self._check(
                exists,
                "artifact_exists",
                VerificationCode.ARTIFACT_MISSING,
                "Result artifact is missing.",
                artifact.artifact_id,
                checks,
                issues,
            )
            belongs = exists and path.is_relative_to(layout.artifacts.resolve())
            self._check(
                belongs,
                "artifact_belongs_to_task",
                VerificationCode.ARTIFACT_OUTSIDE_TASK,
                "Result artifact is outside its task-owned artifact directory.",
                artifact.artifact_id,
                checks,
                issues,
            )
            matches = exists and self._sha256(path) == artifact.sha256
            self._check(
                matches,
                "sha256_matches",
                VerificationCode.ARTIFACT_HASH_MISMATCH,
                "Result artifact hash does not match AgentResult.",
                artifact.artifact_id,
                checks,
                issues,
            )
        for evidence in result.evidence:
            valid = evidence.artifact_ref is None or evidence.artifact_ref in artifact_ids
            self._check(
                valid,
                "evidence_reference_valid",
                VerificationCode.EVIDENCE_REFERENCE_INVALID,
                "Result evidence references an unknown artifact.",
                evidence.evidence_id,
                checks,
                issues,
            )
        if issues:
            return self._outcome(checks, issues)
        return await self._with_semantics(
            kind="agent_result",
            objective=result.summary,
            task=task,
            state=state,
            evidence_refs=tuple(item.evidence_id for item in result.evidence),
            checks=checks,
            issues=issues,
            semantic_required=False,
        )

    async def verify_request(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        decision: VerifyDecision,
    ) -> GlobalVerificationOutcome:
        checks: list[DeterministicCheck] = []
        issues: list[VerificationIssue] = []
        semantic_required = False
        for evidence_id in decision.evidence_refs:
            evidence = state.evidence.get(evidence_id)
            if evidence is None:
                issues.append(
                    VerificationIssue(
                        VerificationCode.EVIDENCE_UNKNOWN,
                        "Verification references unknown evidence.",
                        evidence_id,
                    )
                )
                continue
            for check_name in decision.verification_checks:
                if check_name == "evidence_reference_valid":
                    passed = (
                        evidence.artifact_ref is None
                        or evidence.artifact_ref in state.artifacts
                    )
                    self._check(
                        passed,
                        check_name,
                        VerificationCode.EVIDENCE_REFERENCE_INVALID,
                        "Evidence has an invalid artifact reference.",
                        evidence_id,
                        checks,
                        issues,
                    )
                elif check_name in {
                    "artifact_exists",
                    "sha256_matches",
                    "artifact_belongs_to_task",
                }:
                    self._check_state_artifact(
                        check_name, evidence_id, state, checks, issues
                    )
                elif check_name == "semantic_support":
                    semantic_required = True
                else:
                    issues.append(
                        VerificationIssue(
                            VerificationCode.CHECK_UNSUPPORTED,
                            "The requested deterministic check is not implemented.",
                            check_name,
                        )
                    )
        if any(issue.code is not VerificationCode.SEMANTIC_MODEL_UNAVAILABLE for issue in issues):
            return self._outcome(checks, issues)
        return await self._with_semantics(
            kind="verification_request",
            objective=decision.objective,
            task=task,
            state=state,
            evidence_refs=decision.evidence_refs,
            checks=checks,
            issues=issues,
            semantic_required=semantic_required,
        )

    async def verify_completion(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        decision: CompleteDecision,
    ) -> GlobalVerificationOutcome:
        checks: list[DeterministicCheck] = []
        issues: list[VerificationIssue] = []
        required = set(task.success_conditions)
        declared = set(decision.satisfied_conditions)
        for condition in sorted(required - declared):
            issues.append(
                VerificationIssue(
                    VerificationCode.SUCCESS_CONDITION_MISSING,
                    "A required success condition is missing.",
                    condition,
                )
            )
        if required:
            for condition in sorted(declared - required):
                issues.append(
                    VerificationIssue(
                        VerificationCode.SUCCESS_CONDITION_UNKNOWN,
                        "Completion declares an unknown success condition.",
                        condition,
                    )
                )
        evidence_refs = tuple(
            dict.fromkeys(
                reference
                for references in decision.satisfied_conditions.values()
                for reference in references
            )
        )
        for reference in evidence_refs:
            passed = reference in state.evidence
            self._check(
                passed,
                "completion_evidence_exists",
                VerificationCode.EVIDENCE_UNKNOWN,
                "Completion references unknown evidence.",
                reference,
                checks,
                issues,
            )
        for question in state.unresolved_questions.values():
            if question.priority >= self.critical_question_priority:
                issues.append(
                    VerificationIssue(
                        VerificationCode.CRITICAL_QUESTION_UNRESOLVED,
                        "A critical question remains unresolved.",
                        question.question_id,
                    )
                )
        if issues:
            return self._outcome(checks, issues)
        return await self._with_semantics(
            kind="global_completion",
            objective=decision.summary,
            task=task,
            state=state,
            evidence_refs=evidence_refs,
            checks=checks,
            issues=issues,
            semantic_required=False,
        )

    async def _with_semantics(
        self,
        *,
        kind: str,
        objective: str,
        task: TaskSpec,
        state: HunterWorldState,
        evidence_refs: tuple[str, ...],
        checks: list[DeterministicCheck],
        issues: list[VerificationIssue],
        semantic_required: bool,
    ) -> GlobalVerificationOutcome:
        if self.semantic_model is None:
            if semantic_required:
                issues.append(
                    VerificationIssue(
                        VerificationCode.SEMANTIC_MODEL_UNAVAILABLE,
                        "Semantic verification was requested but no model is configured.",
                    )
                )
                return self._outcome(checks, issues, inconclusive=True)
            return self._outcome(checks, issues)
        assessment = await self.semantic_model.assess(
            SemanticVerificationRequest(
                kind=kind,
                objective=objective,
                user_goal=state.user_goal,
                success_conditions=state.success_conditions,
                evidence_refs=evidence_refs,
                facts=tuple(
                    {
                        "fact_id": item.fact_id,
                        "statement": item.statement,
                        "evidence_refs": list(item.evidence_refs),
                    }
                    for item in state.facts.values()
                ),
                unresolved_questions=tuple(
                    {
                        "question_id": item.question_id,
                        "question": item.question,
                        "priority": item.priority,
                    }
                    for item in state.unresolved_questions.values()
                ),
            )
        )
        self._validate_semantic_assessment(assessment, state, issues)
        if assessment.supported is False:
            issues.append(
                VerificationIssue(
                    VerificationCode.SEMANTIC_NOT_SUPPORTED,
                    "The semantic verifier did not support the proposed conclusion.",
                )
            )
        if assessment.supported is None:
            return self._outcome(
                checks,
                issues,
                resolutions=assessment.resolutions,
                semantic_rationale=assessment.rationale,
                inconclusive=True,
            )
        return self._outcome(
            checks,
            issues,
            resolutions=assessment.resolutions,
            semantic_rationale=assessment.rationale,
        )

    @staticmethod
    def _validate_semantic_assessment(
        assessment: SemanticAssessment,
        state: HunterWorldState,
        issues: list[VerificationIssue],
    ) -> None:
        for resolution in assessment.resolutions:
            if resolution.question_id not in state.unresolved_questions or not set(
                resolution.fact_refs
            ).issubset(state.facts):
                issues.append(
                    VerificationIssue(
                        VerificationCode.SEMANTIC_REFERENCE_INVALID,
                        "Semantic verification cited an unknown question or fact.",
                        resolution.question_id,
                    )
                )
        for first, second in assessment.conflicting_fact_pairs:
            if first not in state.facts or second not in state.facts:
                issues.append(
                    VerificationIssue(
                        VerificationCode.SEMANTIC_REFERENCE_INVALID,
                        "Semantic conflict cites an unknown fact.",
                        f"{first},{second}",
                    )
                )
            else:
                issues.append(
                    VerificationIssue(
                        VerificationCode.CONFLICTING_FACTS,
                        "Semantic verification found conflicting facts.",
                        f"{first},{second}",
                    )
                )

    @staticmethod
    def _check_state_artifact(
        check_name: str,
        evidence_id: str,
        state: HunterWorldState,
        checks: list[DeterministicCheck],
        issues: list[VerificationIssue],
    ) -> None:
        evidence = state.evidence[evidence_id]
        artifact = (
            state.artifacts.get(evidence.artifact_ref)
            if evidence.artifact_ref is not None
            else None
        )
        path = Path(artifact.path).resolve() if artifact is not None else None
        if check_name == "artifact_exists":
            passed = path is not None and path.is_file()
            code = VerificationCode.ARTIFACT_MISSING
            message = "Evidence has no existing artifact."
        elif check_name == "sha256_matches":
            passed = (
                artifact is not None
                and path is not None
                and path.is_file()
                and GlobalVerifier._sha256(path) == artifact.sha256
            )
            code = VerificationCode.ARTIFACT_HASH_MISMATCH
            message = "Evidence artifact hash does not match world state."
        else:
            passed = artifact is not None and artifact.source_task_id in {
                state.task_id,
                *state.child_task_ids,
            }
            code = VerificationCode.ARTIFACT_OUTSIDE_TASK
            message = "Evidence artifact is outside the task lineage."
        GlobalVerifier._check(
            passed,
            check_name,
            code,
            message,
            evidence_id,
            checks,
            issues,
        )

    @staticmethod
    def _check(
        passed: bool,
        check_name: str,
        code: VerificationCode,
        message: str,
        reference: str | None,
        checks: list[DeterministicCheck],
        issues: list[VerificationIssue],
    ) -> None:
        checks.append(DeterministicCheck(check_name, passed, reference, None if passed else message))
        if not passed:
            issues.append(VerificationIssue(code, message, reference))

    @staticmethod
    def _outcome(
        checks: list[DeterministicCheck],
        issues: list[VerificationIssue],
        *,
        resolutions: tuple[QuestionResolution, ...] = (),
        semantic_rationale: str | None = None,
        inconclusive: bool = False,
    ) -> GlobalVerificationOutcome:
        if inconclusive and not any(
            issue.code
            not in {VerificationCode.SEMANTIC_MODEL_UNAVAILABLE}
            for issue in issues
        ):
            status = GlobalVerificationStatus.INCONCLUSIVE
        else:
            status = (
                GlobalVerificationStatus.FAILED
                if issues
                else GlobalVerificationStatus.PASSED
            )
        return GlobalVerificationOutcome(
            status,
            tuple(checks),
            tuple(issues),
            resolutions if status is GlobalVerificationStatus.PASSED else (),
            semantic_rationale,
        )

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
