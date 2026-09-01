"""Independent completion-truth determination.

Separates four meanings that the older completion path conflated:

1. ``backend process completed`` -- the OS/subprocess returned and declared
   artifact files exist (``ExecutionStatus.SUCCESS`` on an ``AgentResult``).
2. ``AgentResult structurally succeeded`` -- the frozen protocol validated the
   result; findings/evidence/artifacts entered canonical world state.
3. ``task goal verified`` -- deterministic evidence satisfies every
   ``TaskSpec.success_conditions`` entry (a canonical ``VerifiedFact`` cites the
   evidence), independent of any model text.
4. ``benchmark oracle verdict`` -- an explicitly configured per-run benchmark
   oracle (AutoPenBench judge, crash trigger evidence, reverse analysis truth,
   cross-domain provenance, DFIR availability) returns success.

``AgentResult.SUCCESS`` and "an artifact file exists" are candidate evidence,
never final truth. A completion is only ``VERIFIED`` when a benchmark oracle
confirms success, or every success condition is deterministically grounded in a
verified fact. ``NOT_VERIFIED`` blocks a global ``COMPLETE``;
``INCONCLUSIVE``/``UNAVAILABLE`` leave the run honestly open and are excluded
from verified-success/failure denominators by the evaluation layer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, Sequence

from pentestgpt_agent.protocol import TaskSpec

from .decisions import CompleteDecision
from .state import ArtifactRecord, HunterWorldState


class CompletionVerdict(StrEnum):
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    INCONCLUSIVE = "inconclusive"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class CompletionTruth:
    """One deterministic completion-truth outcome with a machine-readable reason."""

    verdict: CompletionVerdict
    verifier_id: str
    reason: str
    message: str
    evidence_refs: tuple[str, ...] = ()
    checked_conditions: dict[str, bool] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.verifier_id.strip():
            raise ValueError("verifier_id must be nonempty")
        if not self.reason.strip():
            raise ValueError("completion-truth reason must be nonempty")
        if not self.message.strip():
            raise ValueError("completion-truth message must be nonempty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "verifier_id": self.verifier_id,
            "reason": self.reason,
            "message": self.message,
            "evidence_refs": list(self.evidence_refs),
            "checked_conditions": dict(self.checked_conditions),
            "metadata": dict(self.metadata),
        }


class BenchmarkOracle(Protocol):
    """A per-run external ground-truth evaluator; never scheduled by Hunter."""

    oracle_id: str

    def applies(self, task: TaskSpec) -> bool: ...

    async def assess(self, *, task: TaskSpec, state: HunterWorldState) -> CompletionTruth: ...


def _artifact_by_type(state: HunterWorldState, artifact_type: str) -> ArtifactRecord | None:
    for artifact in state.artifacts.values():
        if artifact.artifact_type == artifact_type:
            return artifact
    return None


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("oracle evidence must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _truth(
    verdict: CompletionVerdict,
    verifier_id: str,
    reason: str,
    message: str,
    *,
    evidence_refs: tuple[str, ...] = (),
    checked_conditions: dict[str, bool] | None = None,
    metadata: dict[str, Any] | None = None,
) -> CompletionTruth:
    return CompletionTruth(
        verdict,
        verifier_id,
        reason,
        message,
        evidence_refs,
        dict(checked_conditions or {}),
        dict(metadata or {}),
    )


class AutoPenBenchOracle:
    """Authoritative judge verdict for a benchmark-run pentest case.

    The AutoPenBench judge is the benchmark's own oracle: it compares the
    submitted/captured flag to the exact upstream ``games.json`` flag. A
    completion is only ``VERIFIED`` when the judge reports success under that
    exact-flag oracle and a flag was actually submitted. The benchmark's own
    ground truth is never written into general production logic.
    """

    oracle_id = "autopenbench_judge"

    @staticmethod
    def applies(task: TaskSpec) -> bool:
        benchmark = task.metadata.get("benchmark")
        return (
            task.domain == "pentest"
            and isinstance(benchmark, dict)
            and benchmark.get("source") == "autopenbench_games_json"
        )

    async def assess(self, *, task: TaskSpec, state: HunterWorldState) -> CompletionTruth:
        artifact = _artifact_by_type(state, "backend_output")
        if artifact is None:
            return _truth(
                CompletionVerdict.UNAVAILABLE,
                self.oracle_id,
                "autopenbench_evaluation_missing",
                "No AutoPenBench evaluation artifact is present in canonical state.",
            )
        path = Path(artifact.path)
        if not path.is_file():
            return _truth(
                CompletionVerdict.UNAVAILABLE,
                self.oracle_id,
                "autopenbench_evaluation_missing",
                f"AutoPenBench evaluation artifact is missing on disk: {path}",
                evidence_refs=(artifact.artifact_id,),
            )
        try:
            evaluation = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "autopenbench_evaluation_malformed",
                f"AutoPenBench evaluation artifact could not be parsed: {exc}",
                evidence_refs=(artifact.artifact_id,),
            )
        judge = evaluation.get("judge")
        if not isinstance(judge, dict):
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "autopenbench_judge_missing",
                "AutoPenBench evaluation has no judge verdict.",
                evidence_refs=(artifact.artifact_id,),
                metadata={"result": evaluation.get("result")},
            )
        success = judge.get("success") is True
        submitted = tuple(
            str(item) for item in judge.get("submitted_answers", []) if item
        )
        oracle = str(judge.get("oracle") or "")
        exact_flag_match = bool(submitted) and oracle == "upstream_data_games_json_exact_flag"
        metadata = {
            "judge_success": success,
            "submitted_flags": list(submitted),
            "oracle": oracle,
            "result": evaluation.get("result"),
        }
        if success and exact_flag_match:
            return _truth(
                CompletionVerdict.VERIFIED,
                self.oracle_id,
                "judge_success_exact_flag_match",
                "The benchmark judge verified the captured flag against the exact ground truth.",
                evidence_refs=(artifact.artifact_id,),
                metadata=metadata,
            )
        if success:
            return _truth(
                CompletionVerdict.NOT_VERIFIED,
                self.oracle_id,
                "flag_exact_match_not_established",
                "The judge reported success but no exact-flag submission was established.",
                evidence_refs=(artifact.artifact_id,),
                metadata=metadata,
            )
        return _truth(
            CompletionVerdict.NOT_VERIFIED,
            self.oracle_id,
            "judge_not_success",
            "The AutoPenBench judge did not verify the goal.",
            evidence_refs=(artifact.artifact_id,),
            metadata=metadata,
        )


class VulnerabilityResearchOracle:
    """Crash-trigger evidence for a bounded fuzzing campaign.

    A reproduced ``trigger_sample`` is deterministic positive goal evidence.
    A campaign that ended in timeout without a trigger is ``INCONCLUSIVE``:
    it never proves "no vulnerability". A campaign that finished without a
    trigger is ``NOT_VERIFIED`` (the goal "reproduce a crash" was not met).
    """

    oracle_id = "fuzzingbrain_crash_evidence"

    @staticmethod
    def applies(task: TaskSpec) -> bool:
        return task.domain == "vulnerability_research"

    async def assess(self, *, task: TaskSpec, state: HunterWorldState) -> CompletionTruth:
        triggers = [
            artifact.artifact_id
            for artifact in state.artifacts.values()
            if artifact.artifact_type == "trigger_sample"
        ]
        if triggers:
            return _truth(
                CompletionVerdict.VERIFIED,
                self.oracle_id,
                "crash_trigger_reproduced",
                "FuzzingBrain reproduced a real crash trigger.",
                evidence_refs=tuple(triggers),
            )
        timed_out = any(
            dispatch.status == "timeout" for dispatch in state.dispatch_history
        )
        if timed_out:
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "campaign_timeout_no_crash",
                "The fuzzing campaign timed out without a trigger; no-vulnerability is not claimed.",
            )
        return _truth(
            CompletionVerdict.NOT_VERIFIED,
            self.oracle_id,
            "no_crash_reproduced",
            "The fuzzing campaign finished without reproducing a crash trigger.",
        )


class KongReverseOracle:
    """Production reverse-analysis truth without any benchmark function names.

    When Kong's LLM synthesis failed for the overwhelming majority of functions
    (``errors`` dominant, zero names), the analysis is a backend tool failure and
    a completion claiming success must be rejected. When named analysis exists
    but no external ground truth is configured, the goal is honestly
    ``INCONCLUSIVE``: structured output alone does not prove a backdoor finding.
    """

    oracle_id = "kong_analysis_truth"

    @staticmethod
    def applies(task: TaskSpec) -> bool:
        return task.domain == "reverse"

    async def assess(self, *, task: TaskSpec, state: HunterWorldState) -> CompletionTruth:
        artifact = _artifact_by_type(state, "reverse_analysis")
        if artifact is None:
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "no_reverse_analysis",
                "No Kong reverse-analysis artifact is present.",
            )
        path = Path(artifact.path)
        try:
            analysis = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "reverse_analysis_malformed",
                f"Kong analysis artifact could not be parsed: {exc}",
                evidence_refs=(artifact.artifact_id,),
            )
        stats = analysis.get("stats")
        if not isinstance(stats, dict):
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "reverse_stats_missing",
                "Kong analysis has no stats section.",
                evidence_refs=(artifact.artifact_id,),
            )
        errors = int(stats.get("errors", 0) or 0)
        named = int(stats.get("named", 0) or 0)
        analyzed = int(stats.get("analyzed", 0) or 0)
        stats_metadata = {
            "errors": errors,
            "named": named,
            "analyzed": analyzed,
            "total_functions": stats.get("total_functions"),
            "duration_seconds": stats.get("duration_seconds"),
        }
        if errors > 0 and named == 0:
            return _truth(
                CompletionVerdict.NOT_VERIFIED,
                self.oracle_id,
                "backend_tool_failure",
                "Kong LLM synthesis failed for most functions; the analysis is not trustworthy.",
                evidence_refs=(artifact.artifact_id,),
                metadata=stats_metadata,
            )
        if named > 0:
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "analysis_complete_ground_truth_unverified",
                "Kong produced named analysis but no benchmark ground truth is configured for this run.",
                evidence_refs=(artifact.artifact_id,),
                metadata=stats_metadata,
            )
        return _truth(
            CompletionVerdict.NOT_VERIFIED,
            self.oracle_id,
            "no_named_function_analysis",
            "Kong produced no named reverse-engineering analysis.",
            evidence_refs=(artifact.artifact_id,),
            metadata=stats_metadata,
        )


class ReverseExpectedFunctionsOracle:
    """Evaluation-layer oracle for a reverse benchmark with expected functions.

    This oracle is only active when the run explicitly configures the expected
    function names in ``TaskSpec.metadata.completion_oracle``. General Kong
    production logic never hardcodes function names.
    """

    oracle_id = "reverse_expected_functions"

    @classmethod
    def applies(cls, task: TaskSpec) -> bool:
        oracle = task.metadata.get("completion_oracle")
        return (
            isinstance(oracle, dict)
            and oracle.get("type") == "reverse_expected_functions"
            and bool(oracle.get("functions"))
        )

    async def assess(self, *, task: TaskSpec, state: HunterWorldState) -> CompletionTruth:
        oracle = task.metadata.get("completion_oracle")
        expected = tuple(str(item).strip().lower() for item in oracle.get("functions", []))
        expected = tuple(item for item in expected if item)
        artifact = _artifact_by_type(state, "reverse_analysis")
        if artifact is None:
            return _truth(
                CompletionVerdict.NOT_VERIFIED,
                self.oracle_id,
                "no_reverse_analysis",
                "No reverse-analysis artifact exists to check against the expected functions.",
            )
        path = Path(artifact.path)
        try:
            analysis = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "reverse_analysis_malformed",
                f"Kong analysis artifact could not be parsed: {exc}",
                evidence_refs=(artifact.artifact_id,),
            )
        names: set[str] = set()
        for item in analysis.get("functions", []):
            if not isinstance(item, dict):
                continue
            for key in ("name", "original_name"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    names.add(value.strip().lower())
        found = [name for name in expected if name in names]
        stats = analysis.get("stats")
        stats_metadata = {
            "expected_functions": list(expected),
            "found_functions": found,
        }
        if isinstance(stats, dict):
            stats_metadata["errors"] = stats.get("errors")
            stats_metadata["named"] = stats.get("named")
        if set(found) >= set(expected):
            return _truth(
                CompletionVerdict.VERIFIED,
                self.oracle_id,
                "all_expected_backdoor_functions_identified",
                "All expected backdoor functions were identified by reverse analysis.",
                evidence_refs=(artifact.artifact_id,),
                metadata=stats_metadata,
            )
        return _truth(
            CompletionVerdict.NOT_VERIFIED,
            self.oracle_id,
            "expected_backdoor_functions_not_identified",
            "Reverse analysis did not identify every expected backdoor function.",
            evidence_refs=(artifact.artifact_id,),
            metadata=stats_metadata,
        )


class CrossDomainProvenanceOracle:
    """Verify that a TRUDI export was actually consumed by the reverse subtask.

    The reverse analysis records the exact staged input it analyzed
    (``binary.path``). The completion is only ``VERIFIED`` when that input's
    SHA-256 equals the ``suspect_binary`` artifact exported by TRUDI, and a
    reverse-analysis artifact exists. This proves the cross-domain handoff
    consumed the same byte-identical evidence, not a paraphrase.
    """

    oracle_id = "cross_domain_provenance"

    @staticmethod
    def applies(task: TaskSpec) -> bool:
        oracle = task.metadata.get("completion_oracle")
        return isinstance(oracle, dict) and oracle.get("type") == "cross_domain_provenance"

    async def assess(self, *, task: TaskSpec, state: HunterWorldState) -> CompletionTruth:
        suspect = _artifact_by_type(state, "suspect_binary")
        analysis = _artifact_by_type(state, "reverse_analysis")
        if suspect is None or analysis is None:
            missing = [name for name, item in (
                ("suspect_binary", suspect),
                ("reverse_analysis", analysis),
            ) if item is None]
            return _truth(
                CompletionVerdict.NOT_VERIFIED,
                self.oracle_id,
                "cross_domain_artifact_missing",
                "Cross-domain completion lacks the required artifacts.",
                metadata={"missing": missing},
            )
        suspect_path = Path(suspect.path)
        if not suspect_path.is_file():
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "suspect_binary_missing_on_disk",
                "The exported suspect binary artifact is missing on disk.",
                evidence_refs=(suspect.artifact_id,),
            )
        try:
            analysis_value = _read_json(Path(analysis.path))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "reverse_analysis_malformed",
                f"Kong analysis artifact could not be parsed: {exc}",
                evidence_refs=(analysis.artifact_id,),
            )
        binary = analysis_value.get("binary")
        consumed_path_value = binary.get("path") if isinstance(binary, dict) else None
        if not isinstance(consumed_path_value, str) or not consumed_path_value:
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "reverse_input_path_unknown",
                "The reverse analysis does not record the consumed input path.",
                evidence_refs=(analysis.artifact_id,),
            )
        consumed_path = Path(consumed_path_value)
        if not consumed_path.is_file():
            return _truth(
                CompletionVerdict.INCONCLUSIVE,
                self.oracle_id,
                "reverse_input_missing_on_disk",
                "The input the reverse analysis consumed is missing on disk.",
                evidence_refs=(analysis.artifact_id,),
            )
        consumed_sha = _sha256(consumed_path)
        metadata = {
            "export_sha256": suspect.sha256,
            "consumed_sha256": consumed_sha,
            "consumed_path": str(consumed_path),
        }
        if consumed_sha == suspect.sha256:
            return _truth(
                CompletionVerdict.VERIFIED,
                self.oracle_id,
                "reverse_consumed_trudi_export_with_sha",
                "The reverse subtask consumed the exact TRUDI-exported binary (SHA-256 match).",
                evidence_refs=(suspect.artifact_id, analysis.artifact_id),
                metadata=metadata,
            )
        return _truth(
            CompletionVerdict.NOT_VERIFIED,
            self.oracle_id,
            "cross_domain_provenance_mismatch",
            "The reverse subtask did not consume the TRUDI-exported binary.",
            evidence_refs=(suspect.artifact_id, analysis.artifact_id),
            metadata=metadata,
        )


class DfirUnavailableOracle:
    """Explicitly mark a benchmark run whose ground truth cannot be exercised.

    DFIR cases whose benchmark images or runtime are unavailable are reported as
    ``UNAVAILABLE`` and excluded from verified-success/failure denominators.
    """

    oracle_id = "dfir_benchmark_unavailable"

    @staticmethod
    def applies(task: TaskSpec) -> bool:
        oracle = task.metadata.get("completion_oracle")
        return (
            isinstance(oracle, dict)
            and oracle.get("type") == "dfir_benchmark"
            and oracle.get("status") in {"missing", "unavailable"}
        )

    async def assess(self, *, task: TaskSpec, state: HunterWorldState) -> CompletionTruth:
        oracle = task.metadata.get("completion_oracle")
        return _truth(
            CompletionVerdict.UNAVAILABLE,
            self.oracle_id,
            "benchmark_unavailable",
            str(
                oracle.get("message")
                or "The DFIR benchmark is unavailable and cannot be verified."
            ),
            metadata={
                "status": oracle.get("status"),
                "reason": oracle.get("reason"),
            },
        )


DEFAULT_ORACLES: tuple[BenchmarkOracle, ...] = (
    ReverseExpectedFunctionsOracle(),
    AutoPenBenchOracle(),
    VulnerabilityResearchOracle(),
    KongReverseOracle(),
    CrossDomainProvenanceOracle(),
    DfirUnavailableOracle(),
)


def _deterministic_goal_evidence(
    task: TaskSpec,
    state: HunterWorldState,
    decision: CompleteDecision,
) -> CompletionTruth:
    fact_evidence: set[str] = set()
    for fact in state.facts.values():
        fact_evidence.update(fact.evidence_refs)
    checked: dict[str, bool] = {}
    evidence_refs: list[str] = []
    for condition, references in decision.satisfied_conditions.items():
        evidence_refs.extend(reference for reference in references if reference not in evidence_refs)
        checked[condition] = any(reference in fact_evidence for reference in references)
    if all(checked.values()):
        return _truth(
            CompletionVerdict.VERIFIED,
            "deterministic_goal_evidence",
            "goal_evidence_satisfied",
            "Every success condition is grounded in a canonical verified fact.",
            evidence_refs=tuple(evidence_refs),
            checked_conditions=checked,
        )
    ungrounded = [condition for condition, ok in checked.items() if not ok]
    return _truth(
        CompletionVerdict.NOT_VERIFIED,
        "deterministic_goal_evidence",
        "goal_evidence_insufficient",
        "Some success conditions cite evidence that is not grounded in a verified fact.",
        evidence_refs=tuple(evidence_refs),
        checked_conditions=checked,
        metadata={"ungrounded_conditions": ungrounded},
    )


class CompletionTruthVerifier:
    """Resolve the single authoritative completion truth for a task."""

    def __init__(self, oracles: Sequence[BenchmarkOracle] | None = None) -> None:
        self.oracles = tuple(oracles) if oracles is not None else DEFAULT_ORACLES

    def oracle_for(self, task: TaskSpec) -> BenchmarkOracle | None:
        for oracle in self.oracles:
            if oracle.applies(task):
                return oracle
        return None

    async def determine(
        self,
        *,
        task: TaskSpec,
        state: HunterWorldState,
        decision: CompleteDecision,
    ) -> CompletionTruth:
        task.validate()
        state.validate()
        oracle = self.oracle_for(task)
        if oracle is not None:
            return await oracle.assess(task=task, state=state)
        return _deterministic_goal_evidence(task, state, decision)
