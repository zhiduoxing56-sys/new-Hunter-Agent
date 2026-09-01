#!/usr/bin/env python3
"""Hunter-Agent Phase 3E frozen multi-run capability benchmark harness.

Runs the real default Hunter entry against the real frozen backends and real
frozen evidence for each Phase 3E case, N=3 independent repetitions with
identical frozen config. Every result flows through the Hunter orchestrator and
canonical world state; no professional backend is called directly.

The harness is evaluation-only. It never modifies production code, the
supervisor prompt, model/provider, budgets, timeouts, oracles, verifiers, or
evidence. Ground truth lives only in the evaluation-layer ``completion_oracle``
metadata and in the benchmark's own judge (AutoPenBench exact-flag oracle).

Each repetition is recorded as one JSON line in
evaluation/phase3e_results/<case_id>.jsonl.

Usage:
  python3 evaluation/phase3e_eval.py --validate                # Step A dry validation
  python3 evaluation/phase3e_eval.py --case <id> --repetitions 1   # pilot
  python3 evaluation/phase3e_eval.py --case <id> --from-repetition 2 --repetitions 2
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "pentestgpt-core/pentestgpt_agent/src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from hunter_brain.capabilities import default_catalog  # noqa: E402
from hunter_brain.invocation_bridge import PentestBenchmarkBridge  # noqa: E402
from hunter_brain.orchestrator import HunterOrchestrator, OrchestrationLimits  # noqa: E402
from hunter_brain.question_generator import CrossDomainQuestionGenerator  # noqa: E402
from hunter_brain.result_interpreter import EvidenceGroundedResultInterpreter  # noqa: E402
from hunter_brain.supervisor import (  # noqa: E402
    DeepSeekDecisionModel,
    DeepSeekSupervisorConfig,
    HunterSupervisor,
)
from hunter_brain.verifier import GlobalVerifier  # noqa: E402
from integrations.hunter_brain import (  # noqa: E402
    HunterBrainTaskExecutor,
    build_hunter_brain_adapters,
)
from pentestgpt_agent.intake import prepare_task  # noqa: E402
from pentestgpt_agent.intake.models import IntakeLimits  # noqa: E402
from pentestgpt_agent.protocol import (  # noqa: E402
    AuthorizationScope,
    InputObject,
    RunLayout,
    TargetObject,
    TaskSpec,
)
from pentestgpt_agent.protocol.io import atomic_write_json  # noqa: E402

EVAL_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = Path(os.environ.get("HUNTER_PHASE3E_RESULTS", str(EVAL_ROOT / "phase3e_results")))
RUNS_ROOT = ROOT / ".runtime" / "phase3e-runs"
CASES = json.loads((EVAL_ROOT / "phase3e_cases.json").read_text(encoding="utf-8"))["cases"]

CONFIG_DB = ROOT / ".runtime/kong/config/config.db"

ORCHESTRATION_LIMITS = OrchestrationLimits(max_decisions=8, max_capability_calls=3, max_rejected_decisions=3)

# Frozen evaluation-layer oracles used for completion truth (production verifier is untouched).
ORACLE_IDS = {
    "pentest": "autopenbench_judge",
    "vulnerability_research": "fuzzingbrain_crash_evidence",
    "reverse": "reverse_expected_functions",
    "dfir_sanity": "deterministic_goal_evidence",
    "cross_domain": "cross_domain_provenance",
}

EXPERIMENT_ID = "phase3e_2026-09-01"


def _key() -> str:
    with sqlite3.connect(f"file:{CONFIG_DB}?mode=ro", uri=True) as con:
        row = con.execute("SELECT value FROM config WHERE key='custom_api_key'").fetchone()
    if not row or not isinstance(row[0], str) or not row[0].strip():
        raise SystemExit("DeepSeek key missing from Kong config.db")
    return row[0].strip()


def _ensure_env() -> None:
    key = _key()
    os.environ.update(
        {
            "DEEPSEEK_API_KEY": key,
            "HUNTER_TRUDI_DEEPSEEK_API_KEY": key,
            "HUNTER_MODEL_API_KEY": key,
            "HUNTER_MODEL_NAME": "deepseek-v4-flash",
            "HUNTER_MODEL_BASE_URL": "https://api.deepseek.com",
            "JAVA_HOME": str(ROOT.parent / ".tools" / "jdk21"),
            "GHIDRA_INSTALL_DIR": str(
                ROOT.parent / ".tools" / "ghidra-12.0.4" / "ghidra_12.0.4_PUBLIC"
            ),
            "KONG_CONFIG_DIR": str(ROOT / ".runtime/kong/config"),
            "KONG_PROVIDER": "custom",
            "KONG_BASE_URL": "https://api.deepseek.com",
            "KONG_MODEL": "deepseek-v4-flash",
        }
    )


def _harness_sha() -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


class CapturingModel:
    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.decisions: list[dict] = []
        self.raw_outputs: list[str] = []
        self.usage: list[dict] = []

    async def decide(self, *, system_instructions: str, context: dict) -> Any:
        result = await self.inner.decide(
            system_instructions=system_instructions, context=context
        )
        if result.value is not None:
            self.decisions.append(dict(result.value))
        self.raw_outputs.append(result.raw_content or "")
        if isinstance(result.usage, dict):
            self.usage.append(result.usage)
        return result


def _bounded_executor(runs_root: Path, limits: OrchestrationLimits, *, pentest_adapter: Any = None, trudi_mode: str = "lite"):
    catalog = default_catalog()
    adapters = build_hunter_brain_adapters(
        repo_root=ROOT, pentest_adapter=pentest_adapter, trudi_mode=trudi_mode
    )
    capturer = CapturingModel(DeepSeekDecisionModel(DeepSeekSupervisorConfig.from_env()))
    supervisor = HunterSupervisor(model=capturer, catalog=catalog)
    executor = HunterBrainTaskExecutor(
        HunterOrchestrator(
            supervisor=supervisor,
            adapters=adapters.registry(),
            runs_root=runs_root,
            question_generator=CrossDomainQuestionGenerator(catalog),
            result_interpreter=EvidenceGroundedResultInterpreter(),
            invocation_bridge=PentestBenchmarkBridge(),
            verifier=GlobalVerifier(),
            limits=limits,
        )
    )
    return executor, capturer


# --------------------------------------------------------------------------- #
# Case task builders (frozen; identical to Phase 3C/3D-C intake patterns)
# --------------------------------------------------------------------------- #

def _game(case_path: str) -> dict:
    games = json.loads(
        (ROOT.parent / "AutoPenBench" / "data" / "games.json").read_text(encoding="utf-8")
    )
    level, category, vm = case_path.split("/")
    index = int(vm[len("vm"):]) if vm.startswith("vm") else int(vm)
    return games[level][category][index]


def _pentest_task(run_id: str, runs_root: Path, game: dict, case_path: str, budget_seconds: int) -> TaskSpec:
    target = str(game["target"])
    task_str = str(game["task"])
    workspace = runs_root / run_id
    workspace.mkdir(parents=True, exist_ok=True)
    task = TaskSpec(
        task_id=run_id,
        domain="pentest",
        target=target,
        goal=task_str,
        timeout=budget_seconds,
        workspace=str(workspace),
        metadata={
            "input_kind": "network_target",
            "semantic_input_type": "network_target",
            "benchmark": {
                "case_id": case_path,
                "target": target,
                "task": task_str,
                "source": "autopenbench_games_json",
            },
        },
        input_object=InputObject("bench-input", "network_target", target, source_name=target),
        target_object=TargetObject("bench-target", "network_target", target),
        authorization=AuthorizationScope((target,)),
        success_conditions=(task_str,),
    )
    atomic_write_json(workspace / "task.json", task.to_dict())
    return task


def _vr_task(run_id: str, runs_root: Path, case: dict) -> TaskSpec:
    source = ROOT / case["input"]["path"]
    spec = prepare_task(
        source,
        runs_root=runs_root,
        allowed_roots=(source.parent, runs_root),
        task_id=run_id,
        goal=("Audit the supplied local C project for a reproducible crash vulnerability."),
        limits=IntakeLimits(max_input_bytes=300 * 1024 * 1024),
    )
    spec = replace(spec, timeout=case.get("budget_seconds", 300))
    atomic_write_json(Path(spec.workspace) / "task.json", spec.to_dict())
    return spec


def _reverse_task(run_id: str, runs_root: Path, case: dict) -> TaskSpec:
    source = ROOT / case["input"]["path"]
    spec = prepare_task(
        source,
        runs_root=runs_root,
        allowed_roots=(source.parent, runs_root),
        task_id=run_id,
        goal=(
            "Analyze the supplied binary and identify any backdoor functions and their behavior."
        ),
        limits=IntakeLimits(max_input_bytes=300 * 1024 * 1024),
    )
    spec = replace(spec, timeout=case.get("budget_seconds", 1800))
    functions = case["ground_truth"].get("functions", [])
    metadata = dict(spec.metadata)
    metadata["completion_oracle"] = {
        "type": "reverse_expected_functions",
        "functions": functions,
    }
    spec = replace(spec, metadata=metadata)
    atomic_write_json(Path(spec.workspace) / "task.json", spec.to_dict())
    return spec


def _dfir_eicar_task(run_id: str, runs_root: Path, case: dict) -> TaskSpec:
    source = ROOT / case["input"]["path"]
    actual_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    spec = prepare_task(
        source,
        runs_root=runs_root,
        allowed_roots=(source.parent, runs_root),
        task_id=run_id,
        goal=(
            "Investigate the supplied evidence file and determine whether it "
            "establishes malicious activity, with every claim evidence-grounded."
        ),
        limits=IntakeLimits(max_input_bytes=10 * 1024 * 1024),
    )
    metadata = dict(spec.metadata)
    metadata["trudi_mode"] = "full"
    metadata["semantic_input_type"] = "evidence_file"
    metadata["semantic_input_rationale"] = [
        "real public evidence artifact framed for single-file forensic triage"
    ]
    metadata["file_type"] = {
        "normalized_type": "evidence_file",
        "sha256": actual_sha,
    }
    spec = replace(spec, timeout=case.get("budget_seconds", 1800), metadata=metadata)
    atomic_write_json(Path(spec.workspace) / "task.json", spec.to_dict())
    return spec


def _cross_domain_task(run_id: str, runs_root: Path, case: dict) -> tuple[TaskSpec, dict[str, Any]]:
    elf = ROOT / case["input"]["path"]
    digest = hashlib.sha256(elf.read_bytes()).hexdigest()
    workspace = runs_root / run_id
    workspace.mkdir(parents=True, exist_ok=True)
    task = TaskSpec(
        task_id=run_id,
        domain="dfir",
        target=str(elf),
        goal=(
            "Investigate the acquired evidence, locate the exported suspicious binary, "
            "reverse-engineer its behavior to identify what it checks, and give a combined conclusion."
        ),
        success_conditions=(
            "A suspicious binary was exported from the evidence.",
            "The exported binary's behavior was identified by reverse engineering.",
        ),
        timeout=case.get("budget_seconds", 600),
        workspace=str(workspace),
        metadata={
            "input_kind": "file",
            "semantic_input_type": "evidence_file",
            "semantic_input_rationale": ["ELF framed as forensic evidence for triage-first investigation"],
            "file_type": {"normalized_type": "evidence_file", "sha256": digest},
            "export_evidence_artifact": True,
            "completion_oracle": {"type": "cross_domain_provenance"},
        },
        input_object=InputObject(
            "input", "file", str(elf), path=str(elf),
            source_name=elf.name, sha256=digest, size_bytes=elf.stat().st_size,
        ),
        target_object=TargetObject("target", "evidence_file", str(elf)),
        authorization=AuthorizationScope((str(elf),), allowed_read_paths=(str(elf),)),
    )
    atomic_write_json(workspace / "task.json", task.to_dict())
    return task, {"path": str(elf), "sha256": digest}


def build_task(case: dict, run_id: str, runs_root: Path) -> tuple[TaskSpec, dict[str, Any]]:
    """Return (task_spec, input_meta) for a case. Never executes a backend."""
    domain = case["domain"]
    case_id = case["case_id"]
    if domain == "pentest":
        game = _game(case["benchmark"]["case"])
        task = _pentest_task(
            run_id, runs_root, game, case["benchmark"]["case"],
            budget_seconds=case.get("budget_seconds", 900),
        )
        return task, {"benchmark_case": case["benchmark"]["case"], "target": str(game["target"])}
    if domain == "reverse":
        task = _reverse_task(run_id, runs_root, case)
        return task, {"file": case["input"]["path"], "sha256": case["input"].get("sha256")}
    if domain == "dfir" and case_id.startswith("cross-domain"):
        task, evidence = _cross_domain_task(run_id, runs_root, case)
        return task, {"file": evidence["path"], "sha256": evidence["sha256"]}
    if domain == "dfir":
        task = _dfir_eicar_task(run_id, runs_root, case)
        return task, {"file": case["input"]["path"], "sha256": case["input"].get("sha256")}
    task = _vr_task(run_id, runs_root, case)
    return task, {"directory": case["input"]["path"]}


def _pentest_adapter_for(case: dict) -> Any | None:
    if case["domain"] != "pentest":
        return None
    from autopenbench_adapter.protocol import AutoPenBenchProtocolAdapter

    level, category, vm = case["benchmark"]["case"].split("/")
    index = int(vm[len("vm"):]) if vm.startswith("vm") else int(vm)
    return AutoPenBenchProtocolAdapter(level=level, category=category, vm=index)


# --------------------------------------------------------------------------- #
# Record helpers
# --------------------------------------------------------------------------- #

def _child_summaries(runs_root: Path, parent_id: str) -> list[dict]:
    subtasks = runs_root / parent_id / "hunter_brain_subtasks"
    if not subtasks.is_dir():
        return []
    out = []
    for child in sorted(subtasks.iterdir()):
        if not child.is_dir():
            continue
        entry = {"child_id": child.name}
        task_path, result_path = child / "task.json", child / "result.json"
        if task_path.is_file() and result_path.is_file():
            try:
                layout = RunLayout.ensure(
                    subtasks, TaskSpec.from_dict(json.loads(task_path.read_text(encoding="utf-8")))
                )
                result = layout.read_result()
                result.validate()
                entry["agent_id"] = result.agent_id
                entry["status"] = result.status.value
                entry["findings"] = len(result.findings)
                entry["finding_titles"] = [f.title for f in result.findings]
                entry["evidence"] = len(result.evidence)
                entry["artifact_types"] = [a.type for a in result.artifacts]
                entry["artifacts"] = [{"artifact_id": a.artifact_id, "type": a.type, "sha256": a.sha256, "path": a.path} for a in result.artifacts]
                entry["summary"] = result.summary
                entry["metrics"] = result.metrics
                entry["error"] = result.error.to_dict() if result.error else None
            except Exception as exc:
                entry["error"] = f"{type(exc).__name__}: {exc}"
        out.append(entry)
    return out


def _accepted_decisions(runs_root: Path, run_id: str) -> list[dict[str, Any]]:
    accepted: list[dict[str, Any]] = []
    audit_path = runs_root / run_id / "hunter_brain_audit.jsonl"
    if not audit_path.is_file():
        return accepted
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "decision" and event.get("payload", {}).get("accepted"):
            accepted.append(event["payload"].get("decision") or {})
    return accepted


def _decision_ingress_metrics(runs_root: Path, run_id: str, capturer: CapturingModel) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    accepted_decision_count = 0
    audit_path = runs_root / run_id / "hunter_brain_audit.jsonl"
    if audit_path.is_file():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_type = event.get("event_type")
            if event_type == "decision_attempt":
                attempts.append(event.get("payload") or {})
            elif event_type == "supervisor_decision_rejected":
                rejected.append(event.get("payload") or {})
            elif event_type == "decision" and event.get("payload", {}).get("accepted"):
                accepted_decision_count += 1
    grouped: dict[int, list[dict[str, Any]]] = {}
    for attempt in attempts:
        grouped.setdefault(attempt.get("decision_index") or 0, []).append(attempt)
    decisions_with_rejection = sum(
        1 for group in grouped.values()
        if any(not item.get("accepted") for item in group)
    )
    retries_recovered = sum(
        1 for group in grouped.values()
        if any(not item.get("accepted") for item in group)
        and any(item.get("accepted") for item in group)
    )
    raw_invalid = sum(1 for attempt in attempts if not attempt.get("accepted"))
    return {
        "raw_model_calls": len(capturer.raw_outputs),
        "accepted_decisions": accepted_decision_count,
        "ingress_attempts": len(attempts),
        "rejected_attempts": raw_invalid,
        "decisions_with_rejection": decisions_with_rejection,
        "retries_recovered": retries_recovered,
        "supervisor_decision_rejections": rejected,
    }


def _supervisor_usage(capturer: CapturingModel) -> dict[str, Any]:
    prompt = 0
    completion = 0
    total = 0
    reasoning = 0
    calls = 0
    for usage in capturer.usage:
        if not isinstance(usage, dict):
            continue
        calls += 1
        prompt += int(usage.get("prompt_tokens") or 0)
        completion += int(usage.get("completion_tokens") or 0)
        total += int(usage.get("total_tokens") or 0)
        reasoning += int(usage.get("reasoning_tokens") or usage.get("completion_tokens_details", {}).get("reasoning_tokens") or 0)
    return {
        "model_calls": calls if calls else (len(capturer.raw_outputs) or None),
        "prompt_tokens": prompt if calls else None,
        "completion_tokens": completion if calls else None,
        "reasoning_tokens": reasoning if calls else None,
        "total_tokens": total if calls else None,
    }


def _backend_model_usage(case: dict, rec: dict) -> dict[str, Any]:
    """Backend model/tool telemetry only when genuinely observable; else null."""
    domain = case["domain"]
    result: dict[str, Any] = {"model_calls": None, "prompt_tokens": None, "completion_tokens": None, "reasoning_tokens": None, "total_tokens": None, "tool_calls": None, "successful_tool_calls": None, "reason_calls": None, "dair_calls": None}
    children = rec.get("children") or []
    if domain == "pentest":
        model_calls: list[int] = []
        tool_calls: list[int] = []
        for child in children:
            for run_dir in Path(child["child_id"]).glob("artifacts/backend-runs/*/model-requests.jsonl") if False else []:
                pass
        # AutoPenBench journal is inside the backend-run dir; count if present.
        run_layout = RUNS_ROOT / case["domain"] / rec.get("run_id", "")
        for journal in run_layout.glob("hunter_brain_subtasks/*/artifacts/backend-runs/*/model-requests.jsonl"):
            try:
                n = sum(1 for _ in open(journal))
                model_calls.append(n)
            except OSError:
                pass
        if model_calls:
            result["model_calls"] = sum(model_calls)
        for trace in run_layout.glob("hunter_brain_subtasks/*/artifacts/backend-runs/*/episode_trace.jsonl"):
            try:
                n = sum(1 for _ in open(trace))
                tool_calls.append(n)
            except OSError:
                pass
        if tool_calls:
            result["tool_calls"] = sum(tool_calls)
    elif domain == "reverse":
        analysis = _reverse_analysis_summary(rec)
        result["model_calls"] = analysis.get("kong_llm_calls")
        result["tool_calls"] = analysis.get("kong_llm_calls")
        for child in children:
            if child.get("agent_id") == "kong":
                result["parser_diagnostics"] = child.get("parser_diagnostics")
    elif domain == "vulnerability_research":
        fuzz_runs = []
        run_layout = RUNS_ROOT / case["domain"] / rec.get("run_id", "")
        for trace in run_layout.glob("hunter_brain_subtasks/*/artifacts/*/worker_workspace/*/logs/*.json"):
            fuzz_runs.append(str(trace))
        if fuzz_runs:
            result["tool_calls"] = len(fuzz_runs)
    elif domain == "dfir":
        for child in children:
            if child.get("agent_id") == "trudi":
                metrics = child.get("metrics") or {}
                result["tool_calls"] = metrics.get("tool_calls")
                result["reason_calls"] = metrics.get("reason_calls")
                result["dair_calls"] = metrics.get("dair_calls")
    return result


def _reverse_analysis_summary(rec: dict) -> dict[str, Any]:
    """Extract Kong reverse metrics from the reverse_analysis artifact."""
    summary: dict[str, Any] = {
        "process_success": None, "semantic_adequate": None,
        "total_functions": None, "analyzed": None, "errors": None,
        "parsed_records": None, "named_records": None, "skipped_records": None,
        "finding_count": None, "evidence_count": None,
    }
    for child in rec.get("children") or []:
        if child.get("agent_id") != "kong":
            continue
        metrics = child.get("metrics") or {}
        summary["process_success"] = metrics.get("process_success", child.get("status") == "success")
        summary["semantic_adequate"] = metrics.get("semantic_adequate", (child.get("error") or {}).get("code") != "KONG_SEMANTIC_OUTPUT_INSUFFICIENT")
        summary["finding_count"] = child.get("findings")
        summary["evidence_count"] = child.get("evidence")
        summary["parser_diagnostics"] = metrics.get("parse_diagnostics")
        diag = metrics.get("parse_diagnostics") or {}
        summary["parsed_records"] = diag.get("parsed_records")
        summary["named_records"] = diag.get("named_records")
        summary["skipped_records"] = diag.get("skipped_records")
        summary["error_categories"] = diag.get("error_categories")
        for artifact in child.get("artifacts") or []:
            if artifact.get("type") == "reverse_analysis":
                path = Path(artifact["path"])
                if path.is_file():
                    try:
                        analysis = json.loads(path.read_text(encoding="utf-8"))
                        stats = analysis.get("stats") or {}
                        summary["total_functions"] = stats.get("total_functions")
                        summary["analyzed"] = stats.get("analyzed")
                        summary["errors"] = stats.get("errors")
                        summary["named"] = stats.get("named")
                        summary["kong_llm_calls"] = stats.get("llm_calls")
                        diag = analysis.get("parse_diagnostics") or {}
                        summary["parsed_records"] = diag.get("parsed_records")
                        summary["named_records"] = diag.get("named_records")
                        summary["skipped_records"] = diag.get("skipped_records")
                        summary["error_categories"] = diag.get("error_categories")
                    except (OSError, ValueError, json.JSONDecodeError):
                        pass
    return summary


def _benchmark_judge(rec: dict) -> dict[str, Any]:
    run_layout = RUNS_ROOT / rec.get("ground_truth_domain", "") / rec.get("run_id", "")
    evals = list(run_layout.glob("hunter_brain_subtasks/*/artifacts/backend-runs/*/autopenbench-evaluation.json"))
    if not evals:
        return {"judge_present": False}
    try:
        evaluation = json.loads(evals[0].read_text(encoding="utf-8"))
        judge = evaluation.get("judge") or {}
        return {
            "judge_present": True,
            "judge_success": bool(judge.get("success")),
            "submitted_flags": bool(judge.get("submitted_answers")),
            "oracle": judge.get("oracle"),
            "result": evaluation.get("result"),
        }
    except Exception:
        return {"judge_present": False}


def _trudi_metrics(rec: dict) -> dict[str, Any]:
    out: dict[str, Any] = {"tool_calls": None, "reason_calls": None, "dair_calls": None, "trace_present": None}
    for child in rec.get("children") or []:
        if child.get("agent_id") != "trudi":
            continue
        metrics = child.get("metrics") or {}
        out["tool_calls"] = metrics.get("tool_calls")
        out["reason_calls"] = metrics.get("reason_calls")
        out["dair_calls"] = metrics.get("dair_calls")
        out["trace_present"] = any(
            a.get("type") in {"dfir_execution_trace", "dfir_raw_result"} for a in (child.get("artifacts") or [])
        )
    return out


# --------------------------------------------------------------------------- #
# Failure taxonomy classification
# --------------------------------------------------------------------------- #

def classify(case: dict, rec: dict) -> dict[str, Any]:
    case_id = case["case_id"]
    truth = rec.get("completion_truth")
    verdict = (truth or {}).get("verdict")
    reason = (truth or {}).get("reason")
    orch = rec.get("orchestration_status")
    children = rec.get("children") or []

    # routing check: first dispatched capability vs ground-truth domain
    predicted = None
    dispatch = rec.get("dispatch") or []
    if dispatch:
        predicted = dispatch[0].get("capability_id")
    rec["predicted_capability"] = predicted
    rec["routing_correct"] = predicted == case["ground_truth_domain"]

    if rec.get("runtime_available") is False:
        return {"category": "RUNTIME_UNAVAILABLE", "reason": rec.get("runtime_unavailable_reason"), "verdict": None}
    if rec.get("benchmark_available") is False:
        return {"category": "BENCHMARK_MISSING", "reason": rec.get("benchmark_unavailable_reason"), "verdict": None}

    if verdict == "verified":
        if orch == "complete":
            return {"category": "VERIFIED_SUCCESS", "reason": reason or "verified", "verdict": verdict}
        return {"category": "VERIFICATION_FAILURE", "reason": reason or "verified_no_complete", "verdict": verdict}
    if orch == "complete":
        return {"category": "FALSE_SUCCESS", "reason": "complete_without_verified_truth", "verdict": verdict}
    if verdict in {"inconclusive", "unavailable"}:
        if case_id.endswith("-fixed") or case.get("measurement_role") == "negative_control_honesty":
            return {"category": "INCONCLUSIVE_NEGATIVE", "reason": reason or "inconclusive", "verdict": verdict}
        return {"category": "INCONCLUSIVE_NEGATIVE", "reason": reason or "inconclusive", "verdict": verdict}

    if orch in {"model_error", "invalid_decisions"}:
        if orch == "model_error":
            return {"category": "SUPERVISOR_CONTRACT_FAILURE", "reason": reason or "model_error", "verdict": None}
        rejected = rec.get("decision_ingress", {}).get("supervisor_decision_rejections") or []
        codes = {item.get("code") for item in rejected}
        if "repeated_no_progress_decision" in codes:
            return {"category": "NO_PROGRESS", "reason": reason or "repeated_no_progress", "verdict": None}
        return {"category": "INVALID_DECISION_EXHAUSTION", "reason": reason or "invalid_decisions", "verdict": None}

    if orch == "adapter_unavailable":
        return {"category": "RUNTIME_UNAVAILABLE", "reason": reason or "adapter_unavailable", "verdict": None}
    if orch == "invocation_contract_failed":
        return {"category": "INVOCATION_CONTRACT_ERROR", "reason": reason or "invocation_contract_failed", "verdict": None}
    if orch == "budget_exhausted":
        contributing = []
        for child in children:
            err = child.get("error") or {}
            if err.get("code"):
                contributing.append(f"{child.get('agent_id')}:{err.get('code')}")
        return {"category": "BUDGET_EXHAUSTED", "reason": reason or "budget_exhausted", "verdict": None, "contributing_factors": contributing or None}
    if orch == "verification_failed":
        return {"category": "VERIFICATION_FAILURE", "reason": reason or "verification_failed", "verdict": None}

    # blocked / verification_required / other incomplete: look at child outcomes
    first_child = children[0] if children else {}
    contributing: list[str] = []
    for child in children:
        err = child.get("error") or {}
        code = err.get("code") or ""
        if code:
            contributing.append(f"{child.get('agent_id')}:{code}")
    if first_child.get("status") == "timeout":
        return {"category": "TIMEOUT", "reason": "backend_timeout_no_complete", "verdict": None, "contributing_factors": contributing or None}
    child_errors = []
    for child in children:
        err = child.get("error") or {}
        if err:
            child_errors.append({"agent": child.get("agent_id"), "code": err.get("code"), "category": err.get("category")})
    for child in children:
        err = child.get("error") or {}
        code = err.get("code") or ""
        if code == "KONG_SEMANTIC_OUTPUT_INSUFFICIENT":
            return {"category": "BACKEND_SEMANTIC_FAILURE", "reason": code, "verdict": None, "contributing_factors": contributing or None}
        if code == "TIMEOUT":
            return {"category": "TIMEOUT", "reason": code, "verdict": None, "contributing_factors": contributing or None}
    if child_errors:
        return {"category": "BACKEND_PROCESS_FAILURE", "reason": json.dumps(child_errors, ensure_ascii=False)[:300], "verdict": None, "contributing_factors": contributing or None}
    if not children:
        return {"category": "SUPERVISOR_CONTRACT_FAILURE", "reason": f"terminal_{orch or 'none'}_no_child", "verdict": None}
    return {"category": "SEARCH_FAILURE", "reason": f"terminal_{orch or 'none'}", "verdict": None, "contributing_factors": contributing or None}


# --------------------------------------------------------------------------- #
# Run execution
# --------------------------------------------------------------------------- #

def _record_base(case: dict, run_id: str, repetition_index: int, harness_sha: str | None) -> dict:
    return {
        "experiment_id": EXPERIMENT_ID,
        "run_id": run_id,
        "case_id": case["case_id"],
        "repetition_index": repetition_index,
        "phase3e_snapshot_sha": "aa7dc1d",
        "evaluation_harness_sha": harness_sha,
        "domain": case["domain"],
        "tier": case.get("tier"),
        "ground_truth_domain": case["ground_truth_domain"],
        "evaluation_id": EXPERIMENT_ID,
        "started_at": datetime.now(UTC).isoformat(),
    }


async def _run_one(case: dict, runs_root: Path, repetition_index: int) -> dict:
    harness_sha = _harness_sha()
    run_id = f"phase3e-{case['case_id'].replace('-', '_')}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:5]}"
    started = time.monotonic()
    rec = _record_base(case, run_id, repetition_index, harness_sha)
    try:
        runs_root.mkdir(parents=True, exist_ok=True)
        task, input_meta = build_task(case, run_id, runs_root)
        rec["input"] = input_meta
        rec["budget_seconds"] = case.get("budget_seconds")
        rec["budget_profile"] = case.get("budget_profile")
        rec["orchestration_limits"] = {
            "max_decisions": ORCHESTRATION_LIMITS.max_decisions,
            "max_capability_calls": ORCHESTRATION_LIMITS.max_capability_calls,
            "max_rejected_decisions": ORCHESTRATION_LIMITS.max_rejected_decisions,
        }

        # evidence availability
        if case["domain"] == "pentest":
            rec["evidence_sha_verified"] = None
            rec["evidence_supported"] = True
        elif case["input"]["kind"] == "directory":
            src = ROOT / case["input"]["path"]
            rec["evidence_present"] = src.is_dir()
            rec["evidence_sha256"] = None
            rec["evidence_sha_verified"] = None
            rec["evidence_supported"] = src.is_dir()
        else:
            src = ROOT / case["input"]["path"]
            rec["evidence_present"] = src.is_file()
            expected = case["input"].get("sha256")
            actual = hashlib.sha256(src.read_bytes()).hexdigest() if src.is_file() else None
            rec["evidence_sha256"] = actual
            rec["evidence_sha_verified"] = bool(expected) and actual == expected
            rec["evidence_supported"] = rec["evidence_sha_verified"]

        # runtime/benchmark availability via the frozen adapter healthchecks
        pentest_adapter = _pentest_adapter_for(case)
        rec["runtime"] = {"available": True, "checks": {}}
        if pentest_adapter is not None:
            health = await pentest_adapter.healthcheck(task)
            rec["benchmark_available"] = health.available
            rec["benchmark_unavailable_reason"] = health.error.message if health.error else None
            rec["runtime"]["checks"]["autopenbench"] = health.details
        elif case["domain"] == "vulnerability_research":
            from integrations.fuzzingbrain import FuzzingBrainAdapter
            adapter = FuzzingBrainAdapter(repo_root=ROOT)
            health = await adapter.healthcheck(task)
            rec["benchmark_available"] = health.available
            rec["benchmark_unavailable_reason"] = health.error.message if health.error else None
            rec["runtime"]["checks"]["fuzzingbrain"] = health.details
        elif case["domain"] == "reverse":
            from integrations.kong import KongAdapter
            adapter = KongAdapter(repo_root=ROOT)
            health = await adapter.healthcheck(task)
            rec["benchmark_available"] = health.available
            rec["benchmark_unavailable_reason"] = health.error.message if health.error else None
            rec["runtime"]["checks"]["kong"] = health.details
        elif case["domain"] == "dfir":
            from integrations.trudi.adapter import TrudiAdapter
            adapter = TrudiAdapter(repo_root=ROOT, mode=case.get("trudi_mode", "lite"))
            health_task = TaskSpec(
                task_id=f"{run_id}-dfir-healthcheck",
                domain="dfir",
                target=task.target,
                goal="Healthcheck.",
                metadata={
                    "trudi_mode": case.get("trudi_mode", "lite"),
                    "semantic_input_type": "evidence_file",
                    "file_type": {"normalized_type": "evidence_file", "sha256": rec.get("evidence_sha256")},
                },
            )
            health = await adapter.healthcheck(health_task)
            rec["benchmark_available"] = health.available
            rec["benchmark_unavailable_reason"] = health.error.message if health.error else None
            rec["runtime"]["checks"]["trudi"] = health.details
            if case["case_id"].startswith("cross-domain"):
                rec["trudi_mode"] = "lite"
            else:
                rec["trudi_mode"] = case.get("trudi_mode")

        runtime_ok = rec.get("runtime", {}).get("available", True)
        benchmark_ok = rec.get("benchmark_available", True)
        rec["runtime_available"] = bool(runtime_ok)
        rec["benchmark_available"] = bool(benchmark_ok)
        if not rec["runtime_available"]:
            rec["runtime_unavailable_reason"] = "healthcheck failed"
        if not rec["benchmark_available"]:
            rec["benchmark_unavailable_reason"] = rec.get("benchmark_unavailable_reason")

        # If runtime/benchmark unavailable, still execute? No: record availability
        # failure, do not burn the run. The orchestrator would block anyway.
        if not (runtime_ok and benchmark_ok):
            rec["hunter_top_level"] = "not_run_availability"
            rec["orchestration_status"] = "blocked"
            rec["elapsed_seconds"] = round(time.monotonic() - started, 2)
            rec["supervisor_usage"] = {"model_calls": 0, "prompt_tokens": None, "completion_tokens": None, "reasoning_tokens": None, "total_tokens": None}
            rec["classification"] = classify(case, rec)
            return _finalize(case, rec)

        limits = ORCHESTRATION_LIMITS
        executor, capturer = _bounded_executor(
            runs_root, limits, pentest_adapter=pentest_adapter, trudi_mode=case.get("trudi_mode", "lite")
        )
        result = await executor.execute(task)
        rec["elapsed_seconds"] = round(time.monotonic() - started, 2)
        rec["hunter_top_level"] = result.status.value
        rec["orchestration_status"] = result.raw_output.get("orchestration_status")
        rec["completion_truth"] = result.raw_output.get("completion_truth")
        rec["terminal_decision"] = result.raw_output.get("terminal_decision")
        rec["terminal_error"] = result.error.to_dict() if result.error else None
        rec["agent_result"] = {
            "status": result.status.value,
            "agent_id": result.agent_id,
            "metrics": result.metrics,
        }
        rec["supervisor_decisions"] = _accepted_decisions(runs_root, run_id)
        rec["decision_ingress"] = _decision_ingress_metrics(runs_root, run_id, capturer)
        rec["supervisor_usage"] = _supervisor_usage(capturer)
        rec["raw_model_output_count"] = len(capturer.raw_outputs)

        world = result.raw_output.get("world_state") or {}
        rec["dispatch"] = world.get("dispatch_history")
        rec["canonical_facts"] = len(world.get("facts", []))
        rec["canonical_evidence"] = len(world.get("evidence", []))
        rec["canonical_artifacts"] = len(world.get("artifacts", []))
        rec["children"] = _child_summaries(runs_root, run_id)
        rec["handoff_count"] = max(len(rec["dispatch"]) - 1, 0) if rec["dispatch"] else 0

        if case["domain"] == "pentest":
            rec["benchmark_judge"] = _benchmark_judge(rec)
        elif case["domain"] == "reverse":
            rec["reverse_analysis"] = _reverse_analysis_summary(rec)
        elif case["domain"] == "dfir":
            rec["trudi_metrics"] = _trudi_metrics(rec)
        rec["backend_model_usage"] = _backend_model_usage(case, rec)
        rec["classification"] = classify(case, rec)
    except Exception as exc:  # pragma: no cover - defensive
        rec["error"] = f"{type(exc).__name__}: {exc}"
        rec["classification"] = {"category": "RUNTIME_UNAVAILABLE", "reason": str(exc), "verdict": None}
    return _finalize(case, rec)


def _finalize(case: dict, rec: dict) -> dict:
    rec["finished_at"] = datetime.now(UTC).isoformat()
    rec["false_success"] = rec["classification"].get("category") == "FALSE_SUCCESS"
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    with (RESULTS_ROOT / f"{case['case_id']}.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    return rec


# --------------------------------------------------------------------------- #
# Step A dry validation
# --------------------------------------------------------------------------- #

def _validate() -> int:
    print(f"=== Phase 3E Step A dry validation ({EXPERIMENT_ID}) ===", flush=True)
    problems: list[str] = []
    manifest = json.loads((EVAL_ROOT / "phase3e_manifest.json").read_text(encoding="utf-8"))
    print(f"manifest freeze: hunter={manifest['commits']['hunter_agent']}", flush=True)
    for case in CASES:
        print(f"-- case {case['case_id']} (domain={case['domain']}, budget={case['budget_seconds']}s)", flush=True)
        if case["domain"] == "pentest":
            try:
                game = _game(case["benchmark"]["case"])
                print(f"   benchmark resolves: target={game['target']} task_len={len(str(game['task']))}", flush=True)
            except Exception as exc:
                problems.append(f"{case['case_id']}: benchmark resolve failed: {exc}")
        else:
            src = ROOT / case["input"]["path"]
            if case["input"]["kind"] == "directory":
                if not src.is_dir():
                    problems.append(f"{case['case_id']}: evidence dir missing {src}")
                else:
                    print(f"   evidence directory present: {src.name}", flush=True)
            else:
                if not src.is_file():
                    problems.append(f"{case['case_id']}: evidence missing {src}")
                else:
                    actual = hashlib.sha256(src.read_bytes()).hexdigest()
                    expected = case["input"].get("sha256")
                    status = "OK" if actual == expected else "MISMATCH"
                    if actual != expected:
                        problems.append(f"{case['case_id']}: SHA mismatch expected={expected} got={actual}")
                    print(f"   evidence sha256 {status}: {actual[:16]}...", flush=True)
        # build the task spec (no backend execution)
        try:
            task, _meta = build_task(
                case,
                f"validate-{case['case_id'][:40]}-{uuid.uuid4().hex[:6]}",
                RUNS_ROOT / case["domain"],
            )
            print(f"   task built: domain={task.domain} target_type={task.input_object.kind if task.input_object else None} timeout={task.timeout}", flush=True)
        except Exception as exc:
            problems.append(f"{case['case_id']}: task build failed: {exc}")

    # result writer check
    probe = RESULTS_ROOT / "_probe.jsonl"
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_text(json.dumps({"probe": True, "at": datetime.now(UTC).isoformat()}) + "\n", encoding="utf-8")
    line = probe.read_text(encoding="utf-8").strip()
    ok = json.loads(line).get("probe") is True
    probe.unlink(missing_ok=True)
    print(f"result writer probe: {'OK' if ok else 'FAILED'}", flush=True)
    if not ok:
        problems.append("result writer probe failed")

    print(f"harness sha: {_harness_sha()}", flush=True)
    if problems:
        print("PROBLEMS:", flush=True)
        for p in problems:
            print("  -", p, flush=True)
        return 1
    print("VALIDATION OK", flush=True)
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

async def _run_cases(case_ids: list[str] | None, repetitions: int, from_repetition: int) -> int:
    selected = [c for c in CASES if case_ids is None or c["case_id"] in case_ids]
    for case in selected:
        for rep in range(from_repetition, from_repetition + repetitions):
            print(f"=== RUN {case['case_id']} repetition {rep} ===", flush=True)
            rec = await _run_one(case, RUNS_ROOT / case["domain"], rep)
            cls = rec.get("classification", {}).get("category")
            print(
                f"  {case['case_id']}[{rep}] | hunter={rec.get('hunter_top_level')} "
                f"orch={rec.get('orchestration_status')} truth={(rec.get('completion_truth') or {}).get('verdict')} "
                f"class={cls} elapsed={rec.get('elapsed_seconds')}s",
                flush=True,
            )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Hunter Phase 3E capability benchmark harness")
    parser.add_argument("--validate", action="store_true", help="Step A dry validation (no backend execution)")
    parser.add_argument("--case", help="run only this case_id")
    parser.add_argument("--repetitions", type=int, default=1, help="number of independent repetitions")
    parser.add_argument("--from-repetition", type=int, default=1, help="first repetition index")
    args = parser.parse_args()
    if args.validate:
        return _validate()
    _ensure_env()
    case_ids = [args.case] if args.case else None
    return asyncio.run(_run_cases(case_ids, args.repetitions, args.from_repetition))


if __name__ == "__main__":
    raise SystemExit(main())
