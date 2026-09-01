#!/usr/bin/env python3
"""Hunter-Agent Phase 3C completion-truth evaluation harness.

Runs each phase3c case through the real default Hunter entry and records the
deterministic completion-truth verdict (VERIFIED / NOT_VERIFIED / INCONCLUSIVE /
UNAVAILABLE) produced by ``GlobalVerifier.verify_completion``. No professional
backend is called directly; every result flows through the Hunter orchestrator
and canonical world state. Benchmark ground truth (expected reverse backdoor
functions, cross-domain provenance marker) is attached only through the
evaluation-layer ``completion_oracle`` metadata.

Each run is recorded as one JSON line in evaluation/phase3c_results/<case_id>.jsonl.
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

CONFIG_DB = ROOT / ".runtime/kong/config/config.db"
EVAL_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = Path(os.environ.get("HUNTER_PHASE3C_RESULTS", str(EVAL_ROOT / "phase3c_results")))
RUNS_ROOT = ROOT / ".runtime" / "phase3c-runs"
CASES = json.loads((EVAL_ROOT / "phase3c_cases.json").read_text(encoding="utf-8"))["cases"]


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


class CapturingModel:
    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.decisions: list[dict] = []
        self.usage: list[dict] = []

    async def decide(self, *, system_instructions: str, context: dict) -> Any:
        result = await self.inner.decide(
            system_instructions=system_instructions, context=context
        )
        self.decisions.append(dict(result.value))
        if isinstance(result.usage, dict):
            self.usage.append(result.usage)
        return result


def _bounded_executor(
    runs_root: Path, limits: OrchestrationLimits, *, pentest_adapter: Any = None
) -> HunterBrainTaskExecutor:
    catalog = default_catalog()
    adapters = build_hunter_brain_adapters(repo_root=ROOT, pentest_adapter=pentest_adapter)
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


def _game(case: str) -> dict:
    games = json.loads(
        (ROOT.parent / "AutoPenBench" / "data" / "games.json").read_text(encoding="utf-8")
    )
    level, category, vm = case.split("/")
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
    from dataclasses import replace

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
    from dataclasses import replace

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


def _compile_elf(path: Path) -> Path:
    source = path.with_suffix(".c")
    source.write_text(
        "#include <string.h>\n"
        "static int rot13(int c) { return (c >= 'a' && c <= 'z') ? 'a' + (c - 'a' + 13) % 26 : c; }\n"
        "int check_payload(const char* data) { return data && data[0] == 0x41 && data[1] == 0x42; }\n"
        "const char* banner(void) { return \"hunter-e2e-marker\"; }\n"
        "int main(int argc, char** argv) { const char* data = argc > 1 ? argv[1] : \"AB\"; "
        "return check_payload(data) ? 0 : rot13(banner()[0]); }\n",
        encoding="utf-8",
    )
    subprocess.run(["gcc", "-o", str(path), str(source)], check=True, capture_output=True)
    return path


def _cross_domain_task(run_id: str, runs_root: Path, case: dict) -> tuple[TaskSpec, dict[str, Any]]:
    elf = ROOT / ".runtime/live-smoke/samples/evidence_suspect"
    elf.parent.mkdir(parents=True, exist_ok=True)
    _compile_elf(elf)
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
                entry["summary"] = result.summary
                entry["metrics"] = result.metrics
                entry["error"] = result.error.to_dict() if result.error else None
            except Exception as exc:
                entry["error"] = f"{type(exc).__name__}: {exc}"
        out.append(entry)
    return out


async def _run_one(case: dict, runs_root: Path) -> dict:
    run_id = f"phase3c-{case['case_id'].replace('-', '_')}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:5]}"
    started = time.monotonic()
    rec: dict = {
        "run_id": run_id,
        "case_id": case["case_id"],
        "ground_truth_domain": case["domain"],
        "evaluation_id": "phase3c_2026-08-31",
        "started_at": datetime.now(UTC).isoformat(),
    }
    try:
        runs_root.mkdir(parents=True, exist_ok=True)
        domain = case["domain"]
        pentest_adapter = None
        if domain == "pentest":
            game = _game(case["benchmark"]["case"])
            task = _pentest_task(
                run_id, runs_root, game, case["benchmark"]["case"],
                budget_seconds=case.get("budget_seconds", 900),
            )
            rec["input"] = {"benchmark_case": case["benchmark"]["case"], "target": str(game["target"])}
            from autopenbench_adapter.protocol import AutoPenBenchProtocolAdapter

            level, category, vm = case["benchmark"]["case"].split("/")
            index = int(vm[len("vm"):]) if vm.startswith("vm") else int(vm)
            pentest_adapter = AutoPenBenchProtocolAdapter(level=level, category=category, vm=index)
            rec["adapter_config"] = {"level": level, "category": category, "vm": index}
        elif domain == "reverse":
            task = _reverse_task(run_id, runs_root, case)
            rec["input"] = {"file": case["input"]["path"], "sha256": case["input"].get("sha256")}
        elif domain == "dfir" and case["case_id"].startswith("cross-domain"):
            task, evidence = _cross_domain_task(run_id, runs_root, case)
            rec["input"] = {"file": evidence["path"], "sha256": evidence["sha256"]}
        else:
            task = _vr_task(run_id, runs_root, case)
            rec["input"] = {"directory": case["input"]["path"]}
        limits = OrchestrationLimits(max_decisions=8, max_capability_calls=3, max_rejected_decisions=3)
        executor, capturer = _bounded_executor(
            runs_root, limits, pentest_adapter=pentest_adapter
        )
        result = await executor.execute(task)
        rec["elapsed_seconds"] = round(time.monotonic() - started, 2)
        rec["hunter_top_level"] = result.status.value
        rec["orchestration_status"] = result.raw_output.get("orchestration_status")
        rec["completion_truth"] = result.raw_output.get("completion_truth")
        rec["terminal_decision"] = result.raw_output.get("terminal_decision")
        rec["terminal_error"] = result.error.to_dict() if result.error else None
        rec["supervisor_decisions"] = capturer.decisions
        world = result.raw_output.get("world_state") or {}
        rec["dispatch"] = world.get("dispatch_history")
        rec["canonical_facts"] = len(world.get("facts", []))
        rec["canonical_evidence"] = len(world.get("evidence", []))
        rec["canonical_artifacts"] = len(world.get("artifacts", []))
        rec["children"] = _child_summaries(runs_root, run_id)
        if domain == "pentest":
            evals = list(
                runs_root.glob(
                    f"{run_id}/hunter_brain_subtasks/*/artifacts/backend-runs/*/autopenbench-evaluation.json"
                )
            )
            if evals:
                try:
                    evaluation = json.loads(evals[0].read_text(encoding="utf-8"))
                    judge = evaluation.get("judge") or {}
                    rec["benchmark_judge_success"] = bool(judge.get("success"))
                    rec["benchmark_submitted_flag"] = bool(judge.get("submitted_answers"))
                    rec["benchmark_oracle"] = judge.get("oracle")
                    rec["benchmark_result"] = evaluation.get("result")
                except Exception:
                    rec["benchmark_judge_success"] = False
            else:
                rec["benchmark_judge_success"] = False
        rec["cross_domain_handoff_count"] = max(len(rec["dispatch"]) - 1, 0) if rec["dispatch"] else 0
        rec["classification"] = classify(case, rec)
    except Exception as exc:  # pragma: no cover - defensive
        rec["error"] = f"{type(exc).__name__}: {exc}"
        rec["classification"] = {"category": "ENVIRONMENT_FAILURE", "reason": str(exc)}
    finally:
        rec["finished_at"] = datetime.now(UTC).isoformat()
        RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
        with (RESULTS_ROOT / f"{case['case_id']}.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    return rec


def classify(case: dict, rec: dict) -> dict[str, Any]:
    truth = rec.get("completion_truth")
    verdict = (truth or {}).get("verdict")
    reason = (truth or {}).get("reason")
    orch = rec.get("orchestration_status")
    if verdict == "not_verified":
        return {
            "category": "NOT_VERIFIED",
            "reason": reason or "completion_verifier_rejected",
            "verdict": verdict,
        }
    if verdict == "inconclusive":
        return {"category": "INCONCLUSIVE", "reason": reason or "completion_inconclusive", "verdict": verdict}
    if verdict == "unavailable":
        return {"category": "UNAVAILABLE", "reason": reason or "benchmark_unavailable", "verdict": verdict}
    if verdict == "verified":
        if orch == "complete":
            return {"category": "VERIFIED_SUCCESS", "reason": reason or "verified", "verdict": verdict}
        return {"category": "VERIFIED_BUT_NOT_COMPLETE", "reason": reason or "verified_no_complete", "verdict": verdict}
    first_child = (rec.get("children") or [{}])[0] if rec.get("children") else {}
    if first_child.get("status") == "timeout":
        return {"category": "TIMEOUT", "reason": "backend_timeout_no_complete", "verdict": None}
    if orch == "complete":
        return {"category": "FALSE_SUCCESS", "reason": "complete_without_verified_truth", "verdict": verdict}
    if orch in {"model_error", "invalid_decisions", "invocation_contract_failed", "adapter_unavailable", "budget_exhausted", "blocked"}:
        return {"category": "HONEST_INCOMPLETE", "reason": f"terminal_{orch}", "verdict": None}
    return {"category": "HONEST_INCOMPLETE", "reason": "no_complete_attempt", "verdict": None}


async def _run_one_with_retry(case: dict, runs_root: Path, *, retries: int) -> dict:
    """Run a case, retrying only when the run ended before any real backend
    work (supervisor contract rejection / model transport error). Those are the
    documented Phase 3B supervisor contract-flakiness cases, not measurements of
    completion truth. A run that dispatched any child is never retried.
    """

    for attempt in range(1 + max(retries, 0)):
        rec = await _run_one(case, runs_root)
        dispatched = bool(rec.get("children"))
        category = (rec.get("classification") or {}).get("category")
        if dispatched or category not in {"HONEST_INCOMPLETE"} or attempt == retries:
            return rec
        orch = rec.get("orchestration_status")
        if orch not in {"invalid_decisions", "model_error", "adapter_unavailable"}:
            return rec
        print(
            f"  retrying {case['case_id']} (attempt {attempt + 1} terminal {orch}, no backend dispatched)",
            flush=True,
        )
    return rec


async def main() -> int:
    parser = argparse.ArgumentParser(description="Hunter Phase 3C completion-truth evaluation")
    parser.add_argument("--case", help="run only this case_id")
    parser.add_argument(
        "--retries", type=int, default=0,
        help="bounded retries for runs that ended before dispatching any backend",
    )
    args = parser.parse_args()
    _ensure_env()
    cases = [c for c in CASES if args.case is None or c["case_id"] == args.case]
    for case in cases:
        print(f"=== RUN {case['case_id']} ===", flush=True)
        (RESULTS_ROOT / f"{case['case_id']}.jsonl").unlink(missing_ok=True)
        rec = await _run_one_with_retry(case, RUNS_ROOT / case["domain"], retries=args.retries)
        print(
            f"  {rec.get('case_id')} | hunter={rec.get('hunter_top_level')} "
            f"orch={rec.get('orchestration_status')} truth={(rec.get('completion_truth') or {}).get('verdict')} "
            f"class={rec.get('classification', {}).get('category')} elapsed={rec.get('elapsed_seconds')}s",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
