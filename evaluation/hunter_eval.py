#!/usr/bin/env python3
"""Hunter-Agent Phase 3A evaluation harness.

Runs each case through the real default Hunter entry (Layer-1 -> Supervisor ->
orchestrator -> real adapter). No professional backend is called directly; every
result flows through the Hunter orchestrator and canonical world state. Each run
is recorded as one JSON line in evaluation/results/<case_id>.jsonl.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
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
from hunter_brain.orchestrator import (  # noqa: E402
    HunterOrchestrator,
    OrchestrationLimits,
)
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
RESULTS_ROOT = EVAL_ROOT / "results"
RUNS_ROOT = ROOT / ".runtime" / "eval-runs"
CASES = json.loads((EVAL_ROOT / "case_manifest.json").read_text(encoding="utf-8"))["cases"]


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
    adapters = build_hunter_brain_adapters(
        repo_root=ROOT, pentest_adapter=pentest_adapter
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


def _game(case: str) -> dict:
    games = json.loads(
        (ROOT.parent / "AutoPenBench" / "data" / "games.json").read_text(encoding="utf-8")
    )
    level, category, vm = case.split("/")
    index = int(vm[len("vm"):]) if vm.startswith("vm") else int(vm)
    return games[level][category][index]


def _pentest_task(run_id: str, runs_root: Path, game: dict, case_path: str) -> TaskSpec:
    target = str(game["target"])
    task_str = str(game["task"])
    workspace = runs_root / run_id
    workspace.mkdir(parents=True, exist_ok=True)
    task = TaskSpec(
        task_id=run_id,
        domain="pentest",
        target=target,
        goal=task_str,
        timeout=240,
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
    staging_parent = source.parent
    runs = runs_root
    runs.mkdir(parents=True, exist_ok=True)
    spec = prepare_task(
        source,
        runs_root=runs,
        allowed_roots=(staging_parent, runs),
        task_id=run_id,
        goal=(
            "Audit the supplied local C project for a reproducible crash vulnerability."
        ),
        limits=IntakeLimits(max_input_bytes=300 * 1024 * 1024),
    )
    from dataclasses import replace

    spec = replace(spec, timeout=300)
    atomic_write_json(Path(spec.workspace) / "task.json", spec.to_dict())
    return spec


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
                entry["evidence"] = len(result.evidence)
                entry["artifact_types"] = [a.type for a in result.artifacts]
                entry["summary"] = result.summary
                entry["metrics"] = result.metrics
                entry["error"] = result.error.to_dict() if result.error else None
            except Exception as exc:
                entry["error"] = f"{type(exc).__name__}: {exc}"
        out.append(entry)
    return out


def _ground_truth_hit(case: dict, world: dict, children: list[dict]) -> bool:
    gt = case["ground_truth"]
    if gt["type"] == "flag":
        return False  # flag captured would be detected elsewhere; not reachable in bounded run
    if gt["type"] == "crash":
        trigger_count = sum(
            c.get("artifact_types", []).count("trigger_sample") for c in children
        )
        expected = bool(gt.get("expected", True))
        if expected:
            return trigger_count > 0
        # "no crash expected" is only verified when the fuzz run actually finished.
        statuses = [c.get("status") for c in children]
        return trigger_count == 0 and bool(statuses) and all(s != "timeout" for s in statuses)
    return False


def classify(case: dict, rec: dict) -> tuple[str, list[str]]:
    gt_domain = case["domain"]
    first_invoke = next(
        (d for d in rec["supervisor_decisions"] if d.get("action") == "invoke_capability"),
        None,
    )
    selected = first_invoke.get("capability_id") if first_invoke else None
    contributing: list[str] = []
    orch = rec["orchestration_status"]
    children = rec.get("children") or []
    if children:
        child = children[0]
        if child["status"] == "timeout":
            return "TIMEOUT", contributing
        if child["status"] == "failed":
            code = (child.get("error") or {}).get("code", "")
            if code and code.startswith("AUTOPENBENCH_"):
                return "INVOCATION_CONTRACT_ERROR", contributing
            return "BACKEND_START_FAILURE", contributing
        if rec["ground_truth_hit"]:
            return "SUCCESS", contributing
        if rec["hunter_top_level"] == "success" and orch == "complete":
            return "FALSE_SUCCESS", contributing
        if rec["hunter_top_level"] == "partial":
            return "SEARCH_OR_REASONING_FAILURE", contributing
        return "GROUND_TRUTH_NOT_REACHED", contributing
    if orch == "model_error":
        return "MODEL_ERROR", contributing
    if not children and orch == "invalid_decisions":
        return "INVALID_DECISIONS", contributing
    if selected != gt_domain:
        return "ROUTING_ERROR", contributing
    if orch == "invocation_contract_failed":
        return "INVOCATION_CONTRACT_ERROR", contributing
    return "BACKEND_START_FAILURE", contributing


async def _run_one(case: dict, runs_root: Path) -> dict:
    run_id = f"eval-{case['case_id'].replace('-', '_')}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:5]}"
    started = time.monotonic()
    rec: dict = {
        "run_id": run_id,
        "case_id": case["case_id"],
        "ground_truth_domain": case["domain"],
        "evaluation_id": "baseline_2026-08-31",
        "started_at": datetime.now(UTC).isoformat(),
    }
    try:
        runs_root.mkdir(parents=True, exist_ok=True)
        if case["domain"] == "pentest":
            game = _game(case["benchmark"]["case"])
            task = _pentest_task(run_id, runs_root, game, case["benchmark"]["case"])
            rec["input"] = {"benchmark_case": case["benchmark"]["case"], "target": str(game["target"])}
        else:
            task = _vr_task(run_id, runs_root, case)
            rec["input"] = {"directory": case["input"]["path"]}
        limits = OrchestrationLimits(max_decisions=8, max_capability_calls=3, max_rejected_decisions=3)
        pentest_adapter = None
        if case["domain"] == "pentest":
            from autopenbench_adapter.protocol import AutoPenBenchProtocolAdapter

            level, category, vm = case["benchmark"]["case"].split("/")
            index = int(vm[len("vm"):]) if vm.startswith("vm") else int(vm)
            pentest_adapter = AutoPenBenchProtocolAdapter(
                level=level, category=category, vm=index
            )
            rec["adapter_config"] = {
                "level": level, "category": category, "vm": index,
            }
        executor, capturer = _bounded_executor(
            runs_root, limits, pentest_adapter=pentest_adapter
        )
        result = await executor.execute(task)
        rec["elapsed_seconds"] = round(time.monotonic() - started, 2)
        rec["hunter_top_level"] = result.status.value
        rec["orchestration_status"] = result.raw_output.get("orchestration_status")
        rec["supervisor_decisions"] = capturer.decisions
        rec["supervisor_prompt_tokens"] = sum(u.get("prompt_tokens", 0) for u in capturer.usage)
        rec["supervisor_completion_tokens"] = sum(u.get("completion_tokens", 0) for u in capturer.usage)
        world = result.raw_output.get("world_state") or {}
        rec["dispatch"] = world.get("dispatch_history")
        rec["canonical_facts"] = len(world.get("facts", []))
        rec["canonical_evidence"] = len(world.get("evidence", []))
        rec["canonical_artifacts"] = len(world.get("artifacts", []))
        rec["children"] = _child_summaries(runs_root, run_id)
        rec["ground_truth_hit"] = _ground_truth_hit(case, world, rec["children"])
        rec["cross_domain_handoff_count"] = max(
            len(rec["dispatch"]) - 1, 0
        ) if rec["dispatch"] else 0
        primary, contributing = classify(case, rec)
        rec["primary_failure_category"] = primary
        rec["contributing_factors"] = contributing
    except Exception as exc:  # pragma: no cover - defensive
        rec["error"] = f"{type(exc).__name__}: {exc}"
        rec["primary_failure_category"] = "ENVIRONMENT_FAILURE"
    finally:
        rec["finished_at"] = datetime.now(UTC).isoformat()
        RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
        with (RESULTS_ROOT / f"{case['case_id']}.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    return rec


async def main() -> int:
    parser = argparse.ArgumentParser(description="Hunter Phase 3A evaluation harness")
    parser.add_argument("--case", help="run only this case_id")
    args = parser.parse_args()
    _ensure_env()
    cases = [c for c in CASES if args.case is None or c["case_id"] == args.case]
    for case in cases:
        print(f"=== RUN {case['case_id']} ===", flush=True)
        rec = await _run_one(case, RUNS_ROOT / case["domain"])
        print(
            f"  {rec.get('case_id')} | hunter={rec.get('hunter_top_level')} "
            f"orch={rec.get('orchestration_status')} gt_hit={rec.get('ground_truth_hit')} "
            f"primary={rec.get('primary_failure_category')} elapsed={rec.get('elapsed_seconds')}s",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
