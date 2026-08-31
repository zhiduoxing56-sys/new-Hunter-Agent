#!/usr/bin/env python3
"""Phase 2B live smoke: run one real professional backend through the default
Hunter entry (Intake -> TaskSpec -> Hunter Brain capability selection -> real
adapter -> AgentResult).

Uses the real four-domain registry, the real DeepSeek supervisor model and the
real professional adapters. The orchestration budget is kept minimal so the
smoke never escalates into large or costly runs. API keys are read from the
local Kong config database and are never printed.

Usage:
    pentestgpt-core/pentestgpt_agent/.venv/bin/python scripts/hunter_live_smoke.py \
        --domain dfir
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
from hunter_brain.orchestrator import (  # noqa: E402
    HunterOrchestrator,
    OrchestrationLimits,
)
from hunter_brain.invocation_bridge import PentestBenchmarkBridge  # noqa: E402
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
from autopenbench_adapter.protocol import AutoPenBenchProtocolAdapter  # noqa: E402

CONFIG_DB = ROOT / ".runtime" / "kong" / "config" / "config.db"
REPORT_ROOT = ROOT / ".runtime" / "live-smoke"
RUNS_ROOT = ROOT / ".runtime" / "live-runs"


def _load_deepseek_key() -> str:
    with sqlite3.connect(f"file:{CONFIG_DB}?mode=ro", uri=True) as database:
        row = database.execute(
            "SELECT value FROM config WHERE key = ?", ("custom_api_key",)
        ).fetchone()
    if not row or not isinstance(row[0], str) or not row[0].strip():
        raise SystemExit("DeepSeek key is missing from Kong config.db")
    return row[0].strip()


def _ensure_env() -> None:
    key = _load_deepseek_key()
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
            "KONG_CONFIG_DIR": str(ROOT / ".runtime" / "kong" / "config"),
            "KONG_PROVIDER": "custom",
            "KONG_BASE_URL": "https://api.deepseek.com",
            "KONG_MODEL": "deepseek-v4-flash",
        }
    )


def _run_id(domain: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"live-{domain}-{stamp}-{uuid.uuid4().hex[:6]}"


def _bounded_executor(runs_root: Path) -> tuple[HunterBrainTaskExecutor, CapturingModel]:
    catalog = default_catalog()
    adapters = build_hunter_brain_adapters(repo_root=ROOT)
    capturer = CapturingModel(
        DeepSeekDecisionModel(DeepSeekSupervisorConfig.from_env())
    )
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
            limits=OrchestrationLimits(
                max_decisions=5,
                max_capability_calls=1,
                max_rejected_decisions=3,
            ),
        )
    )
    return executor, capturer


class CapturingModel:
    """Wrap the real model to record raw decisions without altering them."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.decisions: list[dict] = []

    async def decide(self, *, system_instructions: str, context: dict) -> Any:
        result = await self.inner.decide(
            system_instructions=system_instructions, context=context
        )
        self.decisions.append(dict(result.value))
        return result


def _write_log(sample: Path, lines: list[str]) -> Path:
    sample.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return sample


def _dfir_sample() -> Path:
    root = REPORT_ROOT / "samples"
    root.mkdir(parents=True, exist_ok=True)
    return _write_log(
        root / "live_security.log",
        [
            "2026-08-31T08:11:22Z SECURITY 4625 An account failed to log on. SourceNetworkAddress: 10.0.0.7",
            "2026-08-31T08:11:23Z SECURITY 4624 An account was successfully logged on. SourceNetworkAddress: 10.0.0.7",
            "2026-08-31T08:12:01Z SYSTEM  7045 A service was installed in the system. ServiceName: EvtSvc",
        ],
    )


def _vulnerability_sample() -> Path:
    root = REPORT_ROOT / "samples"
    root.mkdir(parents=True, exist_ok=True)
    fixture = ROOT / "third_party" / "fuzzingbrain" / "fixtures" / "hunterdemo"
    project = root / "live_fuzz_project"
    if project.exists():
        import shutil

        shutil.rmtree(project)
    import shutil

    shutil.copytree(
        fixture,
        project,
        ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "results", "logs"),
    )
    return project


def _reverse_sample() -> Path:
    root = REPORT_ROOT / "samples"
    root.mkdir(parents=True, exist_ok=True)
    source = root / "sample.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    binary = root / "sample"
    import subprocess

    subprocess.run(["gcc", "-o", str(binary), str(source)], check=True, capture_output=True)
    return binary


def _task(
    domain: str,
    run_id: str,
    value: str | Path,
    *,
    goal: str,
    timeout: float,
    allowed_roots: tuple[Path, ...],
    metadata: dict | None = None,
) -> TaskSpec:
    runs = RUNS_ROOT / domain
    runs.mkdir(parents=True, exist_ok=True)
    from dataclasses import replace

    spec = prepare_task(
        value,
        runs_root=runs,
        allowed_roots=allowed_roots,
        task_id=run_id,
        goal=goal,
        limits=IntakeLimits(max_input_bytes=200 * 1024 * 1024),
    )
    if spec.timeout != timeout:
        spec = replace(spec, timeout=timeout)
        assert spec.workspace is not None
        atomic_write_json(Path(spec.workspace) / "task.json", spec.to_dict())
    return spec


def _child_summaries(runs_root: Path, parent_id: str) -> list[dict]:
    subtasks = runs_root / parent_id / "hunter_brain_subtasks"
    if not subtasks.is_dir():
        return []
    summaries = []
    for child_dir in sorted(subtasks.iterdir()):
        if not child_dir.is_dir():
            continue
        entry = {"child_id": child_dir.name}
        task_path = child_dir / "task.json"
        result_path = child_dir / "result.json"
        if task_path.is_file():
            task = TaskSpec.from_dict(json.loads(task_path.read_text(encoding="utf-8")))
            entry["domain"] = task.domain
        if result_path.is_file():
            try:
                layout = RunLayout.ensure(subtasks, TaskSpec.from_dict(
                    json.loads(task_path.read_text(encoding="utf-8"))
                ))
                result = layout.read_result()
                result.validate()
                entry["agent_result_validate"] = True
                entry["agent_id"] = result.agent_id
                entry["status"] = result.status.value
                entry["summary"] = result.summary
                entry["findings"] = len(result.findings)
                entry["evidence"] = len(result.evidence)
                entry["artifacts"] = len(result.artifacts)
                entry["metrics"] = result.metrics
                entry["error"] = result.error.to_dict() if result.error else None
                entry["artifact_types"] = [a.type for a in result.artifacts]
                raw = result.raw_output or {}
                entry["backend_returncode"] = raw.get("returncode")
                entry["backend_status"] = raw.get("backend_status")
            except Exception as exc:  # pragma: no cover - defensive
                entry["agent_result_validate"] = False
                entry["validation_error"] = f"{type(exc).__name__}: {exc}"
        entry["events"] = child_dir / "events.jsonl"
        entry["has_result_json"] = result_path.is_file()
        summaries.append(entry)
    return summaries


async def _pentest_parent_task(
    run_id: str, runs_root: Path, report: dict, *, launch_benchmark: bool = False
) -> tuple[TaskSpec, dict]:
    bench = AutoPenBenchProtocolAdapter()
    game = bench.game()
    expected_target = str(game.get("target", ""))
    expected_task = str(game.get("task", ""))
    report["benchmark_case"] = "in-vitro/web_security/vm0"
    report["benchmark_target"] = expected_target

    exact = TaskSpec(
        task_id=f"{run_id}-exact",
        domain="pentest",
        target=expected_target,
        goal=expected_task,
        timeout=60,
        workspace=str(runs_root / f"{run_id}-exact"),
        input_object=InputObject(
            "bench-input", "network_target", expected_target, source_name=expected_target
        ),
        target_object=TargetObject("bench-target", "network_target", expected_target),
        authorization=AuthorizationScope((expected_target,)),
        metadata={"input_kind": "network_target", "semantic_input_type": "network_target"},
    )
    try:
        layout = RunLayout.ensure(runs_root, exact)
        prepared = await bench.prepare(exact, layout)
        report["prepare_contract"] = {
            "status": "passes",
            "backend_input_has_command": bool(prepared.backend_input.get("command")),
            "note": "exact benchmark case passes AutoPenBench.prepare() target/goal gate",
        }
    except Exception as exc:
        report["prepare_contract"] = {
            "status": "fails",
            "error": f"{type(exc).__name__}: {exc}",
        }

    # In launch mode the parent goal IS the canonical benchmark task string so a
    # supervisor objective that copies it can pass prepare(); the run is tightly
    # bounded in wall time. Otherwise keep a paraphrase that only exercises the
    # benchmark-case gate without launching the docker benchmark.
    parent_goal = expected_task if launch_benchmark else (
        "Obtain authorized proof of access for the AutoPenBench in-vitro web target."
    )
    benchmark_metadata = (
        {
            "case_id": "in-vitro/web_security/vm0",
            "target": expected_target,
            "task": expected_task,
            "source": "autopenbench_games_json",
        }
        if launch_benchmark
        else None
    )
    parent = TaskSpec(
        task_id=run_id,
        domain="pentest",
        target=expected_target,
        goal=parent_goal,
        timeout=240 if launch_benchmark else 120,
        workspace=str(runs_root / run_id),
        input_object=InputObject(
            "bench-input", "network_target", expected_target, source_name=expected_target
        ),
        target_object=TargetObject("bench-target", "network_target", expected_target),
        authorization=AuthorizationScope((expected_target,)),
        metadata={
            "input_kind": "network_target",
            "semantic_input_type": "network_target",
            "semantic_input_rationale": [
                "AutoPenBench benchmark case identifier used as the authorized target"
            ],
            "launch_benchmark": launch_benchmark,
            **({"benchmark": benchmark_metadata} if benchmark_metadata else {}),
        },
        success_conditions=(expected_task,),
    )
    (runs_root / run_id).mkdir(parents=True, exist_ok=True)
    atomic_write_json(runs_root / run_id / "task.json", parent.to_dict())
    return parent, report


async def _smoke(domain: str, *, launch_benchmark: bool = False) -> int:
    run_id = _run_id(domain)
    started = time.monotonic()
    report: dict = {"domain": domain, "run_id": run_id, "started_at": datetime.now(UTC).isoformat()}
    runs_root = RUNS_ROOT / domain
    runs_root.mkdir(parents=True, exist_ok=True)
    try:
        if domain == "pentest":
            task, report = await _pentest_parent_task(
                run_id, runs_root, report, launch_benchmark=launch_benchmark
            )
        else:
            if domain == "dfir":
                sample = _dfir_sample()
                task = _task(
                    domain, run_id, sample,
                    goal=("Triage the acquired Windows security log evidence and report forensic indicators."),
                    timeout=300, allowed_roots=(REPORT_ROOT / "samples",),
                )
            elif domain == "vulnerability_research":
                sample = _vulnerability_sample()
                task = _task(
                    domain, run_id, sample,
                    goal=("Audit the supplied local C project for a reproducible crash vulnerability."),
                    timeout=300, allowed_roots=(REPORT_ROOT / "samples",),
                )
            else:
                sample = _reverse_sample()
                task = _task(
                    domain, run_id, sample,
                    goal=("Identify the format, architecture, and key function metadata of the supplied binary."),
                    timeout=600, allowed_roots=(REPORT_ROOT / "samples",),
                )
        report["goal"] = task.goal
        report["semantic_input_type"] = task.metadata.get("semantic_input_type")
        report["semantic_input_rationale"] = task.metadata.get("semantic_input_rationale")
        report["task_domain"] = task.domain
        report["target"] = task.target
        report["input_kind"] = task.metadata.get("input_kind")
        report["normalized_type"] = (
            task.metadata.get("file_type") or {}
        ).get("normalized_type")

        executor, capturer = _bounded_executor(runs_root)
        result = await executor.execute(task)
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        report["raw_model_decisions"] = capturer.decisions
        report["top_level_status"] = result.status.value
        report["top_level_error"] = result.error.to_dict() if result.error else None
        report["orchestration_status"] = result.raw_output.get("orchestration_status")
        report["decisions_used"] = result.metrics.get("decisions_used")
        report["capability_calls_used"] = result.metrics.get("capability_calls_used")
        report["tool_calls_used"] = result.metrics.get("tool_calls_used")
        world = result.raw_output.get("world_state") or {}
        report["dispatch_history"] = world.get("dispatch_history")
        report["child_task_ids"] = world.get("child_task_ids")
        report["child_summaries"] = _child_summaries(runs_root, run_id)
        return 0
    finally:
        report["finished_at"] = datetime.now(UTC).isoformat()
        REPORT_ROOT.mkdir(parents=True, exist_ok=True)
        out = REPORT_ROOT / f"report-{run_id}.json"
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description="Hunter Phase 2B live smoke")
    parser.add_argument(
        "--domain",
        required=True,
        choices=["dfir", "vulnerability_research", "reverse", "pentest"],
    )
    parser.add_argument(
        "--launch-benchmark",
        action="store_true",
        help="pentest: parent goal is the exact benchmark task and the real docker "
        "benchmark is launched under a bounded wall timeout",
    )
    args = parser.parse_args()
    _ensure_env()
    raise SystemExit(asyncio.run(_smoke(args.domain, launch_benchmark=args.launch_benchmark)))


if __name__ == "__main__":
    main()
