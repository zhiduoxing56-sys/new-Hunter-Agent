#!/usr/bin/env python3
"""Phase 2D: real TRUDI -> Kong cross-domain autonomous handoff smoke.

Runs the real default Hunter entry (intake-framed TaskSpec -> real supervisor
model -> real TRUDI -> canonical state -> real supervisor model -> real Kong)
and records the auditable decision chain, artifacts, evidence and question
resolutions. No backend internal function is called; everything flows through
the Hunter orchestrator.

The evidence is a real small ELF framed as forensic evidence (the scenario the
user goal describes: "investigate this evidence, locate the exported suspicious
binary, reverse it"). TRUDI lite exports it as a ``suspect_binary`` artifact,
which routes to the reverse capability and is consumed by Kong.
"""

from __future__ import annotations

import asyncio
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
from hunter_brain.orchestrator import HunterOrchestrator, OrchestrationLimits  # noqa: E402
from hunter_brain.invocation_bridge import PentestBenchmarkBridge  # noqa: E402
from hunter_brain.question_generator import CrossDomainQuestionGenerator  # noqa: E402
from hunter_brain.result_interpreter import EvidenceGroundedResultInterpreter  # noqa: E402
from hunter_brain.supervisor import (  # noqa: E402
    DeepSeekDecisionModel,
    DeepSeekSupervisorConfig,
    HunterSupervisor,
)
from hunter_brain.verifier import GlobalVerifier  # noqa: E402
from integrations.hunter_brain import HunterBrainTaskExecutor, build_hunter_brain_adapters  # noqa: E402
from pentestgpt_agent.protocol import (  # noqa: E402
    AuthorizationScope,
    InputObject,
    RunLayout,
    TargetObject,
    TaskSpec,
)
from pentestgpt_agent.protocol.io import atomic_write_json  # noqa: E402

CONFIG_DB = ROOT / ".runtime" / "kong" / "config" / "config.db"
RUNS_ROOT = ROOT / ".runtime" / "live-runs" / "cross-domain"
REPORT_ROOT = ROOT / ".runtime" / "live-smoke"


def _key() -> str:
    with sqlite3.connect(f"file:{CONFIG_DB}?mode=ro", uri=True) as con:
        row = con.execute("SELECT value FROM config WHERE key='custom_api_key'").fetchone()
    if not row or not isinstance(row[0], str) or not row[0].strip():
        raise SystemExit("DeepSeek key missing from Kong config.db")
    return row[0].strip()


def _env() -> None:
    key = _key()
    os.environ.update({
        "DEEPSEEK_API_KEY": key,
        "HUNTER_MODEL_API_KEY": key,
        "HUNTER_MODEL_NAME": "deepseek-v4-flash",
        "HUNTER_MODEL_BASE_URL": "https://api.deepseek.com",
        "JAVA_HOME": str(ROOT.parent / ".tools" / "jdk21"),
        "GHIDRA_INSTALL_DIR": str(ROOT.parent / ".tools/ghidra-12.0.4/ghidra_12.0.4_PUBLIC"),
        "KONG_CONFIG_DIR": str(ROOT / ".runtime/kong/config"),
        "KONG_PROVIDER": "custom",
        "KONG_BASE_URL": "https://api.deepseek.com",
        "KONG_MODEL": "deepseek-v4-flash",
    })


class CapturingModel:
    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.decisions: list[dict] = []

    async def decide(self, *, system_instructions: str, context: dict) -> Any:
        result = await self.inner.decide(system_instructions=system_instructions, context=context)
        self.decisions.append(dict(result.value))
        return result


def _bounded_executor(runs_root: Path):
    catalog = default_catalog()
    adapters = build_hunter_brain_adapters(repo_root=ROOT)
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
            limits=OrchestrationLimits(max_decisions=8, max_capability_calls=3, max_rejected_decisions=3),
        )
    )
    return executor, capturer


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


def _build_task(run_id: str, elf: Path) -> TaskSpec:
    digest = __import__("hashlib").sha256(elf.read_bytes()).hexdigest()
    workspace = RUNS_ROOT / run_id
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
        timeout=600,
        workspace=str(workspace),
        metadata={
            "input_kind": "file",
            "semantic_input_type": "evidence_file",
            "semantic_input_rationale": ["ELF framed as forensic evidence for triage-first investigation"],
            "file_type": {"normalized_type": "evidence_file", "sha256": digest},
            "export_evidence_artifact": True,
        },
        input_object=InputObject(
            "input", "file", str(elf), path=str(elf),
            source_name=elf.name, sha256=digest, size_bytes=elf.stat().st_size,
        ),
        target_object=TargetObject("target", "evidence_file", str(elf)),
        authorization=AuthorizationScope((str(elf),), allowed_read_paths=(str(elf),)),
    )
    atomic_write_json(workspace / "task.json", task.to_dict())
    return task


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
        if task_path.is_file():
            entry["domain"] = TaskSpec.from_dict(
                json.loads(task_path.read_text(encoding="utf-8"))
            ).domain
        if result_path.is_file():
            layout = RunLayout.ensure(subtasks, TaskSpec.from_dict(
                json.loads(task_path.read_text(encoding="utf-8"))
            ))
            result = layout.read_result()
            result.validate()
            entry["agent_id"] = result.agent_id
            entry["status"] = result.status.value
            entry["findings"] = len(result.findings)
            entry["evidence"] = len(result.evidence)
            entry["artifacts"] = [a.type for a in result.artifacts]
            entry["summary"] = result.summary
            entry["metrics"] = result.metrics
            entry["error"] = result.error.to_dict() if result.error else None
        out.append(entry)
    return out


async def main() -> int:
    run_id = f"live-cross-domain-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    started = time.monotonic()
    report: dict = {"run_id": run_id, "started_at": datetime.now(UTC).isoformat()}
    try:
        elf = REPORT_ROOT / "samples" / "evidence_suspect"
        elf.parent.mkdir(parents=True, exist_ok=True)
        _compile_elf(elf)
        report["evidence"] = str(elf)
        task = _build_task(run_id, elf)
        report["goal"] = task.goal
        report["success_conditions"] = list(task.success_conditions)
        report["semantic_input_type"] = task.metadata["semantic_input_type"]

        executor, capturer = _bounded_executor(RUNS_ROOT)
        result = await executor.execute(task)
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        report["top_level_status"] = result.status.value
        report["orchestration_status"] = result.raw_output.get("orchestration_status")
        report["top_level_error"] = result.error.to_dict() if result.error else None
        report["decisions_used"] = result.metrics.get("decisions_used")
        report["raw_model_decisions"] = capturer.decisions
        world = result.raw_output.get("world_state") or {}
        report["dispatch"] = world.get("dispatch_history")
        report["unresolved_questions"] = world.get("unresolved_questions")
        report["facts"] = world.get("facts")
        report["evidence"] = world.get("evidence")
        report["artifacts"] = world.get("artifacts")
        report["terminal_decision"] = result.raw_output.get("terminal_decision")
        report["child_summaries"] = _child_summaries(RUNS_ROOT, run_id)
        return 0
    finally:
        report["finished_at"] = datetime.now(UTC).isoformat()
        REPORT_ROOT.mkdir(parents=True, exist_ok=True)
        path = REPORT_ROOT / f"report-{run_id}.json"
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    _env()
    raise SystemExit(asyncio.run(main()))
