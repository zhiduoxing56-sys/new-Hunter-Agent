#!/usr/bin/env python3
"""Hunter-Agent Phase 3D-C DFIR availability evaluation harness.

Runs the real default Hunter entry against the real public EICAR evidence with
TRUDI Full, and records runtime availability (separately from capability) plus
the honest completion truth. No professional backend is called directly; every
result flows through the Hunter orchestrator and canonical world state.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
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
from integrations.trudi.adapter import TrudiAdapter  # noqa: E402
from pentestgpt_agent.intake import prepare_task  # noqa: E402
from pentestgpt_agent.intake.models import IntakeLimits  # noqa: E402
from pentestgpt_agent.protocol import RunLayout, TaskSpec  # noqa: E402
from pentestgpt_agent.protocol.io import atomic_write_json  # noqa: E402

EVAL_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = Path(os.environ.get("HUNTER_PHASE3DC_RESULTS", str(EVAL_ROOT / "phase3d_c_results")))
RUNS_ROOT = ROOT / ".runtime" / "phase3dc-runs"
CASES = json.loads((EVAL_ROOT / "phase3d_c_cases.json").read_text(encoding="utf-8"))["cases"]


def _key() -> str:
    with sqlite3.connect(f"file:{ROOT / '.runtime/kong/config/config.db'}?mode=ro", uri=True) as con:
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


def _bounded_executor(runs_root: Path, limits: OrchestrationLimits):
    catalog = default_catalog()
    adapters = build_hunter_brain_adapters(repo_root=ROOT, trudi_mode="full")
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


async def _full_healthcheck_record(evidence: Path) -> dict[str, Any]:
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    task = TaskSpec(
        task_id="phase3dc-healthcheck",
        domain="dfir",
        target=str(evidence.resolve()),
        goal="Healthcheck.",
        metadata={
            "trudi_mode": "full",
            "file_type": {"normalized_type": "evidence_file", "sha256": digest},
        },
    )
    adapter = TrudiAdapter(repo_root=ROOT, mode="full")
    health = await adapter.healthcheck(task)
    record = {"available": health.available, "details": health.details}
    if health.error is not None:
        record["error_code"] = health.error.code
        record["error_message"] = health.error.message
    return record


async def _run_one(case: dict, runs_root: Path) -> dict:
    run_id = f"phase3dc-{case['case_id'].replace('-', '_')}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:5]}"
    started = time.monotonic()
    rec: dict = {
        "run_id": run_id,
        "case_id": case["case_id"],
        "ground_truth_domain": case["domain"],
        "evaluation_id": "phase3d_c_2026-08-31",
        "started_at": datetime.now(UTC).isoformat(),
    }
    try:
        runs_root.mkdir(parents=True, exist_ok=True)
        source = ROOT / case["input"]["path"]
        if not source.is_file():
            raise RuntimeError(f"evidence artifact is missing: {source} (run scripts/dfir_evidence_acquire.py)")
        actual_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        expected_sha = case["input"]["sha256"]
        rec["evidence_source"] = case["input"]["source"]
        rec["evidence_sha_verified"] = actual_sha == expected_sha
        rec["evidence_sha256"] = actual_sha
        if not rec["evidence_sha_verified"]:
            raise RuntimeError(
                f"evidence SHA mismatch: expected {expected_sha} got {actual_sha}"
            )
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
        from dataclasses import replace

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
        spec = replace(
            spec,
            timeout=case.get("budget_seconds", 1800),
            metadata=metadata,
        )
        atomic_write_json(Path(spec.workspace) / "task.json", spec.to_dict())
        rec["intake_normalized_type"] = spec.metadata.get("semantic_input_type")
        rec["task_domain"] = spec.domain
        rec["trudi_mode"] = spec.metadata.get("trudi_mode")

        rec["healthcheck"] = await _full_healthcheck_record(source)

        limits = OrchestrationLimits(max_decisions=8, max_capability_calls=3, max_rejected_decisions=3)
        executor, capturer = _bounded_executor(runs_root, limits)
        result = await executor.execute(spec)
        rec["elapsed_seconds"] = round(time.monotonic() - started, 2)
        rec["hunter_top_level"] = result.status.value
        rec["orchestration_status"] = result.raw_output.get("orchestration_status")
        rec["completion_truth"] = result.raw_output.get("completion_truth")
        rec["terminal_decision"] = result.raw_output.get("terminal_decision")
        rec["terminal_error"] = result.error.to_dict() if result.error else None
        rec["supervisor_decisions"] = [d for d in capturer.decisions if isinstance(d, dict)]
        world = result.raw_output.get("world_state") or {}
        rec["dispatch"] = world.get("dispatch_history")
        rec["canonical_facts"] = len(world.get("facts", []))
        rec["canonical_evidence"] = len(world.get("evidence", []))
        rec["canonical_artifacts"] = len(world.get("artifacts", []))
        rec["children"] = _child_summaries(runs_root, run_id)
        rec["runtime"] = {
            "node_ready": (rec["healthcheck"]["details"] or {}).get("node_version") is not None,
            "claude_ready": (rec["healthcheck"]["details"] or {}).get("claude_code_version") is not None,
            "tool_count": (rec["healthcheck"]["details"] or {}).get("available_tool_count"),
            "lite_fallback": (rec["healthcheck"]["details"] or {}).get("lite_fallback"),
        }
        rec["classification"] = classify(rec)
    except Exception as exc:  # pragma: no cover - defensive
        rec["error"] = f"{type(exc).__name__}: {exc}"
        rec["classification"] = {"category": "ENVIRONMENT_FAILURE", "reason": str(exc)}
    finally:
        rec["finished_at"] = datetime.now(UTC).isoformat()
        RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
        with (RESULTS_ROOT / f"{case['case_id']}.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    return rec


def classify(rec: dict) -> dict[str, Any]:
    health = rec.get("healthcheck") or {}
    if not health.get("available"):
        return {
            "category": "RUNTIME_UNAVAILABLE",
            "error_code": health.get("error_code"),
            "reason": health.get("error_message"),
        }
    truth = rec.get("completion_truth")
    verdict = (truth or {}).get("verdict")
    orch = rec.get("orchestration_status")
    if verdict == "verified":
        return {"category": "VERIFIED_SUCCESS", "verdict": verdict, "reason": (truth or {}).get("reason")}
    if verdict == "not_verified":
        return {"category": "NOT_VERIFIED", "verdict": verdict, "reason": (truth or {}).get("reason")}
    if verdict in {"inconclusive", "unavailable"}:
        return {"category": "HONEST_INCONCLUSIVE", "verdict": verdict, "reason": (truth or {}).get("reason")}
    if orch == "complete":
        return {"category": "FALSE_SUCCESS", "reason": "complete_without_verified_truth"}
    return {"category": "HONEST_INCOMPLETE", "reason": f"terminal_{orch or 'none'}"}


async def main() -> int:
    parser = argparse.ArgumentParser(description="Hunter Phase 3D-C DFIR availability evaluation")
    parser.add_argument("--case", help="run only this case_id")
    args = parser.parse_args()
    _ensure_env()
    cases = [c for c in CASES if args.case is None or c["case_id"] == args.case]
    for case in cases:
        print(f"=== RUN {case['case_id']} ===", flush=True)
        rec = await _run_one(case, RUNS_ROOT / case["domain"])
        print(
            f"  {rec.get('case_id')} | hunter={rec.get('hunter_top_level')} "
            f"orch={rec.get('orchestration_status')} truth={(rec.get('completion_truth') or {}).get('verdict')} "
            f"class={rec.get('classification', {}).get('category')} elapsed={rec.get('elapsed_seconds')}s",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
