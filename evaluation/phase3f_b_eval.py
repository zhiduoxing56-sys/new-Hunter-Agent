#!/usr/bin/env python3
"""Phase 3F-B specialist-only control harness (post-reliability-fix).

Same specialist-only control as Phase 3F-A (real run_baseline.py, bypassing
Hunter), now running against the fixed PentestGPT/AutoPenBench runtime-budget
boundary (submodule 69a42f9). Records the Workstream D taxonomy, the
machine-readable budget ledger, and decode diagnostics per run.

Each repetition is one JSON line in evaluation/phase3f_b_results/<case_id>.jsonl.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sqlite3
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVAL_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = Path(os.environ.get("HUNTER_PHASE3FB_RESULTS", str(EVAL_ROOT / "phase3f_b_results")))
CONTROL_RUNS_ROOT = ROOT / ".runtime" / "phase3fb-runs"
CONFIG_DB = ROOT / ".runtime/kong/config/config.db"
EXPERIMENT_ID = "phase3f_b_2026-09-02"

import importlib.util  # noqa: E402

if str(EVAL_ROOT) not in sys.path:
    sys.path.insert(0, str(EVAL_ROOT))

_spec = importlib.util.spec_from_file_location("p3fa", str(EVAL_ROOT / "phase3f_a_eval.py"))
p3fa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p3fa)

import phase3f_b_taxonomy as taxonomy  # noqa: E402

CASES = json.loads((EVAL_ROOT / "phase3f_b_cases.json").read_text(encoding="utf-8"))["cases"]
TASK_TIMEOUT_SECONDS = 900


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


def _harness_sha() -> str | None:
    try:
        import subprocess

        out = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def _extract_budget_ledger(run_dir: Path) -> dict[str, Any]:
    summary = p3fa._read_json(run_dir / "summary.json") or {}
    sb = summary.get("search_budget") or {}
    return {
        "total_budget": sb.get("total_budget"),
        "remaining_budget": sb.get("remaining_budget"),
        "conservative_mode": sb.get("conservative_mode"),
        "grant_ledger": sb.get("grant_ledger"),
        "hypotheses": sb.get("hypotheses"),
    }


def _extract_decode_diagnostics(run_dir: Path) -> list[dict[str, Any]]:
    events_path = run_dir / "adapter-tool-events.jsonl"
    out = []
    if not events_path.is_file():
        return out
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("decode_error"):
            out.append({
                "kind": event.get("kind"),
                "raw_sha256": event.get("raw_sha256"),
                "raw_bytes": event.get("raw_bytes"),
                "raw_artifact": event.get("raw_artifact"),
                "command": event.get("command"),
            })
    return out


async def _run_one(case: dict, repetition_index: int) -> dict:
    harness_sha = _harness_sha()
    run_id = f"phase3fb-{case['case_id'].replace('-', '_')}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:5]}"
    backend_id = f"{run_id}-backend"
    runs_root = CONTROL_RUNS_ROOT / case["case_id"] / run_id / "backend-runs"
    workspace_root = CONTROL_RUNS_ROOT / case["case_id"] / run_id / "backend-workspaces"
    runs_root.mkdir(parents=True, exist_ok=True)
    workspace_root.mkdir(parents=True, exist_ok=True)

    command = [
        str(p3fa.PENTEST_VENV_PYTHON),
        str(p3fa.RUN_BASELINE),
        "--benchmark-root", str(p3fa.BENCHMARK_ROOT),
        "--level", "in-vitro",
        "--category", "web_security",
        "--vm", str(case["vm"]),
        *p3fa.DEFAULT_ARGS,
        "--run-id", backend_id,
        "--runs-root", str(runs_root),
        "--workspace-root", str(workspace_root),
    ]
    pythonpath = f"{ROOT}:{ROOT / 'pentestgpt-core/pentestgpt_agent/src'}"
    if os.environ.get("PYTHONPATH"):
        pythonpath += f":{os.environ['PYTHONPATH']}"
    env = os.environ.copy()
    env["PYTHONPATH"] = pythonpath

    rec: dict[str, Any] = {
        "experiment_id": EXPERIMENT_ID,
        "run_id": run_id,
        "case_id": case["case_id"],
        "repetition_index": repetition_index,
        "phase3e_snapshot_sha": "aa7dc1d",
        "pentestgpt_core_sha": "69a42f9 (Phase 3F-B fix)",
        "evaluation_harness_sha": harness_sha,
        "domain": "pentest",
        "vm": case["vm"],
        "ground_truth_domain": "pentest",
        "phase3e_counterpart": case.get("phase3e_counterpart"),
        "started_at": datetime.now(UTC).isoformat(),
        "budget_seconds": TASK_TIMEOUT_SECONDS,
    }
    started = time.monotonic()
    timed_out = False
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *command, cwd=str(ROOT), env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=TASK_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            rec["backend_exit_code"] = None
        else:
            rec["backend_exit_code"] = proc.returncode
    except Exception as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"

    rec["elapsed_seconds"] = round(time.monotonic() - started, 2)
    rec["timed_out"] = timed_out

    run_dir = runs_root / backend_id
    evaluation = p3fa._read_json(run_dir / "autopenbench-evaluation.json")
    summary = p3fa._read_json(run_dir / "summary.json")
    rec["backend_process_status"] = "timeout" if timed_out else ("completed" if rec.get("backend_exit_code") == 0 else "failed")

    if evaluation:
        judge = evaluation.get("judge") or {}
        rec["judge"] = {
            "oracle": judge.get("oracle"),
            "submitted_answers": judge.get("submitted_answers"),
            "success": judge.get("success"),
            "actual_kali_commands": judge.get("actual_kali_commands"),
            "valid_execution": judge.get("valid_execution"),
        }
        rec["evaluation_result"] = evaluation.get("result")
        rec["run_error"] = evaluation.get("run_error")
    else:
        rec["judge"] = {"present": False}

    mq = run_dir / "model-requests.jsonl"
    rec["model_request_count"] = sum(1 for _ in open(mq)) if mq.is_file() else 0

    decomposition = p3fa.decompose_specialist_summary(summary)
    rec["specialist"] = decomposition
    rec["last_successful_stage"] = decomposition["last_successful_stage"]
    rec["error_kind"] = decomposition["error_kind"]

    rec["budget_ledger"] = _extract_budget_ledger(run_dir)
    rec["decode_diagnostics"] = _extract_decode_diagnostics(run_dir)

    rec["verified_success"] = bool(rec.get("judge", {}).get("success"))
    rec["primary_class"] = taxonomy.classify_primary(rec)
    rec["taxonomy_category"] = rec["primary_class"]

    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    rec["finished_at"] = datetime.now(UTC).isoformat()
    with (RESULTS_ROOT / f"{case['case_id']}.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    return rec


async def _run_cases(case_ids: list[str] | None, repetitions: int, from_repetition: int) -> int:
    selected = [c for c in CASES if case_ids is None or c["case_id"] in case_ids]
    for case in selected:
        for rep in range(from_repetition, from_repetition + repetitions):
            print(f"=== RUN {case['case_id']} repetition {rep} ===", flush=True)
            rec = await _run_one(case, rep)
            ledger = rec.get("budget_ledger") or {}
            print(
                f"  {case['case_id']}[{rep}] | judge={rec.get('judge', {}).get('success')} "
                f"tax={rec.get('taxonomy_category')} stage={rec.get('last_successful_stage')} "
                f"err={rec.get('error_kind')} model_req={rec.get('model_request_count')} "
                f"dur={rec.get('elapsed_seconds')}s exit={rec.get('backend_exit_code')} "
                f"budget_rem={ledger.get('remaining_budget')} decode={len(rec.get('decode_diagnostics') or [])}",
                flush=True,
            )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 3F-B specialist-only control")
    parser.add_argument("--case", help="run only this case_id")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--from-repetition", type=int, default=1)
    args = parser.parse_args()
    _ensure_env()
    case_ids = [args.case] if args.case else None
    return asyncio.run(_run_cases(case_ids, args.repetitions, args.from_repetition))


if __name__ == "__main__":
    raise SystemExit(main())
